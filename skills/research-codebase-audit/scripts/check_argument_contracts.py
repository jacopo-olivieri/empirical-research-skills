#!/usr/bin/env python3
"""Emit deterministic cross-language script argument-contract findings."""

import argparse
import ast
import hashlib
import json
import os
import posixpath
import re
import shlex
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import source_projection


SCHEMA = "ac-raw/v1"
CALL_COLS = [
    "Source ID", "Site Anchor", "Caller Adapter", "Interpreter",
    "Callee Token", "Resolved Callee", "Resolution", "Passed Positions",
    "Read Positions", "Outcome",
]
FINDING_COLS = [
    "Source ID", "Witness ID", "Finding Kind", "Argument Position",
    "Callee Path", "Site Anchor",
]
FINDING_KINDS = {
    "passed_but_unread", "read_but_never_passed", "unresolved_callee",
}
OUTCOMES = {"consumed", "contract_mismatch", "unresolved_callee"}
RESOLUTIONS = {
    "direct", "macro_direct", "audited_root_alias",
    "unresolved_unknown_option", "unresolved_unknown_path",
    "unresolved_ambiguous_path", "unresolved_syntax",
    "unresolved_interpreter",
}
SCRIPT_EXTENSIONS = {".py", ".r", ".jl", ".do", ".ado", ".sh", ".bash", ".zsh"}
CALLER_EXTENSIONS = SCRIPT_EXTENSIONS
INTERPRETER_NAMES = {
    "python": "python", "python2": "python", "python3": "python",
    "rscript": "r", "r": "r", "julia": "julia",
    "stata": "stata", "stata-mp": "stata", "stata-se": "stata",
    "sh": "shell", "bash": "shell", "zsh": "shell", "dash": "shell",
}

# spelling -> (operand count, separate form, attached-with-= form)
OPTION_TABLES = {
    "python": {
        "-B": (0, True, False), "-E": (0, True, False),
        "-I": (0, True, False), "-O": (0, True, False),
        "-OO": (0, True, False), "-s": (0, True, False),
        "-S": (0, True, False), "-u": (0, True, False),
        "-v": (0, True, False), "-W": (1, True, False),
        "-X": (1, True, False),
    },
    "r": {
        "--vanilla": (0, True, False), "--no-echo": (0, True, False),
        "--no-restore": (0, True, False), "--no-save": (0, True, False),
        "--slave": (0, True, False), "--verbose": (0, True, False),
        "--encoding": (1, True, True),
    },
    "julia": {
        "--banner": (1, True, True), "--color": (1, True, True),
        "--compile": (1, True, True), "--depwarn": (1, True, True),
        "--project": (1, True, True), "--startup-file": (1, True, True),
        "--threads": (1, True, True), "-t": (1, True, False),
        "-O": (1, True, False), "-q": (0, True, False),
        "--quiet": (0, True, False),
    },
    "stata": {
        "-b": (0, True, False), "-e": (0, True, False),
        "-q": (0, True, False), "-s": (0, True, False),
    },
    "shell": {
        "-e": (0, True, False), "-u": (0, True, False),
        "-x": (0, True, False), "-eu": (0, True, False),
        "-eux": (0, True, False),
    },
}


class ArgumentContractError(RuntimeError):
    """The argument-contract artifact or source is malformed."""


@dataclass(frozen=True)
class RawInvocation:
    caller: str
    line: int
    offset: int
    adapter: str
    tokens: tuple[str, ...]
    expanded: bool = False
    alias_suffix: str | None = None
    syntax_error: bool = False


@dataclass(frozen=True)
class CallSite:
    source_id: str
    site_anchor: str
    caller_adapter: str
    interpreter: str
    callee_token: str
    resolved_callee: str
    resolution: str
    passed_positions: tuple[int, ...]
    read_positions: tuple[int, ...]
    outcome: str


@dataclass(frozen=True)
class Finding:
    source_id: str
    witness_id: str
    finding_kind: str
    argument_position: str
    callee_path: str
    site_anchor: str


@dataclass(frozen=True)
class Artifact:
    projection_sha256: str
    call_sites: tuple[CallSite, ...]
    findings: tuple[Finding, ...]


def _read_manifest(audit):
    path = Path(audit) / "_run" / "manifest.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArgumentContractError(f"cannot read manifest {path}: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ArgumentContractError(f"{path}: expected a JSON object")
    return manifest


def _projected_files(package_root, manifest):
    return source_projection.audited_regular_files(package_root, manifest)


def projection_digest(package_root, manifest):
    records = []
    root = Path(package_root).resolve()
    for path in _projected_files(root, manifest):
        relative = path.relative_to(root).as_posix()
        records.append((relative, hashlib.sha256(path.read_bytes()).hexdigest()))
    wire = "\n".join(f"{path},{digest}" for path, digest in sorted(records))
    return hashlib.sha256(wire.encode("utf-8")).hexdigest()


def _literal_assignments(text, adapter):
    values = {}
    patterns = {
        "shell": re.compile(r"(?m)^\s*([A-Za-z_]\w*)\s*=\s*(['\"])(.*?)\2\s*$"),
        "r": re.compile(r"(?m)^\s*([A-Za-z_]\w*)\s*(?:<-|=)\s*(['\"])(.*?)\2\s*$"),
        "julia": re.compile(r"(?m)^\s*([A-Za-z_]\w*)\s*=\s*(['\"])(.*?)\2\s*$"),
    }
    pattern = patterns.get(adapter)
    if pattern:
        for match in pattern.finditer(text):
            values[match.group(1)] = match.group(3)
    return values


_STATA_ASSIGN_RE = re.compile(
    r"(?im)^\s*(global|local)\s+([A-Za-z_]\w*)\s+(['\"])(.*?)\3\s*$"
)


def _stata_literal_assignments(text):
    """Split one Stata file's literal assignments by namespace."""
    namespaces = {"global": {}, "local": {}}
    for match in _STATA_ASSIGN_RE.finditer(text):
        namespaces[match.group(1).lower()][match.group(2)] = match.group(4)
    return namespaces


def stata_global_table(files):
    """Package-wide literal ``global`` values from every projected do/ado file.

    Conservative lexical inference: no execution order, no ``include`` flow, no
    conditionals.  A name assigned two *different* literal values anywhere in
    the package is unresolvable and is dropped; equal values never conflict.
    """
    values, conflicting = {}, set()
    for path in files:
        if path.suffix.lower() not in {".do", ".ado"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for name, value in _stata_literal_assignments(text)["global"].items():
            if name in values and values[name] != value:
                conflicting.add(name)
            values.setdefault(name, value)
    return {name: value for name, value in values.items()
            if name not in conflicting}


_VAR_RE = re.compile(
    r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)|`([A-Za-z_]\w*)'"
)


def _reference_syntax(match):
    """Return the namespace a reference addresses: ``global`` or ``local``."""
    return "local" if match.group(3) is not None else "global"


class MacroScope:
    """Name lookup for macro expansion, split by reference syntax.

    Non-Stata adapters keep a single namespace: both syntaxes read the same
    map, so their behavior is unchanged.  The Stata adapter passes distinct
    maps, and the two namespaces never merge.
    """

    def __init__(self, global_values, local_values=None):
        self._values = {
            "global": dict(global_values),
            "local": dict(global_values if local_values is None else local_values),
        }

    def resolve(self, name, syntax):
        return self._values[syntax].get(name)


def _scope(variables):
    """Accept either a plain single-namespace mapping or an existing scope."""
    return variables if isinstance(variables, MacroScope) else MacroScope(variables)


def _expand_text(value, variables, stack=()):
    scope = _scope(variables)
    expanded = False
    alias_suffix = None
    unresolved_leading = None

    def replace(match):
        nonlocal expanded, unresolved_leading
        name = next(group for group in match.groups() if group is not None)
        if name in stack:
            raise ArgumentContractError(f"literal macro/global expansion cycle at {name}")
        replacement_value = scope.resolve(name, _reference_syntax(match))
        if replacement_value is None:
            if match.start() == 0:
                unresolved_leading = match.end()
            return match.group(0)
        expanded = True
        replacement, _was_expanded, _suffix, _unresolved = _expand_text(
            replacement_value, scope, stack + (name,)
        )
        return replacement

    result = _VAR_RE.sub(replace, value)
    if unresolved_leading is not None:
        alias_suffix = result[unresolved_leading:].lstrip("/\\")
    elif expanded:
        first = _VAR_RE.match(value)
        if first:
            original_tail = value[first.end():].lstrip("/\\")
            root_name = next(group for group in first.groups() if group is not None)
            root_value, *_ = _expand_text(
                scope.resolve(root_name, _reference_syntax(first)), scope,
                stack + (root_name,),
            )
            if (_placeholder(root_value) or _absolute_external(root_value)) and original_tail:
                alias_suffix = original_tail
    return result, expanded, alias_suffix, unresolved_leading is not None


def _placeholder(value):
    return bool(re.match(r"^\[[^\]]*(?:path|root|directory|dir)[^\]]*\]", value, re.I))


def _absolute_external(value):
    return value.startswith(("/", "\\")) or bool(re.match(r"^[A-Za-z]:[\\/]", value))


def _operator_token(token):
    return bool(token) and set(token) <= set(";|&")


def _redirection_token(token):
    return (bool(token) and set(token) <= set("<>&")
            and ("<" in token or ">" in token))


def _tokenize_command(command):
    """Quote-aware lex of one command string; operator runs become tokens."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars="<>|&;")
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def _strip_redirections(tokens):
    stripped, index = [], 0
    while index < len(tokens):
        token = tokens[index]
        if _redirection_token(token):
            index += 2  # drop the operator and its operand
            continue
        if (token.isdigit() and index + 1 < len(tokens)
                and _redirection_token(tokens[index + 1])):
            index += 3  # drop fd, operator, and operand (e.g. 2>&1)
            continue
        stripped.append(token)
        index += 1
    return stripped


def _segment_commands(command, strip_control=False):
    """Split a command string on ;/&&/||/|/& into per-command token lists."""
    segments, current = [], []
    for token in _tokenize_command(command):
        if _operator_token(token):
            if current:
                segments.append(current)
            current = []
        else:
            current.append(token)
    if current:
        segments.append(current)
    cleaned = []
    for segment in segments:
        segment = _strip_redirections(segment)
        if strip_control:
            while segment and segment[0] in {"do", "then"}:
                segment = segment[1:]
        if segment:
            cleaned.append(segment)
    return cleaned


def _lex(command, variables, strip_control=False):
    """Lex a command string into one (tokens, expanded, alias, bad) per command."""
    try:
        segments = _segment_commands(command, strip_control)
    except ValueError:
        return [((), False, None, True)]
    results = []
    for segment in segments:
        tokens, any_expanded, alias_suffix = [], False, None
        try:
            for token in segment:
                value, expanded, suffix, _unresolved = _expand_text(token, variables)
                tokens.append(value)
                any_expanded |= expanded
                if suffix and (Path(value.replace("\\", "/")).suffix.lower()
                               in SCRIPT_EXTENSIONS):
                    alias_suffix = suffix
        except ArgumentContractError:
            results.append(((), False, None, True))
            continue
        results.append((tuple(tokens), any_expanded, alias_suffix, False))
    return results


def _python_value(node, variables):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, (ast.List, ast.Tuple)):
        values = [_python_value(item, variables) for item in node.elts]
        if all(isinstance(item, str) for item in values):
            return values
    if isinstance(node, ast.Name):
        return variables.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _python_value(node.left, variables), _python_value(node.right, variables)
        if isinstance(left, str) and isinstance(right, str):
            return left + right
        if isinstance(left, list) and isinstance(right, list):
            return left + right
    if isinstance(node, ast.JoinedStr):
        parts = []
        for item in node.values:
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                parts.append(item.value)
            elif isinstance(item, ast.FormattedValue) and isinstance(item.value, ast.Name):
                value = variables.get(item.value.id)
                if not isinstance(value, str):
                    return None
                parts.append(value)
            else:
                return None
        return "".join(parts)
    return None


def _python_invocations(relative, text):
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    variables = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value_node = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = _python_value(value_node, variables)
            for target in targets:
                if isinstance(target, ast.Name) and value is not None:
                    variables[target.id] = value
    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        name = ""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            name = f"{node.func.value.id}.{node.func.attr}"
        allowed = {
            "subprocess.run", "subprocess.call", "subprocess.Popen",
            "subprocess.check_call", "subprocess.check_output", "os.system",
        }
        if name not in allowed:
            continue
        value = _python_value(node.args[0], variables)
        if isinstance(value, str):
            results = _lex(value, {})
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            results = [(tuple(value), False, None, False)]
        else:
            results = [((), False, None, True)]
        for index, (tokens, expanded, alias, bad) in enumerate(results):
            calls.append(RawInvocation(
                relative, node.lineno, node.col_offset + index, name, tokens,
                expanded, alias, bad,
            ))
    return calls


def _call_arg_text(body, start):
    quote = None
    depth = 0
    for index in range(start, len(body)):
        char = body[index]
        if quote:
            if char == quote and (index == 0 or body[index - 1] != "\\"):
                quote = None
            continue
        if char in {'"', "'", "`"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return body[start + 1:index], index + 1
    return None, start


def _quoted_values(value):
    return [match.group(2) for match in re.finditer(r"(['\"])(.*?)\1", value, re.S)]


def _r_invocations(relative, text):
    variables = _literal_assignments(text, "r")
    calls = []
    for match in re.finditer(r"\b(system2?|SYSTEM2?)\s*\(", text):
        args, _end = _call_arg_text(text, match.end() - 1)
        if args is None:
            calls.append(RawInvocation(relative, text.count("\n", 0, match.start()) + 1,
                                       match.start(), "r:system", (), syntax_error=True))
            continue
        values = _quoted_values(args)
        if not values:
            calls.append(RawInvocation(relative, text.count("\n", 0, match.start()) + 1,
                                       match.start(), "r:system", (), syntax_error=True))
            continue
        command = values[0] if match.group(1).lower() == "system" else " ".join(values)
        for index, (tokens, expanded, alias, bad) in enumerate(_lex(command, variables)):
            calls.append(RawInvocation(
                relative, text.count("\n", 0, match.start()) + 1, match.start() + index,
                f"r:{match.group(1).lower()}", tokens, expanded, alias, bad,
            ))
    return calls


def _julia_invocations(relative, text):
    variables = _literal_assignments(text, "julia")
    calls = []
    for match in re.finditer(r"\brun\s*\(\s*`([^`]*)`\s*\)", text):
        for index, (tokens, expanded, alias, bad) in enumerate(
                _lex(match.group(1), variables)):
            calls.append(RawInvocation(
                relative, text.count("\n", 0, match.start()) + 1, match.start() + index,
                "julia:run", tokens, expanded, alias, bad,
            ))
    return calls


def _stata_invocations(relative, text, cross_file_globals=None):
    namespaces = _stata_literal_assignments(text)
    # Namespaces never merge; a same-file global overrides a cross-file value.
    variables = MacroScope({**(cross_file_globals or {}), **namespaces["global"]},
                           namespaces["local"])
    calls = []
    offset = 0
    for line_no, line in enumerate(text.splitlines(keepends=True), start=1):
        match = re.match(r"\s*(?:!|shell\b|winexec\b)\s*(.*)$", line, re.I)
        if match:
            for index, (tokens, expanded, alias, bad) in enumerate(
                    _lex(match.group(1), variables)):
                calls.append(RawInvocation(
                    relative, line_no, offset + match.start() + index, "stata:shell",
                    tokens, expanded, alias, bad,
                ))
        offset += len(line.encode("utf-8"))
    return calls


def _logical_lines(text):
    """Join backslash line continuations; yield (first physical line, text)."""
    lines = text.split("\n")
    joined, index = [], 0
    while index < len(lines):
        start = index + 1
        line = lines[index].rstrip("\r")
        while line.rstrip().endswith("\\") and index + 1 < len(lines):
            line = line.rstrip()[:-1] + " " + lines[index + 1].rstrip("\r").strip()
            index += 1
        joined.append((start, line))
        index += 1
    return joined


def _shell_invocations(relative, text):
    variables = _literal_assignments(text, "shell")
    line_offsets, total = [], 0
    for line in text.split("\n"):
        line_offsets.append(total)
        total += len(line.encode("utf-8")) + 1
    calls = []
    for line_no, line in _logical_lines(text):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or re.match(
                r"^[A-Za-z_]\w*\s*=", stripped):
            continue
        results = _lex(line, variables, strip_control=True)
        if any(bad for _tokens, _expanded, _alias, bad in results):
            # Only an invocation-shaped line may mint an unresolved finding:
            # a non-command line with an odd quote (a heredoc body, prose)
            # is skipped rather than flagged.
            first = stripped.split()[0] if stripped.split() else ""
            if _interpreter((first,))[0] is None:
                results = [item for item in results if not item[3]]
        base = line_offsets[line_no - 1]
        for index, (tokens, expanded, alias, bad) in enumerate(results):
            if tokens or bad:
                calls.append(RawInvocation(
                    relative, line_no, base + index, "shell",
                    tokens, expanded, alias, bad,
                ))
    return calls


def _invocations(path, package_root, stata_globals=None):
    relative = path.relative_to(package_root).as_posix()
    suffix = path.suffix.lower()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    if suffix == ".py":
        return _python_invocations(relative, text)
    if suffix == ".r":
        return _r_invocations(relative, text)
    if suffix == ".jl":
        return _julia_invocations(relative, text)
    if suffix in {".do", ".ado"}:
        return _stata_invocations(relative, text, stata_globals)
    if suffix in {".sh", ".bash", ".zsh"}:
        return _shell_invocations(relative, text)
    return []


def _normalize_candidate(value):
    value = value.replace("\\", "/")
    drive = re.match(r"^[A-Za-z]:/", value)
    leading = value.startswith("/") or bool(drive)
    prefix = value[:2] if drive else ""
    body = value[2:] if drive else value
    depth = 0
    for part in body.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            depth -= 1
            if depth < 0 and not leading:
                raise ArgumentContractError("candidate path escapes its suffix")
        else:
            depth += 1
    normalized = posixpath.normpath(value)
    if normalized == ".." or normalized.startswith("../"):
        raise ArgumentContractError("candidate path escapes its suffix")
    return prefix + normalized[2:] if drive and not normalized.startswith(prefix) else normalized


def _interpreter(tokens):
    if not tokens:
        return None, 0
    base = Path(tokens[0].replace("\\", "/")).name.lower()
    base = re.sub(r"(?:\.exe)$", "", base)
    if base in INTERPRETER_NAMES:
        return INTERPRETER_NAMES[base], 1
    if Path(base).suffix.lower() in SCRIPT_EXTENSIONS:
        return "direct", 0
    return None, 0


def _consume_options(interpreter, tokens, index):
    table = OPTION_TABLES.get(interpreter, {})
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return index + 1, None
        if not token.startswith("-") or token == "-":
            break
        exact = table.get(token)
        attached = None
        if exact is None and "=" in token:
            spelling = token.split("=", 1)[0]
            option = table.get(spelling)
            if option and option[2] and token.split("=", 1)[1]:
                attached = option
        option = exact or attached
        if option is None:
            return index, "unresolved_unknown_option"
        arity, separate, _attached = option
        if attached is not None:
            index += 1
            continue
        if not separate or index + arity >= len(tokens):
            return index, "unresolved_unknown_option"
        index += 1 + arity
    if interpreter == "stata" and index < len(tokens) and tokens[index].lower() == "do":
        index += 1
    return index, None


def _suffix_matches(suffix, projected):
    parts = tuple(part for part in suffix.replace("\\", "/").split("/") if part not in {"", "."})
    if not parts:
        return [], False
    for start in range(len(parts)):
        probe = parts[start:]
        matches = [path for path in projected
                   if len(path.parts) >= len(probe) and tuple(path.parts[-len(probe):]) == probe]
        if matches:
            return matches, len(matches) > 1
    return [], False


def _display_token(token, alias_suffix):
    """Keep the raw artifact free of machine-specific absolute host prefixes."""
    if _absolute_external(token):
        suffix = (alias_suffix or Path(token.replace("\\", "/")).name).lstrip("/\\")
        return "<audited-root>/" + suffix
    return token


def _interpreter_candidate(tokens):
    """Return the callee candidate of a macro-fronted call, or None.

    The trigger is adapter-independent: after expansion the first token still
    carries an unresolved macro reference and a *later* token carries a known
    script extension.  The first such later token is the candidate; further
    tokens are never scanned for a more convenient script.
    """
    if not tokens or not _VAR_RE.search(tokens[0]):
        return None
    for token in tokens[1:]:
        if Path(token.replace("\\", "/")).suffix.lower() in SCRIPT_EXTENSIONS:
            return token
    return None


def _candidate_path(token, projected):
    """Resolve the callee candidate, but only when it uniquely matches."""
    try:
        normalized = _normalize_candidate(token)
    except ArgumentContractError:
        return ""
    direct = normalized.lstrip("./")
    if direct in projected:
        return direct
    matches, ambiguous = _suffix_matches(direct, [Path(item) for item in projected])
    return matches[0].as_posix() if len(matches) == 1 and not ambiguous else ""


def _resolve(raw, projected):
    if raw.syntax_error or not raw.tokens:
        return "unknown", "", "", (), "unresolved_syntax"
    interpreter, index = _interpreter(raw.tokens)
    if interpreter is None:
        candidate = _interpreter_candidate(raw.tokens)
        if candidate is not None:
            # The interpreter is exactly what could not be resolved.
            return ("unknown", _display_token(candidate, raw.alias_suffix),
                    _candidate_path(candidate, projected), (),
                    "unresolved_interpreter")
        return "unknown", "", "", (), "unresolved_syntax"
    if interpreter != "direct":
        index, failure = _consume_options(interpreter, raw.tokens, index)
        if failure:
            return interpreter, "", "", (), failure
    if index >= len(raw.tokens):
        return interpreter, "", "", (), "unresolved_syntax"
    callee_token = raw.tokens[index]
    display_token = _display_token(callee_token, raw.alias_suffix)
    try:
        normalized = _normalize_candidate(callee_token)
    except ArgumentContractError:
        return interpreter, display_token, "", (), "unresolved_syntax"
    if Path(normalized).suffix.lower() not in SCRIPT_EXTENSIONS:
        return interpreter, display_token, "", (), "unresolved_unknown_path"
    direct = normalized.lstrip("./")
    if direct in projected:
        resolution = "macro_direct" if raw.expanded else "direct"
        return interpreter, display_token, direct, raw.tokens[index + 1:], resolution
    suffix = raw.alias_suffix
    if not suffix and (_placeholder(normalized) or _absolute_external(normalized)
                       or _VAR_RE.match(normalized)):
        if _VAR_RE.match(normalized):
            match = _VAR_RE.match(normalized)
            suffix = normalized[match.end():].lstrip("/\\")
        elif _placeholder(normalized):
            end = normalized.find("]") + 1
            suffix = normalized[end:].lstrip("/\\")
        else:
            suffix = normalized.lstrip("/")
    if suffix:
        try:
            suffix = _normalize_candidate(suffix)
        except ArgumentContractError:
            return interpreter, display_token, "", (), "unresolved_syntax"
        matches, ambiguous = _suffix_matches(suffix, [Path(item) for item in projected])
        if ambiguous:
            return interpreter, display_token, "", (), "unresolved_ambiguous_path"
        if len(matches) == 1:
            return (interpreter, display_token, matches[0].as_posix(),
                    raw.tokens[index + 1:], "audited_root_alias")
    return interpreter, display_token, "", (), "unresolved_unknown_path"


def _read_positions(path, passed_count):
    text = path.read_text(encoding="utf-8", errors="replace")
    suffix = path.suffix.lower()
    positions = set()
    read_all = False
    if suffix == ".jl":
        positions |= {int(value) for value in re.findall(r"ARGS\s*\[\s*(\d+)\s*\]", text)}
        read_all = bool(re.search(r"\b(?:for\s+\w+\s+in\s+ARGS|ARGS\s*\.\.\.|eachindex\s*\(\s*ARGS)", text))
    elif suffix == ".py":
        positions |= {int(value) for value in re.findall(r"sys\.argv\s*\[\s*(\d+)\s*\]", text)
                     if int(value) > 0}
        positional = []
        try:
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "add_argument" and node.args
                        and isinstance(node.args[0], ast.Constant)
                        and isinstance(node.args[0].value, str)
                        and not node.args[0].value.startswith("-")):
                    positional.append((node.lineno, node.args[0].value))
        except SyntaxError:
            pass
        positions |= set(range(1, len(sorted(positional)) + 1))
        read_all = bool(re.search(r"sys\.argv\s*\[\s*1\s*:\s*\]", text))
    elif suffix == ".r":
        variables = re.findall(r"([A-Za-z_.]\w*)\s*<-\s*commandArgs\s*\([^)]*trailingOnly\s*=\s*TRUE", text, re.I)
        for variable in variables:
            positions |= {int(value) for value in re.findall(
                rf"\b{re.escape(variable)}\s*\[\[?\s*(\d+)\s*\]?\]", text)}
        read_all = bool(variables and any(re.search(
            rf"\b(?:for\s*\([^)]*\bin\s+{re.escape(variable)}\b|lapply\s*\(\s*{re.escape(variable)})",
            text) for variable in variables))
    elif suffix in {".do", ".ado"}:
        for match in re.finditer(r"(?im)^\s*args\s+([^\r\n]+)", text):
            names = [part for part in re.split(r"\s+", match.group(1).strip()) if part]
            positions |= set(range(1, len(names) + 1))
        read_all = bool(re.search(r"`0'", text))
    elif suffix in {".sh", ".bash", ".zsh"}:
        positions |= {int(value) for value in re.findall(r"\$(?:\{)?(\d+)(?:\})?", text)
                     if int(value) > 0}
        read_all = bool(re.search(r"\$(?:@|\*)|\$\{(?:@|\*)\}", text))
    if read_all:
        positions |= set(range(1, passed_count + 1))
    return tuple(sorted(positions))


def source_id(caller, line, ordinal):
    raw = f"ac-call/v1\0{caller}\0{line}\0{ordinal}".encode("utf-8")
    return "AC-" + hashlib.sha256(raw).hexdigest()[:12]


def scan(package_root, audit):
    root = Path(package_root).resolve()
    manifest = _read_manifest(audit)
    files = _projected_files(root, manifest)
    projected = {path.relative_to(root).as_posix(): path for path in files
                 if path.suffix.lower() in SCRIPT_EXTENSIONS}
    stata_globals = stata_global_table(files)
    raw_calls = []
    for path in files:
        if path.suffix.lower() in CALLER_EXTENSIONS:
            raw_calls.extend(
                raw for raw in _invocations(path, root, stata_globals)
                if raw.syntax_error or _interpreter(raw.tokens)[0] is not None
                or _interpreter_candidate(raw.tokens) is not None
            )
    grouped = {}
    for raw in sorted(raw_calls, key=lambda item: (item.caller, item.line, item.offset)):
        grouped.setdefault((raw.caller, raw.line), []).append(raw)
    calls, findings, identities = [], [], set()
    for (caller, line), group in sorted(grouped.items()):
        for ordinal, raw in enumerate(sorted(group, key=lambda item: item.offset), start=1):
            sid = source_id(caller, line, ordinal)
            identity = (caller, line, ordinal)
            if identity in identities or any(call.source_id == sid for call in calls):
                raise ArgumentContractError(f"duplicate or colliding AC call identity {sid}")
            identities.add(identity)
            interpreter, token, callee, passed, resolution = _resolve(raw, set(projected))
            anchor = f"{caller}:{line}@call={ordinal}"
            if resolution.startswith("unresolved_"):
                calls.append(CallSite(
                    sid, anchor, raw.adapter, interpreter, token or "—",
                    callee or "—", resolution, (), (), "unresolved_callee",
                ))
                findings.append(Finding(
                    sid, "callsite", "unresolved_callee", "—", token or "—", anchor,
                ))
                continue
            passed_positions = tuple(range(1, len(passed) + 1))
            read_positions = _read_positions(projected[callee], len(passed))
            passed_set, read_set = set(passed_positions), set(read_positions)
            missing_reads = sorted(passed_set - read_set)
            missing_passes = sorted(read_set - passed_set)
            outcome = "contract_mismatch" if missing_reads or missing_passes else "consumed"
            calls.append(CallSite(
                sid, anchor, raw.adapter, interpreter, token, callee, resolution,
                passed_positions, read_positions, outcome,
            ))
            for position in missing_reads:
                findings.append(Finding(
                    sid, f"argpos:{position}", "passed_but_unread", str(position),
                    callee, anchor,
                ))
            for position in missing_passes:
                findings.append(Finding(
                    sid, f"argpos:{position}", "read_but_never_passed", str(position),
                    callee, anchor,
                ))
    return Artifact(projection_digest(root, manifest), tuple(calls), tuple(findings))


def _cell(value):
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _positions(values):
    return "; ".join(map(str, values)) if values else "—"


def render(artifact):
    lines = [
        f"Schema: {SCHEMA}",
        f"Audited source projection sha256: {artifact.projection_sha256}",
        f"Recognized call sites: {len(artifact.call_sites)}",
        f"Findings: {len(artifact.findings)}",
        "",
        "## Call sites",
        "",
    ]
    if not artifact.call_sites:
        lines += ["No call sites.", ""]
    else:
        lines += ["| " + " | ".join(CALL_COLS) + " |",
                  "| " + " | ".join(["---"] * len(CALL_COLS)) + " |"]
        for row in artifact.call_sites:
            values = [
                row.source_id, row.site_anchor, row.caller_adapter, row.interpreter,
                row.callee_token, row.resolved_callee, row.resolution,
                _positions(row.passed_positions), _positions(row.read_positions), row.outcome,
            ]
            lines.append("| " + " | ".join(_cell(value) for value in values) + " |")
        lines.append("")
    lines += ["## Findings", ""]
    if not artifact.findings:
        lines += ["No findings.", ""]
    else:
        lines += ["| " + " | ".join(FINDING_COLS) + " |",
                  "| " + " | ".join(["---"] * len(FINDING_COLS)) + " |"]
        for row in artifact.findings:
            values = [
                row.source_id, row.witness_id, row.finding_kind,
                row.argument_position, row.callee_path, row.site_anchor,
            ]
            lines.append("| " + " | ".join(_cell(value) for value in values) + " |")
        lines.append("")
    return "\n".join(lines)


def _split_row(line):
    value = line.strip()
    if value.startswith("|"):
        value = value[1:]
    if value.endswith("|"):
        value = value[:-1]
    cells, current, escaped = [], [], False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "|":
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    cells.append("".join(current).strip())
    return cells


def _tables(text):
    lines = text.splitlines()
    found = []
    index = 0
    while index + 1 < len(lines):
        headers = _split_row(lines[index]) if lines[index].lstrip().startswith("|") else []
        divider = _split_row(lines[index + 1]) if lines[index + 1].lstrip().startswith("|") else []
        if headers and len(headers) == len(divider) and all(re.fullmatch(r":?-{3,}:?", cell) for cell in divider):
            rows = []
            index += 2
            while index < len(lines) and lines[index].lstrip().startswith("|"):
                rows.append(_split_row(lines[index]))
                index += 1
            found.append((headers, rows))
            continue
        index += 1
    return found


def _parse_positions(value, label):
    if value in {"", "—"}:
        return ()
    try:
        values = tuple(int(part.strip()) for part in value.split(";"))
    except ValueError as exc:
        raise ArgumentContractError(f"{label}: invalid position list {value!r}") from exc
    if any(value < 1 for value in values) or tuple(sorted(set(values))) != values:
        raise ArgumentContractError(f"{label}: positions must be sorted unique positive integers")
    return values


def parse_artifact(text):
    if "\r" in text:
        raise ArgumentContractError("argument-contract artifact must use LF line endings")
    preamble = text.splitlines()[:4]
    if len(preamble) != 4 or preamble[0] != f"Schema: {SCHEMA}":
        raise ArgumentContractError(f"expected Schema: {SCHEMA} preamble")
    digest_match = re.fullmatch(r"Audited source projection sha256: ([0-9a-f]{64})", preamble[1])
    call_match = re.fullmatch(r"Recognized call sites: (\d+)", preamble[2])
    finding_match = re.fullmatch(r"Findings: (\d+)", preamble[3])
    if not (digest_match and call_match and finding_match):
        raise ArgumentContractError("malformed argument-contract preamble")
    tables = _tables(text)
    call_tables = [rows for headers, rows in tables if headers == CALL_COLS]
    finding_tables = [rows for headers, rows in tables if headers == FINDING_COLS]
    call_count, finding_count = int(call_match.group(1)), int(finding_match.group(1))
    if call_count == 0:
        if call_tables or text.count("No call sites.") != 1:
            raise ArgumentContractError("call-site explicit zero conflicts with count or table")
        raw_calls = []
    elif len(call_tables) != 1 or "No call sites." in text:
        raise ArgumentContractError("expected exactly one call-site table")
    else:
        raw_calls = call_tables[0]
    if finding_count == 0:
        if finding_tables or text.count("No findings.") != 1:
            raise ArgumentContractError("finding explicit zero conflicts with count or table")
        raw_findings = []
    elif len(finding_tables) != 1 or "No findings." in text:
        raise ArgumentContractError("expected exactly one findings table")
    else:
        raw_findings = finding_tables[0]
    if len(raw_calls) != call_count or len(raw_findings) != finding_count:
        raise ArgumentContractError("argument-contract preamble count disagrees with rows")
    calls = []
    identities, ids = set(), set()
    for index, raw in enumerate(raw_calls, start=1):
        if len(raw) != len(CALL_COLS):
            raise ArgumentContractError(f"malformed call-site row {index}")
        row = dict(zip(CALL_COLS, raw))
        match = re.fullmatch(r"(.+):(\d+)@call=(\d+)", row["Site Anchor"])
        if not match:
            raise ArgumentContractError(f"call-site row {index} has invalid Site Anchor")
        identity = (match.group(1), int(match.group(2)), int(match.group(3)))
        expected_id = source_id(*identity)
        if row["Source ID"] != expected_id:
            raise ArgumentContractError(f"call-site row {index} has invalid Source ID")
        if identity in identities or row["Source ID"] in ids:
            raise ArgumentContractError("duplicate AC tuple, Source ID, or truncated-hash collision")
        identities.add(identity)
        ids.add(row["Source ID"])
        if row["Resolution"] not in RESOLUTIONS or row["Outcome"] not in OUTCOMES:
            raise ArgumentContractError(f"call-site row {index} has invalid vocabulary")
        calls.append(CallSite(
            row["Source ID"], row["Site Anchor"], row["Caller Adapter"],
            row["Interpreter"], row["Callee Token"], row["Resolved Callee"],
            row["Resolution"], _parse_positions(row["Passed Positions"], "passed"),
            _parse_positions(row["Read Positions"], "read"), row["Outcome"],
        ))
    by_id = {call.source_id: call for call in calls}
    findings, keys = [], set()
    for index, raw in enumerate(raw_findings, start=1):
        if len(raw) != len(FINDING_COLS):
            raise ArgumentContractError(f"malformed finding row {index}")
        row = dict(zip(FINDING_COLS, raw))
        call = by_id.get(row["Source ID"])
        if call is None or row["Site Anchor"] != call.site_anchor:
            raise ArgumentContractError(f"finding row {index} names an unknown call site")
        if row["Finding Kind"] not in FINDING_KINDS:
            raise ArgumentContractError(f"finding row {index} has invalid Finding Kind")
        if row["Finding Kind"] == "unresolved_callee":
            if row["Witness ID"] != "callsite" or row["Argument Position"] != "—":
                raise ArgumentContractError("unresolved finding must use witness callsite and position —")
        else:
            if row["Witness ID"] != f"argpos:{row['Argument Position']}" \
                    or not re.fullmatch(r"[1-9]\d*", row["Argument Position"]):
                raise ArgumentContractError("position finding has invalid witness identity")
        key = (row["Source ID"], row["Witness ID"])
        if key in keys:
            raise ArgumentContractError("duplicate AC source/witness key")
        keys.add(key)
        findings.append(Finding(
            row["Source ID"], row["Witness ID"], row["Finding Kind"],
            row["Argument Position"], row["Callee Path"], row["Site Anchor"],
        ))
    finding_sources = {row.source_id for row in findings}
    for call in calls:
        expected_outcome = "consumed" if call.source_id not in finding_sources else (
            "unresolved_callee" if call.resolution.startswith("unresolved_")
            else "contract_mismatch"
        )
        if call.outcome != expected_outcome:
            raise ArgumentContractError(f"{call.source_id}: outcome disagrees with findings")
    return Artifact(digest_match.group(1), tuple(calls), tuple(findings))


def _write_atomic(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
        os.replace(temp_name, path)
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_root", type=Path)
    parser.add_argument("--audit-dir", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    root = args.package_root.expanduser().resolve()
    audit = (args.audit_dir or root / "audit").expanduser().resolve()
    output = args.output or audit / "_run" / "argument_contracts.md"
    try:
        artifact = scan(root, audit)
        _write_atomic(output, render(artifact))
    except (ArgumentContractError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {len(artifact.findings)} argument-contract finding(s): {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
