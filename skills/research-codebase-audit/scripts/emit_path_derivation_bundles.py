#!/usr/bin/env python3
"""Emit the mechanical path/import derivation sweep at certified b3d.

The sweep finds path derivations and relative calls in the projected source
files of three languages (Python, Stata, R), decides each one two ways --
chain arithmetic (Check A) and existence at a language-defined anchor
(Check B) -- and closes over what it finds: every instance gets exactly one
of ``verified``, ``failed candidate``, or ``unchecked candidate``, and every
projected source file is either parsed or named on the visible unparsed list.

The invocation-time working directory is never guessed.  The conductor takes
the entry script(s) and their working directories from the package's
documented invocation and passes them on the command line; when no such
invocation exists, ``--no-documented-invocation`` says so out loud and every
cwd-anchored Check B instance is demoted to an unchecked candidate.

Usage:
    emit_path_derivation_bundles.py PACKAGE_ROOT [--audit-dir audit]
        (--entry SCRIPT@CWD [--entry ...] | --no-documented-invocation)
        [-o OUTPUT.md]
"""

import argparse
import ast
import json
import os
import re
import sys
import tempfile
from pathlib import Path, PurePosixPath

from source_projection import audited_regular_files
import emit_definition_use_bundles as du_emit


SCHEMA = "pd-raw/v1"

# ------------------------------------------------------------------ pinned §1a
PARSED_SUFFIXES = {".py", ".do", ".ado", ".r"}
UNPARSED_CODE_SUFFIXES = {
    ".m", ".jl", ".sh", ".zsh", ".bash", ".bat", ".ps1", ".sas", ".sps",
    ".ipynb",
}

# ------------------------------------------------------------ closed vocabulary
UNCHECKED_REASONS = (
    "runtime_cwd", "no_known_caller", "unresolved_anchor", "unrecognized_form",
    "unresolved_target", "parse_failure",
)
UNPARSED_REASONS = ("unsupported_language", "shebang_script", "parse_failure")
CANDIDATE_KINDS = ("failed", "unchecked")

FAILED_QUESTION = (
    "Does this path derivation resolve to the target the code needs at the "
    "moment it runs?"
)
UNCHECKED_QUESTION = (
    "Verify every listed path derivation or relative call: does each resolve "
    "correctly under the package's documented invocation?"
)

VERIFIED_COLS = [
    "File", "Line", "Idiom", "Check", "Steps Counted", "True Depth",
    "Resolved Target",
]
CANDIDATE_COLS = [
    "Source ID", "Witness ID", "Kind", "File", "Line", "Idiom", "Check",
    "Statement", "Machine Numbers", "Obligation Question",
]

VERIFIED_ZERO = "No verified path derivations."
CANDIDATE_ZERO = "No path-derivation candidates."
UNPARSED_ZERO = "No unparsed source files."
DASH = "\u2014"

COUNT_LABELS = [
    "Files parsed", "Files unparsed (listed below)", "Instances verified",
    "Failed candidates", "Unchecked candidate groups (files)",
    "Unchecked lines",
]

# cwd sentinels -- three distinct flavours of "not known", each with its own
# unchecked reason, so a demoted instance always says why.
NO_CONTEXT = "\x00no_known_caller"
RUNTIME_CWD = "\x00runtime_cwd"
UNRESOLVED_CWD = "\x00unresolved_anchor"
_SENTINEL_REASON = {
    NO_CONTEXT: "no_known_caller",
    RUNTIME_CWD: "runtime_cwd",
    UNRESOLVED_CWD: "unresolved_anchor",
}

HERE_MARKER_NAMES = {".here"}
HERE_MARKER_SUFFIX = ".rproj"


class PathDerivationError(RuntimeError):
    """The path-derivation artifact is malformed or the seed is missing."""


# --------------------------------------------------------------- small helpers


def _cell(value):
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _normalize_parts(parts):
    """Normalize path parts, letting leading ``..`` escape the tree."""
    out = []
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            if out and out[-1] != "..":
                out.pop()
            else:
                out.append("..")
        else:
            out.append(part)
    return out


def _join(cwd, target):
    """Join a package-root-relative cwd with a relative target."""
    base = [] if cwd in (".", "") else list(PurePosixPath(cwd).parts)
    return _normalize_parts(base + list(PurePosixPath(target).parts))


def _display(parts):
    return "/".join(parts) if parts else "."


def _leading_ups(target):
    count = 0
    for part in PurePosixPath(target).parts:
        if part == "..":
            count += 1
        else:
            break
    return count


def _depth(cwd):
    return 0 if cwd in (".", "") else len(PurePosixPath(cwd).parts)


def _is_relative(target):
    """True when a raw target is a relative path we can anchor."""
    if not target:
        return False
    if target.startswith("/") or target.startswith("~"):
        return False
    return not re.match(r"^[A-Za-z]:[\\/]", target)


# ------------------------------------------------------------------ seed record


class SeedRecord:
    """The conductor-recorded invocation seed, as written and as replayed."""

    def __init__(self, entries=(), no_documented_invocation=False):
        self.entries = tuple(entries)
        self.no_documented_invocation = bool(no_documented_invocation)

    def __eq__(self, other):
        return (isinstance(other, SeedRecord)
                and self.entries == other.entries
                and self.no_documented_invocation == other.no_documented_invocation)

    def __repr__(self):  # pragma: no cover - debugging aid
        return (f"SeedRecord(entries={self.entries!r}, "
                f"no_documented_invocation={self.no_documented_invocation!r})")

    def flags(self):
        """Return the exact CLI flags that reproduce this seed."""
        if self.no_documented_invocation:
            return ["--no-documented-invocation"]
        return [flag for script, cwd in self.entries
                for flag in ("--entry", f"{script}@{cwd}")]

    def render(self):
        lines = ["## Invocation seed", ""]
        if self.no_documented_invocation:
            return lines + ["- No documented invocation.", ""]
        return lines + [f"- Entry: `{script}` @ `{cwd}`"
                        for script, cwd in self.entries] + [""]


def _validate_entry(script, cwd):
    if not script or script.startswith("/") or ".." in PurePosixPath(script).parts:
        raise PathDerivationError(
            f"--entry script must be a relative path inside the package: {script!r}")
    if cwd != "unknown":
        if cwd.startswith("/") or ".." in PurePosixPath(cwd).parts:
            raise PathDerivationError(
                f"--entry cwd must be `unknown` or a relative path inside the "
                f"package: {cwd!r}")
    return script, cwd


def parse_entry_flag(value):
    if "@" not in value:
        raise PathDerivationError(
            f"--entry needs the form <script-relpath>@<cwd-relpath|unknown>: {value!r}")
    script, cwd = value.rsplit("@", 1)
    return _validate_entry(script.strip(), cwd.strip())


# ------------------------------------------------------------------ projection


class Projection:
    """The §1a source-file denominator over the shared U2 projection."""

    def __init__(self, root):
        root = Path(root).expanduser().resolve()
        try:
            manifest = json.loads(
                (root / "audit" / "_run" / "manifest.json").read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            manifest = {}
        self.root = root
        self.files = sorted(
            path.relative_to(root).as_posix()
            for path in audited_regular_files(root, manifest))
        self.file_set = set(self.files)
        self.dirs = {"."}
        for relative in self.files:
            parts = PurePosixPath(relative).parts[:-1]
            for index in range(len(parts) + 1):
                self.dirs.add(_display(list(parts[:index])))
        self.parsed = []
        self.unparsed = []          # (relpath, reason)
        for relative in self.files:
            suffix = PurePosixPath(relative).suffix.lower()
            if suffix in PARSED_SUFFIXES:
                self.parsed.append(relative)
            elif suffix in UNPARSED_CODE_SUFFIXES:
                self.unparsed.append((relative, "unsupported_language"))
            elif not suffix and self._has_shebang(root / relative):
                self.unparsed.append((relative, "shebang_script"))
        self.py_stems = {
            PurePosixPath(relative).stem for relative in self.files
            if PurePosixPath(relative).suffix.lower() == ".py"
        }

    @staticmethod
    def _has_shebang(path):
        try:
            with open(path, "rb") as handle:
                return handle.read(2) == b"#!"
        except OSError:
            return False

    def has_file(self, parts):
        return _display(parts) in self.file_set

    def has_dir(self, parts):
        return _display(parts) in self.dirs

    def here_anchor(self, relative):
        """here()'s own walk-up: `.here` / `*.Rproj` / `.git`, never the cwd."""
        parts = list(PurePosixPath(relative).parts[:-1])
        while True:
            prefix = _display(parts)
            for candidate in self.files:
                candidate_parts = PurePosixPath(candidate).parts
                if _display(list(candidate_parts[:-1])) != prefix:
                    continue
                name = candidate_parts[-1]
                if name in HERE_MARKER_NAMES or name.lower().endswith(HERE_MARKER_SUFFIX):
                    return prefix
            if _display(list(parts) + [".git"]) in self.dirs:
                return prefix
            if not parts:
                return None
            parts.pop()


# -------------------------------------------------------------------- instances


class Instance:
    """One found path derivation, before it is decided."""

    def __init__(self, file, line, idiom, statement, role, **payload):
        self.file = file
        self.line = line
        self.idiom = idiom
        self.statement = statement
        self.role = role
        self.payload = payload


class Unrecognized:
    """A marker-bearing statement the parser could not classify (§1 R1)."""

    def __init__(self, file, line, idiom, statement):
        self.file = file
        self.line = line
        self.idiom = idiom
        self.statement = statement


class ParsedFile:
    def __init__(self, relative, language):
        self.file = relative
        self.language = language
        self.events = []            # Instance, in statement order
        self.unrecognized = []      # Unrecognized


# ------------------------------------------------------------- marker scanning

_PY_STRING_RE = re.compile(r"""(['"])((?:\\.|(?!\1).)*)\1""")
_UPDOWN_RE = re.compile(r"(?:^|/)\.\.(?:/|$)")


def _strip_python_comment(line):
    out, quote, index = [], None, 0
    while index < len(line):
        char = line[index]
        if quote:
            out.append(char)
            if char == "\\":
                if index + 1 < len(line):
                    out.append(line[index + 1])
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in "'\"":
            quote = char
            out.append(char)
            index += 1
            continue
        if char == "#":
            break
        out.append(char)
        index += 1
    return "".join(out)


def _strip_r_comment(line):
    return _strip_python_comment(line)


def _literal_updown(text):
    """True when a quoted string on this line holds a `..` path segment."""
    for _quote, body in _PY_STRING_RE.findall(text):
        if _UPDOWN_RE.search(body):
            return True
    return False


_GENERIC_MARKERS = [
    ("dirname", re.compile(r"\bdirname\b")),
    (".parent", re.compile(r"\.parent\b")),
    ("sys.path", re.compile(r"\bsys\.path\b")),
    ("source", re.compile(r"\bsource\b")),
    ("setwd", re.compile(r"\bsetwd\b")),
    ("file.path", re.compile(r"\bfile\.path\b")),
    ("here", re.compile(r"\bhere\b")),
]
_STATA_CALL_MARKER = re.compile(
    r"^(?:(?:capture|cap|quietly|qui|noisily|noi)\s*:?[ \t]*)*(do|include|run)\b",
    re.IGNORECASE,
)


def _markers_in(text, *, stata_statement=False, config_import=None):
    """Return the pinned markers this comment-stripped statement mentions."""
    found = []
    for name, pattern in _GENERIC_MARKERS:
        if pattern.search(text):
            found.append(name)
    if _literal_updown(text):
        found.append("..")
    if stata_statement:
        match = _STATA_CALL_MARKER.match(text.strip())
        if match:
            found.append(match.group(1).lower())
    if config_import:
        found.append("import")
    return found


_PY_IMPORT_RE = re.compile(r"^\s*(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)\b")


def _python_config_import_marker(text, stems):
    match = _PY_IMPORT_RE.match(text)
    return bool(match) and match.group(1) in stems


# ---------------------------------------------------------------- Python parser


class ChainValue:
    """A file-anchored path chain: `steps` up-moves plus a constant tail."""

    def __init__(self, steps, tail=(), line=None, statement="", idiom="os.path.dirname"):
        self.steps = steps
        self.tail = tuple(tail)
        self.line = line
        self.statement = statement
        self.idiom = idiom

    def dirname(self):
        if self.tail:
            return ChainValue(self.steps, self.tail[:-1], self.line,
                              self.statement, self.idiom)
        return ChainValue(self.steps + 1, (), self.line, self.statement, self.idiom)

    def joined(self, parts):
        tail = list(self.tail)
        steps = self.steps
        for part in parts:
            for piece in PurePosixPath(part).parts:
                if piece in ("", "."):
                    continue
                if piece == "..":
                    if tail:
                        tail.pop()
                    else:
                        steps += 1
                else:
                    tail.append(piece)
        return ChainValue(steps, tail, self.line, self.statement, self.idiom)


def _dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _stmt_text(lines, node):
    start = getattr(node, "lineno", 1)
    end = getattr(node, "end_lineno", start) or start
    chunk = " ".join(line.strip() for line in lines[start - 1:end])
    return re.sub(r"\s+", " ", chunk).strip()


def _python_chain(node, chains, strings):
    """Return the ChainValue this expression denotes, or None."""
    if isinstance(node, ast.Name):
        return chains.get(node.id)
    if isinstance(node, ast.Attribute):
        if node.attr in {"parent"}:
            base = _python_chain(node.value, chains, strings)
            if base is not None:
                return base.dirname()
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        base = _python_chain(node.left, chains, strings)
        piece = _python_string(node.right, strings)
        if base is not None and piece is not None:
            return base.joined([piece])
        return None
    if not isinstance(node, ast.Call):
        return None
    name = _dotted(node.func)
    if name is None:
        return None
    tail = name.rsplit(".", 1)[-1]
    if tail in {"abspath", "realpath", "normpath", "resolve", "absolute", "expanduser"}:
        if node.args:
            return _python_chain(node.args[0], chains, strings)
        base = _python_chain(node.func.value, chains, strings) \
            if isinstance(node.func, ast.Attribute) else None
        return base
    if tail == "dirname" and node.args:
        base = _python_chain(node.args[0], chains, strings)
        return base.dirname() if base is not None else None
    if tail == "Path" and node.args:
        base = _python_chain(node.args[0], chains, strings)
        return base
    if tail == "join" and node.args:
        base = _python_chain(node.args[0], chains, strings)
        if base is None:
            return None
        parts = []
        for extra in node.args[1:]:
            piece = _python_string(extra, strings)
            if piece is None:
                return None
            parts.append(piece)
        return base.joined(parts)
    return None


def _python_string(node, strings):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return strings.get(node.id)
    return None


def _is_file_anchor(node):
    return isinstance(node, ast.Name) and node.id == "__file__"


def _python_root_chain(node, chains, strings, line, statement):
    """Seed `__file__` before delegating to the generic chain evaluator."""
    if _is_file_anchor(node):
        return ChainValue(0, (), line, statement)
    return None


def _parse_python(relative, text, projection):
    parsed = ParsedFile(relative, "Python")
    lines = text.splitlines()
    tree = ast.parse(text)          # SyntaxError handled by the caller

    chains, strings = {}, {}
    claimed = set()

    def claim(node):
        start = getattr(node, "lineno", None)
        if start is None:
            return
        end = getattr(node, "end_lineno", start) or start
        claimed.update(range(start, end + 1))

    def chain_of(node, line, statement):
        seeded = _python_root_chain(node, chains, strings, line, statement)
        if seeded is not None:
            return seeded
        saved = chains.get("__file__")
        chains["__file__"] = ChainValue(0, (), line, statement)
        try:
            value = _python_chain(node, chains, strings)
        finally:
            if saved is None:
                chains.pop("__file__", None)
            else:
                chains["__file__"] = saved
        if value is None:
            return None
        return ChainValue(value.steps, value.tail, value.line or line,
                          value.statement or statement, value.idiom)

    statements = sorted(
        (node for node in ast.walk(tree) if isinstance(node, ast.stmt)),
        key=lambda node: (node.lineno, node.col_offset))
    calls = sorted(
        (node for node in ast.walk(tree) if isinstance(node, ast.Call)),
        key=lambda node: (node.lineno, node.col_offset))
    literals = sorted(
        (node for node in ast.walk(tree)
         if isinstance(node, ast.Constant) and isinstance(node.value, str)),
        key=lambda node: (node.lineno, node.col_offset))

    stream = []
    for node in statements:
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign)):
            stream.append((node.lineno, node.col_offset, 0, node))
    for node in calls:
        stream.append((node.lineno, node.col_offset, 1, node))
    for node in literals:
        stream.append((node.lineno, node.col_offset, 2, node))
    stream.sort(key=lambda item: (item[0], item[1], item[2]))

    pending_appends = []
    syspath_entries = []

    for _line, _col, _rank, node in stream:
        statement = _stmt_text(lines, node)
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                value = chain_of(node.value, node.lineno, statement)
                if value is not None:
                    chains[name] = ChainValue(
                        value.steps, value.tail, node.lineno, statement,
                        "pathlib.parent" if ".parent" in statement
                        else "os.path.dirname")
                    claim(node)
                    continue
                literal = _python_string(node.value, strings)
                if literal is not None:
                    strings[name] = literal
            continue
        if isinstance(node, ast.ImportFrom) and node.level:
            claim(node)
            base = list(PurePosixPath(relative).parts[:-1])
            for _ in range(node.level - 1):
                if base:
                    base.pop()
            prefix = base + (list(PurePosixPath(node.module.replace(".", "/")).parts)
                             if node.module else [])
            for alias in node.names:
                parsed.events.append(Instance(
                    relative, node.lineno, "relative import", statement,
                    "check_b_package", target=prefix + [alias.name]))
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = ([alias.name for alias in node.names]
                     if isinstance(node, ast.Import) else [node.module or ""])
            for name in names:
                if "." in name or name not in projection.py_stems:
                    continue
                claim(node)
                if pending_appends:
                    chain, chain_line, chain_statement, chain_idiom = \
                        pending_appends.pop(0)
                    parsed.events.append(Instance(
                        relative, chain_line, chain_idiom, chain_statement,
                        "check_a", chain=chain, module=name))
                else:
                    parsed.events.append(Instance(
                        relative, node.lineno, "import", statement,
                        "check_b_syspath", module=name,
                        entries=list(syspath_entries)))
            continue
        if isinstance(node, ast.Call):
            name = _dotted(node.func) or ""
            if name in {"sys.path.append", "path.append"} and node.args:
                claim(node)
                chain = chain_of(node.args[0], node.lineno, statement)
                if chain is not None:
                    syspath_entries.append(chain)
                    pending_appends.append(
                        (chain, chain.line or node.lineno,
                         chain.statement or statement, chain.idiom))
                else:
                    parsed.events.append(Instance(
                        relative, node.lineno, "sys.path.append", statement,
                        "unchecked", reason="unresolved_target"))
                continue
            if name in {"os.chdir", "chdir"} and node.args:
                claim(node)
                target = _python_string(node.args[0], strings)
                parsed.events.append(Instance(
                    relative, node.lineno, "os.chdir", statement,
                    "cwd_set", target=target if target and _is_relative(target) else None))
                continue
            if name in {"open", "io.open"} and node.args:
                chain = chain_of(node.args[0], node.lineno, statement)
                if chain is not None:
                    claim(node)
                    parsed.events.append(Instance(
                        relative, chain.line or node.lineno, chain.idiom,
                        chain.statement or statement, "check_a", chain=chain,
                        module=None))
                continue
            continue
        # bare string constant
        value = node.value
        if _UPDOWN_RE.search(value) and "/" in value and not re.search(r"\s", value):
            claim(node)
            parsed.events.append(Instance(
                relative, node.lineno, "path literal", statement,
                "check_b_cwd", target=value))

    for chain, chain_line, chain_statement, chain_idiom in pending_appends:
        parsed.events.append(Instance(
            relative, chain_line, chain_idiom, chain_statement,
            "unchecked", reason="unresolved_target"))

    for number, raw in enumerate(lines, start=1):
        if number in claimed:
            continue
        code = _strip_python_comment(raw)
        if not code.strip():
            continue
        markers = _markers_in(
            code, config_import=_python_config_import_marker(
                code, projection.py_stems))
        if markers:
            parsed.unrecognized.append(Unrecognized(
                relative, number, markers[0], code.strip()))
    return parsed


# ----------------------------------------------------------------- Stata parser

_STATA_CALL_RE = re.compile(
    r"^(?:(?:capture|cap|quietly|qui|noisily|noi)\s*:?[ \t]*)*"
    r"(?P<command>do|include|run)\s+(?P<rest>.+)$",
    re.IGNORECASE,
)
_STATA_CD_RE = re.compile(
    r"^(?:(?:capture|cap|quietly|qui|noisily|noi)\s*:?[ \t]*)*"
    r"cd\s+(?P<rest>.+)$", re.IGNORECASE)
_STATA_LOCAL_RE = re.compile(
    r"^(?:local|global)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=)?\s*(?P<value>.*)$",
    re.IGNORECASE,
)
_STATA_MACRO_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)'|\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
_DELIMIT_RE = re.compile(r"^#delimit\s*(?P<mode>;|cr)\s*$", re.IGNORECASE)


def _unquote(value):
    value = value.strip()
    if value.startswith('"') and value.endswith('"') and len(value) >= 2:
        return value[1:-1]
    return value


def _first_stata_token(rest):
    rest = rest.strip()
    if rest.startswith('"'):
        end = rest.find('"', 1)
        if end == -1:
            return rest[1:]
        return rest[1:end]
    return re.split(r"[\s,]", rest, maxsplit=1)[0]


def _expand_stata(value, macros, used):
    """Textually expand macros; return (text, resolved)."""
    resolved = True

    def replace(match):
        nonlocal resolved
        name = match.group(1) or match.group(2)
        if name in macros:
            used.add(name)
            return macros[name]
        resolved = False
        return ""

    for _ in range(5):
        expanded = _STATA_MACRO_RE.sub(replace, value)
        if expanded == value:
            break
        value = expanded
    return value, resolved


def _parse_stata(relative, text, _projection):
    parsed = ParsedFile(relative, "Stata")
    raw_lines = text.splitlines()
    logical = du_emit._logical_lines(raw_lines)
    macros, used, assigned_lines = {}, set(), {}
    claimed = set()
    delimit_semicolon = False

    for statement in logical:
        code = statement["code"].strip()
        line = statement["line"]
        if not code:
            continue
        delimiter = _DELIMIT_RE.match(code)
        if delimiter:
            delimit_semicolon = delimiter.group("mode") == ";"
            claimed.add(line)
            continue
        if delimit_semicolon:
            continue
        assignment = _STATA_LOCAL_RE.match(code)
        if assignment:
            value = _unquote(assignment.group("value"))
            expanded, resolved = _expand_stata(value, macros, used)
            if resolved:
                macros[assignment.group("name")] = expanded
                assigned_lines[assignment.group("name")] = line
            continue
        cd_match = _STATA_CD_RE.match(code)
        if cd_match:
            claimed.add(line)
            target = _unquote(cd_match.group("rest"))
            expanded, resolved = _expand_stata(target, macros, used)
            parsed.events.append(Instance(
                relative, line, "cd", code, "cwd_set",
                target=expanded if resolved and _is_relative(expanded) else None))
            continue
        call = _STATA_CALL_RE.match(code)
        if call:
            claimed.add(line)
            token = _first_stata_token(call.group("rest"))
            expanded, resolved = _expand_stata(token, macros, used)
            command = call.group("command").lower()
            if not resolved or not _is_relative(expanded):
                parsed.events.append(Instance(
                    relative, line, command, code, "unchecked",
                    reason="runtime_cwd" if not resolved else "unresolved_target"))
            else:
                parsed.events.append(Instance(
                    relative, line, command, code, "check_b_cwd",
                    target=expanded, call=True))
            continue

    for name, line in assigned_lines.items():
        if name in used:
            claimed.add(line)

    for statement in logical:
        code = statement["code"].strip()
        line = statement["line"]
        if not code or line in claimed:
            continue
        markers = _markers_in(code, stata_statement=True)
        if markers:
            parsed.unrecognized.append(Unrecognized(
                relative, line, markers[0], code))
    return parsed


# --------------------------------------------------------------------- R parser

_R_ASSIGN_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z_.][A-Za-z0-9_.]*)\s*(?:<-|=)\s*(?P<value>.+)$")
_R_STRING_RE = re.compile(r"""(['"])((?:\\.|(?!\1).)*)\1""")


def _r_call_args(code, function):
    """Return the raw argument text of the first `function(...)` call."""
    match = re.search(rf"\b{re.escape(function)}\s*\(", code)
    if not match:
        return None
    depth, index, start = 0, match.end() - 1, match.end()
    quote = None
    while index < len(code):
        char = code[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return code[start:index]
        index += 1
    return None


def _r_constant(argument, variables):
    """Resolve one R argument expression to a constant string, or None."""
    argument = argument.strip()
    match = _R_STRING_RE.fullmatch(argument)
    if match:
        return match.group(2)
    if argument in variables:
        return variables[argument]
    inner = _r_call_args(argument, "file.path")
    if inner is not None and argument.startswith("file.path"):
        parts = _r_constant_list(inner, variables)
        return None if parts is None else "/".join(parts)
    inner = _r_call_args(argument, "dirname")
    if inner is not None and argument.startswith("dirname"):
        base = _r_constant(inner, variables)
        if base is None:
            return None
        parts = list(PurePosixPath(base).parts[:-1])
        return _display(parts)
    return None


def _r_split_args(text):
    parts, current, depth, quote = [], [], 0, None
    for char in text:
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
            current.append(char)
        elif char in "([":
            depth += 1
            current.append(char)
        elif char in ")]":
            depth -= 1
            current.append(char)
        elif char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    if "".join(current).strip():
        parts.append("".join(current))
    return [part.strip() for part in parts]


def _r_constant_list(text, variables):
    values = []
    for argument in _r_split_args(text):
        value = _r_constant(argument, variables)
        if value is None:
            return None
        values.append(value)
    return values


def _parse_r(relative, text, _projection):
    parsed = ParsedFile(relative, "R")
    variables = {}
    claimed = set()
    lines = text.splitlines()
    for number, raw in enumerate(lines, start=1):
        code = _strip_r_comment(raw).strip()
        if not code:
            continue
        handled = False
        inner = _r_call_args(code, "setwd")
        if inner is not None:
            claimed.add(number)
            target = _r_constant(inner, variables)
            parsed.events.append(Instance(
                relative, number, "setwd", code, "cwd_set",
                target=target if target and _is_relative(target) else None))
            handled = True
        inner = _r_call_args(code, "here")
        if inner is not None and re.search(r"(^|[^A-Za-z0-9_.])here\s*\(", code):
            claimed.add(number)
            parts = _r_constant_list(inner, variables)
            if parts is None:
                parsed.events.append(Instance(
                    relative, number, "here", code, "unchecked",
                    reason="unresolved_target"))
            else:
                parsed.events.append(Instance(
                    relative, number, "here", code, "check_b_here",
                    target="/".join(parts)))
            handled = True
        inner = _r_call_args(code, "source")
        if inner is not None and re.search(r"(^|[^A-Za-z0-9_.\"'])source\s*\(", code):
            claimed.add(number)
            arguments = _r_split_args(inner)
            target = _r_constant(arguments[0], variables) if arguments else None
            if target is None or not _is_relative(target):
                parsed.events.append(Instance(
                    relative, number, "source", code, "unchecked",
                    reason="unresolved_target"))
            else:
                parsed.events.append(Instance(
                    relative, number, "source", code, "check_b_cwd",
                    target=target, call=True))
            handled = True
        if handled:
            continue
        assignment = _R_ASSIGN_RE.match(code)
        if assignment:
            value = _r_constant(assignment.group("value"), variables)
            if value is not None:
                variables[assignment.group("name")] = value
                if not _UPDOWN_RE.search(value):
                    claimed.add(number)
                continue
    for number, raw in enumerate(lines, start=1):
        if number in claimed:
            continue
        code = _strip_r_comment(raw).strip()
        if not code:
            continue
        markers = _markers_in(code)
        if markers:
            parsed.unrecognized.append(Unrecognized(
                relative, number, markers[0], code))
    return parsed


PARSERS = {
    ".py": ("Python", _parse_python),
    ".do": ("Stata", _parse_stata),
    ".ado": ("Stata", _parse_stata),
    ".r": ("R", _parse_r),
}


# ------------------------------------------------------------------- resolution


class Outcome:
    __slots__ = ("verdict", "steps", "depth", "resolved", "reason")

    def __init__(self, verdict, steps=None, depth=None, resolved=None, reason=None):
        self.verdict = verdict
        self.steps = steps
        self.depth = depth
        self.resolved = resolved
        self.reason = reason


_RANK = {"failed": 0, "unchecked": 1, "verified": 2}


def _better(current, candidate):
    if current is None:
        return candidate
    return candidate if _RANK[candidate.verdict] < _RANK[current.verdict] else current


def _resolve_call(cwd, target, projection):
    if cwd.startswith("\x00"):
        return None
    parts = _join(cwd, target)
    return _display(parts) if projection.has_file(parts) else None


def _contexts(parsed_files, projection, seed):
    """BFS the call graph from the recorded entries.

    Returns ``file -> {(cwd, entry_script)}``.  The entry script travels with
    the context because Python's ``sys.path[0]`` is the *entry script's*
    directory, never the importing module's -- a config-named import can only
    be resolved by a file that knows which entry chain reached it.
    """
    contexts = {}
    if seed.no_documented_invocation:
        return contexts
    queue = []
    for script, cwd in seed.entries:
        start = UNRESOLVED_CWD if cwd == "unknown" else _display(_normalize_parts(
            PurePosixPath(cwd).parts))
        queue.append((script, start, script))
    seen = set()
    while queue:
        relative, cwd, entry = queue.pop(0)
        if (relative, cwd, entry) in seen:
            continue
        seen.add((relative, cwd, entry))
        contexts.setdefault(relative, set()).add((cwd, entry))
        parsed_file = parsed_files.get(relative)
        if parsed_file is None:
            continue
        current = cwd
        for event in parsed_file.events:
            if event.role == "cwd_set":
                target = event.payload.get("target")
                if target is None:
                    current = RUNTIME_CWD
                elif not current.startswith("\x00"):
                    current = _display(_join(current, target))
                continue
            if event.role == "check_b_cwd" and event.payload.get("call"):
                callee = _resolve_call(current, event.payload["target"], projection)
                if callee is not None:
                    queue.append((callee, current, entry))
            if event.role == "check_b_package":
                callee = _package_target(event.payload["target"], projection)
                if callee is not None:
                    queue.append((callee, current, entry))
    return contexts


def _package_target(parts, projection):
    module = list(parts)
    direct = module[:-1] + [module[-1] + ".py"]
    if projection.has_file(direct):
        return _display(direct)
    package = module + ["__init__.py"]
    if projection.has_file(package):
        return _display(package)
    return None


def _decide_file(parsed_file, projection, start_cwd, entry=None):
    """Decide every instance in one file under one starting cwd context."""
    outcomes = {}
    cwd = start_cwd
    for index, event in enumerate(parsed_file.events):
        key = index
        if event.role == "cwd_set":
            target = event.payload.get("target")
            if target is None:
                # The cd/chdir/setwd statement itself is unchecked because its
                # own argument is a runtime value.  It only demotes later
                # instances to ``runtime_cwd`` when there was a cwd to lose:
                # in a file no entry chain ever reaches, ``no_known_caller``
                # is the honest reason and it keeps precedence.
                outcomes[key] = Outcome("unchecked", reason="runtime_cwd")
                if cwd != NO_CONTEXT:
                    cwd = RUNTIME_CWD
            elif not cwd.startswith("\x00"):
                cwd = _display(_join(cwd, target))
            continue
        if event.role == "unchecked":
            outcomes[key] = Outcome("unchecked", reason=event.payload["reason"])
            continue
        if event.role == "check_a":
            outcomes[key] = _decide_check_a(parsed_file, event, projection)
            continue
        if event.role == "check_b_cwd":
            outcomes[key] = _decide_check_b_cwd(event, projection, cwd)
            continue
        if event.role == "check_b_package":
            target = event.payload["target"]
            resolved = _package_target(target, projection)
            outcomes[key] = Outcome(
                "verified" if resolved else "failed", None, None,
                resolved or _display(list(target[:-1]) + [target[-1] + ".py"]))
            continue
        if event.role == "check_b_here":
            outcomes[key] = _decide_here(parsed_file, event, projection)
            continue
        if event.role == "check_b_syspath":
            outcomes[key] = _decide_syspath(
                parsed_file, event, projection, cwd, entry)
            continue
    return outcomes


def _decide_check_a(parsed_file, event, projection):
    chain = event.payload["chain"]
    parts = list(PurePosixPath(parsed_file.file).parts)
    depth = len(parts) - 1
    if chain.steps > len(parts):
        base = [".."] * (chain.steps - len(parts))
    else:
        base = parts[:len(parts) - chain.steps]
    resolved = _normalize_parts(base + list(chain.tail))
    module = event.payload.get("module")
    if module is None:
        ok = projection.has_file(resolved)
    else:
        ok = projection.has_file(resolved + [module + ".py"]) or \
            projection.has_file(resolved + [module, "__init__.py"])
    return Outcome("verified" if ok else "failed", chain.steps, depth,
                   _display(resolved))


def _decide_check_b_cwd(event, projection, cwd):
    if cwd.startswith("\x00"):
        return Outcome("unchecked", reason=_SENTINEL_REASON[cwd])
    target = event.payload["target"]
    ups = _leading_ups(target)
    parts = _join(cwd, target)
    ok = projection.has_file(parts)
    return Outcome("verified" if ok else "failed",
                   ups or None, _depth(cwd) if ups else None, _display(parts))


def _decide_here(parsed_file, event, projection):
    anchor = projection.here_anchor(parsed_file.file)
    if anchor is None:
        return Outcome("unchecked", reason="unresolved_anchor")
    parts = _join(anchor, event.payload["target"])
    ok = projection.has_file(parts)
    return Outcome("verified" if ok else "failed", None, None, _display(parts))


def _decide_syspath(parsed_file, event, projection, cwd, entry):
    """Resolve a config-named plain import against the effective ``sys.path``.

    ``sys.path[0]`` is the directory of the **entry script**, not of the
    importing module, so a file no entry chain reaches has no effective
    ``sys.path`` at all and is an unchecked candidate -- never a guess, and
    never a ``verified`` earned from a sibling file that the real interpreter
    would not see.  Both demotions happen before any anchor is consulted, so
    the unknown-seed rule of the invocation contract stays reachable.
    """
    if entry is None:
        return Outcome("unchecked", reason="no_known_caller")
    if cwd.startswith("\x00"):
        return Outcome("unchecked", reason=_SENTINEL_REASON[cwd])
    module = event.payload["module"]
    anchors = [_display(list(PurePosixPath(entry).parts[:-1]))]
    file_parts = list(PurePosixPath(parsed_file.file).parts)
    for chain in event.payload.get("entries", ()):
        # Tracked sys.path.append chains are file-anchored, hence genuinely
        # seed-independent, and stay on the anchor list.
        if chain.steps > len(file_parts):
            base = [".."] * (chain.steps - len(file_parts))
        else:
            base = file_parts[:len(file_parts) - chain.steps]
        anchors.append(_display(_normalize_parts(base + list(chain.tail))))
    anchors.append(cwd)
    for anchor in anchors:
        parts = _join(anchor, module + ".py")
        if projection.has_file(parts):
            return Outcome("verified", None, None, _display(parts))
    return Outcome("failed", None, None,
                   _display(_join(anchors[0], module + ".py")))


# ------------------------------------------------------------------ the sweep


class Report:
    def __init__(self, seed):
        self.seed = seed
        self.parsed_files = []
        self.unparsed = []          # (relpath, reason)
        self.verified = []          # dicts for the verified table
        self.failed = []            # dicts, one per failed instance
        self.groups = []            # dicts, one per unchecked file group


def scan_package(root, seed):
    root = Path(root).expanduser().resolve()
    projection = Projection(root)
    report = Report(seed)
    parsed_files, failures = {}, []
    for relative in projection.parsed:
        suffix = PurePosixPath(relative).suffix.lower()
        language, parser = PARSERS[suffix]
        text = (Path(root) / relative).read_text(encoding="utf-8", errors="replace")
        try:
            parsed_files[relative] = parser(relative, text, projection)
        except (SyntaxError, ValueError):
            failures.append(relative)
    for relative in failures:
        parsed_files.pop(relative, None)
    report.unparsed = sorted(
        list(projection.unparsed) + [(relative, "parse_failure") for relative in failures])
    report.parsed_files = sorted(parsed_files)

    contexts = _contexts(parsed_files, projection, seed)

    per_file = {}
    for relative in sorted(parsed_files):
        parsed_file = parsed_files[relative]
        starts = sorted(contexts.get(relative, {(NO_CONTEXT, None)}),
                        key=lambda item: (item[0], item[1] or ""))
        merged = {}
        for start, entry in starts:
            for key, outcome in _decide_file(
                    parsed_file, projection, start, entry).items():
                merged[key] = _better(merged.get(key), outcome)
        per_file[relative] = merged

    for relative in sorted(parsed_files):
        parsed_file = parsed_files[relative]
        merged = per_file[relative]
        unchecked_lines = {}
        for index, event in enumerate(parsed_file.events):
            outcome = merged.get(index)
            if outcome is None:
                continue
            if outcome.verdict == "verified":
                report.verified.append({
                    "File": relative, "Line": str(event.line),
                    "Idiom": event.idiom, "Check": _check_letter(event),
                    "Steps Counted": _number(outcome.steps),
                    "True Depth": _number(outcome.depth),
                    "Resolved Target": outcome.resolved or DASH,
                })
            elif outcome.verdict == "failed":
                report.failed.append({
                    "file": relative, "line": event.line, "idiom": event.idiom,
                    "check": _check_letter(event), "statement": event.statement,
                    "machine": _machine(outcome),
                })
            else:
                unchecked_lines.setdefault(event.line, {
                    "line": event.line, "idiom": event.idiom,
                    "statement": event.statement, "reason": outcome.reason,
                })
        for item in parsed_file.unrecognized:
            unchecked_lines.setdefault(item.line, {
                "line": item.line, "idiom": item.idiom,
                "statement": item.statement, "reason": "unrecognized_form",
            })
        if unchecked_lines:
            report.groups.append({
                "file": relative,
                "witnesses": [unchecked_lines[line] for line in sorted(unchecked_lines)],
            })

    for relative in sorted(failures):
        group = _parse_failure_group(relative)
        if group is not None:
            report.groups.append(group)

    report.failed.sort(key=lambda row: (row["file"], row["line"], row["idiom"]))
    report.groups.sort(key=lambda group: (group["file"],
                                          group["witnesses"][0]["line"]))
    return report


def _parse_failure_group(relative):
    """The §1 parse-failure force: one standard grouped candidate per file."""
    return {
        "file": relative,
        "witnesses": [{"line": 1, "idiom": DASH, "statement": DASH,
                       "reason": "parse_failure", "whole_file": True}],
    }


def _check_letter(event):
    if event.role == "check_a":
        return "A"
    if event.role.startswith("check_b"):
        return "B"
    return DASH


def _number(value):
    return DASH if value is None else str(value)


def _machine(outcome):
    return (f"steps={_number(outcome.steps)}; depth={_number(outcome.depth)}; "
            f"resolved={outcome.resolved or DASH}")


# ------------------------------------------------------------------- rendering


def _assign_ids(report):
    """Assign sequential PD-NNN source IDs in report order."""
    ordered = []
    for row in report.failed:
        ordered.append(("failed", row["file"], row["line"], row))
    for group in report.groups:
        ordered.append(("unchecked", group["file"], group["witnesses"][0]["line"], group))
    ordered.sort(key=lambda item: (item[1], item[2], 0 if item[0] == "failed" else 1))
    sources = []
    for index, (kind, _file, _line, payload) in enumerate(ordered, start=1):
        sources.append((f"PD-{index:03d}", kind, payload))
    return sources


def render_artifact(report):
    sources = _assign_ids(report)
    unchecked_witnesses = sum(
        len(payload["witnesses"]) for _sid, kind, payload in sources
        if kind == "unchecked")
    lines = [
        "# Path derivation bundles", "",
        f"Schema: {SCHEMA}", "",
        "Generated by `scripts/emit_path_derivation_bundles.py` at b3d. Every",
        "found instance carries exactly one result and every projected source",
        "file is parsed or listed unparsed below.", "",
    ]
    lines += report.seed.render()
    lines += [
        "## Languages parsed", "",
        "- Python: `.py`",
        "- Stata: `.do`, `.ado`",
        "- R: `.R`, `.r`", "",
        "## Counts", "",
        f"- Files parsed: {len(report.parsed_files)}",
        f"- Files unparsed (listed below): {len(report.unparsed)}",
        f"- Instances verified: {len(report.verified)}",
        f"- Failed candidates: {len(report.failed)}",
        f"- Unchecked candidate groups (files): "
        f"{sum(1 for _s, kind, _p in sources if kind == 'unchecked')}",
        f"- Unchecked lines: {unchecked_witnesses}", "",
        "## Verified instances", "",
    ]
    if not report.verified:
        lines += [VERIFIED_ZERO, ""]
    else:
        lines += ["| " + " | ".join(VERIFIED_COLS) + " |",
                  "| " + " | ".join(["---"] * len(VERIFIED_COLS)) + " |"]
        for row in sorted(report.verified,
                          key=lambda item: (item["File"], int(item["Line"]),
                                            item["Idiom"])):
            lines.append("| " + " | ".join(_cell(row[column])
                                           for column in VERIFIED_COLS) + " |")
        lines.append("")
    lines += ["## Candidates", ""]
    if not sources:
        lines += [CANDIDATE_ZERO, ""]
    else:
        lines += ["| " + " | ".join(CANDIDATE_COLS) + " |",
                  "| " + " | ".join(["---"] * len(CANDIDATE_COLS)) + " |"]
        for source_id, kind, payload in sources:
            if kind == "failed":
                cells = [
                    source_id, "site", "failed", payload["file"],
                    str(payload["line"]), payload["idiom"], payload["check"],
                    payload["statement"], payload["machine"], FAILED_QUESTION,
                ]
                lines.append("| " + " | ".join(_cell(cell) for cell in cells) + " |")
                continue
            for witness in payload["witnesses"]:
                witness_id = ("file" if witness.get("whole_file")
                              else f"line:{witness['line']}")
                cells = [
                    source_id, witness_id, "unchecked", payload["file"],
                    str(witness["line"]), witness["idiom"], DASH,
                    witness["statement"], f"reason={witness['reason']}",
                    UNCHECKED_QUESTION,
                ]
                lines.append("| " + " | ".join(_cell(cell) for cell in cells) + " |")
        lines.append("")
    lines += _render_unparsed(report)
    return "\n".join(lines).rstrip() + "\n"


def _render_unparsed(report):
    """Render the visible coverage limit: every file the sweep could not parse."""
    lines = ["## Unparsed files", ""]
    if not report.unparsed:
        return lines + [UNPARSED_ZERO, ""]
    return lines + [f"- `{relative}` {DASH} {reason}"
                    for relative, reason in report.unparsed] + [""]


# --------------------------------------------------------------------- parsing


class Witness:
    __slots__ = ("witness_id", "line", "idiom", "check", "statement",
                 "machine", "reason", "question")

    def __init__(self, witness_id, line, idiom, check, statement, machine,
                 reason, question):
        self.witness_id = witness_id
        self.line = line
        self.idiom = idiom
        self.check = check
        self.statement = statement
        self.machine = machine
        self.reason = reason
        self.question = question


class Source:
    __slots__ = ("source_id", "kind", "file", "witnesses")

    def __init__(self, source_id, kind, file, witnesses):
        self.source_id = source_id
        self.kind = kind
        self.file = file
        self.witnesses = witnesses


class Artifact:
    __slots__ = ("seed", "counts", "verified", "sources", "unparsed")

    def __init__(self, seed, counts, verified, sources, unparsed):
        self.seed = seed
        self.counts = counts
        self.verified = verified
        self.sources = sources
        self.unparsed = unparsed


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
    found, index = [], 0
    while index + 1 < len(lines):
        headers = _split_row(lines[index]) if lines[index].lstrip().startswith("|") else []
        divider = _split_row(lines[index + 1]) if lines[index + 1].lstrip().startswith("|") else []
        if headers and len(headers) == len(divider) and all(
                re.fullmatch(r":?-{3,}:?", cell) for cell in divider):
            rows, index = [], index + 2
            while index < len(lines) and lines[index].lstrip().startswith("|"):
                rows.append(_split_row(lines[index]))
                index += 1
            found.append((headers, rows))
            continue
        index += 1
    return found


_SEED_ENTRY_RE = re.compile(r"^- Entry: `(?P<script>[^`]+)` @ `(?P<cwd>[^`]+)`$")
_COUNT_RE = re.compile(r"^- (?P<label>.+): (?P<value>\d+)$")
_UNPARSED_RE = re.compile(rf"^- `(?P<file>[^`]+)` {DASH} (?P<reason>[a-z_]+)$")


def _parse_seed(text):
    if "## Invocation seed" not in text:
        raise PathDerivationError("path-derivation artifact has no invocation seed record")
    block = text.split("## Invocation seed", 1)[1].split("##", 1)[0]
    lines = [line for line in block.splitlines() if line.strip()]
    if not lines:
        raise PathDerivationError("path-derivation seed record is empty")
    if lines == ["- No documented invocation."]:
        return SeedRecord((), True)
    entries = []
    for line in lines:
        match = _SEED_ENTRY_RE.match(line)
        if not match:
            raise PathDerivationError(
                f"malformed path-derivation seed record line: {line!r}")
        entries.append(_validate_entry(match.group("script"), match.group("cwd")))
    if not entries:
        raise PathDerivationError("path-derivation seed record names no entry")
    return SeedRecord(entries, False)


def parse_artifact(text):
    """Validate the PD artifact and return its structured content."""
    if "\r" in text:
        raise PathDerivationError("path-derivation artifact must use LF line endings")
    if f"Schema: {SCHEMA}" not in text:
        raise PathDerivationError(f"expected Schema: {SCHEMA}")
    seed = _parse_seed(text)
    for heading in ("## Counts", "## Verified instances", "## Candidates",
                    "## Unparsed files"):
        if text.count(heading) != 1:
            raise PathDerivationError(
                f"path-derivation artifact needs exactly one {heading} section")
    counts_block = text.split("## Counts", 1)[1].split("##", 1)[0]
    counts = {}
    for line in counts_block.splitlines():
        if not line.strip():
            continue
        match = _COUNT_RE.match(line.strip())
        if not match or match.group("label") not in COUNT_LABELS:
            raise PathDerivationError(f"malformed count line: {line.strip()!r}")
        counts[match.group("label")] = int(match.group("value"))
    if sorted(counts) != sorted(COUNT_LABELS):
        raise PathDerivationError("path-derivation counts block is incomplete")

    tables = _tables(text)
    verified_tables = [rows for headers, rows in tables if headers == VERIFIED_COLS]
    candidate_tables = [rows for headers, rows in tables if headers == CANDIDATE_COLS]
    verified_block = text.split("## Verified instances", 1)[1].split("## Candidates", 1)[0]
    candidate_block = text.split("## Candidates", 1)[1].split("## Unparsed files", 1)[0]
    unparsed_block = text.split("## Unparsed files", 1)[1]

    if VERIFIED_ZERO in verified_block:
        if verified_tables:
            raise PathDerivationError("verified explicit zero conflicts with a table")
        verified_rows = []
    elif len(verified_tables) != 1:
        raise PathDerivationError("expected exactly one verified-instance table")
    else:
        verified_rows = verified_tables[0]
    if CANDIDATE_ZERO in candidate_block:
        if candidate_tables:
            raise PathDerivationError("candidate explicit zero conflicts with a table")
        candidate_rows = []
    elif len(candidate_tables) != 1:
        raise PathDerivationError("expected exactly one candidate table")
    else:
        candidate_rows = candidate_tables[0]

    verified = []
    for index, raw in enumerate(verified_rows, start=1):
        if len(raw) != len(VERIFIED_COLS):
            raise PathDerivationError(f"malformed verified row {index}")
        row = dict(zip(VERIFIED_COLS, raw))
        if row["Check"] not in {"A", "B"}:
            raise PathDerivationError(f"verified row {index} has invalid Check")
        verified.append(row)

    sources, order = {}, []
    for index, raw in enumerate(candidate_rows, start=1):
        if len(raw) != len(CANDIDATE_COLS):
            raise PathDerivationError(f"malformed candidate row {index}")
        row = dict(zip(CANDIDATE_COLS, raw))
        source_id, kind = row["Source ID"], row["Kind"]
        if not re.fullmatch(r"PD-\d{3,}", source_id):
            raise PathDerivationError(f"invalid PD source ID {source_id}")
        if kind not in CANDIDATE_KINDS:
            raise PathDerivationError(f"candidate row {index} has invalid Kind {kind}")
        witness_id = row["Witness ID"]
        reason = None
        if kind == "failed":
            if witness_id != "site":
                raise PathDerivationError(
                    f"failed source {source_id} must use witness ID site")
            if row["Check"] not in {"A", "B"}:
                raise PathDerivationError(f"failed source {source_id} has invalid Check")
        else:
            if witness_id != "file" and not re.fullmatch(r"line:\d+", witness_id):
                raise PathDerivationError(
                    f"unchecked witness {witness_id} must be `file` or `line:<n>`")
            match = re.fullmatch(r"reason=([a-z_]+)", row["Machine Numbers"])
            if not match or match.group(1) not in UNCHECKED_REASONS:
                raise PathDerivationError(
                    f"unchecked witness {source_id}/{witness_id} has an invalid reason")
            reason = match.group(1)
            if (witness_id == "file") != (reason == "parse_failure"):
                raise PathDerivationError(
                    f"unchecked witness {source_id}/{witness_id} disagrees with "
                    "the parse-failure witness rule")
        if not re.fullmatch(r"\d+", row["Line"]):
            raise PathDerivationError(f"candidate row {index} has a non-numeric Line")
        existing = sources.get(source_id)
        if existing is None:
            existing = Source(source_id, kind, row["File"], [])
            sources[source_id] = existing
            order.append(source_id)
        elif existing.kind != kind or existing.file != row["File"]:
            raise PathDerivationError(
                f"PD source {source_id} mixes kinds or files")
        elif kind == "failed":
            raise PathDerivationError(
                f"failed PD source {source_id} carries more than one witness")
        if any(item.witness_id == witness_id for item in existing.witnesses):
            raise PathDerivationError(
                f"duplicate PD witness {source_id}/{witness_id}")
        existing.witnesses.append(Witness(
            witness_id, int(row["Line"]), row["Idiom"], row["Check"],
            row["Statement"], row["Machine Numbers"], reason,
            row["Obligation Question"]))

    unparsed = []
    for line in unparsed_block.splitlines():
        if not line.strip() or line.strip() == UNPARSED_ZERO:
            continue
        match = _UNPARSED_RE.match(line.strip())
        if not match:
            raise PathDerivationError(f"malformed unparsed-file line: {line.strip()!r}")
        if match.group("reason") not in UNPARSED_REASONS:
            raise PathDerivationError(
                f"unparsed file {match.group('file')} has an invalid reason")
        unparsed.append((match.group("file"), match.group("reason")))
    if UNPARSED_ZERO in unparsed_block and unparsed:
        raise PathDerivationError("unparsed explicit zero conflicts with a listing")

    ordered = [sources[source_id] for source_id in order]
    failed_count = sum(1 for source in ordered if source.kind == "failed")
    group_count = sum(1 for source in ordered if source.kind == "unchecked")
    witness_count = sum(len(source.witnesses) for source in ordered
                        if source.kind == "unchecked")
    if counts["Instances verified"] != len(verified):
        raise PathDerivationError("verified count disagrees with the verified table")
    if counts["Failed candidates"] != failed_count:
        raise PathDerivationError("failed count disagrees with the candidate table")
    if counts["Unchecked candidate groups (files)"] != group_count:
        raise PathDerivationError("unchecked group count disagrees with the candidate table")
    if counts["Unchecked lines"] != witness_count:
        raise PathDerivationError("unchecked line count disagrees with the candidate table")
    if counts["Files unparsed (listed below)"] != len(unparsed):
        raise PathDerivationError("unparsed count disagrees with the unparsed listing")
    expected_ids = [f"PD-{index:03d}" for index in range(1, len(ordered) + 1)]
    if order != expected_ids:
        raise PathDerivationError("PD source IDs are not sequential in report order")
    return Artifact(seed, counts, verified, ordered, unparsed)


# ------------------------------------------------------------------------- CLI


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


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_root", type=Path)
    parser.add_argument("--audit-dir", type=Path, default=Path("audit"))
    parser.add_argument("--entry", action="append", default=[],
                        metavar="SCRIPT@CWD")
    parser.add_argument("--no-documented-invocation", action="store_true")
    parser.add_argument("-o", "--output", type=Path)
    return parser


def seed_from_args(args):
    if args.entry and args.no_documented_invocation:
        raise PathDerivationError(
            "--entry and --no-documented-invocation are mutually exclusive")
    if not args.entry and not args.no_documented_invocation:
        raise PathDerivationError(
            "no invocation seed: pass --entry <script>@<cwd> for every documented "
            "entry point, or --no-documented-invocation when the package "
            "documents none")
    if args.no_documented_invocation:
        return SeedRecord((), True)
    return SeedRecord([parse_entry_flag(value) for value in args.entry], False)


def main():
    args = build_parser().parse_args()
    if not args.package_root.is_dir():
        print(f"error: package root is not a directory: {args.package_root}",
              file=sys.stderr)
        return 2
    try:
        seed = seed_from_args(args)
        report = scan_package(args.package_root, seed)
        payload = render_artifact(report)
        parse_artifact(payload)
    except (PathDerivationError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out = args.output or args.audit_dir / "_run" / "path_derivation_bundles.md"
    _write_atomic(out, payload)
    print(f"scanned {len(report.parsed_files)} source file(s); "
          f"{len(report.verified)} verified, {len(report.failed)} failed, "
          f"{len(report.groups)} unchecked group(s) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
