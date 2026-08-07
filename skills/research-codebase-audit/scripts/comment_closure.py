"""Span, comment-block, and name-filter logic for the b5 comment-closure gate.

U13 (issue #18) obliges a recheck worker to quote every in-span name-bearing
comment block before writing `not_error` on a mechanically mapped row.  This
module owns the mechanical half of that duty: it recomputes, from the detector
artifacts and the audited source, exactly which physical comment lines the
worker owed.  It is a pure-logic wire module in the ``definition_use.py``
tradition -- no audit-dir sequencing, no failure wording; the b5 branch of
``lint_registers.py`` owns both.

Everything here fails loud.  A missing or malformed span source, an anchor that
does not parse under its channel's grammar, or a coordinate outside the named
file raises :class:`CommentClosureError`; the caller refuses the gate.  An empty
expected set is only ever produced by a declared accepted limit (a file suffix
outside the closed comment-grammar table, or a span with no name-bearing
comment block), never by a source that could not be resolved.
"""

import re
from pathlib import Path

import definition_use as du


# The closed verdict vocabulary of the `### Comment closure` table.
VERDICTS = ("consistent", "contradicts_guard", "unrelated")
CONTRADICTS_GUARD = "contradicts_guard"

# The closed, suffix-keyed comment-grammar table (design call 5).  Suffixes are
# matched case-insensitively, so `.R` and `.r` are the same entry.  A file whose
# suffix is absent contributes an empty mechanical expected set -- an accepted
# limit backstopped by the worker's read-all-comments prompt duty.
GRAMMARS = {".do": "stata", ".ado": "stata", ".py": "hash", ".r": "hash"}

# What "the guard" -- the mechanically checked proposition a dismissal rests on
# -- means on each detector channel.  Mirrored in prose in `registers.md`.
GUARD_BY_CHANNEL = {
    "DU": "the consumer's guard expression",
    "CV": "the checked convention at the anchor",
    "AC": "the argument contract at the anchored call",
    "MF": "the manifest expectation the witness records",
    "PD": "the asserted path resolution",
}

# Channels whose `Site Anchor` carries the argument-contract call ordinal.
CALL_ANCHOR_CHANNELS = {"AC"}

# Channels whose emitter may write an anchor that carries no usable line
# coordinate.  `check_manifests.py` falls back to the bare manifest name when a
# finding has no line, and `cv_scan.py` anchors every not_divergent witness by
# the verdict digest (the conventions-scan worker contract also permits a
# content anchor for divergent witnesses).  Such an anchor names no span, so it
# yields an empty mechanical expected set rather than a refusal.  Every other
# channel, and any in-range failure on these two, still fails closed.
LINE_OPTIONAL_CHANNELS = {"MF", "CV"}

DU_ARTIFACT_REL = "_run/definition_use_bundles.md"
MF_ARTIFACT_REL = "_run/manifest_check.md"
MF_SOURCE_COLS = ["Source ID", "Manifest", "Format", "Consumer Role",
                  "Witness Count"]

_PLAIN_ANCHOR_RE = re.compile(r"(?P<file>.+):(?P<line>\d+)")
_CALL_ANCHOR_RE = re.compile(r"(?P<file>.+):(?P<line>\d+)@call=(?P<ordinal>\d+)")
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_STATA_LABEL_RE = re.compile(r"\s*label\s+(?:variable|define)\b", re.IGNORECASE)


class CommentClosureError(ValueError):
    """A comment-closure span source is missing, malformed, or out of range."""


# ------------------------------------------------------------------ grammar


def grammar_for(relative_path):
    """Return the comment grammar for *relative_path*, or None when unpinned."""
    return GRAMMARS.get(Path(str(relative_path)).suffix.lower())


def _mask_strings(raw, grammar):
    """Blank out string-literal spans so markers inside them are never comments.

    Length is preserved so every index still addresses the same character of the
    original line.  Stata carries both plain ``"..."`` and the compound
    ``` `"..."' ``` form; Python and R carry single- and double-quoted strings
    with backslash escapes.
    """
    out = list(raw)
    i, n = 0, len(raw)
    while i < n:
        if grammar == "stata" and raw[i:i + 2] == '`"':
            end = raw.find('"\'', i + 2)
            stop = n if end == -1 else end + 2
            for j in range(i, stop):
                out[j] = " "
            i = stop
            continue
        quotes = '"' if grammar == "stata" else "\"'"
        if raw[i] in quotes:
            quote = raw[i]
            out[i] = " "
            j = i + 1
            while j < n:
                if grammar != "stata" and raw[j] == "\\":
                    out[j] = " "
                    if j + 1 < n:
                        out[j + 1] = " "
                    j += 2
                    continue
                closing = raw[j] == quote
                out[j] = " "
                j += 1
                if closing:
                    break
            i = j
            continue
        i += 1
    return "".join(out)


def _stata_scan(raw, in_block):
    """Classify one Stata line.

    Returns ``(has_code, comment_start, block_lines, in_block_after)`` where
    *comment_start* is the index at which a ``*``/``//`` line comment begins (or
    None) and *block_lines* is True when the line lies inside or opens a
    ``/* ... */`` extent.
    """
    masked = _mask_strings(raw, "stata")
    has_code = False
    comment_start = None
    block_lines = in_block
    i, n = 0, len(masked)
    while i < n:
        two = masked[i:i + 2]
        if in_block:
            if two == "*/":
                in_block = False
                i += 2
            else:
                i += 1
            continue
        if two == "/*":
            block_lines = True
            in_block = True
            i += 2
            continue
        if two == "//":
            comment_start = i
            break
        char = masked[i]
        if char.isspace():
            i += 1
            continue
        if char == "*" and not has_code:
            # A `*` in first non-blank position opens a whole-line comment.
            comment_start = i
            break
        has_code = True
        i += 1
    return has_code, comment_start, block_lines, in_block


def _hash_scan(raw):
    """Classify one Python/R line: ``(has_code, comment_start)``."""
    masked = _mask_strings(raw, "hash")
    has_code = False
    for i, char in enumerate(masked):
        if char == "#":
            return has_code, i
        if not char.isspace():
            has_code = True
    return has_code, None


def comment_blocks(lines, grammar):
    """Return the comment blocks of *lines* as lists of 1-based line numbers.

    A block is a ``/* ... */`` extent, a maximal run of consecutive
    comment-only lines, a code line carrying a trailing comment (a one-line
    block attached to its code line), or a Stata ``label variable`` /
    ``label define`` statement (a singleton intent unit that never merges into
    an adjacent comment block).
    """
    blocks = []
    run = []

    def flush():
        if run:
            blocks.append(list(run))
            run.clear()

    if grammar == "stata":
        in_block = False
        extent = []
        for index, raw in enumerate(lines, start=1):
            was_in_block = in_block
            has_code, comment_start, block_lines, in_block = _stata_scan(
                raw, in_block)
            if not was_in_block and _STATA_LABEL_RE.match(raw):
                flush()
                if extent:
                    blocks.append(extent)
                    extent = []
                blocks.append([index])
                continue
            if block_lines:
                flush()
                extent.append(index)
                if not in_block:
                    blocks.append(extent)
                    extent = []
                continue
            if extent:
                blocks.append(extent)
                extent = []
            if comment_start is None:
                flush()
                continue
            if has_code:
                flush()
                blocks.append([index])
            else:
                run.append(index)
        flush()
        if extent:
            blocks.append(extent)
        return blocks

    for index, raw in enumerate(lines, start=1):
        has_code, comment_start = _hash_scan(raw)
        if comment_start is None:
            flush()
            continue
        if has_code:
            flush()
            blocks.append([index])
        else:
            run.append(index)
    flush()
    return blocks


def code_portion(raw, grammar):
    """Return the code half of *raw* -- strings masked, any comment removed."""
    if grammar == "stata":
        has_code, comment_start, block_lines, _after = _stata_scan(raw, False)
        masked = _mask_strings(raw, "stata")
        if block_lines and not has_code:
            return ""
        text = masked if comment_start is None else masked[:comment_start]
        return re.sub(r"/\*.*", " ", text)
    if grammar == "hash":
        masked = _mask_strings(raw, "hash")
        _has_code, comment_start = _hash_scan(raw)
        return masked if comment_start is None else masked[:comment_start]
    return raw


# ------------------------------------------------------------- name filter


def identifier_tokens(text):
    """Return the identifier tokens of *text*, in first-appearance order."""
    seen, tokens = set(), []
    for token in _IDENTIFIER_RE.findall(str(text or "")):
        if token not in seen:
            seen.add(token)
            tokens.append(token)
    return tokens


def name_matcher(names):
    """Compile the full-token, case-sensitive matcher for *names* (or None)."""
    wanted = [name for name in dict.fromkeys(names) if name]
    if not wanted:
        return None
    alternation = "|".join(re.escape(name) for name in wanted)
    return re.compile(rf"(?<![A-Za-z0-9_])(?:{alternation})(?![A-Za-z0-9_])")


def expected_sites(lines, relative_path, span_lines, names):
    """Return the physical line numbers the closure block must quote.

    A block is in span when any of its lines is; a block is selected when any
    listed name appears as a full token anywhere in it.  Selection is
    block-level so a decisive line is captured even when only a sibling line
    names the variable.
    """
    grammar = grammar_for(relative_path)
    if grammar is None:
        return []
    matcher = name_matcher(names)
    if matcher is None:
        return []
    span = set(span_lines)
    sites = []
    for block in comment_blocks(lines, grammar):
        if not any(line in span for line in block):
            continue
        if not any(matcher.search(lines[line - 1]) for line in block):
            continue
        sites.extend(block)
    return sorted(set(sites))


# ------------------------------------------------------- sources and spans


def parse_anchor(anchor, channel):
    """Return ``(relative_path, line)`` from a channel-typed ``Site Anchor``."""
    raw = str(anchor or "").strip().strip("`").strip()
    if channel in CALL_ANCHOR_CHANNELS:
        pattern, shape = _CALL_ANCHOR_RE, "<file>:<line>@call=<n>"
    else:
        pattern, shape = _PLAIN_ANCHOR_RE, "<file>:<line>"
    match = pattern.fullmatch(raw)
    if not match:
        raise CommentClosureError(
            f"{channel} Site Anchor {anchor!r} does not parse as {shape}")
    line = int(match.group("line"))
    if line < 1:
        raise CommentClosureError(
            f"{channel} Site Anchor {anchor!r} names line {line}, not a positive line")
    return match.group("file").strip().strip("`").strip(), line


def anchor_carries_line(anchor):
    """Return True when an anchor names a real ``<file>:<line>`` coordinate.

    Used only for `LINE_OPTIONAL_CHANNELS`.  A source path never contains a
    colon, so a residual colon in the file half means the numeric tail is a
    content token that merely looks like a line -- a 12-digit CV verdict digest,
    say -- and not a coordinate.
    """
    raw = str(anchor or "").strip().strip("`").strip()
    match = _PLAIN_ANCHOR_RE.fullmatch(raw)
    if match is None:
        return False
    return ":" not in match.group("file")


def read_source(package_root, relative, label):
    """Return the physical lines of an audited file, failing loud."""
    text = str(relative)
    if not text or Path(text).is_absolute() or ".." in Path(text).parts:
        raise CommentClosureError(
            f"{label} names {relative!r}, which is not a package-relative path")
    path = Path(package_root) / text
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise CommentClosureError(
            f"{label} source file is missing or unreadable: {text} ({exc})") from exc


def require_in_range(lines, relative, line, label):
    """Validate a coordinate against the file's actual line count."""
    if line < 1 or line > len(lines):
        raise CommentClosureError(
            f"{label} names {relative}:{line}, outside the file's "
            f"{len(lines)} line(s)")


def _artifact_text(audit, relative, label):
    path = Path(audit) / relative
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CommentClosureError(
            f"{label} is missing or unreadable: {path} ({exc})") from exc


def du_artifact_row(audit, source_id, witness_id):
    """Return the one DU artifact row backing a mapped ``(source, witness)``."""
    text = _artifact_text(audit, DU_ARTIFACT_REL, "the definition/use artifact")
    try:
        artifact = du.parse_artifact(text)
    except du.DefinitionUseFormatError as exc:
        raise CommentClosureError(
            f"the definition/use artifact is malformed: {exc}") from exc
    rows = [row for row in artifact.standard_rows
            if row["Bundle ID"] == source_id and row["Witness ID"] == witness_id]
    if len(rows) != 1:
        raise CommentClosureError(
            f"the definition/use artifact resolves {len(rows)} standard rows for "
            f"{source_id}/{witness_id}, expected exactly one")
    return rows[0]


def manifest_names(audit, source_id):
    """Return the declared manifest name tokens for a mapped MF source.

    Review F-2: this return value is unreachable in production today.  Every
    manifest `check_manifests.py` detects is `.toml`, `.txt`, `.yml`, or a conda
    name, none of which has an entry in `GRAMMARS`, and an MF anchor names the
    manifest file itself -- so the span is always empty before the name list is
    consulted.  The fail-closed half (a missing or unresolvable artifact) is
    live and tested.  Pin the exact token derivation if the MF anchor wire ever
    points into a `.py`/`.do` consumer.
    """
    text = _artifact_text(audit, MF_ARTIFACT_REL, "the manifest-check artifact")
    rows = []
    for headers, table_rows, _line in du.parse_markdown_tables(text):
        if headers != MF_SOURCE_COLS:
            continue
        for row in table_rows:
            if len(row) != len(MF_SOURCE_COLS):
                continue
            record = dict(zip(MF_SOURCE_COLS,
                              [du.normalize_cell(cell) for cell in row]))
            if record["Source ID"] == source_id:
                rows.append(record)
    if len(rows) != 1:
        raise CommentClosureError(
            f"the manifest-check artifact resolves {len(rows)} source rows for "
            f"{source_id}, expected exactly one (the MF name source)")
    return identifier_tokens(rows[0]["Manifest"])


def expectation_for_key(package_root, audit, channel, source_id, witness_id,
                        site_anchor):
    """Return ``(relative_path, [line, ...])`` -- the expected comment sites.

    Spans are artifact-authoritative: DU borders come from the definition/use
    artifact's ``Definition Site``/``Consumer Site`` cells and every other
    channel's window comes from the mapping's ``Site Anchor``.  Audited files
    are read only to extract comment blocks and verify coordinates.
    """
    if channel == "DU":
        row = du_artifact_row(audit, source_id, witness_id)
        def_file, def_line = parse_anchor(row["Definition Site"], "DU")
        con_file, con_line = parse_anchor(row["Consumer Site"], "DU")
        if def_file != con_file:
            raise CommentClosureError(
                f"DU span for {source_id}/{witness_id} straddles two files "
                f"({def_file} and {con_file})")
        if def_line > con_line:
            raise CommentClosureError(
                f"DU span for {source_id}/{witness_id} runs backwards "
                f"({def_file}:{def_line} after {con_file}:{con_line})")
        lines = read_source(package_root, def_file, "the DU span")
        require_in_range(lines, def_file, def_line, "the DU Definition Site")
        require_in_range(lines, con_file, con_line, "the DU Consumer Site")
        span = set(range(def_line, con_line + 1)) | {def_line - 1}
        names = (identifier_tokens(row["Variable"])
                 + identifier_tokens(row["Full Guard"]))
        return def_file, expected_sites(lines, def_file, span, names)

    if channel in LINE_OPTIONAL_CHANNELS and not anchor_carries_line(site_anchor):
        return "", []

    relative, line = parse_anchor(site_anchor, channel)
    lines = read_source(package_root, relative, f"the {channel} anchor")
    require_in_range(lines, relative, line, f"the {channel} Site Anchor")
    span = {line, line - 1}
    if channel == "MF":
        names = manifest_names(audit, source_id)
    else:
        names = identifier_tokens(
            code_portion(lines[line - 1], grammar_for(relative)))
    return relative, expected_sites(lines, relative, span, names)
