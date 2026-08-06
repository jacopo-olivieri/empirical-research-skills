"""Shared syntax for the definition/use audit channel.

This module owns only the Markdown wire format.  Consumers remain responsible
for deciding whether mappings are complete and whether a final disposition is
acceptable.
"""

import re
from typing import NamedTuple


MAPPING_COLS = ["Bundle ID", "Error ID", "Mapping Kind"]
MAPPING_KINDS = {"new_candidate", "existing_row"}
ARTIFACT_COLS = [
    "Bundle ID", "Witness ID", "Identity Tuple", "Variable", "Producer Shape",
    "Definition Site", "Producer Statement", "Consumer Site",
    "Consumer Statement", "Full Guard", "Code/Comment Context",
    "Obligation Question",
]

BUNDLE_ID_PATTERN = r"DU-[0-9A-Za-z]+"
BUNDLE_ID_RE = re.compile(rf"{BUNDLE_ID_PATTERN}")
BUNDLE_TOKEN_RE = re.compile(
    rf"(?<![A-Za-z0-9_-]){BUNDLE_ID_PATTERN}(?![A-Za-z0-9_-])"
)
TABLE_RULE_RE = re.compile(r"^\s*\|[\s:|-]+\|\s*$")


class DefinitionUseFormatError(ValueError):
    """The definition/use Markdown wire format is missing or malformed."""


class DefinitionUseArtifact(NamedTuple):
    files_scanned: int
    standard_producer_groups: int
    standard_rows: list
    advisory_rows: list


def normalize_cell(value):
    """Normalize a Markdown cell containing plain text or inline code."""
    return str(value).strip().strip("`").strip()


def split_markdown_row(line):
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    cells, current, escaped = [], [], False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == "|":
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    cells.append("".join(current).strip())
    return cells


def parse_markdown_tables(text):
    """Return Markdown tables as ``(headers, rows, start_line)`` tuples."""
    lines = text.split("\n")
    tables, index = [], 0
    while index < len(lines) - 1:
        if (lines[index].lstrip().startswith("|")
                and TABLE_RULE_RE.match(lines[index + 1])):
            headers = split_markdown_row(lines[index])
            rows, cursor = [], index + 2
            while cursor < len(lines) and lines[cursor].lstrip().startswith("|"):
                rows.append(split_markdown_row(lines[cursor]))
                cursor += 1
            tables.append((headers, rows, index + 1))
            index = cursor
        else:
            index += 1
    return tables


def extract_bundle_tokens(text):
    """Extract complete DU identifiers without accepting prefix substrings."""
    return set(BUNDLE_TOKEN_RE.findall(text or ""))


def _count(text, label):
    matches = re.findall(rf"^- {re.escape(label)}:\s*(\d+)\s*$", text, re.M)
    if len(matches) != 1:
        raise DefinitionUseFormatError(
            f"missing machine-readable '{label}: <n>' count"
        )
    return int(matches[0])


def _section(text, heading):
    match = re.search(rf"^## {re.escape(heading)}\s*$", text, re.M)
    if not match:
        raise DefinitionUseFormatError(f"missing '{heading}' section")
    body = text[match.end():]
    next_heading = re.search(r"^##\s+", body, re.M)
    return body[:next_heading.start()] if next_heading else body


def _bundle_rows(section, label):
    rows = None
    for headers, candidate_rows, _line in parse_markdown_tables(section):
        if headers == ARTIFACT_COLS:
            rows = candidate_rows
            break
    if rows is None:
        raise DefinitionUseFormatError(f"{label} definition/use table is missing")

    parsed = []
    for index, row in enumerate(rows, start=1):
        if len(row) != len(ARTIFACT_COLS):
            raise DefinitionUseFormatError(
                f"malformed {label} row {index}: expected "
                f"{len(ARTIFACT_COLS)} cells, found {len(row)}"
            )
        normalized = [normalize_cell(cell) for cell in row]
        if (normalized[0].lower().startswith("no ")
                and not any(normalized[1:])):
            continue
        if not all(normalized):
            raise DefinitionUseFormatError(
                f"malformed {label} row {index}: empty required cell"
            )
        record = dict(zip(ARTIFACT_COLS, normalized))
        if not BUNDLE_ID_RE.fullmatch(record["Bundle ID"]):
            raise DefinitionUseFormatError(
                f"invalid Bundle ID '{record['Bundle ID']}' in {label} row"
            )
        parsed.append(record)
    return parsed


def parse_artifact(text):
    """Parse the complete emitted definition/use artifact."""
    files_scanned = _count(text, "Stata files scanned")
    producer_groups = _count(text, "Standard producer groups (file + gen line + variable)")
    standard_count = _count(text, "Standard candidates")
    advisory_count = _count(text, "Advisory candidates")
    standard_rows = _bundle_rows(_section(text, "Candidate findings"), "standard")
    advisory_rows = _bundle_rows(
        _section(text, "Advisory candidates"), "advisory"
    )
    if len(standard_rows) != standard_count:
        raise DefinitionUseFormatError(
            f"Standard candidates count is {standard_count} but the table "
            f"contains {len(standard_rows)} Bundle IDs"
        )
    if len(advisory_rows) != advisory_count:
        raise DefinitionUseFormatError(
            f"Advisory candidates count is {advisory_count} but the table "
            f"contains {len(advisory_rows)} Bundle IDs"
        )
    ids = [row["Bundle ID"] for row in standard_rows + advisory_rows]
    duplicate = next((bundle_id for bundle_id in ids if ids.count(bundle_id) > 1), None)
    if duplicate:
        raise DefinitionUseFormatError(f"duplicate Bundle ID '{duplicate}'")
    return DefinitionUseArtifact(
        files_scanned, producer_groups, standard_rows, advisory_rows
    )


def parse_mappings(text):
    """Parse and normalize the exact definition/use mapping table."""
    rows = None
    for headers, candidate_rows, _line in parse_markdown_tables(text):
        if headers == MAPPING_COLS:
            rows = candidate_rows
            break
    if rows is None:
        raise DefinitionUseFormatError(
            "missing Definition/use bundle mapping table with columns "
            + " | ".join(MAPPING_COLS)
        )
    mappings = []
    for index, row in enumerate(rows, start=1):
        if len(row) != len(MAPPING_COLS):
            raise DefinitionUseFormatError(
                f"malformed definition/use mapping row {index}: expected "
                f"{len(MAPPING_COLS)} cells, found {len(row)}"
            )
        record = dict(zip(MAPPING_COLS, map(normalize_cell, row)))
        if not any(record.values()):
            continue
        if not all(record.values()):
            raise DefinitionUseFormatError(
                f"malformed definition/use mapping row {index}: empty required cell"
            )
        if not BUNDLE_ID_RE.fullmatch(record["Bundle ID"]):
            raise DefinitionUseFormatError(
                f"invalid Bundle ID '{record['Bundle ID']}' in mapping row"
            )
        mappings.append(record)
    return mappings
