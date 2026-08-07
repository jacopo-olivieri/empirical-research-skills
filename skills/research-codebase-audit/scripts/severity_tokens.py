#!/usr/bin/env python3
"""Severity-token vocabulary, evidence records, receipts, and gate helpers.

This module owns the U8b wire formats.  It deliberately has no dependency on
``lint_registers`` so the register linter and the production verifier can both
consume the same implementation without an import cycle.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


RA_COLS = [
    "Reported Artifact ID", "Terminal Kind", "Path/Pattern",
    "Declaration Anchor", "Writer Site", "Availability",
]
RA_KINDS = {"table", "figure", "reported_dataset", "author_export"}
RA_AVAILABILITY = {"shipped", "generated_unshipped"}
RA_ZERO = "No qualifying reported artifacts."

TOKEN_RECORD_COLS = [
    "Record Type", "Error ID", "Token", "Obligation Digest", "Mechanism",
    "Witness IDs", "Error Location", "Flawed Identifier", "Cited Target",
    "Lineage JSON", "Probe Path", "Probe Output SHA256", "Verdict",
    "Derived From Receipt ID",
]
TOKEN_RECORD_TYPE = "token_verification"
TOKEN_RECORD_VERDICT = "verified"

TOKEN_RECEIPT_COLS = [
    "Receipt ID", "Error ID", "Token", "Obligation Digest", "Probe Path",
    "Probe Output SHA256", "Verdict",
]
TOKEN_RECEIPT_SCHEMA = "Schema: token-receipts/v1"
TOKEN_RECEIPT_ZERO = "No token receipts."

RESIDUAL_COLS = [
    "Error ID", "Target Kind", "Target ID", "Dispatch Input Head",
    "Target Introduction Head", "Supplementary Outcome",
    "Supplementary Evidence IDs",
]
RESIDUAL_OUTCOMES = {
    "exhausted_attempt", "exhausted_post_plan", "unavailable_blocked",
}

SUPPLEMENTARY_TOKEN_COLS = [
    "Error ID", "Reasons", "Parent Error ID", "Obligation Digest",
    "Witness IDs", "Required Products",
]
SUPPLEMENTARY_REASONS = ("discovery", "late_token", "split_token")

ADJUDICATION_COLS = ["Token Key", "Cited Target", "Verdict", "Evidence"]
ADJUDICATION_VERDICTS = {"upheld", "rejected"}
ADJUDICATION_ZERO = "none"

_STRICT_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:output:O-\d{4}|claim:C-\d{4}|"
    r"artifact:RA-[0-9a-f]{12})(?![A-Za-z0-9_-])"
)
_TOKEN_SHAPED_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:output|claim|artifact):[^\s,;|]+"
)
_ANCHOR_RE = re.compile(r"^([^:]+):(\d+)$")
_HEX64_RE = re.compile(r"[0-9a-f]{64}")


class SeverityTokenError(RuntimeError):
    """A severity-token artifact cannot be trusted."""


def clean(value):
    return str(value or "").strip().strip("`").strip()


def blank(value):
    return clean(value) in {"", "-", "—"}


def split_row(line):
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


def parse_tables(text):
    lines = text.split("\n")
    tables, index = [], 0
    while index < len(lines) - 1:
        if (lines[index].lstrip().startswith("|")
                and re.match(r"^\s*\|[\s:|-]+\|\s*$", lines[index + 1])):
            headers = split_row(lines[index])
            rows, cursor = [], index + 2
            while cursor < len(lines) and lines[cursor].lstrip().startswith("|"):
                rows.append(split_row(lines[cursor]))
                cursor += 1
            tables.append((headers, rows, index + 1))
            index = cursor
        else:
            index += 1
    return tables


def rows_for_columns(path, columns):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise SeverityTokenError(f"cannot read {path}: {exc}") from exc
    found = []
    for headers, rows, _line in parse_tables(text):
        if headers != columns:
            continue
        for index, row in enumerate(rows, start=1):
            if len(row) != len(columns):
                raise SeverityTokenError(f"{path}: malformed table row {index}")
            found.append(dict(zip(columns, map(clean, row))))
    return found


def md_table(columns, rows):
    lines = [
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join(["---"] * len(columns)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(
            str(row[column]).replace("|", "\\|") for column in columns
        ) + " |")
    return "\n".join(lines) + "\n"


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_file(package_root, relative):
    relative = clean(relative)
    candidate = (Path(package_root) / relative).resolve()
    root = Path(package_root).resolve()
    if (Path(relative).is_absolute() or ".." in Path(relative).parts
            or not candidate.is_relative_to(root) or not candidate.is_file()):
        raise SeverityTokenError(f"path does not resolve to a package file: {relative}")
    return candidate


def resolve_anchor(package_root, anchor):
    match = _ANCHOR_RE.fullmatch(clean(anchor))
    if not match:
        raise SeverityTokenError(f"anchor must be repo-relative path:line: {anchor!r}")
    path = _safe_file(package_root, match.group(1))
    line_number = int(match.group(2))
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if line_number < 1 or line_number > len(lines):
        raise SeverityTokenError(f"anchor line is outside the file: {anchor}")
    return path, line_number, lines[line_number - 1]


def reported_artifact_id(row):
    preimage = "\n".join([
        clean(row["Terminal Kind"]), normalized_pattern(row["Path/Pattern"]),
        clean(row["Declaration Anchor"]), clean(row["Writer Site"]), "",
    ]).encode("utf-8")
    return "RA-" + hashlib.sha256(preimage).hexdigest()[:12]


def _codemap_section(text, heading):
    match = re.search(
        rf"^##\s+{re.escape(heading)}\s*$\n(.*?)(?=^##\s+|\Z)",
        text, re.M | re.S,
    )
    return match.group(1) if match else None


def _material_paths(codemap_text):
    paths = set()
    intermediate = set()
    master_deliverables = set()
    for headers, rows, _line in parse_tables(codemap_text):
        if headers == ["Material", "Path", "Notes"]:
            for row in rows:
                if len(row) != 3:
                    continue
                path = clean(row[1])
                paths.add(path)
                if "master" in f"{clean(row[0])} {clean(row[2])}".lower():
                    master_deliverables.add(path)
        if headers == [
            "ID", "Dataset/path", "Type", "Stage", "Created by", "Inputs",
            "Consumed by", "Restricted/manual/external?", "Confidence", "Notes",
        ]:
            for row in rows:
                if len(row) != len(headers):
                    continue
                paths.add(clean(row[1]))
                if clean(row[2]) in {"intermediate dataset", "analysis dataset"}:
                    intermediate.add(clean(row[1]))
    return paths, intermediate, master_deliverables


def normalized_pattern(value):
    normalized = posixpath.normpath(clean(value).replace("\\", "/"))
    return "" if normalized == "." else normalized


def validate_ra_inventory(package_root, audit, manifest):
    """Return ``(rows_by_id, failures)`` for the b0 CODEMAP RA section."""
    path = Path(audit) / "CODEMAP.md"
    failures = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return {}, [f"{path}: cannot read CODEMAP ({exc})"]
    section = _codemap_section(text, "Reported Artifact Token Inventory")
    mode = (manifest or {}).get("mode", "replication")
    if section is None:
        if mode == "code_errors_only":
            failures.append(f"{path}: missing '## Reported Artifact Token Inventory'")
        return {}, failures
    matches = [(rows, line) for headers, rows, line in parse_tables(section)
               if headers == RA_COLS]
    section_tables = parse_tables(section)
    if any(headers != RA_COLS for headers, _rows, _line in section_tables):
        failures.append(f"{path}: reported-artifact section contains a non-RA table")
    if len(matches) > 1:
        failures.append(f"{path}: expected at most one reported-artifact token table")
    raw_rows = matches[0][0] if matches else []
    if not raw_rows and RA_ZERO not in section:
        failures.append(f"{path}: empty RA inventory requires exact '{RA_ZERO}'")
    if not raw_rows and section.strip() != RA_ZERO:
        failures.append(f"{path}: RA zero inventory must contain only '{RA_ZERO}'")
    if raw_rows and RA_ZERO in section:
        failures.append(f"{path}: RA table conflicts with its explicit-zero form")
    if mode != "code_errors_only" and raw_rows:
        failures.append(f"{path}: full mode forbids reported-artifact token rows")
    material_paths, intermediate, master_deliverables = _material_paths(text)
    rows_by_id, identities = {}, {}
    root = Path(package_root)
    paper_sources = set()
    for item in (manifest or {}).get("paper_source_set", []):
        if not isinstance(item, dict):
            continue
        source = Path(clean(item.get("source_path")))
        try:
            paper_sources.add(source.resolve().relative_to(root.resolve()).as_posix())
        except ValueError:
            paper_sources.add(source.as_posix())
    for index, raw in enumerate(raw_rows, start=1):
        if len(raw) != len(RA_COLS):
            failures.append(f"{path}: malformed RA row {index}")
            continue
        row = dict(zip(RA_COLS, map(clean, raw)))
        identity = tuple(row[column] for column in RA_COLS[1:5])
        wanted = reported_artifact_id(row)
        row_id = row["Reported Artifact ID"]
        if not re.fullmatch(r"RA-[0-9a-f]{12}", row_id) or row_id != wanted:
            failures.append(f"{path}: {row_id or 'RA row'} has incorrect derived ID (expected {wanted})")
        if row_id in rows_by_id:
            failures.append(f"{path}: duplicate or colliding Reported Artifact ID {row_id}")
        if identity in identities:
            failures.append(f"{path}: duplicate reported-artifact identity {identity}")
        rows_by_id[row_id] = row
        identities[identity] = row_id
        if row["Terminal Kind"] not in RA_KINDS:
            failures.append(f"{path}: {row_id} invalid Terminal Kind {row['Terminal Kind']!r}")
        if row["Availability"] not in RA_AVAILABILITY:
            failures.append(f"{path}: {row_id} invalid Availability {row['Availability']!r}")
        pattern = row["Path/Pattern"]
        if pattern != normalized_pattern(pattern):
            failures.append(f"{path}: {row_id} Path/Pattern is not normalized")
        if Path(pattern).is_absolute() or ".." in Path(pattern).parts:
            failures.append(f"{path}: {row_id} Path/Pattern must stay repo-relative")
        matches_now = sorted(root.glob(pattern)) if pattern else []
        wanted_availability = "shipped" if any(item.is_file() for item in matches_now) \
            else "generated_unshipped"
        if row["Availability"] != wanted_availability:
            failures.append(f"{path}: {row_id} Availability must be {wanted_availability}")
        if pattern not in material_paths:
            failures.append(f"{path}: {row_id} Path/Pattern is absent from the CODEMAP materials inventory")
        if pattern in intermediate:
            failures.append(f"{path}: {row_id} names an intermediate/analysis-only dataset")
        try:
            declaration_path, _line, declaration_text = resolve_anchor(
                package_root, row["Declaration Anchor"])
            declaration_rel = declaration_path.relative_to(root.resolve()).as_posix()
            declared_as_master = declaration_rel in master_deliverables
            if (declaration_rel not in paper_sources
                    and "readme" not in declaration_path.name.lower()
                    and not declared_as_master):
                failures.append(f"{path}: {row_id} Declaration Anchor is not author-facing")
            if not declaration_text.strip():
                failures.append(f"{path}: {row_id} Declaration Anchor resolves to a blank line")
        except SeverityTokenError as exc:
            failures.append(f"{path}: {row_id} {exc}")
        try:
            _writer_path, _line, writer_text = resolve_anchor(
                package_root, row["Writer Site"])
            if not re.search(r"(?i)\b(save|write|export|print|graph|table|figure|outreg|esttab)\b", writer_text):
                failures.append(f"{path}: {row_id} Writer Site is not a visible write/export site")
        except SeverityTokenError as exc:
            failures.append(f"{path}: {row_id} {exc}")
    return rows_by_id, failures


def literal_tokens(text):
    """Return every strict literal occurrence, preserving duplicates."""
    return [match.group(0) for match in _STRICT_TOKEN_RE.finditer(text or "")]


def malformed_token_shapes(text):
    shaped = []
    for match in _TOKEN_SHAPED_RE.finditer(text or ""):
        candidate = match.group(0).rstrip(".()[]{}")
        if not re.fullmatch(
                r"(?:output:O-\d{4}|claim:C-\d{4}|artifact:RA-[0-9a-f]{12})",
                candidate):
            shaped.append(candidate)
    return shaped


def token_allowed(token, mode):
    if mode == "code_errors_only":
        return bool(re.fullmatch(r"artifact:RA-[0-9a-f]{12}", token))
    return bool(re.fullmatch(r"(?:output:O|claim:C)-\d{4}", token))


def token_key(error_id, token):
    return f"{error_id} {token}"


def token_target(token):
    kind, target = token.split(":", 1)
    return kind, target


def severe_eligible(row):
    return (row.get("Error Type") != "pii_or_disclosure_risk"
            and row.get("Severity") in {"3", "4"}
            and row.get("Status") in {"confirmed", "confirmation_needed"})


def why_text(row):
    return (row.get("Why It Matters Original")
            if "Why It Matters Original" in row else row.get("Why It Matters", ""))


def row_token_state(row, mode):
    text = why_text(row)
    tokens = literal_tokens(text)
    malformed = malformed_token_shapes(text)
    if malformed:
        return None, f"malformed severity token(s): {', '.join(malformed)}"
    allowed = [token for token in tokens if token_allowed(token, mode)]
    forbidden = [token for token in tokens if not token_allowed(token, mode)]
    if forbidden:
        return None, f"token kind is forbidden in {mode} mode: {', '.join(forbidden)}"
    if len(allowed) != 1:
        return None, f"requires exactly one qualifying token (found {len(allowed)})"
    if tokens.count(allowed[0]) != 1:
        return None, f"duplicate literal token {allowed[0]}"
    return allowed[0], None


def _register_rows(path, id_column):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return {}
    for headers, rows, _line in parse_tables(text):
        if id_column not in headers or "Status" not in headers:
            continue
        result = {}
        for raw in rows:
            if len(raw) == len(headers):
                row = dict(zip(headers, map(clean, raw)))
                result[row[id_column]] = row
        return result
    return {}


def resolve_target(package_root, audit, manifest, token):
    """Return ``(state, row)`` where state is live, target_not_live, or invalid."""
    if not token_allowed(token, (manifest or {}).get("mode", "replication")):
        return "invalid", None
    kind, target = token_target(token)
    if kind == "artifact":
        inventory, failures = validate_ra_inventory(package_root, audit, manifest)
        if failures:
            return "invalid", None
        return ("live", inventory[target]) if target in inventory else ("invalid", None)
    filename, id_column = (("output_register.md", "Output ID") if kind == "output"
                           else ("claims_register.md", "Claim ID"))
    rows = _register_rows(Path(audit) / filename, id_column)
    row = rows.get(target)
    if row is None or row.get("Status", "").startswith("duplicate_of:"):
        return "target_not_live", row
    if kind == "output" and blank(row.get("Paper Location", "")):
        return "invalid", row
    if kind == "claim" and row.get("Used in Text") != "TRUE":
        return "invalid", row
    return "live", row


QUANTITATIVE_CLAIM_TYPE = "quantitative_result"


def _claim_qualifies(claim_row, output_id):
    """True when a cross-linked claim earns severity 4 for *output_id*.

    All four conditions hold together: the claim is live (not a
    ``duplicate_of:`` tombstone), it is reciprocal (its own ``Output IDs``
    names the output that cited it), it is used in the text, and its
    ``Claim Type`` is ``quantitative_result``.
    """
    if claim_row is None:
        return False
    if claim_row.get("Status", "").startswith("duplicate_of:"):
        return False
    if claim_row.get("Used in Text") != "TRUE":
        return False
    if claim_row.get("Claim Type") != QUANTITATIVE_CLAIM_TYPE:
        return False
    return output_id in re.findall(r"O-\d{4}", claim_row.get("Output IDs", "") or "")


def severity_four_target_failure(audit, token, target_row):
    """Return the failed severity-4 target-type condition, or ``None``.

    Read-only over the rows ``resolve_target`` already resolved: severity 4
    is earned only when the trace target is, or cross-links to, a live,
    reciprocal, text-used ``quantitative_result`` claim.  Called on ``live``
    targets only, so ``target_not_live`` routing is untouched.
    """
    kind, target = token_target(token)
    if kind == "artifact":
        return ("severity 4 is unavailable in code-errors-only mode "
                "(an RA receipt supports severity 3 at most)")
    if kind == "claim":
        claim_type = (target_row or {}).get("Claim Type", "")
        if claim_type != QUANTITATIVE_CLAIM_TYPE:
            return ("severity 4 requires a quantitative_result trace target; "
                    f"{target} has Claim Type {claim_type or '(none)'}")
        return None
    linked = re.findall(r"C-\d{4}", (target_row or {}).get("Claim IDs", "") or "")
    if not linked:
        return ("severity 4 requires a quantitative_result trace target; "
                f"{target} cross-links to no claim")
    claims = _register_rows(Path(audit) / "claims_register.md", "Claim ID")
    if any(_claim_qualifies(claims.get(claim_id), target) for claim_id in linked):
        return None
    return ("severity 4 requires a quantitative_result trace target; "
            f"{target} has no live, reciprocal, text-used quantitative_result "
            "cross-linked claim")


def decode_mechanism(sidecar):
    value = clean(sidecar)
    if not value.startswith("b64:"):
        raise SeverityTokenError("Mechanism must be a b64: five-field sidecar")
    encoded = value[4:]
    try:
        raw = base64.urlsafe_b64decode((encoded + "=" * (-len(encoded) % 4)).encode("ascii"))
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise SeverityTokenError(f"invalid mechanism sidecar: {exc}") from exc
    if not isinstance(parsed, dict) or list(parsed) != [
            "class", "object", "relation", "expected", "actual"]:
        raise SeverityTokenError("mechanism sidecar does not decode to the five-field schema")
    canonical = json.dumps(parsed, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if canonical != raw:
        raise SeverityTokenError("mechanism sidecar is not canonical JSON")
    return parsed


def list_cell(value):
    if blank(value):
        return []
    return [clean(item) for item in str(value).split(";") if not blank(item)]


def obligation_digest(error_id, token, mechanism_sidecar, witness_ids,
                      error_location, flawed_identifier):
    parsed = decode_mechanism(mechanism_sidecar)
    witnesses = sorted(set(list_cell(witness_ids) if isinstance(witness_ids, str)
                           else map(clean, witness_ids)))
    payload = {
        "schema": "severity-token-obligation/v1",
        "error_id": clean(error_id),
        "token": clean(token),
        "mechanism": parsed,
        "witness_ids": witnesses,
        "error_location": clean(error_location),
        "flawed_identifier": clean(flawed_identifier),
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def receipt_id(error_id, token, digest):
    preimage = "\0".join([
        "token-receipt/v1", clean(error_id), clean(token), clean(digest),
    ]).encode("utf-8")
    return "TR-" + hashlib.sha256(preimage).hexdigest()[:12]


def result_digest(returncode, stdout, stderr):
    preimage = f"exit={returncode}\n".encode("ascii") + stdout + b"\0" + stderr
    return hashlib.sha256(preimage).hexdigest()


def _run_probe(shard, probe_path):
    relative = Path(clean(probe_path))
    if relative.is_absolute() or ".." in relative.parts:
        raise SeverityTokenError(f"probe path must stay under its record artifact: {probe_path}")
    source = (Path(shard).parent / relative).resolve()
    if not source.is_relative_to(Path(shard).parent.resolve()) or not source.is_file():
        raise SeverityTokenError(f"persisted token probe is missing: {source}")
    with tempfile.TemporaryDirectory(prefix="rca-token-probe-") as temp:
        target = Path(temp) / source.name
        shutil.copy2(source, target)
        if target.suffix == ".py":
            command = [sys.executable, "-I", target.name]
        elif target.suffix in {".sh", ".bash"}:
            command = ["/bin/sh", target.name]
        else:
            command = [str(target)]
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C",
               "HOME": str(Path(temp) / "home"), "NO_PROXY": "*", "no_proxy": "*"}
        completed = subprocess.run(command, cwd=temp, capture_output=True, env=env)
    return source, completed


def _anchor_path(anchor):
    match = _ANCHOR_RE.fullmatch(clean(anchor))
    return match.group(1) if match else None


def _cell_paths(cell):
    return set(re.findall(r"[A-Za-z0-9_./-]+\.[A-Za-z0-9_]+", clean(cell)))


def validate_lineage(package_root, audit, manifest, record, error_row,
                     allow_nonlive=False):
    try:
        hops = json.loads(record["Lineage JSON"])
    except json.JSONDecodeError as exc:
        raise SeverityTokenError(f"{record['Error ID']}: Lineage JSON is invalid: {exc}") from exc
    if (not isinstance(hops, list) or not hops
            or not all(isinstance(hop, dict) and set(hop) == {"anchor", "carries"}
                       for hop in hops)):
        raise SeverityTokenError(
            f"{record['Error ID']}: lineage must be a non-empty ordered anchor/carries array")
    for hop in hops:
        _path, _line, source_line = resolve_anchor(package_root, hop["anchor"])
        carried = clean(hop["carries"])
        if not carried or carried not in source_line:
            raise SeverityTokenError(
                f"{record['Error ID']}: lineage hop {hop['anchor']} does not contain {carried!r}")
    first = hops[0]
    if clean(first["anchor"]) != clean(error_row.get("Code Location")):
        raise SeverityTokenError(f"{record['Error ID']}: lineage does not start at the error location")
    if clean(first["carries"]) != clean(record["Flawed Identifier"]):
        raise SeverityTokenError(f"{record['Error ID']}: lineage start is not anchored to the flawed identifier")
    kind, target = token_target(record["Token"])
    state, target_row = resolve_target(package_root, audit, manifest, record["Token"])
    if state == "invalid":
        raise SeverityTokenError(f"{record['Error ID']}: cited target is invalid")
    # A target may become non-live after a valid receipt was issued.  Receipt
    # verification therefore accepts the persisted endpoint evidence; gates
    # later route that row as target_not_live.
    if target_row is None:
        if allow_nonlive and state == "target_not_live":
            return
        raise SeverityTokenError(
            f"{record['Error ID']}: cited target was not live when the receipt was issued")
    anchors = [clean(hop["anchor"]) for hop in hops]
    anchor_paths = [_anchor_path(anchor) for anchor in anchors]
    if kind == "output":
        expected = _cell_paths(target_row.get("Producing Script", ""))
        if not expected.intersection(anchor_paths[-1:]):
            raise SeverityTokenError(f"{record['Error ID']}: output lineage endpoint is not its producing script")
    elif kind == "claim":
        expected = _cell_paths(target_row.get("Code/Data Source", ""))
        if not expected.intersection(anchor_paths[-1:]):
            raise SeverityTokenError(f"{record['Error ID']}: claim lineage endpoint is not its recorded location")
    else:
        required = {clean(target_row["Writer Site"]), clean(target_row["Declaration Anchor"])}
        if len(anchors) < 2 or set(anchors[-2:]) != required:
            raise SeverityTokenError(
                f"{record['Error ID']}: RA lineage must terminate through writer and declaration anchors")


def _load_register_error_rows(audit, prefer_staging=False):
    paths = [Path(audit) / "code_error_register.md"]
    if prefer_staging:
        paths.insert(0, Path(audit) / "_staging/code_error_register.md")
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for headers, rows, _line in parse_tables(text):
            if "Error ID" not in headers or "Code Location" not in headers:
                continue
            return {
                dict(zip(headers, map(clean, row)))["Error ID"]:
                dict(zip(headers, map(clean, row)))
                for row in rows if len(row) == len(headers)
            }
    return {}


def _record_paths(audit, stage):
    audit = Path(audit)
    if stage == "bC":
        return [audit / "plans/late_observation_corrections.md"]
    roots = [audit / "_code_error_recheck"]
    if stage == "code_b6b":
        roots.append(audit / "_code_error_recheck_supplementary")
    return [path for root in roots if root.is_dir() for path in sorted(root.rglob("*.md"))]


def _ledger_rows(paths):
    # Kept local to avoid importing the linter.  The distinctive tail makes
    # the code-ledger table unambiguous while allowing future base columns.
    ledgers = {}
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for headers, rows, _line in parse_tables(text):
            required = {"ID", "Accepted Mechanism", "Outcome Witness IDs"}
            if not required.issubset(headers):
                continue
            for raw in rows:
                if len(raw) != len(headers):
                    continue
                row = dict(zip(headers, map(clean, raw)))
                ledgers.setdefault(row["ID"], []).append((path, row))
    return ledgers


def load_token_records(audit, stage):
    records, failures = {}, []
    paths = _record_paths(audit, stage)
    for path in paths:
        try:
            rows = rows_for_columns(path, TOKEN_RECORD_COLS)
        except SeverityTokenError as exc:
            failures.append(str(exc))
            continue
        for row in rows:
            key = (row["Error ID"], row["Token"], row["Obligation Digest"])
            if key in records:
                failures.append(f"{path}: duplicate token_verification composite key {key}")
            records[key] = (path, row)
            if row["Record Type"] != TOKEN_RECORD_TYPE:
                failures.append(f"{path}: {row['Error ID']} Record Type must be {TOKEN_RECORD_TYPE}")
            if row["Verdict"] != TOKEN_RECORD_VERDICT:
                failures.append(f"{path}: {row['Error ID']} token verdict must be {TOKEN_RECORD_VERDICT}")
            if not _HEX64_RE.fullmatch(row["Probe Output SHA256"]):
                failures.append(f"{path}: {row['Error ID']} has invalid probe-output digest")
    return records, failures


def verify_token_records(package_root, audit, manifest, stage,
                         prefer_staging=False):
    records, failures = load_token_records(audit, stage)
    prior_receipts = {}
    prior_path = receipt_path(audit, stage)
    if prior_path.is_file():
        prior_receipts, prior_failures = load_receipts(audit, stage)
        if prior_failures:
            failures.extend(prior_failures)
            prior_receipts = {}
    paths = _record_paths(audit, stage)
    ledgers = _ledger_rows(paths) if stage != "bC" else {}
    error_rows = _load_register_error_rows(audit, prefer_staging)
    verified = []
    for key, (path, record) in sorted(records.items()):
        error_id, token, digest = key
        error_row = error_rows.get(error_id)
        if error_row is None:
            failures.append(f"{path}: token record names absent Error ID {error_id}")
            continue
        if record["Cited Target"] != token_target(token)[1]:
            failures.append(f"{path}: {error_id} Cited Target disagrees with Token")
        if clean(record["Error Location"]) != clean(error_row.get("Code Location")):
            failures.append(f"{path}: {error_id} token record has stale Error Location")
        try:
            parsed_mechanism = decode_mechanism(record["Mechanism"])
            if clean(record["Flawed Identifier"]) != clean(parsed_mechanism["object"]):
                failures.append(f"{path}: {error_id} Flawed Identifier disagrees with mechanism object")
            wanted = obligation_digest(
                error_id, token, record["Mechanism"], record["Witness IDs"],
                record["Error Location"], record["Flawed Identifier"],
            )
            if digest != wanted:
                failures.append(f"{path}: {error_id} obligation digest disagrees with its bound fields")
        except SeverityTokenError as exc:
            failures.append(f"{path}: {error_id} {exc}")
            continue
        if stage != "bC":
            candidates = ledgers.get(error_id, [])
            matching = [item for item in candidates
                        if clean(item[1].get("Accepted Mechanism")) == record["Mechanism"]
                        and sorted(list_cell(item[1].get("Outcome Witness IDs")))
                        == sorted(list_cell(record["Witness IDs"]))]
            if len(matching) != 1:
                failures.append(f"{path}: {error_id} token record does not join exactly to one code ledger")
                continue
        try:
            validate_lineage(
                package_root, audit, manifest, record, error_row,
                allow_nonlive=key in prior_receipts,
            )
            _source, result = _run_probe(path, record["Probe Path"])
            observed = result_digest(result.returncode, result.stdout, result.stderr)
            if result.returncode != 0:
                raise SeverityTokenError(f"probe exited {result.returncode}")
            if observed != record["Probe Output SHA256"]:
                raise SeverityTokenError("probe output digest disagrees with the record")
        except (OSError, SeverityTokenError) as exc:
            failures.append(f"{path}: {error_id} {exc}")
            continue
        verified.append({
            "Receipt ID": receipt_id(error_id, token, digest),
            "Error ID": error_id,
            "Token": token,
            "Obligation Digest": digest,
            "Probe Path": record["Probe Path"],
            "Probe Output SHA256": record["Probe Output SHA256"],
            "Verdict": TOKEN_RECORD_VERDICT,
        })
    return verified, failures


def render_receipts(receipts):
    lines = [TOKEN_RECEIPT_SCHEMA, ""]
    if not receipts:
        return "\n".join(lines + [TOKEN_RECEIPT_ZERO, ""])
    return "\n".join(lines) + md_table(
        TOKEN_RECEIPT_COLS,
        sorted(receipts, key=lambda row: row["Receipt ID"]),
    )


def receipt_path(audit, stage):
    if stage not in {"code_b6a", "code_b6b", "bC"}:
        raise SeverityTokenError(f"invalid token-receipt stage {stage!r}")
    return Path(audit) / "_run" / stage / "token_receipts.md"


def write_atomic(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def load_receipts(audit, stage, records=None):
    path = receipt_path(audit, stage)
    failures, parsed = [], {}
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return {}, [f"{path}: cannot read token receipts ({exc})"]
    if b"\r" in raw:
        failures.append(f"{path}: token receipts must use LF newlines")
    if not text.startswith(TOKEN_RECEIPT_SCHEMA + "\n"):
        failures.append(f"{path}: first line must be '{TOKEN_RECEIPT_SCHEMA}'")
    rows = []
    for headers, raw_rows, _line in parse_tables(text):
        if headers == TOKEN_RECEIPT_COLS:
            rows.extend(raw_rows)
    if not rows and TOKEN_RECEIPT_ZERO not in text:
        failures.append(f"{path}: requires its table or exact '{TOKEN_RECEIPT_ZERO}'")
    if rows and TOKEN_RECEIPT_ZERO in text:
        failures.append(f"{path}: receipt table conflicts with explicit zero")
    last_id = None
    ids = {}
    for index, raw_row in enumerate(rows, start=1):
        if len(raw_row) != len(TOKEN_RECEIPT_COLS):
            failures.append(f"{path}: malformed receipt row {index}")
            continue
        row = dict(zip(TOKEN_RECEIPT_COLS, map(clean, raw_row)))
        key = (row["Error ID"], row["Token"], row["Obligation Digest"])
        wanted = receipt_id(*key)
        if row["Receipt ID"] != wanted:
            failures.append(f"{path}: {row['Receipt ID']} has wrong derived Receipt ID (expected {wanted})")
        if row["Receipt ID"] in ids or key in parsed:
            failures.append(f"{path}: duplicate or colliding token receipt {row['Receipt ID']}")
        if last_id is not None and row["Receipt ID"] < last_id:
            failures.append(f"{path}: token receipts are not sorted by Receipt ID")
        last_id = row["Receipt ID"]
        ids[row["Receipt ID"]] = key
        parsed[key] = row
        if row["Verdict"] != TOKEN_RECORD_VERDICT:
            failures.append(f"{path}: {row['Receipt ID']} verdict must be {TOKEN_RECORD_VERDICT}")
        if records is not None and key not in records:
            failures.append(f"{path}: {row['Receipt ID']} has no matching verifier record")
    if not failures:
        expected = render_receipts(list(parsed.values())).encode("utf-8")
        if raw != expected:
            failures.append(f"{path}: token receipts do not match the pinned serialization")
    return parsed, failures


TOKENLESS_FAILURE = "requires exactly one qualifying token (found 0)"
UNRECEIPTED_FAILURE = "requires exactly one verifier token receipt (found 0)"


def excuse_uncovered_failures(package_root, audit, manifest, rows, failures,
                              allowed_uncovered=(), tokenless_ok=()):
    """Drop per-row gate failures excused by pending or residual coverage.

    ``allowed_uncovered`` rows (open late/split supplementary obligations) may
    lack a verifier receipt while their token still resolves live.
    ``tokenless_ok`` rows (validated residual coverage) may additionally lack
    the token literal entirely — the residual lint proves the target
    separately, and the partition still requires exactly-once coverage.
    """
    allowed = set(allowed_uncovered)
    tokenless = set(tokenless_ok)
    by_id = {row.get("Error ID"): row for row in rows}
    mode = (manifest or {}).get("mode", "replication")
    remaining = []
    for failure in failures:
        match = re.match(r"(E-\d{4}): (.*)$", failure)
        eid = match.group(1) if match else None
        detail = match.group(2) if match else ""
        if eid in tokenless and detail in {TOKENLESS_FAILURE, UNRECEIPTED_FAILURE}:
            continue
        if eid in allowed and detail == UNRECEIPTED_FAILURE:
            row = by_id.get(eid, {})
            token, problem = row_token_state(row, mode)
            state = (resolve_target(package_root, audit, manifest, token)[0]
                     if token and not problem else "invalid")
            if state == "live":
                continue
        remaining.append(failure)
    return remaining


def gate_required(rows):
    """The token gate is mandatory whenever a severe-eligible row exists."""
    return any(severe_eligible(row) for row in rows)


def gate_rows(package_root, audit, manifest, rows, stage):
    """Classify currently eligible rows and validate their receipt coverage.

    Returns ``(classifications, failures)``.  A classification is ``valid``,
    ``target_not_live``, or ``invalid``.  PII rows and non-severe/non-final
    rows are outside the returned mapping.
    """
    mode = (manifest or {}).get("mode", "replication")
    stages = (stage,) if isinstance(stage, str) else tuple(stage)
    if not stages or any(item not in {"code_b6a", "code_b6b", "bC"}
                         for item in stages):
        raise SeverityTokenError(f"invalid token-receipt stage set {stages!r}")
    # A union gate reads each existing receipt home.  If none exists, retain
    # the first home so the ordinary missing-receipt refusal still fires.
    active_stages = tuple(
        item for item in stages if receipt_path(audit, item).is_file())
    if not active_stages:
        active_stages = stages[:1]
    failures, receipts, verified = [], {}, {}
    for item in active_stages:
        records, record_failures = load_token_records(audit, item)
        failures.extend(record_failures)
        home_receipts, receipt_failures = load_receipts(audit, item, records)
        failures.extend(receipt_failures)
        verified_rows, verification_failures = verify_token_records(
            package_root, audit, manifest, item)
        failures.extend(verification_failures)
        home_verified = {
            (row["Error ID"], row["Token"], row["Obligation Digest"]): row
            for row in verified_rows
        }
        for key, receipt in home_receipts.items():
            if key in receipts:
                failures.append(
                    f"token receipt composite key appears in multiple homes: {key}")
            else:
                receipts[key] = receipt
        for key, receipt in home_verified.items():
            if key in verified:
                failures.append(
                    f"re-derived token record appears in multiple homes: {key}")
            else:
                verified[key] = receipt
    if set(receipts) != set(verified):
        failures.append(
            "token receipt set disagrees with re-derived verifier records; "
            f"expected={sorted(verified)}, actual={sorted(receipts)}")
    else:
        for key in sorted(receipts):
            if receipts[key] != verified[key]:
                failures.append(f"token receipt bytes disagree with re-derived record for {key}")
    classifications = {}
    for row in rows:
        if not severe_eligible(row):
            continue
        error_id = row["Error ID"]
        token, problem = row_token_state(row, mode)
        if problem:
            classifications[error_id] = "invalid"
            failures.append(f"{error_id}: {problem}")
            continue
        matching = [key for key in receipts if key[0] == error_id and key[1] == token]
        if len(matching) != 1:
            classifications[error_id] = "invalid"
            failures.append(f"{error_id}: requires exactly one verifier token receipt (found {len(matching)})")
            continue
        state, target_row = resolve_target(package_root, audit, manifest, token)
        if state == "invalid":
            classifications[error_id] = "invalid"
            failures.append(f"{error_id}: token target is invalid")
        else:
            classifications[error_id] = state
            if state == "live" and row.get("Severity") == "4":
                detail = severity_four_target_failure(audit, token, target_row)
                if detail is not None:
                    failures.append(f"{error_id}: {token} {detail}")
    return classifications, failures


def pin_dispatch_inputs(audit):
    """Snapshot claims/output bytes and return the documented dispatch head."""
    audit = Path(audit)
    destination = audit / "_run/snapshots/code_b5_dispatch"
    destination.mkdir(parents=True, exist_ok=True)
    parts = []
    for name, label in (("claims_register.md", "claims"),
                        ("output_register.md", "output")):
        source = audit / name
        if not source.is_file():
            raise SeverityTokenError(f"cannot pin missing dispatch input: {source}")
        target = destination / name
        shutil.copy2(source, target)
        parts.append(f"{label}:{sha256_file(target)}")
    head = ";".join(parts)
    plan = audit / "plans/code_error_recheck_plan.md"
    if not plan.is_file():
        raise SeverityTokenError(
            f"cannot record dispatch inputs before the code recheck plan exists: {plan}")
    text = plan.read_text(encoding="utf-8")
    text = re.sub(r"(?m)^Severity-token dispatch input head: .*\n?", "", text).rstrip()
    write_atomic(plan, text + f"\n\nSeverity-token dispatch input head: {head}\n")
    return head


def dispatch_head(audit):
    destination = Path(audit) / "_run/snapshots/code_b5_dispatch"
    parts = []
    for name, label in (("claims_register.md", "claims"),
                        ("output_register.md", "output")):
        path = destination / name
        if not path.is_file():
            raise SeverityTokenError(f"missing digest-pinned dispatch snapshot: {path}")
        parts.append(f"{label}:{sha256_file(path)}")
    return ";".join(parts)


def main():
    parser = __import__("argparse").ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("verify", "pin-dispatch-inputs"))
    parser.add_argument("package_root", type=Path)
    parser.add_argument("--audit-dir", type=Path)
    parser.add_argument("--stage", choices=("code_b6a", "code_b6b", "bC"),
                        default="code_b6a")
    args = parser.parse_args()
    root = args.package_root.expanduser().resolve()
    audit = (args.audit_dir or root / "audit").expanduser().resolve()
    try:
        if args.command == "pin-dispatch-inputs":
            head = pin_dispatch_inputs(audit)
            print(f"pinned code-b5 dispatch inputs: {head}")
            return 0
        manifest_path = audit / "_run/manifest.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SeverityTokenError(f"cannot read token verifier manifest: {exc}") from exc
        receipts, failures = verify_token_records(
            root, audit, manifest, args.stage, prefer_staging=True)
        if failures:
            raise SeverityTokenError(" | ".join(failures))
        output = receipt_path(audit, args.stage)
        write_atomic(output, render_receipts(receipts))
    except (OSError, SeverityTokenError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {len(receipts)} token receipt(s): {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
