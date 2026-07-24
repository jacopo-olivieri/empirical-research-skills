#!/usr/bin/env python3
"""Build, validate, and atomically apply U8b severity-token rulings."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

import build_detector_mapping as detector_mapping
import severity_tokens as tokens


WORKLIST_SCHEMA = "severity-token-worklist/v2"
RULINGS_SCHEMA = "severity_token_rulings/v1"
WORKLIST_PATH = "_run/snapshots/severity_token_rulings/b7_rejected_worklist.json"
SNAPSHOT_REGISTER = "_run/snapshots/severity_token_rulings/code_error_register.md"
SNAPSHOT_RULINGS = "_run/snapshots/severity_token_rulings/severity_token_rulings.json"
RULINGS_PATH = "_run/severity_token_rulings.json"
B8_SNAPSHOT_REGISTER = "_run/snapshots/b8/code_error_register.md"


class RulingsError(RuntimeError):
    """The certified rejected-token worklist is not completely adjudicated."""


def _section(text, heading):
    match = re.search(
        rf"^##\s+{re.escape(heading)}\s*$\n(.*?)(?=^##\s+|\Z)",
        text, re.M | re.S,
    )
    return match.group(1) if match else None


def _register(path):
    text = Path(path).read_text(encoding="utf-8")
    for headers, rows, _line in tokens.parse_tables(text):
        if not {"Error ID", "Status", "Severity", "Why It Matters"}.issubset(headers):
            continue
        parsed = []
        for row in rows:
            if len(row) == len(headers):
                parsed.append(dict(zip(headers, map(tokens.clean, row))))
        return headers, parsed, text
    raise RulingsError(f"{path}: code-error register table not found")


def parse_adjudications(path):
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    section = _section(text, "Severity-token adjudications")
    if section is None:
        raise RulingsError(f"{path}: missing '## Severity-token adjudications'")
    matches = [rows for headers, rows, _line in tokens.parse_tables(section)
               if headers == tokens.ADJUDICATION_COLS]
    if len(matches) > 1:
        raise RulingsError(f"{path}: expected at most one severity-token adjudication table")
    if not matches:
        if re.search(r"(?m)^none\s*$", section) is None:
            raise RulingsError(
                f"{path}: zero severity tokens require exact '{tokens.ADJUDICATION_ZERO}'")
        return []
    if re.search(r"(?m)^none\s*$", section):
        raise RulingsError(f"{path}: adjudication table conflicts with the none sentinel")
    result = []
    for index, raw in enumerate(matches[0], start=1):
        if len(raw) != len(tokens.ADJUDICATION_COLS):
            raise RulingsError(f"{path}: malformed severity adjudication row {index}")
        result.append(dict(zip(tokens.ADJUDICATION_COLS, map(tokens.clean, raw))))
    return result


def _claim_link_failures(audit, error_row, token):
    if not token.startswith("claim:"):
        return []
    claim_id = token.split(":", 1)[1]
    if claim_id not in re.findall(r"C-\d{4}", error_row.get("Related Claim IDs", "")):
        return [f"{error_row['Error ID']}: claim token {claim_id} lacks the existing error-to-claim link"]
    claims_path = Path(audit) / "claims_register.md"
    try:
        text = claims_path.read_text(encoding="utf-8")
    except OSError:
        return [f"{error_row['Error ID']}: cannot resolve claim token {claim_id}"]
    for headers, rows, _line in tokens.parse_tables(text):
        if "Claim ID" not in headers or "Related Error IDs" not in headers:
            continue
        for raw in rows:
            if len(raw) != len(headers):
                continue
            row = dict(zip(headers, map(tokens.clean, raw)))
            if row["Claim ID"] == claim_id:
                if error_row["Error ID"] not in re.findall(
                        r"E-\d{4}", row.get("Related Error IDs", "")):
                    return [f"{error_row['Error ID']}: claim token {claim_id} lacks the reciprocal claim link"]
                return []
    return [f"{error_row['Error ID']}: claim token {claim_id} is absent"]


def _verified_b7_token_records(audit):
    """Return receipted token records keyed by (Error ID, Token)."""
    found, failures = {}, []
    for stage in ("code_b6b", "bC"):
        if not tokens.receipt_path(audit, stage).is_file():
            continue
        records, record_failures = tokens.load_token_records(audit, stage)
        receipts, receipt_failures = tokens.load_receipts(audit, stage, records)
        failures.extend(record_failures)
        failures.extend(receipt_failures)
        for composite in receipts:
            item = records.get(composite)
            if item is None:
                continue
            key = composite[:2]
            if key in found:
                failures.append(
                    f"verified token record appears in multiple b7 homes: {key}")
            else:
                found[key] = item[1]
    return found, failures


def _resolve_cv_site(package_root, anchor):
    """Resolve a CV line-or-content anchor to a canonical repo path:line."""
    value = tokens.clean(anchor)
    direct = re.fullmatch(r"(.+):(\d+)", value)
    if direct:
        path, line, _source = tokens.resolve_anchor(package_root, value)
        relative = path.relative_to(Path(package_root).resolve()).as_posix()
        return f"{relative}:{line}"
    if ":" not in value:
        raise tokens.SeverityTokenError(
            f"CV witness anchor has no repo-relative path: {anchor!r}")
    relative, detail = value.split(":", 1)
    path = tokens._safe_file(package_root, relative)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    match = re.fullmatch(
        r"\s*lines?\s+(\d+)(?:\s*[–—-]\s*(\d+))?\s*(?::\s*(.*))?",
        detail,
    )
    if match:
        start, end = int(match.group(1)), int(match.group(2) or match.group(1))
        if start < 1 or end < start or end > len(lines):
            raise tokens.SeverityTokenError(
                f"CV witness anchor line is outside the file: {anchor}")
        content = tokens.clean(match.group(3) or "")
        if content:
            hits = [
                number for number in range(start, end + 1)
                if content in lines[number - 1]
            ]
            if len(hits) != 1:
                raise tokens.SeverityTokenError(
                    f"CV content anchor resolves to {len(hits)} lines: {anchor}")
            start = hits[0]
        resolved = path.relative_to(Path(package_root).resolve()).as_posix()
        return f"{resolved}:{start}"
    content = tokens.clean(detail)
    hits = [
        number for number, line in enumerate(lines, start=1)
        if content and content in line
    ]
    if len(hits) != 1:
        raise tokens.SeverityTokenError(
            f"CV content anchor resolves to {len(hits)} lines: {anchor}")
    resolved = path.relative_to(Path(package_root).resolve()).as_posix()
    return f"{resolved}:{hits[0]}"


def _cv_witness_binding_failure(package_root, audit, record):
    """Explain a token lineage that omits one of its mapped CV witness sites."""
    mapping_path = Path(audit) / "_run/detector_mapping.md"
    if not mapping_path.is_file():
        # Historical/non-detector fixtures have no mapped CV metadata, so the
        # content-derived U9c binding is inactive for them.
        return None
    try:
        _declared, _display, mappings = detector_mapping.load_mapping(
            mapping_path)
        by_witness = {
            row["Witness ID"]: row for row in mappings if row["Channel"] == "CV"
        }
        effective_ids = tokens.list_cell(record.get("Witness IDs", ""))
        cv_rows = [by_witness[witness_id] for witness_id in effective_ids
                   if witness_id in by_witness]
        if not cv_rows:
            return None
        required = {
            row["Witness ID"]: _resolve_cv_site(package_root, row["Site Anchor"])
            for row in cv_rows
        }
        lineage = json.loads(record["Lineage JSON"])
        covered = set()
        for hop in lineage:
            path, line, _source = tokens.resolve_anchor(
                package_root, hop["anchor"])
            relative = path.relative_to(Path(package_root).resolve()).as_posix()
            covered.add(f"{relative}:{line}")
    except (OSError, ValueError, detector_mapping.MappingError,
            tokens.SeverityTokenError) as exc:
        return f"cannot resolve mapped CV witness-site binding ({exc})"
    missing = [
        f"{witness_id}={site}" for witness_id, site in sorted(required.items())
        if site not in covered
    ]
    if missing:
        return "lineage omits mapped CV witness site(s): " + ", ".join(missing)
    return None


def validate_b7(package_root, audit, manifest, register_path=None):
    """Return ``(rejected rows, failures)`` for the b7 severity section."""
    audit = Path(audit)
    failures = []
    try:
        if register_path is None:
            register_path = audit / "_staging/code_error_register.md"
            if not register_path.is_file():
                register_path = audit / "code_error_register.md"
        else:
            register_path = Path(register_path)
        _headers, register_rows, _text = _register(
            register_path)
        adjudications = parse_adjudications(audit / "register_cross_link_summary.md")
    except (OSError, RulingsError) as exc:
        return [], [str(exc)]
    eligible = {}
    mode = (manifest or {}).get("mode", "replication")
    for row in register_rows:
        if not tokens.severe_eligible(row):
            continue
        token, problem = tokens.row_token_state(row, mode)
        if problem:
            failures.append(f"{row['Error ID']}: b7 severe row {problem}")
            continue
        eligible[tokens.token_key(row["Error ID"], token)] = (row, token)
    actual = {}
    for row in adjudications:
        key = row["Token Key"]
        if key in actual:
            failures.append(f"duplicate severity-token adjudication {key}")
        actual[key] = row
        if row["Verdict"] not in tokens.ADJUDICATION_VERDICTS:
            failures.append(f"{key}: invalid severity-token Verdict {row['Verdict']!r}")
        if tokens.blank(row["Evidence"]):
            failures.append(f"{key}: severity-token adjudication requires Evidence")
    if set(actual) != set(eligible):
        failures.append(
            "b7 severity-token adjudications do not exactly cover register tokens; "
            f"expected={sorted(eligible)}, actual={sorted(actual)}")
    verified_records, record_failures = _verified_b7_token_records(audit)
    failures.extend(record_failures)
    rejected = []
    for key in sorted(set(actual) & set(eligible)):
        error_row, token = eligible[key]
        adjudication = actual[key]
        kind, target = tokens.token_target(token)
        if adjudication["Cited Target"] != target:
            failures.append(f"{key}: Cited Target disagrees with Token Key")
        state, _target_row = tokens.resolve_target(
            package_root, audit, manifest, token)
        if state == "target_not_live" and adjudication["Verdict"] != "rejected":
            failures.append(f"{key}: recomputed-non-live target cannot be upheld")
        if state == "invalid":
            failures.append(f"{key}: cited target is invalid for this mode")
        failures.extend(_claim_link_failures(audit, error_row, token))
        record = verified_records.get((error_row["Error ID"], token))
        binding_failure = (
            _cv_witness_binding_failure(package_root, audit, record)
            if record is not None else None
        )
        if binding_failure and adjudication["Verdict"] != "rejected":
            failures.append(
                f"{key}: mapped CV witness-site mismatch cannot be upheld "
                f"({binding_failure})"
            )
        if adjudication["Verdict"] == "rejected":
            rejected.append(adjudication)
    # On the post-bC b7 rerun, the original frozen rejected set may shrink
    # after cap/hold, but no newly rejected key is legal.
    worklist_path = audit / WORKLIST_PATH
    if worklist_path.is_file():
        try:
            frozen = json.loads(worklist_path.read_text(encoding="utf-8"))
            frozen_keys = set(frozen.get("lines", []))
            new_keys = {row["Token Key"] for row in rejected} - frozen_keys
            if new_keys:
                failures.append(
                    "post-bC b7 rerun introduced new rejected severity-token key(s): "
                    + ", ".join(sorted(new_keys)))
        except (OSError, json.JSONDecodeError) as exc:
            failures.append(f"{worklist_path}: invalid frozen rejected worklist ({exc})")
    return rejected, failures


def worklist_digest(lines, register_sha256):
    payload = json.dumps({
        "lines": sorted(lines),
        "b7_register_sha256": register_sha256,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def snapshot_stage(package_root, audit, manifest):
    audit = Path(audit)
    rejected, failures = validate_b7(package_root, audit, manifest)
    if failures:
        raise RulingsError(" | ".join(failures))
    lines = sorted(row["Token Key"] for row in rejected)
    destination = audit / WORKLIST_PATH
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_register = audit / "code_error_register.md"
    if not source_register.is_file():
        # In the normal b7 transaction the promoted bytes may still be in
        # staging when the rulings stage starts.
        source_register = audit / "_staging/code_error_register.md"
    snapshot_register = audit / SNAPSHOT_REGISTER
    shutil.copy2(source_register, snapshot_register)
    register_sha256 = hashlib.sha256(snapshot_register.read_bytes()).hexdigest()
    payload = {
        "schema": WORKLIST_SCHEMA,
        "lines": lines,
        "b7_register_sha256": register_sha256,
        "b7_certification_sha256": worklist_digest(lines, register_sha256),
    }
    tokens.write_atomic(destination, json.dumps(payload, indent=2) + "\n")
    return payload


def load_worklist(audit):
    path = Path(audit) / WORKLIST_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RulingsError(f"{path}: cannot read frozen rejected worklist ({exc})") from exc
    if set(payload) != {
            "schema", "lines", "b7_register_sha256",
            "b7_certification_sha256"}:
        raise RulingsError(f"{path}: frozen worklist has unexpected fields")
    lines = payload.get("lines")
    register_sha256 = payload.get("b7_register_sha256")
    if payload.get("schema") != WORKLIST_SCHEMA or not isinstance(lines, list) \
            or not all(isinstance(line, str) for line in lines) \
            or lines != sorted(set(lines)) \
            or not isinstance(register_sha256, str) \
            or not re.fullmatch(r"[0-9a-f]{64}", register_sha256):
        raise RulingsError(f"{path}: malformed frozen worklist")
    snapshot = Path(audit) / SNAPSHOT_REGISTER
    if snapshot.is_symlink() or not snapshot.is_file():
        raise RulingsError(
            f"{snapshot}: frozen pre-ruling register is missing or malformed")
    try:
        actual_register_sha256 = hashlib.sha256(snapshot.read_bytes()).hexdigest()
    except OSError as exc:
        raise RulingsError(
            f"{snapshot}: cannot read frozen pre-ruling register ({exc})") from exc
    if actual_register_sha256 != register_sha256:
        raise RulingsError(f"{snapshot}: snapshot digest mismatch")
    if payload["b7_certification_sha256"] != worklist_digest(
            lines, register_sha256):
        raise RulingsError(f"{path}: frozen worklist digest mismatch")
    return payload


def _load_rulings(audit):
    path = Path(audit) / RULINGS_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RulingsError(f"{path}: missing or invalid rulings artifact ({exc})") from exc
    if not isinstance(payload, dict):
        raise RulingsError(f"{path}: rulings artifact must be an object")
    return path, payload


def _applied_register_path(audit, manifest):
    """Locate the stage-era register the rulings were applied to.

    During the rulings transaction, and while b8 has not yet promoted its
    author-facing rewrite, the applied Status/Severity live in canonical
    ``code_error_register.md``.  Once b8 is ``done`` it copies that rewrite
    (``*Original`` columns, author-facing prose) over canonical, so canonical no
    longer carries the stage-era applied register.  b8's own pre-rewrite
    snapshot is canon-at-rulings-finish byte-for-byte (nothing mutates canonical
    between rulings-finish and b8's snapshot), so honest replay binds there.
    Return ``None`` to fail closed when b8 is ``done`` but that frozen boundary
    is absent, a symlink, or otherwise not a regular file.
    """
    audit = Path(audit)
    stages = (manifest or {}).get("stages")
    b8 = stages.get("b8") if isinstance(stages, dict) else None
    if isinstance(b8, dict) and b8.get("status") == "done":
        snapshot = audit / B8_SNAPSHOT_REGISTER
        if snapshot.is_symlink() or not snapshot.is_file():
            return None
        return snapshot
    return audit / "code_error_register.md"


def validate_rulings(package_root, audit, manifest, require_applied=False):
    audit = Path(audit)
    failures = []
    try:
        worklist = load_worklist(audit)
        path, payload = _load_rulings(audit)
        _headers, before_rows, _text = _register(audit / SNAPSHOT_REGISTER)
    except (OSError, RulingsError) as exc:
        return {}, [str(exc)]
    lines = worklist["lines"]
    expected_keys = {line: line.split(" ", 1) for line in lines}
    if not lines:
        expected_fields = {
            "schema", "cycle", "b7_certification_sha256", "skip_reason", "rulings",
        }
        if set(payload) != expected_fields:
            failures.append(f"{path}: zero-work artifact has unexpected fields")
        if payload.get("skip_reason") != "zero_rejected_severity_tokens" \
                or payload.get("rulings") != []:
            failures.append(f"{path}: zero rejected tokens require the exact skip form")
    else:
        if set(payload) != {"schema", "cycle", "b7_certification_sha256", "rulings"}:
            failures.append(f"{path}: non-empty rulings artifact has unexpected fields")
    if payload.get("schema") != RULINGS_SCHEMA:
        failures.append(f"{path}: schema must be {RULINGS_SCHEMA}")
    if payload.get("cycle") != "main":
        failures.append(f"{path}: cycle must be 'main'")
    if payload.get("b7_certification_sha256") != worklist["b7_certification_sha256"]:
        failures.append(f"{path}: b7_certification_sha256 disagrees with frozen worklist")
    rulings = payload.get("rulings")
    if not isinstance(rulings, list):
        failures.append(f"{path}: rulings must be an array")
        rulings = []
    by_error = {row["Error ID"]: row for row in before_rows}
    decisions = {}
    exact_fields = {
        "error_id", "token", "b7_verdict", "ruling", "resulting_status",
        "resulting_severity", "rationale", "decision_identity",
    }
    for index, ruling in enumerate(rulings, start=1):
        if not isinstance(ruling, dict) or set(ruling) != exact_fields:
            failures.append(f"{path}: ruling {index} has unexpected fields")
            continue
        error_id, token = ruling["error_id"], ruling["token"]
        key = tokens.token_key(error_id, token)
        if error_id in decisions:
            failures.append(f"{path}: duplicate ruling for {error_id}")
        decisions[error_id] = ruling
        if key not in expected_keys:
            failures.append(f"{path}: ruling names non-worklist token {key}")
        if ruling["b7_verdict"] != "rejected":
            failures.append(f"{path}: {error_id} b7_verdict must be rejected")
        if tokens.blank(ruling["rationale"]) or tokens.blank(ruling["decision_identity"]):
            failures.append(f"{path}: {error_id} requires rationale and decision_identity")
        before = by_error.get(error_id)
        if before is None:
            failures.append(f"{path}: ruling names absent Error ID {error_id}")
            continue
        action = ruling["ruling"]
        status, severity = ruling["resulting_status"], str(ruling["resulting_severity"])
        if action == "uphold":
            if (status, severity) != (before["Status"], before["Severity"]):
                failures.append(f"{path}: uphold must retain {error_id} Status/Severity")
            state, _target = tokens.resolve_target(package_root, audit, manifest, token)
            if state != "live":
                failures.append(f"{path}: uphold on recomputed-non-live token {key} is forbidden")
        elif action == "cap":
            if status != before["Status"] or severity not in {"1", "2"}:
                failures.append(f"{path}: cap must retain Status and set Severity 1 or 2 for {error_id}")
        elif action == "hold":
            if status != "confirmation_needed" or severity not in {"1", "2"}:
                failures.append(f"{path}: hold must set confirmation_needed Severity 1 or 2 for {error_id}")
        else:
            failures.append(f"{path}: {error_id} invalid ruling {action!r}")
    wanted_errors = {parts[0] for parts in expected_keys.values()}
    if set(decisions) != wanted_errors:
        failures.append(
            f"{path}: rulings do not exactly cover rejected worklist; "
            f"expected={sorted(wanted_errors)}, actual={sorted(decisions)}")
    if require_applied and not failures:
        applied_register = _applied_register_path(audit, manifest)
        if applied_register is None:
            failures.append(
                f"{audit / B8_SNAPSHOT_REGISTER}: b8 is done but its "
                "pre-rewrite register snapshot is missing or malformed")
            return decisions, failures
        try:
            current_headers, current_rows, _text = _register(applied_register)
            before_headers, _before_rows, _before_text = _register(audit / SNAPSHOT_REGISTER)
            if current_headers != before_headers:
                failures.append("severity rulings cannot change register columns")
            current = {row["Error ID"]: row for row in current_rows}
            if set(current) != set(by_error):
                failures.append("severity rulings cannot mint or delete register rows")
            for error_id, before in by_error.items():
                expected = dict(before)
                if error_id in decisions:
                    expected["Status"] = decisions[error_id]["resulting_status"]
                    expected["Severity"] = str(decisions[error_id]["resulting_severity"])
                if current.get(error_id) != expected:
                    failures.append(f"{error_id}: applied ruling changed fields other than Status/Severity or was not applied")
            fd, temporary = tempfile.mkstemp(
                prefix=".severity-rulings-check.", dir=audit)
            os.close(fd)
            expected_path = Path(temporary)
            try:
                shutil.copy2(audit / SNAPSHOT_REGISTER, expected_path)
                _replace_register_rows(expected_path, decisions)
                if (applied_register.read_bytes()
                        != expected_path.read_bytes()):
                    failures.append(
                        "applied ruling bytes differ outside the authorized Status/Severity cells")
            finally:
                expected_path.unlink(missing_ok=True)
        except (OSError, RulingsError) as exc:
            failures.append(str(exc))
        frozen = audit / SNAPSHOT_RULINGS
        if not frozen.is_file() or frozen.read_bytes() != path.read_bytes():
            failures.append(f"{frozen}: frozen ruling artifact is missing or changed")
    return decisions, failures


def _replace_register_rows(path, decisions):
    path = Path(path)
    headers, rows, text = _register(path)
    lines = text.splitlines(keepends=True)
    header_index = next((
        index for index, line in enumerate(lines)
        if tokens.split_row(line.rstrip("\r\n")) == headers
    ), None)
    if header_index is None:
        raise RulingsError(f"{path}: cannot locate exact register table for atomic ruling apply")

    def replace_cells(line, replacements):
        newline = "\n" if line.endswith("\n") else ""
        body = line[:-1] if newline else line
        if body.endswith("\r"):
            body, newline = body[:-1], "\r" + newline
        separators = []
        escaped = False
        for index, char in enumerate(body):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "|":
                separators.append(index)
        if len(separators) < len(headers) + 1:
            raise RulingsError(f"{path}: malformed register row during atomic ruling apply")
        pieces = []
        for cell_index in range(len(headers)):
            start, end = separators[cell_index] + 1, separators[cell_index + 1]
            raw = body[start:end]
            if cell_index in replacements:
                leading = raw[:len(raw) - len(raw.lstrip())]
                trailing = raw[len(raw.rstrip()):]
                raw = leading + replacements[cell_index] + trailing
            pieces.append(raw)
        return "|" + "|".join(pieces) + "|" + newline

    error_index = headers.index("Error ID")
    status_index = headers.index("Status")
    severity_index = headers.index("Severity")
    row_index = header_index + 2
    seen = set()
    while row_index < len(lines) and lines[row_index].lstrip().startswith("|"):
        values = tokens.split_row(lines[row_index].rstrip("\r\n"))
        if len(values) != len(headers):
            raise RulingsError(f"{path}: malformed register row during atomic ruling apply")
        error_id = tokens.clean(values[error_index])
        ruling = decisions.get(error_id)
        if ruling:
            lines[row_index] = replace_cells(lines[row_index], {
                status_index: ruling["resulting_status"],
                severity_index: str(ruling["resulting_severity"]),
            })
            seen.add(error_id)
        row_index += 1
    if seen != set(decisions):
        raise RulingsError(f"{path}: ruling target is absent from the frozen register")
    tokens.write_atomic(path, "".join(lines))


def apply_rulings(package_root, audit, manifest):
    audit = Path(audit)
    decisions, failures = validate_rulings(package_root, audit, manifest, False)
    if failures:
        raise RulingsError(" | ".join(failures))
    source = audit / RULINGS_PATH
    frozen = audit / SNAPSHOT_RULINGS
    frozen.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, frozen)
    # Render from the frozen pre-stage register, so a failed prior attempt
    # cannot accumulate mutations.  Replace canonical only after validation.
    snapshot = audit / SNAPSHOT_REGISTER
    fd, temporary = tempfile.mkstemp(prefix=".severity-rulings.", dir=audit)
    os.close(fd)
    temp_path = Path(temporary)
    try:
        shutil.copy2(snapshot, temp_path)
        _replace_register_rows(temp_path, decisions)
        os.replace(temp_path, audit / "code_error_register.md")
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise


def main():
    parser = __import__("argparse").ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("snapshot", "apply", "check", "check-b7"))
    parser.add_argument("package_root", type=Path)
    parser.add_argument("--audit-dir", type=Path)
    args = parser.parse_args()
    root = args.package_root.expanduser().resolve()
    audit = (args.audit_dir or root / "audit").expanduser().resolve()
    manifest_path = audit / "_run/manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if args.command == "snapshot":
            snapshot_stage(root, audit, manifest)
        elif args.command == "apply":
            apply_rulings(root, audit, manifest)
        elif args.command == "check-b7":
            _rejected, failures = validate_b7(root, audit, manifest)
            if failures:
                raise RulingsError(" | ".join(failures))
        else:
            _decisions, failures = validate_rulings(root, audit, manifest, True)
            if failures:
                raise RulingsError(" | ".join(failures))
    except (OSError, json.JSONDecodeError, RulingsError) as exc:
        print(f"error: {exc}", file=__import__("sys").stderr)
        return 1
    print(f"{args.command} severity-token rulings: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
