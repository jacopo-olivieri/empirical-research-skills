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

import authorized_deltas
import build_detector_mapping as detector_mapping
import evidence_views
import severity_tokens as tokens


WORKLIST_SCHEMA = evidence_views.WORKLIST_SCHEMA
RULINGS_SCHEMA = "severity_token_rulings/v1"
WORKLIST_PATH = evidence_views.WORKLIST_PATH
SNAPSHOT_REGISTER = evidence_views.PRE_RULING_REGISTER
SNAPSHOT_RULINGS = authorized_deltas.FROZEN_RULINGS
RULINGS_PATH = "_run/severity_token_rulings.json"
B8_SNAPSHOT_REGISTER = evidence_views.B8_SNAPSHOT_DIR + "/code_error_register.md"


class RulingsError(RuntimeError):
    """The certified rejected-token worklist is not completely adjudicated."""


def _section(text, heading):
    match = re.search(
        rf"^##\s+{re.escape(heading)}\s*$\n(.*?)(?=^##\s+|\Z)",
        text, re.M | re.S,
    )
    return match.group(1) if match else None


def _register_text(path, text):
    for headers, rows, _line in tokens.parse_tables(text):
        if not {"Error ID", "Status", "Severity", "Why It Matters"}.issubset(headers):
            continue
        parsed = []
        for row in rows:
            if len(row) == len(headers):
                parsed.append(dict(zip(headers, map(tokens.clean, row))))
        return headers, parsed, text
    raise RulingsError(f"{path}: code-error register table not found")


def _register(path):
    text = Path(path).read_text(encoding="utf-8")
    return _register_text(path, text)


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


def validate_b7(package_root, audit, manifest):
    """Return ``(rejected rows, failures)`` for the b7 severity section."""
    audit = Path(audit)
    failures = []
    resolved = evidence_views.resolve(
        "b7_classification", "code_error_register.md", audit, manifest or {})
    if isinstance(resolved, evidence_views.ViewRefusal):
        return [], [str(resolved)]
    try:
        _headers, register_rows, _text = _register_text(
            resolved.source_path, resolved.text)
        adjudications = parse_adjudications(audit / "register_cross_link_summary.md")
    except (OSError, RulingsError) as exc:
        return [], [str(exc)]
    if evidence_views.stage_done(manifest, "bC"):
        # Post-bC replay-plus-extension: the summary is post-bC-era, so the
        # eligible token set composes the frozen b7_classification with the
        # authorized rulings caps and extends it with exactly the
        # correction plan's new rows — never with mutable current state.
        rulings_delta, delta_failures = authorized_deltas.permitted_delta(
            "pre_ruling", "rulings_applied", "code_error_register.md",
            audit, manifest)
        failures.extend(delta_failures)
        bc_delta, bc_failures = authorized_deltas.permitted_delta(
            "bC_correction", "export_bound", "code_error_register.md",
            audit, manifest)
        failures.extend(bc_failures)
        composed = []
        for row in register_rows:
            updated = dict(row)
            for column in ("Status", "Severity"):
                key = (row["Error ID"], column)
                if key in rulings_delta.exact_cells:
                    updated[column] = rulings_delta.exact_cells[key]
            composed.append(updated)
        composed.extend(
            {key: str(value) for key, value in bc_delta.added_rows[row_id].items()}
            for row_id in sorted(bc_delta.added_rows))
        register_rows = composed
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
    # On a post-b7 rerun, the original frozen rejected set may shrink after
    # cap/hold, but no newly rejected key is legal.
    frozen_worklist = evidence_views.resolve(
        "pre_ruling", "code_error_register.md", audit, manifest or {})
    if isinstance(frozen_worklist, evidence_views.ViewRefusal):
        failures.append(str(frozen_worklist))
    elif isinstance(frozen_worklist, evidence_views.ResolvedView):
        frozen_keys = set(frozen_worklist.payload.get("lines", []))
        new_keys = {
            row["Token Key"] for row in adjudications
            if row.get("Verdict") == "rejected"
        } - frozen_keys
        if new_keys:
            failures.append(
                "post-bC b7 rerun introduced new rejected severity-token key(s): "
                + ", ".join(sorted(new_keys)))
    # A PrematureAsk means the rulings boundary has not been reached yet —
    # the initial b7 certification, where no frozen worklist binds.
    return rejected, failures


worklist_digest = evidence_views.worklist_digest


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


def load_worklist(audit, manifest=None):
    """Resolve the ``pre_ruling`` view: the frozen rejected worklist plus the
    exact pre-ruling register bytes, digest-verified.  Returns the resolved
    view (``payload`` carries the worklist)."""
    resolved = evidence_views.resolve(
        "pre_ruling", "code_error_register.md", audit, manifest or {})
    if isinstance(resolved, evidence_views.PrematureAsk):
        raise RulingsError(
            f"{Path(audit) / WORKLIST_PATH}: cannot read frozen rejected "
            "worklist (the rulings boundary has not been reached)")
    if isinstance(resolved, evidence_views.ViewRefusal):
        raise RulingsError(str(resolved))
    return resolved


def _load_rulings(audit):
    path = Path(audit) / RULINGS_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RulingsError(f"{path}: missing or invalid rulings artifact ({exc})") from exc
    if not isinstance(payload, dict):
        raise RulingsError(f"{path}: rulings artifact must be an object")
    return path, payload


def validate_rulings(package_root, audit, manifest, require_applied=False):
    audit = Path(audit)
    failures = []
    try:
        pre_ruling = load_worklist(audit, manifest)
        worklist = pre_ruling.payload
        path, payload = _load_rulings(audit)
        _headers, before_rows, _text = _register_text(
            pre_ruling.source_path, pre_ruling.text)
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
        applied_view = evidence_views.resolve(
            "rulings_applied", "code_error_register.md", audit, manifest or {})
        if isinstance(applied_view, evidence_views.ViewRefusal):
            if (applied_view.source_path is not None
                    and "snapshots/b8" in applied_view.source_path.as_posix()):
                failures.append(
                    f"{audit / B8_SNAPSHOT_REGISTER}: b8 is done but its "
                    "pre-rewrite register snapshot is missing or malformed")
            else:
                failures.append(str(applied_view))
            return decisions, failures
        applied_register = applied_view.source_path
        try:
            current_headers, current_rows, _text = _register_text(
                applied_register, applied_view.text)
            before_headers, _before_rows, _before_text = _register_text(
                pre_ruling.source_path, pre_ruling.text)
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
                expected_path.write_bytes(pre_ruling.raw)
                _replace_register_rows(expected_path, decisions)
                if applied_view.raw != expected_path.read_bytes():
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
    # Render from the frozen pre-stage register (the resolved, digest-bound
    # pre_ruling bytes), so a failed prior attempt cannot accumulate
    # mutations.  Replace canonical only after validation.
    pre_ruling = load_worklist(audit, manifest)
    fd, temporary = tempfile.mkstemp(prefix=".severity-rulings.", dir=audit)
    os.close(fd)
    temp_path = Path(temporary)
    try:
        temp_path.write_bytes(pre_ruling.raw)
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
