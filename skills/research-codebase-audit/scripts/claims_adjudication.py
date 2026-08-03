#!/usr/bin/env python3
"""Build, apply, and verify the two U7 claims-adjudication stages."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

from anchor_resolver import AnchorError, contains, resolve_quote
from claim_handoffs import ADJUDICATION_RANGE_RE
import lint_registers as registers


FORMAT_VERSION = 1
STAGES = ("claims_adjudication", "claims_adjudication_lineage")
WORKLIST_FILES = {
    "claims_adjudication": "claims_adjudication_worklist.json",
    "claims_adjudication_lineage": "claims_adjudication_lineage_worklist.json",
}
VERDICT_FILES = {
    "claims_adjudication": "claims_adjudication_verdicts.md",
    "claims_adjudication_lineage": "claims_adjudication_lineage_verdicts.md",
}
ADJUDICATION_VERDICT_COLS = [
    "Obligation ID", "Work Kind", "Verdict", "Reason", "Minted C-ID",
    *[column for column in registers.CLAIMS_COLS if column != "Claim ID"],
    "Covering Range",
]
LINEAGE_VERDICT_COLS = ["Obligation ID", "Verdict", "Reason"]
ASSERTION_FIELDS = (
    "Paper Context", "Paper Quote", "Claim Text",
    "Paper ContextOriginal", "Paper QuoteOriginal", "Claim TextOriginal",
)
ADJUDICATION_VERDICTS = {
    "mapping": {"capture_confirmed", "reject_and_resolve"},
    "disposition": {"disposition_accepted", "reject_and_resolve"},
}
LINEAGE_VERDICTS = {"equivalence_confirmed", "equivalence_refused"}


class AdjudicationError(RuntimeError):
    pass


def _json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_atomic(path, payload, binary=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        mode = "wb" if binary else "w"
        kwargs = {} if binary else {"encoding": "utf-8"}
        with os.fdopen(fd, mode, **kwargs) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _load_json(path, label):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdjudicationError(f"cannot read {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AdjudicationError(f"{label} must contain a JSON object")
    return value


def _load_register(path):
    lint = registers.Lint()
    loaded = registers.load_register(lint, Path(path), registers.CLAIMS_COLS, allow_extra=True)
    if loaded is None or lint.errors:
        raise AdjudicationError("; ".join(lint.errors) or f"cannot read {path}")
    headers, rows = loaded
    return headers, [dict(zip(headers, row)) for row in rows]


def _manifest(audit):
    return _load_json(Path(audit) / "_run/manifest.json", "manifest")


def worklist_path(audit, stage):
    return Path(audit) / "_run" / WORKLIST_FILES[stage]


def verdict_path(audit, stage):
    return Path(audit) / "_run" / VERDICT_FILES[stage]


def _ledger_snapshot(audit, stage):
    audit = Path(audit)
    if stage == "claims_adjudication":
        candidates = (
            audit / "_run/snapshots/claims_adjudication/handoff_ledger.json",
            audit / "_run/snapshots/claims_b3b/handoff_ledger.json",
            audit / "_run/handoff_ledger.json",
        )
    else:
        candidates = (
            audit / "_run/snapshots/claims_adjudication_lineage/handoff_ledger.json",
            audit / "_run/handoff_ledger.json",
        )
    path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if path is None:
        raise AdjudicationError(f"no immutable ledger input exists for {stage}")
    return path, _load_json(path, "handoff ledger")


def _pre_claims_path(audit):
    path = Path(audit) / "_run/snapshots/claims_adjudication/claims_register.md"
    if not path.is_file():
        raise AdjudicationError(f"missing adjudication-era claims snapshot {path}")
    return path


def _post_claims_path(audit):
    audit = Path(audit)
    for stage in ("claims_b6a", "claims_b6b", "bC", "b7", "b8"):
        path = audit / "_run/snapshots" / stage / "claims_register.md"
        if path.is_file():
            return path
    return audit / "claims_register.md"


def _post_adjudication_ledger_path(audit):
    """Use the first immutable post-adjudication ledger when it exists."""
    audit = Path(audit)
    lineage = audit / "_run/snapshots/claims_adjudication_lineage/handoff_ledger.json"
    return lineage if lineage.is_file() else audit / "_run/handoff_ledger.json"


def _entry_assertion(entry):
    if entry.get("kind") == "H":
        return entry.get("asserted_substance") or entry.get("quote") or ""
    return entry.get("referencing_sentence") or ""


def derive_adjudication_worklist(package_root, audit):
    ledger_path, ledger = _ledger_snapshot(audit, "claims_adjudication")
    claims_path = _pre_claims_path(audit)
    _headers, claims = _load_register(claims_path)
    by_id = {row["Claim ID"]: row for row in claims}
    items = []
    for entry in sorted(ledger.get("H", []) + ledger.get("X", []), key=lambda row: row["id"]):
        state = entry.get("state")
        if state == "blocked_fallback":
            continue
        if state == "disposition":
            work_kind = "disposition"
        elif state in {"satisfied", "covered", "resolved"}:
            work_kind = "mapping"
            claim_id = entry.get("covering_c_id")
            if claim_id not in by_id:
                raise AdjudicationError(
                    f"mapped obligation {entry.get('id')} cites absent claim {claim_id!r}"
                )
        else:
            raise AdjudicationError(
                f"obligation {entry.get('id')} has non-adjudicable state {state!r}"
            )
        item = {
            "id": entry["id"], "kind": entry["kind"], "work_kind": work_kind,
            "state": state, "assertion": _entry_assertion(entry),
            "resolved_anchor": entry.get("resolved_anchor"),
            "covering_c_id": entry.get("covering_c_id"),
            "disposition": entry.get("disposition"),
        }
        if work_kind == "mapping":
            item["covering_claim"] = {
                field: by_id[entry["covering_c_id"]].get(field, "")
                for field in registers.CLAIMS_COLS
            }
        items.append(item)
    return {
        "format_version": FORMAT_VERSION,
        "stage": "claims_adjudication",
        "inputs": {
            "handoff_ledger": {"path": str(ledger_path), "sha256": _sha256(ledger_path)},
            "claims_register": {"path": str(claims_path), "sha256": _sha256(claims_path)},
        },
        "items": items,
    }


def _baseline_claims(audit):
    _headers, rows = _load_register(_pre_claims_path(audit))
    by_id = {row["Claim ID"]: row for row in rows}
    path = verdict_path(audit, "claims_adjudication")
    if path.is_file():
        for row in _parse_verdicts(path, "claims_adjudication", allow_absent=True):
            if row["Verdict"] == "reject_and_resolve":
                claim = {"Claim ID": row["Minted C-ID"]}
                claim.update({field: row[field] for field in registers.CLAIMS_COLS
                              if field != "Claim ID"})
                by_id[claim["Claim ID"]] = claim
    return by_id


def _terminal_carrier(row, by_id):
    """Resolve the only machine-readable claims lineage edge: duplicate_of."""
    seen, current = set(), row
    while current is not None:
        row_id = current.get("Claim ID")
        if row_id in seen:
            return None, "duplicate cycle"
        seen.add(row_id)
        match = re.fullmatch(r"duplicate_of:(C-\d{4})", current.get("Status", ""))
        if not match:
            return current, None
        current = by_id.get(match.group(1))
        if current is None:
            return None, "tombstone dead-end"
    return None, "tombstone dead-end"


def _assertion_bytes(row):
    return {field: row.get(field, "") for field in ASSERTION_FIELDS if field in row}


def derive_lineage_worklist(package_root, audit):
    ledger_path, ledger = _ledger_snapshot(audit, "claims_adjudication_lineage")
    baseline = _baseline_claims(audit)
    final_path = Path(audit) / "_run/snapshots/claims_adjudication_lineage/claims_register.md"
    if not final_path.is_file():
        raise AdjudicationError(f"missing lineage-era claims snapshot {final_path}")
    _headers, final_rows = _load_register(final_path)
    final = {row["Claim ID"]: row for row in final_rows}
    items = []
    for entry in sorted(ledger.get("H", []) + ledger.get("X", []), key=lambda row: row["id"]):
        claim_id = entry.get("covering_c_id")
        if not claim_id or entry.get("state") in {"blocked_fallback", "disposition_accepted"}:
            continue
        source = baseline.get(claim_id)
        direct = final.get(claim_id)
        carrier, problem = _terminal_carrier(direct, final) if direct else (None, "absent carrier")
        if source is not None and carrier is not None and not problem \
                and _assertion_bytes(source) == _assertion_bytes(carrier):
            continue
        items.append({
            "id": entry["id"], "kind": entry["kind"],
            "source_c_id": claim_id,
            "terminal_c_id": carrier.get("Claim ID") if carrier else None,
            "reason": problem or "assertion-bearing fields changed",
            "source_assertion_fields": _assertion_bytes(source or {}),
            "terminal_assertion_fields": _assertion_bytes(carrier or {}),
        })
    return {
        "format_version": FORMAT_VERSION,
        "stage": "claims_adjudication_lineage",
        "inputs": {
            "handoff_ledger": {"path": str(ledger_path), "sha256": _sha256(ledger_path)},
            "claims_register": {"path": str(final_path), "sha256": _sha256(final_path)},
        },
        "items": items,
    }


def derive_worklist(package_root, audit, stage):
    if stage == "claims_adjudication":
        return derive_adjudication_worklist(package_root, audit)
    if stage == "claims_adjudication_lineage":
        return derive_lineage_worklist(package_root, audit)
    raise AdjudicationError(f"unknown stage {stage!r}")


def build_worklist(package_root, audit, stage):
    value = derive_worklist(package_root, audit, stage)
    _write_atomic(worklist_path(audit, stage), _json_bytes(value), binary=True)
    if not value["items"] and not verdict_path(audit, stage).exists():
        phrase = ("No adjudication verdicts." if stage == "claims_adjudication"
                  else "No lineage verdicts.")
        _write_atomic(verdict_path(audit, stage), phrase + "\n")
    return value


def check_worklist(package_root, audit, stage):
    expected = _json_bytes(derive_worklist(package_root, audit, stage))
    path = worklist_path(audit, stage)
    try:
        actual = path.read_bytes()
    except OSError as exc:
        raise AdjudicationError(f"missing worklist {path}: {exc}") from exc
    if actual != expected:
        raise AdjudicationError(f"worklist is absent, stale, or edited: {path}")
    return json.loads(actual)


def _parse_verdicts(path, stage, allow_absent=False):
    path = Path(path)
    if not path.is_file():
        if allow_absent:
            return []
        raise AdjudicationError(f"missing verdict artifact {path}")
    text = path.read_text(encoding="utf-8")
    columns = (ADJUDICATION_VERDICT_COLS if stage == "claims_adjudication"
               else LINEAGE_VERDICT_COLS)
    matches = [rows for headers, rows, _line in registers.parse_tables(text)
               if headers == columns]
    if not matches:
        zero = ("No adjudication verdicts." if stage == "claims_adjudication"
                else "No lineage verdicts.")
        if zero in text:
            return []
        raise AdjudicationError(f"{path}: missing exact structured verdict table")
    if len(matches) != 1:
        raise AdjudicationError(f"{path}: expected exactly one structured verdict table")
    output = []
    for index, raw in enumerate(matches[0], start=1):
        if len(raw) != len(columns):
            raise AdjudicationError(f"{path}: malformed verdict row {index}")
        output.append(dict(zip(columns, raw)))
    return output


def _adjudication_range(audit):
    plan = Path(audit) / "plans/claims_review_plan.md"
    try:
        matches = ADJUDICATION_RANGE_RE.findall(plan.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AdjudicationError(f"cannot read adjudication range: {exc}") from exc
    if len(matches) != 1:
        raise AdjudicationError("claims plan must declare exactly one adjudication range")
    start, end = (int(value[2:]) for value in matches[0])
    return start, end


def _validate_verdicts(package_root, audit, stage, worklist):
    rows = _parse_verdicts(verdict_path(audit, stage), stage)
    expected = {item["id"]: item for item in worklist["items"]}
    observed = {}
    for row in rows:
        obligation_id = row["Obligation ID"]
        if obligation_id in observed:
            raise AdjudicationError(f"duplicate verdict for {obligation_id}")
        observed[obligation_id] = row
        if obligation_id not in expected:
            raise AdjudicationError(f"verdict names non-worklist obligation {obligation_id}")
        if not row.get("Reason", "").strip() or registers.blank_cell(row["Reason"]):
            raise AdjudicationError(f"verdict {obligation_id} requires a reason")
        if stage == "claims_adjudication":
            item = expected[obligation_id]
            if row["Work Kind"] != item["work_kind"]:
                raise AdjudicationError(f"{obligation_id} verdict changes Work Kind")
            if row["Verdict"] not in ADJUDICATION_VERDICTS[item["work_kind"]]:
                raise AdjudicationError(f"{obligation_id} has invalid verdict {row['Verdict']!r}")
            if row["Verdict"] == "reject_and_resolve":
                mint = row["Minted C-ID"]
                if not re.fullmatch(r"C-\d{4}", mint):
                    raise AdjudicationError(f"{obligation_id} reject-and-resolve requires a C-ID")
                start, end = _adjudication_range(audit)
                if not start <= int(mint[2:]) <= end:
                    raise AdjudicationError(f"minted claim {mint} is outside adjudication range")
                claim = {"Claim ID": mint}
                claim.update({field: row[field] for field in registers.CLAIMS_COLS
                              if field != "Claim ID"})
                lint = registers.Lint()
                registers.check_claims_rows(
                    lint, verdict_path(audit, stage),
                    [[claim[column] for column in registers.CLAIMS_COLS]], final=False,
                )
                if lint.errors:
                    raise AdjudicationError("; ".join(lint.errors))
                try:
                    manifest = _manifest(audit)
                    carried = resolve_quote(
                        manifest["paper_source_set"], row["Covering Range"],
                        row["Paper Quote"], package_root,
                    )
                except (KeyError, AnchorError) as exc:
                    raise AdjudicationError(str(exc)) from exc
                if not contains(carried, item["resolved_anchor"]):
                    raise AdjudicationError(
                        f"adjudicator-minted claim {mint} does not contain {obligation_id}"
                    )
            else:
                nonblank = [column for column in ADJUDICATION_VERDICT_COLS[4:]
                            if not registers.blank_cell(row[column])]
                if nonblank:
                    raise AdjudicationError(
                        f"{obligation_id} non-mint verdict carries mint cells {nonblank}"
                    )
        else:
            if row["Verdict"] not in LINEAGE_VERDICTS:
                raise AdjudicationError(
                    f"{obligation_id} has invalid lineage verdict {row['Verdict']!r}"
                )
            if row["Verdict"] == "equivalence_confirmed" \
                    and expected[obligation_id].get("terminal_c_id") is None:
                raise AdjudicationError(
                    f"{obligation_id} cannot be equivalence_confirmed: "
                    "no terminal live carrier exists "
                    f"({expected[obligation_id].get('reason', 'dead chain')})"
                )
    if set(observed) != set(expected):
        raise AdjudicationError(
            "verdicts do not exactly cover worklist; "
            f"missing={sorted(set(expected) - set(observed))}, "
            f"extra={sorted(set(observed) - set(expected))}"
        )
    if stage == "claims_adjudication":
        minted = [row["Minted C-ID"] for row in rows
                  if row["Verdict"] == "reject_and_resolve"]
        if len(minted) != len(set(minted)):
            raise AdjudicationError("adjudicator minted duplicate C-IDs")
    return rows


def _expected_adjudication_projection(package_root, audit, worklist, verdicts):
    ledger_path, ledger = _ledger_snapshot(audit, "claims_adjudication")
    ledger = json.loads(json.dumps(ledger))
    by_id = {row["id"]: row for row in ledger.get("H", []) + ledger.get("X", [])}
    _headers, baseline = _load_register(_pre_claims_path(audit))
    claims = {row["Claim ID"]: row for row in baseline}
    for verdict in verdicts:
        entry = by_id[verdict["Obligation ID"]]
        old = entry["state"]
        if verdict["Verdict"] == "capture_confirmed":
            new = old
        elif verdict["Verdict"] == "disposition_accepted":
            new = "disposition_accepted"
        else:
            new = "resolved"
            mint = verdict["Minted C-ID"]
            claim = {"Claim ID": mint}
            claim.update({field: verdict[field] for field in registers.CLAIMS_COLS
                          if field != "Claim ID"})
            if mint in claims:
                raise AdjudicationError(f"minted claim {mint} already exists")
            claims[mint] = claim
            entry["covering_c_id"] = mint
            entry["covering_anchor"] = resolve_quote(
                _manifest(audit)["paper_source_set"], verdict["Covering Range"],
                verdict["Paper Quote"], package_root,
            )
            entry["disposition"] = None
            entry["adjudicator_rebind"] = {"from": old, "to": mint}
        if new != old:
            allowed = {
                "satisfied": {"resolved", "blocked_fallback"},
                "covered": {"resolved", "blocked_fallback"},
                "resolved": {"resolved", "blocked_fallback"},
                "disposition": {"disposition_accepted", "resolved", "blocked_fallback"},
            }
            if new not in allowed.get(old, set()):
                raise AdjudicationError(f"illegal adjudication transition {old} -> {new}")
            entry["state"] = new
    ledger["stage"] = "claims_adjudication"
    ordered = [claims[key] for key in sorted(claims)]
    return ledger, ordered


def _register_text(headers, rows):
    def cell(value):
        # Idempotent pipe-escaping: parsed cells retain their `\|` (split_row does
        # not unescape), so escaping every `|` would double-escape pre-escaped
        # cells (LaTeX abs-value bars like `\|A\|`) into `\\|` and corrupt the
        # round-trip. Collapse existing `\|` first, then escape once.
        return str(value).replace("\\|", "|").replace("|", "\\|")
    lines = ["# Claims register", "", "| " + " | ".join(headers) + " |",
             "| " + " | ".join(["---"] * len(headers)) + " |"]
    lines.extend("| " + " | ".join(cell(row.get(header, "")) for header in headers) + " |"
                 for row in rows)
    return "\n".join(lines) + "\n"


def apply_done(package_root, audit, stage):
    worklist = check_worklist(package_root, audit, stage)
    verdicts = _validate_verdicts(package_root, audit, stage, worklist)
    if stage == "claims_adjudication":
        ledger, claims = _expected_adjudication_projection(
            package_root, audit, worklist, verdicts)
        _write_atomic(Path(audit) / "_run/handoff_ledger.json", _json_bytes(ledger), binary=True)
        headers, _rows = _load_register(_pre_claims_path(audit))
        _write_atomic(Path(audit) / "claims_register.md", _register_text(headers, claims))
    return check_done(package_root, audit, stage)


def check_done(package_root, audit, stage):
    worklist = check_worklist(package_root, audit, stage)
    verdicts = _validate_verdicts(package_root, audit, stage, worklist)
    if stage == "claims_adjudication":
        ledger, claims = _expected_adjudication_projection(
            package_root, audit, worklist, verdicts)
        ledger_path = _post_adjudication_ledger_path(audit)
        if not ledger_path.is_file() or ledger_path.read_bytes() != _json_bytes(ledger):
            raise AdjudicationError("adjudication ledger does not re-derive from worklist/verdicts")
        post_path = _post_claims_path(audit)
        _headers, actual = _load_register(post_path)
        wanted = {row["Claim ID"]: row for row in claims}
        got = {row["Claim ID"]: {field: row.get(field, "") for field in registers.CLAIMS_COLS}
               for row in actual}
        if got != wanted:
            raise AdjudicationError(
                f"post-adjudication claims image {post_path} disagrees with validated mints"
            )
        pre_output = Path(audit) / "_run/snapshots/claims_adjudication/output_register.md"
        post_output = next((
            Path(audit) / "_run/snapshots" / name / "output_register.md"
            for name in ("claims_b6a", "claims_b6b", "bC", "b7", "b8")
            if (Path(audit) / "_run/snapshots" / name / "output_register.md").is_file()
        ), Path(audit) / "output_register.md")
        if not pre_output.is_file() or not post_output.is_file() \
                or pre_output.read_bytes() != post_output.read_bytes():
            raise AdjudicationError("claims adjudication must not mutate output_register.md")
    else:
        before_path, _ledger = _ledger_snapshot(audit, stage)
        live_path = Path(audit) / "_run/handoff_ledger.json"
        if not live_path.is_file() or before_path.read_bytes() != live_path.read_bytes():
            raise AdjudicationError("lineage adjudication must not mutate the handoff ledger")
    return True


def block_pending(package_root, audit, stage):
    worklist = check_worklist(package_root, audit, stage)
    rows = _parse_verdicts(verdict_path(audit, stage), stage, allow_absent=True)
    # Existing rows must be a valid, conflict-free subset. Validate them by
    # temporarily narrowing the expected worklist to their IDs.
    if rows:
        subset_ids = {row["Obligation ID"] for row in rows}
        subset = {**worklist, "items": [item for item in worklist["items"]
                                        if item["id"] in subset_ids]}
        _validate_verdicts(package_root, audit, stage, subset)
    verdict_ids = {row["Obligation ID"] for row in rows}
    ledger_path = Path(audit) / "_run/handoff_ledger.json"
    if stage == "claims_adjudication" and rows:
        ledger, claims = _expected_adjudication_projection(
            package_root, audit, {**worklist, "items": [
                item for item in worklist["items"] if item["id"] in verdict_ids
            ]}, rows,
        )
        headers, _old_rows = _load_register(_pre_claims_path(audit))
        _write_atomic(Path(audit) / "claims_register.md", _register_text(headers, claims))
    else:
        ledger = _load_json(ledger_path, "live handoff ledger")
    by_id = {row["id"]: row for row in ledger.get("H", []) + ledger.get("X", [])}
    for item in worklist["items"]:
        if item["id"] in verdict_ids:
            continue
        entry = by_id.get(item["id"])
        if entry is None:
            raise AdjudicationError(f"pending worklist ID {item['id']} is absent from ledger")
        if entry.get("state") != "blocked_fallback":
            entry["state"] = "blocked_fallback"
    ledger["stage"] = stage
    _write_atomic(ledger_path, _json_bytes(ledger), binary=True)


def check_blocked(package_root, audit, stage):
    worklist = check_worklist(package_root, audit, stage)
    rows = _parse_verdicts(verdict_path(audit, stage), stage, allow_absent=True)
    verdict_ids = {row["Obligation ID"] for row in rows}
    if len(verdict_ids) != len(rows):
        raise AdjudicationError("blocked-stage verdict table has duplicate IDs")
    unknown = verdict_ids - {item["id"] for item in worklist["items"]}
    if unknown:
        raise AdjudicationError(f"blocked-stage verdicts name extra IDs: {sorted(unknown)}")
    if rows:
        subset = {**worklist, "items": [item for item in worklist["items"]
                                        if item["id"] in verdict_ids]}
        _validate_verdicts(package_root, audit, stage, subset)
    ledger = _load_json(Path(audit) / "_run/handoff_ledger.json", "live handoff ledger")
    by_id = {row["id"]: row for row in ledger.get("H", []) + ledger.get("X", [])}
    if stage == "claims_adjudication" and rows:
        expected_ledger, expected_claims = _expected_adjudication_projection(
            package_root, audit, {**worklist, "items": [item for item in worklist["items"]
                                                        if item["id"] in verdict_ids]}, rows,
        )
        expected_by_id = {row["id"]: row for row in
                          expected_ledger.get("H", []) + expected_ledger.get("X", [])}
        for obligation_id in verdict_ids:
            if by_id.get(obligation_id) != expected_by_id.get(obligation_id):
                raise AdjudicationError(
                    f"blocked-stage verdict for {obligation_id} does not reconcile to ledger"
                )
        _headers, actual_claims = _load_register(Path(audit) / "claims_register.md")
        wanted = {row["Claim ID"]: row for row in expected_claims}
        got = {row["Claim ID"]: {field: row.get(field, "") for field in registers.CLAIMS_COLS}
               for row in actual_claims}
        if got != wanted:
            raise AdjudicationError(
                "blocked-stage adjudicator mints do not reconcile to claims_register.md"
            )
    for item in worklist["items"]:
        if item["id"] not in verdict_ids and by_id.get(item["id"], {}).get("state") != "blocked_fallback":
            raise AdjudicationError(
                f"blocked stage left pending {item['id']} final-passable instead of blocked_fallback"
            )
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_root", type=Path)
    parser.add_argument("--audit-dir", type=Path)
    parser.add_argument("--stage", required=True, choices=STAGES)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--build-worklist", action="store_true")
    action.add_argument("--check", action="store_true")
    action.add_argument("--apply", action="store_true")
    action.add_argument("--block", action="store_true")
    action.add_argument("--check-blocked", action="store_true")
    args = parser.parse_args(argv)
    audit = args.audit_dir or args.package_root / "audit"
    try:
        if args.build_worklist:
            build_worklist(args.package_root, audit, args.stage)
        elif args.apply:
            apply_done(args.package_root, audit, args.stage)
        elif args.block:
            block_pending(args.package_root, audit, args.stage)
        elif args.check_blocked:
            check_blocked(args.package_root, audit, args.stage)
        else:
            check_done(args.package_root, audit, args.stage)
    except (AdjudicationError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"CLAIMS ADJUDICATION REFUSED: {exc}", file=sys.stderr)
        return 1
    print("CLAIMS ADJUDICATION OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
