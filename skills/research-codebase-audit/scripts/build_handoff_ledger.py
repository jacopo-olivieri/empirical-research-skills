#!/usr/bin/env python3
"""Build or verify the deterministic U7 H/X obligation ledger."""

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

from anchor_resolver import (
    AnchorError, _normalize_with_map, contains, normalize_quote, resolve_quote,
)
from claim_handoffs import (
    HANDOFF_COLS, HANDOFF_RESOLUTION_COLS, X_COVERAGE_COLS,
    allocation_source_entry, load_claims_allocations, owner_for_line,
    parse_line_intervals, validate_disposition,
)
import lint_registers as registers


FINAL_H = {"satisfied", "resolved", "disposition_accepted"}
FINAL_X = {"covered", "resolved", "disposition_accepted"}
LEGAL_TRANSITIONS = {
    "H": {
        "filed": {"satisfied", "forwarded", "blocked_fallback"},
        "forwarded": {"resolved", "disposition", "blocked_fallback"},
        "satisfied": {"resolved", "blocked_fallback"},
        "resolved": {"resolved", "blocked_fallback"},
        "disposition": {"disposition_accepted", "resolved", "blocked_fallback"},
    },
    "X": {
        "open": {"covered", "disposition", "blocked_fallback"},
        "covered": {"resolved", "blocked_fallback"},
        "resolved": {"blocked_fallback"},
        "disposition": {"disposition_accepted", "resolved", "blocked_fallback"},
    },
}


class LedgerError(RuntimeError):
    pass


def _json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)
            + "\n").encode("utf-8")


def _write_atomic(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _load_json(path):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LedgerError(f"cannot read {path}: {exc}") from exc
    return value


def _tables(path, columns, required=False):
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        if required:
            raise LedgerError(f"cannot read shard {path}: {exc}") from exc
        return []
    matches = []
    for headers, rows, _line in registers.parse_tables(text):
        if headers == columns:
            matches.append(rows)
    if required and len(matches) != 1:
        raise LedgerError(
            f"{path}: expected exactly one table with columns {' | '.join(columns)}"
        )
    output = []
    for rows in matches:
        for index, row in enumerate(rows, start=1):
            if len(row) != len(columns):
                raise LedgerError(f"{path}: malformed table row {index}")
            output.append(dict(zip(columns, row)))
    return output


def _wire_path(audit, raw):
    return registers.audit_path(audit, raw)


def _manifest_shard_state(manifest, stage, raw):
    wire = registers.normalized_audit_path(raw)
    return registers.manifest_shard_state(manifest, stage, wire)


def _claim_rows(audit, stage, base=False):
    later_snapshots = (("claims_b3b",) if stage == "claims_b3" or base else
                       ("claims_adjudication", "claims_b6a"))
    path = next((audit / "_run/snapshots" / name / "claims_register.md"
                 for name in later_snapshots
                 if (audit / "_run/snapshots" / name / "claims_register.md").is_file()),
                audit / "claims_register.md")
    lint = registers.Lint()
    loaded = registers.load_register(lint, path, registers.CLAIMS_COLS)
    if loaded is None or lint.errors:
        raise LedgerError("; ".join(lint.errors) or f"cannot load {path}")
    return path, [dict(zip(registers.CLAIMS_COLS, row)) for row in loaded[1]]


def _claims_by_id(claims):
    """Canon membership map. Paper Context stays a prose locator (registers.md);
    coverage anchors travel on the coverage/resolution entry itself."""
    return {claim["Claim ID"]: claim for claim in claims}


_TWIN_NORM_CACHE = {}


def _cached_twin_norm(audit_path):
    """Memoize the constant (text, haystack, positions) per twin file.

    The twin file does not change during a run, so this is byte-for-byte
    behaviour-preserving; it only removes the redundant per-claim re-read and
    re-normalization of the same 372KB twin (an O(obligations x claims) blowup).
    """
    cached = _TWIN_NORM_CACHE.get(audit_path)
    if cached is None:
        text = Path(audit_path).read_text(encoding="utf-8")
        haystack, positions = _normalize_with_map(text)
        cached = (text, haystack, positions)
        _TWIN_NORM_CACHE[audit_path] = cached
    return cached


def _resolve_quote_in_intervals(entry, intervals, quote):
    """Resolve a quote uniquely within a worker's owned line intervals.

    Returns the resolved anchor dict, or None when the quote does not resolve
    to exactly one occurrence starting inside the intervals.
    """
    text, haystack, positions = _cached_twin_norm(entry["audit_path"])
    needle = normalize_quote(quote)
    if not needle:
        return None
    hits, cursor = [], 0
    while True:
        found = haystack.find(needle, cursor)
        if found < 0:
            break
        raw_start = positions[found]
        raw_end = positions[found + len(needle) - 1] + 1
        start_line = text.count("\n", 0, raw_start) + 1
        if any(start <= start_line <= end for start, end in intervals):
            hits.append((raw_start, raw_end, start_line))
        cursor = found + 1
    if len(hits) != 1:
        return None
    raw_start, raw_end, start_line = hits[0]
    return {
        "source_path": entry["source_path"],
        "audit_path": entry["audit_path"],
        "start_char": raw_start,
        "end_char": raw_end,
        "start_line": start_line,
        "end_line": text.count("\n", 0, max(raw_start, raw_end - 1)) + 1,
    }


def _redirect(report, claim_id, claims_by_id):
    if claim_id in claims_by_id:
        return claim_id, None
    redirects = report.get("dedup_redirects", {})
    target = redirects.get(claim_id) if isinstance(redirects, dict) else None
    if target not in claims_by_id:
        raise LedgerError(
            f"cited claim {claim_id} is absent from canon and has no live dedup redirect"
        )
    return target, {"from": claim_id, "to": target}


def _covering_claim(allocations, source_set, obligation_anchor, claims_by_id,
                    package_root):
    """b3 satisfied matching: a destination-span claim row's Paper Quote,
    resolved uniquely within the destination worker's b1 ownership intervals,
    contains the handoff's assertion interval."""
    worker = owner_for_line(
        allocations, source_set, obligation_anchor["source_path"],
        obligation_anchor["start_line"], package_root,
    )
    allocation = next(row for row in allocations if row["Worker ID"] == worker)
    entry = allocation_source_entry(allocation, source_set, package_root)
    intervals = parse_line_intervals(allocation["Line Intervals"])
    candidates = []
    for claim_id, claim in claims_by_id.items():
        claim_anchor = _resolve_quote_in_intervals(entry, intervals, claim["Paper Quote"])
        if claim_anchor and contains(claim_anchor, obligation_anchor):
            candidates.append((
                claim_anchor["end_char"] - claim_anchor["start_char"], claim_id
            ))
    return min(candidates)[1] if candidates else None


def _coverage_mapping(row, obligation_anchor, source_set, claims_by_id,
                      report, package_root):
    outcome = row["Outcome"]
    if outcome == "covered":
        claim_id = row["C-ID / Reason"].strip()
        if not claim_id.startswith("C-"):
            raise LedgerError("covered obligation must name a C-ID")
        claim_id, redirect = _redirect(report, claim_id, claims_by_id)
        claim = claims_by_id[claim_id]
        if row["Covering Quote"] != claim["Paper Quote"]:
            raise LedgerError(
                f"covering quote for {claim_id} is not the cited row's Paper Quote verbatim"
            )
        try:
            carried = resolve_quote(
                source_set, row["Covering Range"], row["Covering Quote"], package_root
            )
        except AnchorError as exc:
            raise LedgerError(str(exc)) from exc
        if not contains(carried, obligation_anchor):
            raise LedgerError(f"covering claim {claim_id} does not contain the obligation")
        return "covered", claim_id, None, redirect, carried
    if outcome == "disposition":
        reason = row["C-ID / Reason"].strip()
        try:
            evidence = validate_disposition(reason, row["Evidence"])
        except ValueError as exc:
            raise LedgerError(str(exc)) from exc
        if not (registers.blank_cell(row["Covering Range"])
                and registers.blank_cell(row["Covering Quote"])):
            raise LedgerError("disposition covering range and quote must be blank")
        return "disposition", None, {"reason": reason, "evidence": evidence}, None, None
    raise LedgerError(f"invalid coverage outcome {outcome!r}")


def _base_entries(package_root, audit, manifest, source_set, allocations,
                  inventory, assignments, claims_by_id, report):
    handoffs, x_rows_by_id = [], {}
    seen_h = set()
    allocation_by_worker = {row["Worker ID"]: row for row in allocations}
    for allocation in allocations:
        state = _manifest_shard_state(
            manifest, "claims_b2", allocation["Shard File"]
        )
        if state == "blocked":
            continue
        shard = _wire_path(audit, allocation["Shard File"])
        for row in _tables(shard, HANDOFF_COLS):
            handoff_id = row["H ID"]
            if handoff_id in seen_h:
                raise LedgerError(f"duplicate handoff ID {handoff_id}")
            seen_h.add(handoff_id)
            try:
                anchor = resolve_quote(source_set, row["Anchor"], row["Quote"], package_root)
            except AnchorError as exc:
                raise LedgerError(str(exc)) from exc
            covering = _covering_claim(
                allocations, source_set, anchor, claims_by_id, package_root
            )
            handoffs.append({
                "id": handoff_id,
                "kind": "H",
                "source_shard": registers.normalized_audit_path(allocation["Shard File"]),
                "anchor": row["Anchor"],
                "resolved_anchor": anchor,
                "quote": row["Quote"],
                "asserted_substance": row["Asserted Substance"],
                "referenced_objects": row["Referenced Objects"],
                "destination_worker": _owner_from_resolved(
                    allocations, source_set, anchor, package_root
                ),
                "state": "satisfied" if covering else "forwarded",
                "covering_c_id": covering,
                "disposition": None,
                "dedup_redirect": None,
            })
        for row in _tables(shard, X_COVERAGE_COLS):
            x_id = row["X ID"]
            if x_id in x_rows_by_id:
                raise LedgerError(f"duplicate X coverage row {x_id}")
            x_rows_by_id[x_id] = (allocation["Worker ID"], row,
                                  registers.normalized_audit_path(allocation["Shard File"]))

    x_entries = []
    inventory_entries = inventory.get("entries")
    assignment_map = assignments.get("assignments")
    if not isinstance(inventory_entries, list) or not isinstance(assignment_map, dict):
        raise LedgerError("malformed crossref inventory or assignments")
    expected_x = {entry["id"] for entry in inventory_entries}
    if set(assignment_map) != expected_x:
        raise LedgerError("crossref assignments do not exactly cover inventory X IDs")
    if set(x_rows_by_id) - expected_x:
        raise LedgerError(
            f"X coverage has unknown IDs: {sorted(set(x_rows_by_id) - expected_x)}"
        )
    for source in inventory_entries:
        x_id = source["id"]
        worker = assignment_map[x_id]
        allocation = allocation_by_worker.get(worker)
        if allocation is None:
            raise LedgerError(f"X assignment {x_id} names unknown worker {worker}")
        if _manifest_shard_state(manifest, "claims_b2", allocation["Shard File"]) == "blocked":
            state, claim_id, disposition, redirect, carried = (
                "blocked_fallback", None, None, None, None
            )
            source_shard = registers.normalized_audit_path(allocation["Shard File"])
        else:
            if x_id not in x_rows_by_id:
                raise LedgerError(f"assigned X ID {x_id} has no terminal shard row")
            row_worker, row, source_shard = x_rows_by_id[x_id]
            if row_worker != worker:
                raise LedgerError(f"X ID {x_id} filed by {row_worker}, assigned to {worker}")
            state, claim_id, disposition, redirect, carried = _coverage_mapping(
                row, source["anchor"], source_set, claims_by_id, report, package_root
            )
        x_entries.append({
            "id": x_id, "kind": "X", "source_shard": source_shard,
            "anchor": source["anchor"], "resolved_anchor": source["anchor"],
            "referencing_sentence": source["referencing_sentence"],
            "referenced_float_labels": source["referenced_float_labels"],
            "destination_worker": worker, "state": state,
            "covering_c_id": claim_id, "disposition": disposition,
            "dedup_redirect": redirect, "covering_anchor": carried,
        })
    return sorted(handoffs, key=lambda item: item["id"]), sorted(
        x_entries, key=lambda item: item["id"]
    )


def _owner_from_resolved(allocations, source_set, anchor, package_root):
    return owner_for_line(
        allocations, source_set, anchor["source_path"], anchor["start_line"], package_root
    )


def _apply_b3b(package_root, audit, manifest, source_set, handoffs,
               claims_by_id, report):
    plan = audit / "plans" / "claims_second_read_plan.md"
    text = plan.read_text(encoding="utf-8")
    matches = [(headers, rows) for headers, rows, _line in registers.parse_tables(text)
               if headers == registers.SECOND_READ_PLAN_COLS["claims"]]
    if len(matches) != 1:
        raise LedgerError(f"{plan}: missing exact claims second-read allocation table")
    headers, rows = matches[0]
    allocations = [dict(zip(headers, row)) for row in rows if len(row) == len(headers)]
    assigned = {}
    resolutions = {}
    for allocation in allocations:
        ids = [item.strip() for item in allocation["Assigned Handoff IDs"].split(",")
               if item.strip() and not registers.blank_cell(item)]
        for handoff_id in ids:
            if handoff_id in assigned:
                raise LedgerError(f"forwarded handoff {handoff_id} assigned more than once")
            assigned[handoff_id] = allocation
        state = _manifest_shard_state(
            manifest, "claims_b3b", allocation["Shard File"]
        )
        if state == "blocked":
            continue
        shard = _wire_path(audit, allocation["Shard File"])
        for row in _tables(shard, HANDOFF_RESOLUTION_COLS):
            if row["H ID"] in resolutions:
                raise LedgerError(f"duplicate handoff resolution {row['H ID']}")
            resolutions[row["H ID"]] = row
    forwarded = {entry["id"] for entry in handoffs if entry["state"] == "forwarded"}
    if set(assigned) != forwarded:
        raise LedgerError(
            f"Assigned Handoff IDs do not exactly cover forwarded ledger IDs; "
            f"missing={sorted(forwarded - set(assigned))}, extra={sorted(set(assigned) - forwarded)}"
        )
    by_id = {entry["id"]: entry for entry in handoffs}
    for handoff_id in sorted(forwarded):
        entry, allocation = by_id[handoff_id], assigned[handoff_id]
        if _manifest_shard_state(manifest, "claims_b3b", allocation["Shard File"]) == "blocked":
            entry["state"] = "blocked_fallback"
            continue
        row = resolutions.get(handoff_id)
        if row is None:
            raise LedgerError(f"assigned handoff {handoff_id} has no resolution row")
        for column, key in zip(HANDOFF_COLS, (
                "id", "anchor", "quote", "asserted_substance", "referenced_objects")):
            if row[column] != entry[key]:
                raise LedgerError(f"{handoff_id} resolution changes filing field {column}")
        synthetic = {
            "Outcome": "covered" if row["Resolution"] == "resolved" else row["Resolution"],
            "C-ID / Reason": row["C-ID / Reason"], "Evidence": row["Evidence"],
            "Covering Range": row["Covering Range"], "Covering Quote": row["Covering Quote"],
        }
        state, claim_id, disposition, redirect, carried = _coverage_mapping(
            synthetic, entry["resolved_anchor"], source_set, claims_by_id,
            report, package_root
        )
        entry["state"] = "resolved" if state == "covered" else state
        entry["covering_c_id"] = claim_id
        entry["disposition"] = disposition
        entry["dedup_redirect"] = redirect
        entry["covering_anchor"] = carried
    if set(resolutions) - forwarded:
        raise LedgerError(
            f"handoff resolutions include unassigned IDs: {sorted(set(resolutions) - forwarded)}"
        )


def _check_disposition_pointers(entries):
    by_id = {entry["id"]: entry for entry in entries}
    for entry in entries:
        disposition = entry.get("disposition")
        if not disposition or disposition["reason"] != "duplicate_of_covered":
            continue
        target = disposition["evidence"]["covering_obligation"]
        seen = {entry["id"]}
        while True:
            if target in seen:
                raise LedgerError(f"disposition pointer cycle reaches {target}")
            seen.add(target)
            other = by_id.get(target)
            if other is None:
                raise LedgerError(f"disposition pointer names unknown obligation {target}")
            if other["state"] in FINAL_H | FINAL_X:
                if other.get("covering_c_id") != disposition["evidence"]["covering_c_id"]:
                    raise LedgerError("duplicate disposition C-ID disagrees with final target")
                break
            nested = other.get("disposition")
            if not nested or nested["reason"] != "duplicate_of_covered":
                raise LedgerError(f"disposition pointer dead-ends at {target}")
            target = nested["evidence"]["covering_obligation"]


def derive(package_root, audit, stage):
    if stage not in {"claims_b3", "claims_b3b"}:
        raise LedgerError(f"unsupported U7a ledger stage {stage!r}")
    package_root, audit = Path(package_root).resolve(), Path(audit).resolve()
    manifest = _load_json(audit / "_run" / "manifest.json")
    source_set = manifest.get("paper_source_set")
    if not isinstance(source_set, list) or not source_set:
        raise LedgerError("manifest has no paper_source_set")
    allocations, _ = load_claims_allocations(audit / "plans" / "claims_review_plan.md")
    inventory = _load_json(audit / "_run" / "crossref_inventory.json")
    assignments = _load_json(audit / "_run" / "crossref_assignments.json")
    report_name = "merge_report_claims.json" if stage == "claims_b3" else "merge_report_claims_b3b.json"
    report = _load_json(audit / "_run" / report_name)
    base_report = (report if stage == "claims_b3" else
                   _load_json(audit / "_run" / "merge_report_claims.json"))
    _claim_path, claims = _claim_rows(audit, stage, base=(stage == "claims_b3b"))
    claims_by_id = _claims_by_id(claims)
    handoffs, x_entries = _base_entries(
        package_root, audit, manifest, source_set, allocations, inventory,
        assignments, claims_by_id, base_report
    )
    if stage == "claims_b3b":
        before = {entry["id"]: entry["state"] for entry in handoffs + x_entries}
        _post_path, post_claims = _claim_rows(audit, stage)
        _apply_b3b(
            package_root, audit, manifest, source_set, handoffs,
            _claims_by_id(post_claims), report
        )
        for entry in handoffs + x_entries:
            old, new = before[entry["id"]], entry["state"]
            if old != new and new not in LEGAL_TRANSITIONS[entry["kind"]].get(old, set()):
                raise LedgerError(f"illegal {entry['kind']} transition {old} -> {new}")
    _check_disposition_pointers(handoffs + x_entries)
    return {
        "format_version": 1,
        "stage": stage,
        "H": handoffs,
        "X": x_entries,
    }, report, audit / "_run" / report_name


def snapshot_path(audit, stage):
    return Path(audit) / "_run" / "snapshots" / stage / "handoff_ledger.json"


def build(package_root, audit, stage):
    ledger, report, report_path = derive(package_root, audit, stage)
    payload = _json_bytes(ledger)
    live = Path(audit) / "_run" / "handoff_ledger.json"
    snapshot = snapshot_path(audit, stage)
    _write_atomic(live, payload)
    _write_atomic(snapshot, payload)
    report["handoff_ledger"] = {
        "H": len(ledger["H"]), "X": len(ledger["X"]),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    _write_atomic(report_path, _json_bytes(report))


def check(package_root, audit, stage):
    ledger, report, _report_path = derive(package_root, audit, stage)
    payload = _json_bytes(ledger)
    snapshot = snapshot_path(audit, stage)
    try:
        actual = snapshot.read_bytes()
    except OSError as exc:
        raise LedgerError(f"missing stage-era handoff ledger {snapshot}: {exc}") from exc
    if actual != payload:
        raise LedgerError(f"stage-era handoff ledger is absent, stale, or edited: {snapshot}")
    expected_block = {
        "H": len(ledger["H"]), "X": len(ledger["X"]),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    if report.get("handoff_ledger") != expected_block:
        raise LedgerError("merge report handoff_ledger block disagrees with immutable ledger")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_root", type=Path)
    parser.add_argument("--audit-dir", type=Path)
    parser.add_argument("--stage", required=True, choices=("claims_b3", "claims_b3b"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    audit = args.audit_dir or args.package_root / "audit"
    try:
        (check if args.check else build)(args.package_root, audit, args.stage)
    except (LedgerError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"HANDOFF LEDGER REFUSED: {exc}", file=sys.stderr)
        return 1
    print("HANDOFF LEDGER OK: " + ("check" if args.check else "build"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
