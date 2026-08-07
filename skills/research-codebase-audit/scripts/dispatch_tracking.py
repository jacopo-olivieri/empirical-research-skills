#!/usr/bin/env python3
"""Record effort-keyed dispatches and best-effort carrier observation events."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import uuid
from collections import Counter
from pathlib import Path

import definition_use as du


EFFORT_TIERS = ("low", "medium", "high", "xhigh", "max")
ROLE_KEYS = (
    "codemap",
    "claims_b1_planner", "claims_b2_section", "claims_b3_merge",
    "claims_b3c_conventions", "claims_b3b_second_read", "claims_b3b_merge",
    "claims_adjudication", "claims_adjudication_lineage",
    "claims_b5_recheck_cluster", "claims_b6_merge",
    "code_b1_planner", "code_b2_chunk", "code_b3_merge",
    "b3d_conventions_scan", "code_b3b_second_read", "code_b3b_merge",
    "code_b5_recheck_cluster", "code_b6_merge",
    "b7_cross_linker", "b7_claim_recheck", "b8_rewriter",
)
DEFAULT_EFFORT_MAP = {
    role: ("low" if role == "b8_rewriter" else "medium")
    for role in ROLE_KEYS
}
LEDGER_COLS = [
    "Role Key", "Carrier", "Stage Key", "Shard or Artifact", "Dispatch Sequence",
]
DISPATCH_MARKER_RE = re.compile(
    r"RCA-DISPATCH\s+role=(?P<role>[a-z0-9_]+)\s+stage=(?P<stage>[a-z0-9_]+)"
)


class DispatchError(RuntimeError):
    """A dispatch record or observation event is malformed."""


def validate_effort_map(value):
    if not isinstance(value, dict):
        raise DispatchError("manifest effort_map must be an object")
    unknown = sorted(set(value) - set(ROLE_KEYS))
    missing = sorted(set(ROLE_KEYS) - set(value))
    bad_tiers = sorted(
        f"{role}={tier!r}" for role, tier in value.items()
        if role in ROLE_KEYS and tier not in EFFORT_TIERS
    )
    details = []
    if unknown:
        details.append("unknown role key(s): " + ", ".join(unknown))
    if missing:
        details.append("missing role key(s): " + ", ".join(missing))
    if bad_tiers:
        details.append("invalid effort tier(s): " + ", ".join(bad_tiers))
    if details:
        raise DispatchError("invalid effort_map: " + "; ".join(details))


def _escape(value):
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def append_dispatch(audit, role, carrier, stage, owner, sequence):
    if role not in ROLE_KEYS:
        raise DispatchError(f"unknown role key {role!r}")
    expected_carriers = {f"rca-carrier-{tier}" for tier in EFFORT_TIERS}
    if carrier not in expected_carriers:
        raise DispatchError(f"unknown carrier {carrier!r}")
    if not stage or not owner:
        raise DispatchError("stage key and shard-or-artifact must be non-empty")
    if sequence < 1:
        raise DispatchError("dispatch sequence must be a positive integer")
    path = Path(audit) / "_run" / "dispatch_ledger.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = _markdown_rows(path)
    prior_sequences = [int(row["Dispatch Sequence"]) for row in existing]
    if prior_sequences and sequence <= max(prior_sequences):
        raise DispatchError(
            f"dispatch sequence {sequence} is not greater than prior sequence "
            f"{max(prior_sequences)}"
        )
    if not path.exists():
        path.write_text(
            "# Dispatch ledger\n\n| " + " | ".join(LEDGER_COLS) + " |\n"
            "| " + " | ".join(["---"] * len(LEDGER_COLS)) + " |\n",
            encoding="utf-8",
        )
    line = "| " + " | ".join(map(_escape, (
        role, carrier, stage, owner, str(sequence),
    ))) + " |\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())
    return path


def _atomic_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise


def resolve_audit_dir(audit_dir, hook_input=None):
    """Resolve the audit root: explicit flag, then hook cwd, then project dir.

    The carrier stop hook cannot rely on its process cwd, so the event path
    prefers the hook payload's `cwd` (the session's working directory) and the
    `CLAUDE_PROJECT_DIR` environment variable before falling back to a relative
    `audit`. Resolution is best-effort reporting plumbing — a wrong or absent
    root degrades to a named instrumentation gap, never a refusal.
    """
    if audit_dir is not None:
        return Path(audit_dir)
    cwd = (hook_input or {}).get("cwd")
    if isinstance(cwd, str) and cwd.strip():
        return Path(cwd) / "audit"
    project = os.environ.get("CLAUDE_PROJECT_DIR")
    if project:
        return Path(project) / "audit"
    return Path("audit")


def _dispatch_metadata(hook_input):
    for key in ("prompt", "task", "transcript"):
        value = hook_input.get(key)
        if isinstance(value, str):
            match = DISPATCH_MARKER_RE.search(value)
            if match:
                return match.group("role"), match.group("stage")
    transcript_path = (hook_input.get("agent_transcript_path")
                       or hook_input.get("transcript_path"))
    if transcript_path:
        try:
            match = DISPATCH_MARKER_RE.search(
                Path(transcript_path).read_text(encoding="utf-8", errors="replace")
            )
        except OSError:
            match = None
        if match:
            return match.group("role"), match.group("stage")
    return "unknown", "unknown"


def write_event(audit, carrier, hook_input):
    role, stage = _dispatch_metadata(hook_input)
    identity = {
        key: hook_input.get(key)
        for key in ("agent_id", "session_id", "agent_type", "model")
        if hook_input.get(key) is not None
    }
    for env_name in ("CLAUDE_CODE_SESSION_ID", "CLAUDE_MODEL"):
        if os.environ.get(env_name):
            identity[env_name.lower()] = os.environ[env_name]
    event_id = str(identity.get("agent_id") or identity.get("session_id") or uuid.uuid4())
    event_id = re.sub(r"[^A-Za-z0-9_.-]", "_", event_id)
    path = Path(audit) / "_run" / "dispatch_events" / f"{event_id}.json"
    if path.exists():
        path = path.with_name(f"{path.stem}-{uuid.uuid4().hex[:8]}.json")
    _atomic_json(path, {
        "carrier": carrier,
        "role_key": role,
        "stage_key": stage,
        "identity": identity,
    })
    return path


def _markdown_rows(path):
    if not path.is_file():
        return []
    matches = [rows for headers, rows, _line in
               du.parse_markdown_tables(path.read_text(encoding="utf-8"))
               if headers == LEDGER_COLS]
    if len(matches) != 1:
        raise DispatchError(f"{path}: dispatch ledger header is malformed")
    parsed = []
    for row in matches[0]:
        if len(row) != len(LEDGER_COLS):
            raise DispatchError(f"{path}: malformed dispatch ledger row")
        values = [str(cell).strip().strip("`").strip() for cell in row]
        try:
            sequence = int(values[-1])
        except ValueError as exc:
            raise DispatchError(f"{path}: invalid dispatch sequence {values[-1]!r}") from exc
        if sequence < 1:
            raise DispatchError(f"{path}: dispatch sequence must be positive")
        parsed.append(dict(zip(LEDGER_COLS, values)))
    return parsed


def read_ledger_rows(path):
    """Public accessor for parsed dispatch-ledger rows (thin wrapper of _markdown_rows)."""
    return _markdown_rows(Path(path))


def accounting_report(audit):
    audit = Path(audit)
    ledger = Counter(
        (row["Stage Key"], row["Role Key"])
        for row in _markdown_rows(audit / "_run" / "dispatch_ledger.md")
    )
    events = Counter()
    event_dir = audit / "_run" / "dispatch_events"
    for path in sorted(event_dir.glob("*.json")) if event_dir.is_dir() else []:
        try:
            event = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise DispatchError(f"{path}: malformed dispatch event: {exc}") from exc
        events[(str(event.get("stage_key", "unknown")),
                str(event.get("role_key", "unknown")))] += 1
    keys = sorted(set(ledger) | set(events))
    lines = [
        "| Stage Key | Role Key | Ledger Dispatches | Observed Events | Instrumentation Gap |",
        "| --- | --- | --- | --- | --- |",
    ]
    for stage, role in keys:
        expected, observed = ledger[(stage, role)], events[(stage, role)]
        gap = "none" if expected == observed else f"ledger={expected}, events={observed}"
        lines.append(f"| {stage} | {role} | {expected} | {observed} | {gap} |")
    if not keys:
        lines.append("| — | — | 0 | 0 | none |")
    return "\n".join(lines) + "\n"


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    record = sub.add_parser("record")
    record.add_argument("--audit-dir", type=Path, default=Path("audit"))
    record.add_argument("--role", required=True)
    record.add_argument("--carrier", required=True)
    record.add_argument("--stage", required=True)
    record.add_argument("--owner", required=True)
    record.add_argument("--sequence", required=True, type=int)
    event = sub.add_parser("event")
    event.add_argument("--audit-dir", type=Path, default=None)
    event.add_argument("--carrier", required=True)
    report = sub.add_parser("report")
    report.add_argument("--audit-dir", type=Path, default=Path("audit"))
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "record":
            path = append_dispatch(
                args.audit_dir, args.role, args.carrier, args.stage,
                args.owner, args.sequence,
            )
            print(f"recorded dispatch: {path}")
        elif args.command == "event":
            try:
                hook_input = json.load(sys.stdin)
            except json.JSONDecodeError as exc:
                raise DispatchError(f"carrier stop-hook input is invalid JSON: {exc}") from exc
            path = write_event(
                resolve_audit_dir(args.audit_dir, hook_input),
                args.carrier, hook_input,
            )
            print(f"recorded dispatch event: {path}")
        else:
            sys.stdout.write(accounting_report(args.audit_dir))
    except (DispatchError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
