#!/usr/bin/env python3
"""Claude Code statusline command that also feeds the audit's usage snapshot.

Configure this script as the session's statusline command.  Claude Code invokes
it with one JSON payload on stdin carrying the session ID, the workspace
directory, and the current rate-limit windows.  The script does two things:

1. prints a short statusline for the human, and
2. when the workspace holds an audit run, writes the windows to
   ``<workspace>/audit/_run/usage.json`` so the conductor's wave-boundary pause
   rule and ``resume_run.py`` can read them.

It **never raises**.  A statusline that crashes takes the host UI's status area
with it, and the pause layer's degraded mode — no data, no hold — is always
safe.  Malformed input, a workspace with no audit run, or an unwritable target
all end the same way: the passthrough line, exit 0, no write.

Expiry is deliberately *not* filtered here.  A snapshot whose ``resets_at`` has
passed is expired, and every consumer decides that for itself against its own
clock; the feed only records what the platform reported.
"""

import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


WINDOWS = ("five_hour", "seven_day")
WINDOW_FIELDS = ("used_percentage", "resets_at")


def _utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def read_payload(stream):
    """Parse one statusline JSON object; ``{}`` for anything unusable."""
    try:
        raw = stream.read()
    except Exception:  # pragma: no cover - stdin already closed by the host
        return {}
    try:
        payload = json.loads(raw)
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def workspace_dir(payload):
    """The audited working directory the payload names, or ``None``.

    Claude Code reports the same directory under ``workspace.current_dir`` and
    the top-level ``cwd``; older payload shapes carry only one of them.  Try
    each documented spelling rather than depending on one.
    """
    workspace = payload.get("workspace")
    candidates = []
    if isinstance(workspace, dict):
        candidates.extend([workspace.get("current_dir"), workspace.get("project_dir")])
    candidates.append(payload.get("cwd"))
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return Path(candidate)
    return None


def payload_windows(payload):
    """The windows this payload actually reports, defensively parsed."""
    limits = payload.get("rate_limits")
    if not isinstance(limits, dict):
        return {}
    reported = {}
    for window in WINDOWS:
        value = limits.get(window)
        if not isinstance(value, dict):
            continue
        fields = {key: value[key] for key in WINDOW_FIELDS if key in value}
        if fields:
            reported[window] = fields
    return reported


def read_existing(path):
    try:
        existing = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return existing if isinstance(existing, dict) else {}


def merge_windows(reported, existing):
    """Per-window merge: an omitted window keeps its last-known value."""
    previous = existing.get("rate_limits")
    previous = previous if isinstance(previous, dict) else {}
    merged = {}
    for window in WINDOWS:
        if window in reported:
            merged[window] = reported[window]
        elif isinstance(previous.get(window), dict):
            merged[window] = previous[window]
    return merged


def build_snapshot(payload, existing):
    """The snapshot to write: merged windows, refreshed identity and time."""
    session_id = payload.get("session_id")
    return {
        "session_id": session_id if isinstance(session_id, str) else None,
        "rate_limits": merge_windows(payload_windows(payload), existing),
        "written_at": _utc_now_iso(),
    }


def write_snapshot_atomic(path, snapshot):
    """Write-temp-then-rename, so no reader ever sees a partial snapshot."""
    payload = json.dumps(snapshot, indent=2) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=".usage.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def passthrough_line(payload):
    """A short statusline: the model, then the higher used percentage."""
    model = payload.get("model")
    name = None
    if isinstance(model, dict):
        for key in ("display_name", "id"):
            value = model.get(key)
            if isinstance(value, str) and value.strip():
                name = value.strip()
                break
    elif isinstance(model, str) and model.strip():
        name = model.strip()
    percentages = []
    for fields in payload_windows(payload).values():
        used = fields.get("used_percentage")
        if isinstance(used, (int, float)) and not isinstance(used, bool):
            percentages.append(float(used))
    usage = f"usage {max(percentages):.0f}%" if percentages else "usage —"
    return f"{name} | {usage}" if name else usage


def update_usage_file(payload):
    """Write the snapshot when this workspace holds an audit run.

    Returns the written path, or ``None`` when there was nothing to write.
    """
    workspace = workspace_dir(payload)
    if workspace is None:
        return None
    run_dir = workspace / "audit" / "_run"
    if not run_dir.is_dir():
        return None
    path = run_dir / "usage.json"
    write_snapshot_atomic(path, build_snapshot(payload, read_existing(path)))
    return path


def main(argv=None):
    payload = read_payload(sys.stdin)
    print(passthrough_line(payload))
    try:
        update_usage_file(payload)
    except Exception:
        # An unwritable target degrades the pause layer; it never degrades the
        # statusline, and it certainly never stops the run.
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
