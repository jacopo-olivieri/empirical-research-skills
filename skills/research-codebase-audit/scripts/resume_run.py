#!/usr/bin/env python3
"""The one guarded recovery command after an audit run's process dies.

Long runs are certainly interrupted — a usage-limit stop, a sleeping laptop, a
crash.  Recovery used to be four manual steps (judge whether the old process is
dead, clear the marker, hand-demote whatever no longer verifies, find the right
conversation), and each one is a place where a stale ``done`` can survive into
the report.  This launcher performs all four and has **no path that skips
re-verification**:

1. refuse while the recorded conductor PID is still alive;
2. report a usage window that has not reset yet and ask before relaunching;
3. run ``certify_stage.resume_check`` in a loop, demoting every stale recorded
   pass with its failed obligation and discarding that boundary's stale staging
   files, until one pass comes back clean — relaunch is reachable only from a
   clean pass;
4. resolve the recorded conversation and ``exec`` ``claude --resume`` into it.

It imports ``certify_stage`` in-process, so refusals arrive as typed
``CertificationError``s and the demote loop reads structured failures instead of
scraped text.  ``certify_stage`` stays the sole, non-interactive status writer;
this script re-implements none of its checks and weakens none of them — an
identity failure (changed tree, canonical root, or mechanism schema) is not
demotable and stops the launcher cold.

The launcher always records **its own** ``os.getpid()`` as the conductor PID.
``os.exec*`` preserves the process ID, so the launcher's PID *is* the resumed
conductor's PID and the marker written during the loop stays correct across the
relaunch.
"""

import argparse
import json
import os
import shlex
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import certify_stage


PAUSE_THRESHOLD_PERCENT = 90.0


class LauncherRefusal(RuntimeError):
    """The launcher cannot safely reach a relaunch."""


# ------------------------------------------------------------- usage snapshot


def parse_iso(value):
    """Parse an ISO 8601 instant defensively; ``None`` when unusable."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def at_threshold_windows(snapshot, now):
    """Non-expired usage windows at or over the pause threshold.

    A window whose ``resets_at`` has passed is expired — it describes a limit
    that has already lifted, so it is never grounds for a confirmation.  A
    window with no usable ``resets_at`` cannot be shown to be current, so it is
    treated the same way.
    """
    limits = snapshot.get("rate_limits")
    if not isinstance(limits, dict):
        return []
    at_threshold = []
    for window in sorted(limits):
        fields = limits[window]
        if not isinstance(fields, dict):
            continue
        used = fields.get("used_percentage")
        if isinstance(used, bool) or not isinstance(used, (int, float)):
            continue
        if float(used) < PAUSE_THRESHOLD_PERCENT:
            continue
        resets_at = parse_iso(fields.get("resets_at"))
        if resets_at is None or resets_at <= now:
            continue
        at_threshold.append((window, float(used), resets_at))
    return at_threshold


# ------------------------------------------------------------ the four gates


def liveness_gate(package_root):
    """Step 1 — never run a second conductor over a live one."""
    _, _, _, marker = certify_stage.audit_paths(package_root)
    if not marker.exists():
        return None
    text = marker.read_text(encoding="utf-8", errors="replace")
    recorded_pid = certify_stage.marker_pid(text)
    if (recorded_pid is not None and recorded_pid != os.getpid()
            and certify_stage.pid_is_alive(recorded_pid)):
        raise LauncherRefusal(certify_stage.live_conductor_refusal(text, recorded_pid))
    return recorded_pid


def reset_time_gate(package_root, assume_yes, out, prompt=input, now=None):
    """Step 2 — a relaunch into a window that has not reset stops immediately."""
    now = datetime.now(timezone.utc) if now is None else now
    snapshot = certify_stage.read_usage_snapshot(package_root)
    at_threshold = at_threshold_windows(snapshot, now)
    if not at_threshold:
        return False
    latest = max(resets_at for _window, _used, resets_at in at_threshold)
    detail = ", ".join(
        f"{window} at {used:.1f}% until {resets_at.isoformat()}"
        for window, used, resets_at in at_threshold
    )
    print(f"usage limit not reset yet: {detail}; the latest reset is "
          f"{latest.isoformat()}", file=out)
    if assume_yes:
        print("--yes given: relaunching without confirmation", file=out)
        return True
    try:
        answer = prompt("Relaunch anyway before the reset? [y/N] ")
    except EOFError:
        raise LauncherRefusal(
            "usage limit has not reset and no confirmation was possible "
            f"(latest reset {latest.isoformat()}); rerun with --yes to relaunch "
            "anyway, or wait for the reset"
        )
    if str(answer).strip().lower() not in {"y", "yes"}:
        raise LauncherRefusal(
            "not relaunching: the usage limit has not reset yet (latest reset "
            f"{latest.isoformat()})"
        )
    return True


def classify_failures(identity_failures, evidence_failures):
    """Split re-verification failures into demotable passes and terminal ones.

    ``verify_done_stages`` shapes every stage-scoped failure as
    ``stage '<key>': <failure>`` — the same re-derivation ``resume-check`` runs.
    Everything else (identity mismatches, run-level evidence failures) names no
    demotable pass and is terminal by construction.
    """
    stale = {}
    terminal = list(identity_failures)
    for failure in evidence_failures:
        prefix, separator, detail = failure.partition(": ")
        if (separator and prefix.startswith("stage '") and prefix.endswith("'")):
            stale.setdefault(prefix[len("stage '"):-1], []).append(detail)
        else:
            terminal.append(failure)
    return stale, terminal


def rederive_failures(package_root):
    """Re-run exactly the checks ``resume_check`` runs, structured."""
    manifest = certify_stage.read_manifest(package_root)
    identity = certify_stage._identity_failures(
        package_root, manifest, check_fingerprint=True)
    evidence = certify_stage.verify_done_stages(package_root, manifest)
    return classify_failures(identity, evidence)


def discard_staging(package_root, out):
    """Design call 7 — after process death every staging file is stale.

    The exception is the frozen b8 state: when ``b8`` is still certified done,
    ``audit/_staging/`` holds the registers the export reads, and losing them
    costs more than one loud manual step.
    """
    manifest = certify_stage.read_manifest(package_root)
    stages = manifest.get("stages")
    b8 = stages.get("b8") if isinstance(stages, dict) else None
    if isinstance(b8, dict) and b8.get("status") == "done":
        raise LauncherRefusal(
            "refusing the automatic staging discard: stage 'b8' is still "
            "certified done, so audit/_staging/ holds the frozen b8 registers. "
            "Discard the stale staging files by hand (or demote b8 first) and "
            "rerun the launcher."
        )
    staging = package_root / "audit" / "_staging"
    if not staging.is_dir():
        return []
    removed = []
    for child in sorted(staging.iterdir()):
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()
        removed.append(child.name)
    print("discarded stale staging file(s): "
          + (", ".join(removed) if removed else "none"), file=out)
    return removed


def clean_loop(package_root, out):
    """Step 3 — demote and discard until one re-verification pass is clean."""
    demoted = []
    while True:
        try:
            summary = certify_stage.resume_check(
                package_root, clear_stale_marker=True, conductor_pid=os.getpid())
        except certify_stage.CertificationError as exc:
            message = str(exc)
        else:
            print(f"resume check clean; {summary}", file=out)
            return summary, demoted
        try:
            stale, terminal = rederive_failures(package_root)
        except certify_stage.CertificationError as exc:
            raise LauncherRefusal(f"{message} | cannot re-derive failures: {exc}")
        if terminal:
            raise LauncherRefusal(
                "re-verification failed on non-demotable ground(s): "
                + " | ".join(terminal)
                + " | restarting the audit from fresh is the only route; the "
                "launcher never demotes around an identity or run-level failure"
            )
        if not stale:
            raise LauncherRefusal(
                "resume check keeps failing but names no recorded pass to "
                f"demote: {message}"
            )
        pass_demotions = []
        for stage in sorted(stale):
            reason = "; ".join(stale[stage])
            try:
                certify_stage.demote_stage(package_root, stage, reason)
            except certify_stage.CertificationError:
                # Already demoted by an earlier pass, or never done: not a new
                # demotion, so it cannot count toward loop progress.
                continue
            pass_demotions.append((stage, reason))
        if not pass_demotions:
            raise LauncherRefusal(
                "resume check keeps failing and no further demotion is "
                f"possible: {message}"
            )
        for stage, reason in pass_demotions:
            print(f"demoted stage {stage!r} to pending: {reason}", file=out)
        demoted.extend(pass_demotions)
        discard_staging(package_root, out)


def resolve_session_id(package_root):
    """Step 4 — freshest first, then the value recorded at init."""
    session_id = certify_stage.recorded_session_id(package_root)
    if session_id:
        return session_id, "audit/_run/usage.json"
    manifest = certify_stage.read_manifest(package_root)
    identity = manifest.get("run_identity")
    if isinstance(identity, dict):
        value = identity.get("session_id")
        if isinstance(value, str) and value.strip():
            return value.strip(), "manifest run_identity.session_id"
    return None, None


def manual_resume_instruction(package_root):
    certify = Path(__file__).resolve().parent / "certify_stage.py"
    return (
        "no session ID is recorded anywhere: audit/_run/usage.json carries "
        "none and run_identity.session_id is null. Resume by hand: run "
        "`claude --resume`, pick this audit's conversation, and — before any "
        "audit work — have that session run `python "
        f"{certify} resume-check --package-root {package_root} "
        "--clear-stale-marker --conductor-pid <its own conductor PID>` to take "
        "marker ownership. Without that re-registration the marker still names "
        "this launcher's dead PID, and a later launcher could clear it out from "
        "under the live manual session."
    )


# ---------------------------------------------------------------------- CLI


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--package-root", type=Path, default=Path.cwd(),
        help="audited package root (default: current working directory)",
    )
    parser.add_argument(
        "--print-only", action="store_true",
        help="print the relaunch command instead of exec'ing it; every gate "
             "above still runs unchanged",
    )
    parser.add_argument(
        "--yes", action="store_true",
        help="skip the interactive reset-time confirmation (scripted use)",
    )
    return parser


def run(args, out=sys.stdout, prompt=input):
    package_root = certify_stage.canonical_package_root(args.package_root)
    liveness_gate(package_root)
    reset_time_gate(package_root, args.yes, out, prompt=prompt)
    _summary, demoted = clean_loop(package_root, out)
    print(f"demotions this recovery: {len(demoted)}", file=out)
    session_id, source = resolve_session_id(package_root)
    if session_id is None:
        raise LauncherRefusal(manual_resume_instruction(package_root))
    command = ["claude", "--resume", session_id]
    print(f"resuming conversation {session_id} (from {source})", file=out)
    if args.print_only:
        print("RESUME COMMAND: " + shlex.join(command), file=out)
        return 0
    out.flush()
    os.execvp(command[0], command)
    raise LauncherRefusal(  # pragma: no cover - exec replaces this process
        "could not exec the claude CLI")


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except (LauncherRefusal, certify_stage.CertificationError,
            json.JSONDecodeError) as exc:
        print(f"RESUME REFUSED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
