"""Unit U16 — usage-limit resilience and manifest stage timestamps.

Two Tier-1 members, exactly:

(a) **the PID-liveness marker check** — silent death of it lets a second
    conductor interleave writes on one audit dir, the exact concurrency failure
    the RUNNING marker exists to defend;
(b) **the launcher-relaunches-only-after-a-clean-resume-check-loop invariant** —
    silent bypass of it lets stale or false ``done`` states survive into the
    report, the central defended failure.

Both get Tests 1-3 plus production-CLI sabotage drills.  Everything else here —
the stage timestamps, the statusline feed script, session-ID recording, and the
launcher's small parts — is Tier-2: Tests 1-2, no Test 3, no drill.

The Test-3 legs run **on a copy** of ``scripts/``: each leg appends one
redefinition that neuters exactly one production predicate, then drives the
copied CLI and asserts the canonical Test-1 assertion it names no longer holds.
"""

import io
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import regbuild as rb
import test_certify_stage as certify_tests

rr = rb.load_script("resume_run")
# The launcher imports ``certify_stage`` through the ordinary import machinery,
# so use *its* module object: a second path-loaded copy would raise a different
# ``CertificationError`` class than the launcher catches.
cs = rr.certify_stage
statusline = rb.load_script("usage_statusline")

pytestmark = pytest.mark.u16

CERTIFY = rb.SCRIPTS_DIR / "certify_stage.py"
RESUME_RUN = rb.SCRIPTS_DIR / "resume_run.py"
STATUSLINE = rb.SCRIPTS_DIR / "usage_statusline.py"

# A tide-gauge maintenance study: twelve lines of invented content, no real
# package, variable, layer, or cutoff anywhere in it.
BUOY_SOURCE = '''"""Tide-gauge maintenance log summariser."""

STATION_INTERVALS_DAYS = {
    "harbour-north": 90,
    "harbour-south": 120,
    "estuary-mouth": 45,
}


def main():
    for station, days in sorted(STATION_INTERVALS_DAYS.items()):
        print(f"{station}: serviced every {days} days")
'''

# The pinned usage snapshot, written literally.  Its ``resets_at`` values sit in
# the past relative to any real test clock, so it is the *expired* snapshot
# whenever a test compares it against ``datetime.now``; the frozen-clock tests
# pass FROZEN_NOW explicitly to read it as current.
USAGE_SNAPSHOT = {
    "session_id": "9d2f41c6-buoy-conductor",
    "rate_limits": {
        "five_hour": {"used_percentage": 93.5,
                      "resets_at": "2026-08-06T14:30:00+00:00"},
        "seven_day": {"used_percentage": 41.0,
                      "resets_at": "2026-08-09T02:00:00+00:00"},
    },
    "written_at": "2026-08-06T11:58:12+00:00",
}
FROZEN_NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=timezone.utc)
SESSION_ID = USAGE_SNAPSHOT["session_id"]
FALLBACK_SESSION_ID = "1a7be053-buoy-recorded-at-init"


# --------------------------------------------------------------- fixtures


def buoy_package(tmp_path, mode="replication", **extra):
    """A synthetic package root carrying the tide-gauge logger."""
    root = tmp_path / "package"
    (root / "code").mkdir(parents=True)
    (root / "code" / "log_buoy_readings.py").write_text(
        BUOY_SOURCE, encoding="utf-8")
    certify_tests.write_intake(
        root, mode=mode, output_prefs="tide-gauge maintenance study", **extra)
    return root


def write_usage(root, snapshot=None):
    path = root / "audit" / "_run" / "usage.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    body = USAGE_SNAPSHOT if snapshot is None else snapshot
    path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    return path


def live_window_snapshot(hours=2):
    """The pinned snapshot with a reset that has not happened yet."""
    resets_at = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
    snapshot = json.loads(json.dumps(USAGE_SNAPSHOT))
    snapshot["rate_limits"]["five_hour"]["resets_at"] = resets_at
    return snapshot


def certified_run(tmp_path, with_usage=True, with_staging=True):
    """A run with one certified ``done`` stage, built through the real CLI.

    ``claims_b3c`` is the stage the existing sabotage tests already use: its
    single obligation is the ``_run/conventions.md`` artifact, so a drill can
    corrupt a *claimed* artifact without inventing a new obligation.
    """
    root = buoy_package(tmp_path)
    if with_usage:
        write_usage(root)
    assert certify_tests.cli(root, "init").returncode == 0
    assert certify_tests.cli(root, "start", "--stage", "claims_b3c").returncode == 0
    (root / "audit" / "_run" / "conventions.md").write_text(
        "# Shared conventions\n", encoding="utf-8")
    assert certify_tests.cli(
        root, "finish", "--stage", "claims_b3c", "--outcome", "done"
    ).returncode == 0
    if with_staging:
        staging = root / "audit" / "_staging"
        staging.mkdir(parents=True, exist_ok=True)
        (staging / "claims_register.md").write_text("# staging\n", encoding="utf-8")
    return root


def read_manifest(root):
    return certify_tests.read_manifest(root)


def write_manifest(root, manifest):
    (Path(root) / "audit" / "_run" / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")


def plant_marker(root, pid=None, started="2026-08-06T09:00:00+00:00"):
    """Write a RUNNING marker directly — the liveness fixture."""
    marker = root / "audit" / "_run" / "RUNNING"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(
        f"started_at={started}\n" + (f"pid={pid}\n" if pid is not None else ""),
        encoding="utf-8")
    return marker


@pytest.fixture
def live_pid():
    """Spawn ``sleep 60`` children and reap them in teardown."""
    spawned = []

    def spawn():
        process = subprocess.Popen(["sleep", "60"])
        spawned.append(process)
        return process.pid

    yield spawn
    for process in spawned:
        process.kill()
        process.wait()


def dead_pid():
    """A PID that is provably gone: spawn a child, wait it, reuse its ID."""
    process = subprocess.Popen([sys.executable, "-c", "pass"])
    process.wait()
    return process.pid


def launcher(root, *args, stdin="", scripts_dir=None, script="resume_run.py"):
    directory = rb.SCRIPTS_DIR if scripts_dir is None else scripts_dir
    return subprocess.run(
        [sys.executable, str(Path(directory) / script),
         "--package-root", str(root), *args],
        capture_output=True, text=True, input=stdin,
    )


def certify_cli(root, command, *args, scripts_dir=None):
    directory = rb.SCRIPTS_DIR if scripts_dir is None else scripts_dir
    return subprocess.run(
        [sys.executable, str(Path(directory) / "certify_stage.py"), command,
         "--package-root", str(root), *args],
        capture_output=True, text=True,
    )


def run_statusline(payload, stdin=None):
    body = stdin if stdin is not None else json.dumps(payload)
    return subprocess.run(
        [sys.executable, str(STATUSLINE)],
        capture_output=True, text=True, input=body,
    )


def statusline_payload(root, rate_limits=None, session_id=SESSION_ID):
    payload = {
        "session_id": session_id,
        "workspace": {"current_dir": str(root), "project_dir": str(root)},
        "cwd": str(root),
        "model": {"display_name": "Buoy Model"},
    }
    limits = (USAGE_SNAPSHOT["rate_limits"] if rate_limits is None
              else rate_limits)
    if limits is not None:
        payload["rate_limits"] = limits
    return payload


# =========================================================== Tier 2 — #30
#
# The five write points, the retry overwrite, the legacy exception, reader
# tolerance, and the encoding identity with the marker's helper.


def timestamped_run(tmp_path):
    root = buoy_package(tmp_path)
    cs.init_run(root)
    (root / "audit" / "_run" / "conventions.md").write_text(
        "# Shared conventions\n", encoding="utf-8")
    return root


def test_init_writes_neither_timestamp_field(tmp_path):
    """Fields are ABSENT on fresh entries, never null."""
    root = timestamped_run(tmp_path)
    for entry in read_manifest(root)["stages"].values():
        assert entry == {"status": "pending", "retries": 0, "shards": {}}
        assert "started_at" not in entry and "ended_at" not in entry


def test_start_stamps_started_at_and_leaves_no_end(tmp_path):
    root = timestamped_run(tmp_path)
    cs.start_stage(root, "claims_b3c")
    entry = read_manifest(root)["stages"]["claims_b3c"]
    assert entry["status"] == "running"
    assert _parsed(entry["started_at"]).tzinfo is not None
    assert "ended_at" not in entry


def test_finish_done_stamps_ended_at_beside_the_status_flip(tmp_path):
    root = timestamped_run(tmp_path)
    cs.start_stage(root, "claims_b3c")
    cs.finish_stage(root, "claims_b3c", "done")
    entry = read_manifest(root)["stages"]["claims_b3c"]
    assert entry["status"] == "done"
    assert _parsed(entry["ended_at"]) >= _parsed(entry["started_at"])


def test_finish_blocked_also_stamps_ended_at(tmp_path):
    """A blocked stage has ended, and the operator must see when."""
    root = timestamped_run(tmp_path)
    cs.start_stage(root, "claims_b3c")
    cs.finish_stage(root, "claims_b3c", "blocked", "evidence unavailable")
    entry = read_manifest(root)["stages"]["claims_b3c"]
    assert entry["status"] == "blocked"
    assert entry["reason"] == "evidence unavailable"
    assert _parsed(entry["ended_at"]) >= _parsed(entry["started_at"])


def test_demote_clears_both_times(tmp_path):
    root = timestamped_run(tmp_path)
    cs.start_stage(root, "claims_b3c")
    cs.finish_stage(root, "claims_b3c", "done")
    cs.demote_stage(root, "claims_b3c", "artifact vanished")
    entry = read_manifest(root)["stages"]["claims_b3c"]
    assert entry["status"] == "pending"
    assert "started_at" not in entry and "ended_at" not in entry


def test_retry_overwrites_in_place_leaving_exactly_one_pair(tmp_path):
    """blocked -> running -> done leaves one fresh pair, not a history."""
    root = timestamped_run(tmp_path)
    cs.start_stage(root, "claims_b3c")
    cs.finish_stage(root, "claims_b3c", "blocked", "first attempt failed")
    first = read_manifest(root)["stages"]["claims_b3c"]
    cs.start_stage(root, "claims_b3c")
    running = read_manifest(root)["stages"]["claims_b3c"]
    # The retry's fresh start clears the stale end rather than carrying it.
    assert "ended_at" not in running
    assert _parsed(running["started_at"]) >= _parsed(first["started_at"])
    cs.finish_stage(root, "claims_b3c", "done")
    final = read_manifest(root)["stages"]["claims_b3c"]
    assert [key for key in final if key.endswith("_at")] == [
        "started_at", "ended_at"]
    assert final["retries"] == 1


def test_legacy_running_entry_finishes_without_synthesizing_a_start(tmp_path):
    """The #30 legacy exception: no code path invents a time it did not see."""
    root = timestamped_run(tmp_path)
    cs.start_stage(root, "claims_b3c")
    manifest = read_manifest(root)
    manifest["stages"]["claims_b3c"].pop("started_at")
    write_manifest(root, manifest)
    cs.finish_stage(root, "claims_b3c", "done")
    entry = read_manifest(root)["stages"]["claims_b3c"]
    assert entry["status"] == "done"
    assert "started_at" not in entry
    assert _parsed(entry["ended_at"]).tzinfo is not None


def test_readers_tolerate_absent_timestamps_everywhere(tmp_path):
    """resume-check / verify-run / demote never read a time field."""
    root = timestamped_run(tmp_path)
    cs.start_stage(root, "claims_b3c")
    cs.finish_stage(root, "claims_b3c", "done")
    manifest = read_manifest(root)
    manifest["stages"]["claims_b3c"].pop("started_at")
    manifest["stages"]["claims_b3c"].pop("ended_at")
    write_manifest(root, manifest)
    cs.verify_run(root)
    cs.resume_check(root, clear_stale_marker=True)
    cs.demote_stage(root, "claims_b3c", "stale after the pause")
    assert read_manifest(root)["stages"]["claims_b3c"]["status"] == "pending"


def test_timestamp_encoding_equals_the_marker_helper(tmp_path):
    """One time convention: the marker's exact call, factored not duplicated."""
    root = timestamped_run(tmp_path)
    cs.replace_running_marker(root, clear_stale=True)
    marker_started = (root / "audit" / "_run" / "RUNNING").read_text(
        encoding="utf-8").splitlines()[0].split("=", 1)[1]
    cs.start_stage(root, "claims_b3c")
    entry_started = read_manifest(root)["stages"]["claims_b3c"]["started_at"]
    for value in (marker_started, entry_started):
        parsed = datetime.fromisoformat(value)
        assert parsed.tzinfo is not None
        assert parsed.utcoffset() == timedelta(0)
    assert len(marker_started.split("+")[0]) == len(entry_started.split("+")[0])


def _parsed(value):
    return datetime.fromisoformat(value)


def test_no_timestamp_reaches_the_stage_state_machine(tmp_path):
    """The times ride on the existing transitions; they add none."""
    root = timestamped_run(tmp_path)
    with pytest.raises(cs.CertificationError, match="done -> pending"):
        cs.demote_stage(root, "claims_b3c")
    cs.start_stage(root, "claims_b3c")
    with pytest.raises(cs.CertificationError, match="pending -> running"):
        cs.start_stage(root, "claims_b3c")


# ============================ Tier 1 (a) — the PID-liveness marker check
#
# Test 1 — fires.


def test_t1a_live_foreign_pid_refuses_resume_check_even_with_the_flag(
        tmp_path, live_pid):
    root = certified_run(tmp_path)
    pid = live_pid()
    plant_marker(root, pid)
    result = certify_cli(root, "resume-check", "--clear-stale-marker")
    assert result.returncode != 0
    assert "CERTIFICATION REFUSED" in result.stderr
    assert str(pid) in result.stderr
    assert "continue that session in its own window" in result.stderr
    assert "terminate that process first" in result.stderr


def test_t1a_a_second_conductors_own_pid_does_not_unlock_a_live_marker(
        tmp_path, live_pid):
    """Self-ownership must not become a way past the concurrency marker.

    The accidental second launch resolves *its own* conductor PID, which is not
    the one the marker records — so the refusal stands.  Only a caller naming
    the live conductor's PID gets through, and that is deliberate evasion, not
    the accident this marker defends against.
    """
    root = certified_run(tmp_path)
    recorded = live_pid()
    plant_marker(root, recorded)
    other = live_pid()
    assert other != recorded
    result = certify_cli(
        root, "resume-check", "--clear-stale-marker",
        "--conductor-pid", str(other))
    assert result.returncode != 0
    assert "CERTIFICATION REFUSED" in result.stderr
    assert str(recorded) in result.stderr


def test_t1a_live_foreign_pid_refuses_init_second_launch(tmp_path, live_pid):
    root = certified_run(tmp_path)
    pid = live_pid()
    plant_marker(root, pid)
    result = certify_cli(root, "init", "--clear-stale-marker")
    assert result.returncode != 0
    assert str(pid) in result.stderr


def test_t1a_live_foreign_pid_refuses_the_launcher_with_no_relaunch(
        tmp_path, live_pid):
    root = certified_run(tmp_path)
    pid = live_pid()
    plant_marker(root, pid)
    result = launcher(root, "--print-only", "--yes")
    assert result.returncode != 0
    assert "RESUME REFUSED" in result.stderr
    assert str(pid) in result.stderr
    assert "RESUME COMMAND" not in result.stdout


def test_t1a_init_cli_threads_conductor_pid_into_the_marker(tmp_path):
    """Review F4: assert the CLI-to-marker wiring on the file itself."""
    root = buoy_package(tmp_path)
    assert certify_cli(root, "init", "--conductor-pid", "424242").returncode == 0
    marker = (root / "audit" / "_run" / "RUNNING").read_text(encoding="utf-8")
    assert "pid=424242\n" in marker
    assert cs.marker_pid(marker) == 424242


def test_t1a_resume_check_cli_threads_conductor_pid_into_the_marker(tmp_path):
    root = certified_run(tmp_path)
    result = certify_cli(root, "resume-check", "--clear-stale-marker",
                         "--conductor-pid", "515151")
    assert result.returncode == 0, result.stderr
    marker = (root / "audit" / "_run" / "RUNNING").read_text(encoding="utf-8")
    assert "pid=515151\n" in marker


# Test 2 — stays quiet.


def test_t2a_dead_pid_marker_plus_flag_clears_and_proceeds(tmp_path):
    root = certified_run(tmp_path)
    plant_marker(root, dead_pid())
    result = certify_cli(root, "resume-check", "--clear-stale-marker")
    assert result.returncode == 0, result.stderr


def test_t2a_legacy_marker_without_a_pid_line_plus_flag_clears(tmp_path):
    root = certified_run(tmp_path)
    plant_marker(root, None)
    assert certify_cli(
        root, "resume-check", "--clear-stale-marker").returncode == 0


def test_t2a_unparseable_marker_pid_still_needs_the_flag(tmp_path):
    root = certified_run(tmp_path)
    marker = root / "audit" / "_run" / "RUNNING"
    marker.write_text("started_at=whenever\npid=not-a-number\n", encoding="utf-8")
    assert cs.marker_pid(marker.read_text(encoding="utf-8")) is None
    refused = certify_cli(root, "resume-check")
    assert refused.returncode != 0
    assert "--clear-stale-marker" in refused.stderr
    assert certify_cli(
        root, "resume-check", "--clear-stale-marker").returncode == 0


def test_t2a_out_of_range_marker_pid_is_dead_not_a_traceback(tmp_path):
    """Review F3: `os.kill` raises OverflowError past `pid_t`, not OSError.

    A garbled marker — or a best-effort ancestry walk that yielded nonsense —
    must never brick every later command on the run; design call 3 says PID
    resolution failure can never block a run.
    """
    root = certified_run(tmp_path)
    marker = root / "audit" / "_run" / "RUNNING"
    marker.write_text(
        "started_at=whenever\npid=999999999999999\n", encoding="utf-8")
    assert cs.pid_is_alive(999999999999999) is False
    refused = certify_cli(root, "resume-check")
    assert refused.returncode != 0
    assert "--clear-stale-marker" in refused.stderr
    assert "Traceback" not in refused.stderr
    cleared = certify_cli(root, "resume-check", "--clear-stale-marker")
    assert cleared.returncode == 0, cleared.stderr


def test_t2a_self_owned_marker_is_replaceable(tmp_path):
    """Review F1: two consecutive own-PID resume-checks both succeed.

    A marker naming the calling process cannot be a second process, so the
    guarded loop never deadlocks on the marker its own previous pass wrote.
    """
    root = certified_run(tmp_path)
    cs.resume_check(root, clear_stale_marker=True, conductor_pid=os.getpid())
    marker = (root / "audit" / "_run" / "RUNNING").read_text(encoding="utf-8")
    assert cs.marker_pid(marker) == os.getpid()
    assert cs.pid_is_alive(os.getpid())
    cs.resume_check(root, clear_stale_marker=True, conductor_pid=os.getpid())
    assert cs.marker_pid(
        (root / "audit" / "_run" / "RUNNING").read_text(encoding="utf-8")
    ) == os.getpid()


def test_t2a_self_owned_marker_is_replaceable_through_the_cli(tmp_path):
    """The same leg through the production CLI, where `os.getpid()` differs.

    Run as a subprocess, `certify_stage.py`'s own PID is the short-lived
    certify process, never the conductor — so self-ownership has to key on the
    passed-in conductor PID, not on `os.getpid()`.  Without that, the second
    pass of the manual resume loop SKILL.md documents ("rerun `resume-check`
    until all remaining recorded passes verify") refuses with a message saying
    `--clear-stale-marker` cannot override, stranding the run.
    """
    root = certified_run(tmp_path)
    live_pid = os.getpid()  # this test process: recorded, foreign to the CLI, alive
    first = certify_cli(
        root, "resume-check", "--clear-stale-marker",
        "--conductor-pid", str(live_pid))
    assert first.returncode == 0, first.stderr
    marker = root / "audit" / "_run" / "RUNNING"
    assert cs.marker_pid(marker.read_text(encoding="utf-8")) == live_pid
    second = certify_cli(
        root, "resume-check", "--clear-stale-marker",
        "--conductor-pid", str(live_pid))
    assert second.returncode == 0, second.stderr
    assert cs.marker_pid(marker.read_text(encoding="utf-8")) == live_pid


def test_t2a_no_marker_at_all_lets_the_launcher_proceed(tmp_path):
    root = certified_run(tmp_path)
    (root / "audit" / "_run" / "RUNNING").unlink()
    result = launcher(root, "--print-only", "--yes")
    assert result.returncode == 0, result.stderr
    assert "RESUME COMMAND" in result.stdout


def test_t2a_permission_error_counts_as_alive(tmp_path, monkeypatch):
    """A live process owned by another user is live."""
    def refuse(pid, signal):
        raise PermissionError(pid)

    monkeypatch.setattr(cs.os, "kill", refuse)
    assert cs.pid_is_alive(4321) is True


# ============ Tier 1 (b) — relaunch only after a clean resume-check loop
#
# Test 1 — fires.


def test_t1b_corrupted_claimed_artifact_is_demoted_before_any_relaunch(tmp_path):
    root = certified_run(tmp_path)
    plant_marker(root, dead_pid())
    (root / "audit" / "_run" / "conventions.md").unlink()
    result = launcher(root, "--print-only", "--yes")
    assert result.returncode == 0, result.stderr
    entry = read_manifest(root)["stages"]["claims_b3c"]
    assert entry["status"] == "pending"
    assert "conventions.md" in entry["note"]
    assert "demoted stage 'claims_b3c'" in result.stdout
    # The relaunch command is emitted only after the demotion.
    assert result.stdout.index("demoted stage") < result.stdout.index(
        "RESUME COMMAND")
    assert not list((root / "audit" / "_staging").iterdir())
    assert "discarded stale staging file(s): claims_register.md" in result.stdout


def test_t1b_hand_flipped_done_is_demoted_never_trusted(tmp_path):
    """The run-seven sabotage: status edited without evidence."""
    root = certified_run(tmp_path)
    plant_marker(root, dead_pid())
    manifest = read_manifest(root)
    manifest["stages"]["code_b3"]["status"] = "done"
    write_manifest(root, manifest)
    result = launcher(root, "--print-only", "--yes")
    assert result.returncode == 0, result.stderr
    entry = read_manifest(root)["stages"]["code_b3"]
    assert entry["status"] == "pending"
    assert "code_error_register.md" in entry["note"]
    assert "RESUME COMMAND" in result.stdout


def test_t1b_edited_tree_refuses_and_never_prints_a_relaunch(tmp_path):
    root = certified_run(tmp_path)
    plant_marker(root, dead_pid())
    (root / "code" / "log_buoy_readings.py").write_text(
        BUOY_SOURCE + "\nEXTRA = 1\n", encoding="utf-8")
    result = launcher(root, "--print-only", "--yes")
    assert result.returncode != 0
    assert "audited tree changed across the pause" in result.stderr
    assert "non-demotable" in result.stderr
    assert "RESUME COMMAND" not in result.stdout
    # An identity failure is never demoted around.
    assert read_manifest(root)["stages"]["claims_b3c"]["status"] == "done"


def test_t1b_missing_session_id_everywhere_refuses_with_the_manual_route(
        tmp_path):
    root = certified_run(tmp_path, with_usage=False)
    plant_marker(root, dead_pid())
    assert read_manifest(root)["run_identity"]["session_id"] is None
    result = launcher(root, "--print-only", "--yes")
    assert result.returncode != 0
    assert "no session ID is recorded anywhere" in result.stderr
    assert "claude --resume" in result.stderr
    assert "--conductor-pid" in result.stderr
    assert "take marker ownership" in result.stderr
    assert "RESUME COMMAND" not in result.stdout


# Test 2 — stays quiet.


def test_t2b_healthy_run_makes_one_clean_pass_and_relaunches(tmp_path):
    root = certified_run(tmp_path)
    plant_marker(root, dead_pid())
    staging_before = sorted(
        path.name for path in (root / "audit" / "_staging").iterdir())
    result = launcher(root, "--print-only", "--yes")
    assert result.returncode == 0, result.stderr
    assert "demotions this recovery: 0" in result.stdout
    assert "demoted stage" not in result.stdout
    assert "discarded stale staging" not in result.stdout
    assert sorted(
        path.name for path in (root / "audit" / "_staging").iterdir()
    ) == staging_before
    assert f"RESUME COMMAND: claude --resume {SESSION_ID}" in result.stdout
    assert "from audit/_run/usage.json" in result.stdout
    assert read_manifest(root)["stages"]["claims_b3c"]["status"] == "done"


def test_t2b_session_id_falls_back_to_run_identity(tmp_path):
    """Design call 6's source order: usage.json first, then the init record."""
    root = buoy_package(tmp_path)
    write_usage(root, {**USAGE_SNAPSHOT, "session_id": FALLBACK_SESSION_ID})
    assert certify_tests.cli(root, "init").returncode == 0
    assert read_manifest(root)["run_identity"]["session_id"] == FALLBACK_SESSION_ID
    # The freshest source loses its value; the recorded one still answers.
    write_usage(root, {**USAGE_SNAPSHOT, "session_id": None})
    plant_marker(root, dead_pid())
    result = launcher(root, "--print-only", "--yes")
    assert result.returncode == 0, result.stderr
    assert f"RESUME COMMAND: claude --resume {FALLBACK_SESSION_ID}" in result.stdout
    assert "from manifest run_identity.session_id" in result.stdout


def test_t2b_expired_usage_snapshot_raises_no_confirmation(tmp_path):
    """A reset that already happened is never grounds for a prompt."""
    root = certified_run(tmp_path)
    plant_marker(root, dead_pid())
    # No --yes, no stdin: an expired snapshot must not reach the prompt at all.
    result = launcher(root, "--print-only")
    assert result.returncode == 0, result.stderr
    assert "usage limit not reset yet" not in result.stdout
    assert "RESUME COMMAND" in result.stdout


# Test 3 — test of the test.  Four legs, on a copy.


def neutered_scripts(tmp_path, filename, anchor, insertion):
    """Copy ``scripts/`` and insert one redefinition before *anchor*."""
    destination = tmp_path / "neutered_scripts"
    shutil.copytree(
        rb.SCRIPTS_DIR, destination,
        ignore=shutil.ignore_patterns("tests", "__pycache__"))
    path = destination / filename
    text = path.read_text(encoding="utf-8")
    assert text.count(anchor) == 1, f"anchor is not unique in {filename}"
    path.write_text(text.replace(anchor, insertion + anchor, 1), encoding="utf-8")
    return destination


MARKER_ANCHOR = "def replace_running_marker(package_root, clear_stale=False"
LOOP_ANCHOR = "def resolve_session_id(package_root):"


def test_t3_leg1_neutering_the_liveness_check_breaks_the_live_pid_refusal(
        tmp_path, live_pid):
    """Predicate: ``certify_stage.pid_is_alive``.

    Canonical assertion it must break:
    ``test_t1a_live_foreign_pid_refuses_resume_check_even_with_the_flag``.
    """
    root = certified_run(tmp_path)
    pid = live_pid()
    plant_marker(root, pid)
    scripts = neutered_scripts(
        tmp_path, "certify_stage.py", MARKER_ANCHOR,
        "def pid_is_alive(pid):\n    return False\n\n\n")
    result = certify_cli(root, "resume-check", "--clear-stale-marker",
                         scripts_dir=scripts)
    assert result.returncode == 0
    assert str(pid) not in result.stderr


def test_t3_leg2_neutering_the_loops_reverification_breaks_the_demotion(
        tmp_path):
    """Predicate: ``resume_run.clean_loop`` (skips ``resume_check`` entirely).

    Canonical assertions it must break:
    ``test_t1b_corrupted_claimed_artifact_is_demoted_before_any_relaunch`` and
    ``test_t1b_hand_flipped_done_is_demoted_never_trusted``.
    """
    root = certified_run(tmp_path)
    plant_marker(root, dead_pid())
    (root / "audit" / "_run" / "conventions.md").unlink()
    manifest = read_manifest(root)
    manifest["stages"]["code_b3"]["status"] = "done"
    write_manifest(root, manifest)
    scripts = neutered_scripts(
        tmp_path, "resume_run.py", LOOP_ANCHOR,
        "def clean_loop(package_root, out):\n"
        "    return 'neutered', []\n\n\n")
    result = launcher(root, "--print-only", "--yes", scripts_dir=scripts)
    assert result.returncode == 0
    stages = read_manifest(root)["stages"]
    assert stages["claims_b3c"]["status"] == "done"
    assert stages["code_b3"]["status"] == "done"
    assert "demoted stage" not in result.stdout
    assert "RESUME COMMAND" in result.stdout


def test_t3_leg3_neutering_the_relaunch_guard_breaks_the_no_relaunch_rule(
        tmp_path):
    """Predicate: the guard that only a clean ``clean_loop`` reaches relaunch.

    Canonical assertion it must break:
    ``test_t1b_edited_tree_refuses_and_never_prints_a_relaunch``.
    """
    root = certified_run(tmp_path)
    plant_marker(root, dead_pid())
    (root / "code" / "log_buoy_readings.py").write_text(
        BUOY_SOURCE + "\nEXTRA = 1\n", encoding="utf-8")
    scripts = neutered_scripts(
        tmp_path, "resume_run.py", LOOP_ANCHOR,
        "_guarded_clean_loop = clean_loop\n\n\n"
        "def clean_loop(package_root, out):\n"
        "    try:\n"
        "        return _guarded_clean_loop(package_root, out)\n"
        "    except (LauncherRefusal, certify_stage.CertificationError):\n"
        "        return 'neutered', []\n\n\n")
    result = launcher(root, "--print-only", "--yes", scripts_dir=scripts)
    assert result.returncode == 0
    assert "RESUME COMMAND" in result.stdout


def test_t3_leg4_dropping_the_pid_threading_breaks_the_wiring_assertions(
        tmp_path):
    """Predicate: ``certify_stage._marker_text``'s ``conductor_pid`` threading.

    Canonical assertions it must break:
    ``test_t1a_init_cli_threads_conductor_pid_into_the_marker`` and
    ``test_t1a_resume_check_cli_threads_conductor_pid_into_the_marker``.
    """
    root = buoy_package(tmp_path)
    scripts = neutered_scripts(
        tmp_path, "certify_stage.py", MARKER_ANCHOR,
        "def _marker_text(conductor_pid=None):\n"
        "    return f'started_at={_utc_now_iso()}\\n'\n\n\n")
    result = certify_cli(root, "init", "--conductor-pid", "424242",
                         scripts_dir=scripts)
    assert result.returncode == 0, result.stderr
    marker = (root / "audit" / "_run" / "RUNNING").read_text(encoding="utf-8")
    assert "pid=424242" not in marker
    assert cs.marker_pid(marker) is None


# ------------------------------------------ production-CLI sabotage drills


def test_drill_i_live_marker_refuses_then_proceeds_once_the_process_dies(
        tmp_path):
    """#28's named drill, both directions asserted through the real launcher."""
    root = certified_run(tmp_path)
    process = subprocess.Popen(["sleep", "60"])
    try:
        plant_marker(root, process.pid)
        refused = launcher(root, "--print-only", "--yes")
        assert refused.returncode != 0
        assert str(process.pid) in refused.stderr
        assert "RESUME COMMAND" not in refused.stdout
    finally:
        process.kill()
        process.wait()
    proceeds = launcher(root, "--print-only", "--yes")
    assert proceeds.returncode == 0, proceeds.stderr
    assert "RESUME COMMAND" in proceeds.stdout


def test_drill_ii_restart_demotes_a_corrupted_pass_then_a_hand_flip(tmp_path):
    """#28's named drill: the restart demotes; it never trusts."""
    root = certified_run(tmp_path)
    plant_marker(root, dead_pid())
    conventions = root / "audit" / "_run" / "conventions.md"
    conventions.unlink()
    first = launcher(root, "--print-only", "--yes")
    assert first.returncode == 0, first.stderr
    assert read_manifest(root)["stages"]["claims_b3c"]["status"] == "pending"
    assert first.stdout.index("demoted stage") < first.stdout.index(
        "RESUME COMMAND")

    # Re-certify, re-corrupt, and hand-flip a second stage on top.
    assert certify_tests.cli(root, "start", "--stage", "claims_b3c").returncode == 0
    conventions.write_text("# Shared conventions\n", encoding="utf-8")
    assert certify_tests.cli(
        root, "finish", "--stage", "claims_b3c", "--outcome", "done"
    ).returncode == 0
    conventions.unlink()
    manifest = read_manifest(root)
    manifest["stages"]["code_b3"]["status"] = "done"
    write_manifest(root, manifest)
    plant_marker(root, dead_pid())
    second = launcher(root, "--print-only", "--yes")
    assert second.returncode == 0, second.stderr
    stages = read_manifest(root)["stages"]
    assert stages["claims_b3c"]["status"] == "pending"
    assert stages["code_b3"]["status"] == "pending"
    assert "RESUME COMMAND" in second.stdout


def test_drill_iii_certification_cli_refuses_the_live_marker_on_its_own(
        tmp_path, live_pid):
    """The Tier-1 member exercised through the certification CLI itself."""
    root = certified_run(tmp_path)
    pid = live_pid()
    plant_marker(root, pid)
    manifest_before = (root / "audit" / "_run" / "manifest.json").read_bytes()
    result = certify_cli(root, "resume-check", "--clear-stale-marker")
    assert result.returncode != 0
    assert "CERTIFICATION REFUSED" in result.stderr
    assert str(pid) in result.stderr
    assert (root / "audit" / "_run" / "manifest.json").read_bytes() == manifest_before
    assert cs.marker_pid(
        (root / "audit" / "_run" / "RUNNING").read_text(encoding="utf-8")) == pid


# ================================================ Tier 2 — the feed script


def test_feed_writes_the_snapshot_with_both_windows(tmp_path):
    root = buoy_package(tmp_path)
    result = run_statusline(statusline_payload(root))
    assert result.returncode == 0
    snapshot = json.loads(
        (root / "audit" / "_run" / "usage.json").read_text(encoding="utf-8"))
    assert snapshot["session_id"] == SESSION_ID
    assert snapshot["rate_limits"] == USAGE_SNAPSHOT["rate_limits"]
    assert datetime.fromisoformat(snapshot["written_at"]).tzinfo is not None


def test_feed_merge_keeps_an_omitted_windows_last_known_value(tmp_path):
    root = buoy_package(tmp_path)
    assert run_statusline(statusline_payload(root)).returncode == 0
    only_five_hour = {"five_hour": {"used_percentage": 12.0,
                                    "resets_at": "2026-08-06T19:00:00+00:00"}}
    assert run_statusline(
        statusline_payload(root, rate_limits=only_five_hour)).returncode == 0
    snapshot = json.loads(
        (root / "audit" / "_run" / "usage.json").read_text(encoding="utf-8"))
    assert snapshot["rate_limits"]["five_hour"] == only_five_hour["five_hour"]
    assert snapshot["rate_limits"]["seven_day"] == (
        USAGE_SNAPSHOT["rate_limits"]["seven_day"])


def test_feed_refreshes_session_id_and_written_at_every_update(tmp_path):
    root = buoy_package(tmp_path)
    assert run_statusline(statusline_payload(root)).returncode == 0
    path = root / "audit" / "_run" / "usage.json"
    first = json.loads(path.read_text(encoding="utf-8"))
    assert run_statusline(
        statusline_payload(root, session_id="c0ffee-second-conversation")
    ).returncode == 0
    second = json.loads(path.read_text(encoding="utf-8"))
    assert second["session_id"] == "c0ffee-second-conversation"
    assert second["written_at"] >= first["written_at"]


def test_feed_leaves_no_partial_file_behind(tmp_path):
    root = buoy_package(tmp_path)
    assert run_statusline(statusline_payload(root)).returncode == 0
    run_dir = root / "audit" / "_run"
    assert [path.name for path in run_dir.iterdir()
            if path.name.startswith(".usage.")] == []
    json.loads((run_dir / "usage.json").read_text(encoding="utf-8"))


def test_feed_skips_a_workspace_with_no_audit_run(tmp_path):
    """Safe to configure globally: no audit dir, no write, exit 0."""
    elsewhere = tmp_path / "unrelated"
    elsewhere.mkdir()
    result = run_statusline(statusline_payload(elsewhere))
    assert result.returncode == 0
    assert result.stdout.strip()
    assert not (elsewhere / "audit").exists()


def test_feed_survives_malformed_stdin_without_writing(tmp_path):
    root = buoy_package(tmp_path)
    result = run_statusline(None, stdin="not json {")
    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout.strip()
    assert not (root / "audit" / "_run" / "usage.json").exists()


def test_feed_survives_an_unwritable_target(tmp_path, monkeypatch, capsys):
    """An unwritable target degrades the pause layer, never the statusline."""
    root = buoy_package(tmp_path)

    def explode(*args, **kwargs):
        raise OSError("read-only file system")

    monkeypatch.setattr(statusline, "write_snapshot_atomic", explode)
    # The unit itself does raise; ``main`` is what must swallow it.
    with pytest.raises(OSError):
        statusline.update_usage_file(statusline_payload(root))
    monkeypatch.setattr(
        statusline.sys, "stdin",
        io.StringIO(json.dumps(statusline_payload(root))))
    assert statusline.main() == 0
    assert capsys.readouterr().out.strip()
    assert not (root / "audit" / "_run" / "usage.json").exists()


def test_feed_passthrough_names_the_model_and_the_higher_percentage(tmp_path):
    root = buoy_package(tmp_path)
    result = run_statusline(statusline_payload(root))
    assert "Buoy Model" in result.stdout
    assert "94%" in result.stdout


def test_feed_never_filters_expired_snapshots(tmp_path):
    """Expiry is the consumer's job; the feed records what it was told."""
    root = buoy_package(tmp_path)
    assert run_statusline(statusline_payload(root)).returncode == 0
    snapshot = json.loads(
        (root / "audit" / "_run" / "usage.json").read_text(encoding="utf-8"))
    assert snapshot["rate_limits"]["five_hour"]["resets_at"] == (
        "2026-08-06T14:30:00+00:00")


def test_feed_workspace_falls_back_to_the_top_level_cwd(tmp_path):
    root = buoy_package(tmp_path)
    payload = statusline_payload(root)
    payload.pop("workspace")
    assert run_statusline(payload).returncode == 0
    assert (root / "audit" / "_run" / "usage.json").is_file()


# ============================================== Tier 2 — the session ID key


def test_run_identity_records_the_session_id_when_usage_is_readable(tmp_path):
    root = buoy_package(tmp_path)
    write_usage(root)
    cs.init_run(root)
    assert read_manifest(root)["run_identity"]["session_id"] == SESSION_ID


def test_run_identity_records_null_without_a_usage_snapshot(tmp_path):
    root = buoy_package(tmp_path)
    cs.init_run(root)
    assert read_manifest(root)["run_identity"]["session_id"] is None


def test_session_id_is_never_an_identity_failure_input(tmp_path):
    """A renumbered conversation is not an identity change."""
    root = buoy_package(tmp_path)
    write_usage(root)
    cs.init_run(root)
    manifest = read_manifest(root)
    manifest["run_identity"]["session_id"] = "an-entirely-different-conversation"
    write_manifest(root, manifest)
    assert cs._identity_failures(root, read_manifest(root), True) == []
    cs.verify_run(root)


def test_run_identity_tolerates_a_malformed_usage_snapshot(tmp_path):
    root = buoy_package(tmp_path)
    (root / "audit" / "_run" / "usage.json").write_text(
        "not json {", encoding="utf-8")
    cs.init_run(root)
    assert read_manifest(root)["run_identity"]["session_id"] is None


# ========================================= Tier 2 — the launcher small parts


def test_reset_gate_fires_only_on_a_non_expired_at_threshold_window(tmp_path):
    root = buoy_package(tmp_path)
    write_usage(root)
    fresh = cs.read_usage_snapshot(root)
    assert [window for window, _used, _resets
            in rr.at_threshold_windows(fresh, FROZEN_NOW)] == ["five_hour"]
    # The same snapshot read after both resets is expired: no hold, no prompt.
    later = FROZEN_NOW + timedelta(days=7)
    assert rr.at_threshold_windows(fresh, later) == []


def test_reset_gate_ignores_a_window_below_the_threshold(tmp_path):
    snapshot = {"rate_limits": {"five_hour": {
        "used_percentage": 89.9, "resets_at": "2026-08-06T14:30:00+00:00"}}}
    assert rr.at_threshold_windows(snapshot, FROZEN_NOW) == []


def test_reset_gate_ignores_unparseable_and_missing_fields(tmp_path):
    snapshot = {"rate_limits": {
        "five_hour": {"used_percentage": 99.0, "resets_at": "never"},
        "seven_day": {"used_percentage": 99.0},
    }}
    assert rr.at_threshold_windows(snapshot, FROZEN_NOW) == []
    assert rr.at_threshold_windows({"rate_limits": "nonsense"}, FROZEN_NOW) == []


def test_reset_gate_prompt_refuses_on_a_declined_confirmation(tmp_path):
    root = certified_run(tmp_path)
    write_usage(root, live_window_snapshot())
    out = _Capture()
    with pytest.raises(rr.LauncherRefusal, match="has not reset yet"):
        rr.reset_time_gate(root, False, out, prompt=lambda _text: "n")
    assert "usage limit not reset yet" in out.text()


def test_reset_gate_prompt_accepts_an_explicit_yes(tmp_path):
    root = certified_run(tmp_path)
    write_usage(root, live_window_snapshot())
    out = _Capture()
    assert rr.reset_time_gate(root, False, out, prompt=lambda _text: "y") is True


def test_yes_bypasses_the_confirmation_end_to_end(tmp_path):
    root = certified_run(tmp_path)
    write_usage(root, live_window_snapshot())
    plant_marker(root, dead_pid())
    result = launcher(root, "--print-only", "--yes")
    assert result.returncode == 0, result.stderr
    assert "usage limit not reset yet" in result.stdout
    assert "--yes given" in result.stdout
    assert "RESUME COMMAND" in result.stdout


def test_a_declined_confirmation_stops_the_real_launcher(tmp_path):
    root = certified_run(tmp_path)
    write_usage(root, live_window_snapshot())
    plant_marker(root, dead_pid())
    result = launcher(root, "--print-only", stdin="n\n")
    assert result.returncode != 0
    assert "has not reset yet" in result.stderr
    assert "RESUME COMMAND" not in result.stdout
    # Nothing was demoted: the gate is before the loop.
    assert read_manifest(root)["stages"]["claims_b3c"]["status"] == "done"


def test_staging_discard_refuses_while_the_frozen_b8_state_stands(tmp_path):
    """Design call 7's tail state: one loud manual step beats losing b8."""
    root = certified_run(tmp_path)
    manifest = read_manifest(root)
    manifest["stages"]["b8"]["status"] = "done"
    write_manifest(root, manifest)
    out = _Capture()
    with pytest.raises(rr.LauncherRefusal, match="frozen b8 registers"):
        rr.discard_staging(root, out)
    assert [path.name for path in (root / "audit" / "_staging").iterdir()] == [
        "claims_register.md"]


def test_staging_discard_removes_files_and_directories(tmp_path):
    root = certified_run(tmp_path)
    nested = root / "audit" / "_staging" / "snapshots"
    nested.mkdir()
    (nested / "frozen.md").write_text("# nested\n", encoding="utf-8")
    out = _Capture()
    assert sorted(rr.discard_staging(root, out)) == [
        "claims_register.md", "snapshots"]
    assert not list((root / "audit" / "_staging").iterdir())


def test_classify_failures_separates_stale_passes_from_terminal_ones():
    stale, terminal = rr.classify_failures(
        ["audited tree changed across the pause (…); only path forward"],
        ["run is missing certified stage-era evidence version 1",
         "stage 'code_b3': artifact:code_error_register.md matched nothing",
         "stage 'code_b3': validate:lint:b3-code exited 1"],
    )
    assert set(stale) == {"code_b3"}
    assert len(stale["code_b3"]) == 2
    assert len(terminal) == 2


def test_launcher_refuses_a_run_level_evidence_failure_without_demoting(
        tmp_path):
    """A run-level failure names no demotable pass: terminal, not a loop."""
    root = certified_run(tmp_path)
    plant_marker(root, dead_pid())
    manifest = read_manifest(root)
    manifest.pop("certified_stage_evidence_version")
    write_manifest(root, manifest)
    result = launcher(root, "--print-only", "--yes")
    assert result.returncode != 0
    assert "non-demotable" in result.stderr
    assert "certified stage-era evidence version" in result.stderr
    assert "RESUME COMMAND" not in result.stdout
    assert read_manifest(root)["stages"]["claims_b3c"]["status"] == "done"


def test_launcher_marker_after_a_clean_pass_names_the_launcher_pid(tmp_path):
    """Review F2: os.exec* preserves the PID, so the marker stays correct."""
    root = certified_run(tmp_path)
    plant_marker(root, dead_pid())
    out = _Capture()
    args = rr.build_parser().parse_args(
        ["--package-root", str(root), "--print-only", "--yes"])
    assert rr.run(args, out=out, prompt=lambda _text: "y") == 0
    marker = (root / "audit" / "_run" / "RUNNING").read_text(encoding="utf-8")
    assert cs.marker_pid(marker) == os.getpid()


class _Capture:
    """A minimal stdout stand-in for the in-process launcher unit tests."""

    def __init__(self):
        self.lines = []

    def write(self, value):
        self.lines.append(value)

    def flush(self):
        pass

    def text(self):
        return "".join(self.lines)
