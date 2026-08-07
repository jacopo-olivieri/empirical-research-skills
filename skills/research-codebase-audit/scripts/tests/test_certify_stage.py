"""Unit U2 tests for the descoped stage-certification core."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import regbuild as rb

cs = rb.load_script("certify_stage")

pytestmark = pytest.mark.u2

CERTIFY = rb.SCRIPTS_DIR / "certify_stage.py"


def write_intake(root, mode="replication", **extra):
    root = Path(root)
    (root / "audit" / "_run").mkdir(parents=True, exist_ok=True)
    manifest = {
        "mode": mode,
        "ladder_level": 1,
        "scope_exclusions": [],
        "off_limits": [],
        "known_context": "keep me",
        "effort_map": dict(cs.dispatch_tracking.DEFAULT_EFFORT_MAP),
    }
    manifest.update(extra)
    if manifest.get("mode") == "replication" and "paper_source_path" not in manifest:
        # U7a: replication init refuses paperless manifests unless they carry
        # the fixture/development discriminator.
        manifest.setdefault(
            "allocation_override", {"purpose": "development", "allocation": []})
    path = root / "audit" / "_run" / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path


def read_manifest(root):
    return json.loads(
        (Path(root) / "audit" / "_run" / "manifest.json").read_text(encoding="utf-8")
    )


def cli(root, command, *args):
    return subprocess.run(
        [sys.executable, str(CERTIFY), command, "--package-root", str(root), *args],
        capture_output=True,
        text=True,
    )


def simple_run(tmp_path, mode="replication"):
    root = tmp_path / "package"
    root.mkdir()
    (root / "source.py").write_text("VALUE = 1\n", encoding="utf-8")
    write_intake(root, mode=mode, output_prefs="preserve me too")
    cs.init_run(root)
    return root


def healthy_b0(tmp_path):
    audit = rb.make_b0(tmp_path)
    # U7a: paperless replication init needs the fixture/development discriminator.
    audit.write_manifest(
        allocation_override={"purpose": "development", "allocation": []})
    cs.init_run(audit.root)
    cs.start_stage(audit.root, "b0")
    return audit


# ------------------------------------------------------- identity and marker


def test_init_records_exact_identity_and_mode_stages(tmp_path):
    root = simple_run(tmp_path)
    manifest = read_manifest(root)
    assert set(manifest["run_identity"]) == {
        "git_commit",
        "canonical_package_root",
        "tree_fingerprint",
        "mechanism_schema_version",
        # U16: informational only; never an identity-failure input.
        "session_id",
    }
    assert manifest["run_identity"]["canonical_package_root"] == str(root.resolve())
    assert manifest["run_identity"]["mechanism_schema_version"] == "1.0.0"
    assert set(manifest["run_identity"]["tree_fingerprint"]) == {
        "aggregate_sha256", "file_count",
    }
    assert tuple(manifest["stages"]) == cs.FULL_STAGES
    assert all(entry == {"status": "pending", "retries": 0, "shards": {}}
               for entry in manifest["stages"].values())
    assert manifest["known_context"] == "keep me"
    assert manifest["output_prefs"] == "preserve me too"
    assert (root / "audit" / "_run" / "RUNNING").is_file()


def test_init_code_only_uses_descoped_stage_set(tmp_path):
    root = simple_run(tmp_path, mode="code_errors_only")
    assert tuple(read_manifest(root)["stages"]) == cs.CODE_ONLY_STAGES


def test_init_rejects_unknown_mode_without_manifest_write(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    path = write_intake(root, mode="wip")
    before = path.read_bytes()
    with pytest.raises(cs.CertificationError, match="manifest mode"):
        cs.init_run(root)
    assert path.read_bytes() == before


def test_second_init_requires_explicit_stale_marker_override(tmp_path):
    root = simple_run(tmp_path)
    with pytest.raises(cs.CertificationError, match="--clear-stale-marker"):
        cs.init_run(root)
    cs.init_run(root, clear_stale_marker=True)
    assert (root / "audit" / "_run" / "RUNNING").is_file()


def test_close_run_removes_marker_and_refuses_missing_marker(tmp_path):
    root = simple_run(tmp_path)
    cs.close_run(root)
    assert not (root / "audit" / "_run" / "RUNNING").exists()
    with pytest.raises(cs.CertificationError, match="does not exist"):
        cs.close_run(root)


def test_canonical_path_mismatch_refuses_later_writes(tmp_path):
    first = simple_run(tmp_path)
    second = tmp_path / "other"
    (second / "audit" / "_run").mkdir(parents=True)
    source_manifest = first / "audit" / "_run" / "manifest.json"
    target_manifest = second / "audit" / "_run" / "manifest.json"
    target_manifest.write_bytes(source_manifest.read_bytes())
    before = target_manifest.read_bytes()
    with pytest.raises(cs.CertificationError, match="canonical package root mismatch"):
        cs.start_stage(second, "b0")
    assert target_manifest.read_bytes() == before


# ------------------------------------------------------------ state machine


def test_start_and_blocked_retry_follow_legal_transitions(tmp_path):
    root = simple_run(tmp_path)
    cs.start_stage(root, "claims_b3c")
    assert read_manifest(root)["stages"]["claims_b3c"]["status"] == "running"
    cs.finish_stage(root, "claims_b3c", "blocked", " evidence unavailable ")
    blocked = read_manifest(root)["stages"]["claims_b3c"]
    assert blocked["status"] == "blocked"
    assert blocked["reason"] == "evidence unavailable"
    cs.start_stage(root, "claims_b3c")
    retried = read_manifest(root)["stages"]["claims_b3c"]
    assert retried["status"] == "running"
    assert retried["retries"] == 1
    assert "reason" not in retried


def test_start_refuses_illegal_transition(tmp_path):
    root = simple_run(tmp_path)
    cs.start_stage(root, "b0")
    before = (root / "audit" / "_run" / "manifest.json").read_bytes()
    with pytest.raises(cs.CertificationError, match="running.*pending -> running"):
        cs.start_stage(root, "b0")
    assert (root / "audit" / "_run" / "manifest.json").read_bytes() == before


def test_finish_blocked_requires_reason_and_preserves_manifest(tmp_path):
    root = simple_run(tmp_path)
    cs.start_stage(root, "claims_b3c")
    path = root / "audit" / "_run" / "manifest.json"
    before = path.read_bytes()
    with pytest.raises(cs.CertificationError, match="non-empty --reason"):
        cs.finish_stage(root, "claims_b3c", "blocked", "  ")
    assert path.read_bytes() == before


def test_demote_is_explicit_done_to_pending_with_note(tmp_path):
    root = simple_run(tmp_path)
    conventions = root / "audit" / "_run" / "conventions.md"
    conventions.write_text("# Shared conventions\n", encoding="utf-8")
    cs.start_stage(root, "claims_b3c")
    cs.finish_stage(root, "claims_b3c", "done")
    cs.demote_stage(root, "claims_b3c")
    entry = read_manifest(root)["stages"]["claims_b3c"]
    assert entry["status"] == "pending"
    assert entry["note"] == "demoted after failed verification"


def test_demote_refuses_non_done_stage(tmp_path):
    root = simple_run(tmp_path)
    with pytest.raises(cs.CertificationError, match="done -> pending"):
        cs.demote_stage(root, "b0")


def test_set_shard_done_requires_existing_nonempty_file(tmp_path):
    root = simple_run(tmp_path)
    cs.start_stage(root, "claims_b2")
    path = root / "audit" / "_run" / "manifest.json"
    before = path.read_bytes()
    with pytest.raises(cs.CertificationError, match="missing or empty"):
        cs.set_shard(root, "claims_b2", "audit/_work/w1.md", "done")
    assert path.read_bytes() == before
    shard = root / "audit" / "_work" / "w1.md"
    shard.parent.mkdir(parents=True)
    shard.write_text("# shard\n", encoding="utf-8")
    cs.set_shard(root, "claims_b2", "audit/_work/w1.md", "done")
    assert read_manifest(root)["stages"]["claims_b2"]["shards"][
        "audit/_work/w1.md"
    ]["status"] == "done"


def test_set_shard_blocked_requires_reason(tmp_path):
    root = simple_run(tmp_path)
    cs.start_stage(root, "code_b2")
    with pytest.raises(cs.CertificationError, match="blocked shard"):
        cs.set_shard(root, "code_b2", "audit/_code_errors/k1.md", "blocked")
    cs.set_shard(
        root, "code_b2", "audit/_code_errors/k1.md", "blocked", "worker failed twice"
    )
    entry = read_manifest(root)["stages"]["code_b2"]["shards"][
        "audit/_code_errors/k1.md"
    ]
    assert entry["reason"] == "worker failed twice"


# ---------------------------------------- Tier 1: certification refusal


def test_certification_refusal_bad_missing_artifact_is_read_only(tmp_path):
    audit = healthy_b0(tmp_path)
    audit.write("CODEMAP.md", "")
    path = audit.audit / "_run" / "manifest.json"
    before = path.read_bytes()
    with pytest.raises(cs.CertificationError, match=r"b0.*artifact:CODEMAP\.md"):
        cs.finish_stage(audit.root, "b0", "done")
    assert path.read_bytes() == before


def test_certification_refusal_good_artifact_and_validator_pass(tmp_path):
    audit = healthy_b0(tmp_path)
    cs.finish_stage(audit.root, "b0", "done")
    assert read_manifest(audit.root)["stages"]["b0"]["status"] == "done"


def test_certification_refusal_test_has_teeth_when_resolver_is_broken(tmp_path, monkeypatch):
    audit = healthy_b0(tmp_path)
    audit.write("CODEMAP.md", "")
    monkeypatch.setattr(cs, "resolve_stage_obligations", lambda *args, **kwargs: [])
    cs.finish_stage(audit.root, "b0", "done")
    assert read_manifest(audit.root)["stages"]["b0"]["status"] == "done"


def test_sabotage_cli_missing_artifact_cannot_be_certified(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    (root / "source.py").write_text("VALUE = 1\n", encoding="utf-8")
    write_intake(root)
    assert cli(root, "init").returncode == 0
    assert cli(root, "start", "--stage", "claims_b3c").returncode == 0
    artifact = root / "audit" / "_run" / "conventions.md"
    artifact.write_text("# conventions\n", encoding="utf-8")
    artifact.unlink()
    manifest_path = root / "audit" / "_run" / "manifest.json"
    before = manifest_path.read_bytes()
    result = cli(
        root, "finish", "--stage", "claims_b3c", "--outcome", "done"
    )
    assert result.returncode != 0
    assert "claims_b3c" in result.stderr
    assert "artifact:_run/conventions.md" in result.stderr
    assert manifest_path.read_bytes() == before


def test_missing_or_empty_obligation_entry_cannot_certify(tmp_path):
    root = simple_run(tmp_path)
    for table, message in (({}, "no entry"), ({"b0": []}, "is empty")):
        failures = cs.resolve_stage_obligations(root, read_manifest(root), "b0", table)
        assert message in failures[0]


def test_worker_stage_with_done_and_blocked_shards_can_certify(tmp_path, monkeypatch):
    root = simple_run(tmp_path)
    cs.start_stage(root, "claims_b2")
    done = root / "audit" / "_work" / "w1.md"
    done.parent.mkdir(parents=True)
    done.write_text("# passing shard\n", encoding="utf-8")
    cs.set_shard(root, "claims_b2", "audit/_work/w1.md", "done")
    cs.set_shard(
        root, "claims_b2", "audit/_work/w2.md", "blocked", "failed lint twice"
    )
    commands = []

    def passing_lint(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "LINT PASS\n", "")

    monkeypatch.setattr(cs.subprocess, "run", passing_lint)
    cs.finish_stage(root, "claims_b2", "done")
    assert read_manifest(root)["stages"]["claims_b2"]["status"] == "done"
    assert len(commands) == 1
    assert commands[0][-1] == str(done)


def test_worker_stage_with_only_blocked_shards_cannot_certify(tmp_path):
    root = simple_run(tmp_path)
    cs.start_stage(root, "claims_b2")
    blocked = root / "audit" / "_work" / "w1.md"
    blocked.parent.mkdir(parents=True)
    blocked.write_text("# invalid but nonempty shard\n", encoding="utf-8")
    cs.set_shard(
        root, "claims_b2", "audit/_work/w1.md", "blocked", "failed lint twice"
    )
    path = root / "audit" / "_run" / "manifest.json"
    before = path.read_bytes()
    with pytest.raises(cs.CertificationError, match="requires at least one done shard"):
        cs.finish_stage(root, "claims_b2", "done")
    assert path.read_bytes() == before


def test_worker_stage_with_nonterminal_shard_cannot_certify(tmp_path):
    root = simple_run(tmp_path)
    cs.start_stage(root, "claims_b2")
    shard = root / "audit" / "_work" / "w1.md"
    shard.parent.mkdir(parents=True)
    shard.write_text("# shard\n", encoding="utf-8")
    manifest = read_manifest(root)
    manifest["stages"]["claims_b2"]["shards"] = {
        "audit/_work/w1.md": {"status": "pending", "retries": 0}
    }
    cs.write_manifest_atomic(root, manifest)
    path = root / "audit" / "_run" / "manifest.json"
    before = path.read_bytes()
    with pytest.raises(cs.CertificationError, match="requires every shard.*nonterminal"):
        cs.finish_stage(root, "claims_b2", "done")
    assert path.read_bytes() == before


# ------------------------------------------ Tier 1: verify-run evidence


def test_verify_bad_hand_flipped_status_fails_without_mutation(tmp_path):
    root = simple_run(tmp_path)
    artifact = root / "audit" / "_run" / "conventions.md"
    artifact.write_text("# conventions\n", encoding="utf-8")
    cs.start_stage(root, "claims_b3c")
    cs.finish_stage(root, "claims_b3c", "done")
    manifest = read_manifest(root)
    manifest["stages"]["code_b3"]["status"] = "done"
    path = root / "audit" / "_run" / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    before = path.read_bytes()
    with pytest.raises(cs.CertificationError, match=r"code_b3.*code_error_register\.md"):
        cs.verify_run(root)
    assert path.read_bytes() == before


def test_verify_bad_legitimate_pass_with_deleted_artifact(tmp_path):
    root = simple_run(tmp_path)
    artifact = root / "audit" / "_run" / "conventions.md"
    artifact.write_text("# conventions\n", encoding="utf-8")
    cs.start_stage(root, "claims_b3c")
    cs.finish_stage(root, "claims_b3c", "done")
    artifact.unlink()
    with pytest.raises(cs.CertificationError, match=r"claims_b3c.*conventions\.md"):
        cs.verify_run(root)


def test_verify_good_untampered_run_passes(tmp_path):
    root = simple_run(tmp_path)
    artifact = root / "audit" / "_run" / "conventions.md"
    artifact.write_text("# conventions\n", encoding="utf-8")
    cs.start_stage(root, "claims_b3c")
    cs.finish_stage(root, "claims_b3c", "done")
    cs.verify_run(root)


def test_verify_test_has_teeth_when_rederivation_is_broken(tmp_path, monkeypatch):
    root = simple_run(tmp_path)
    artifact = root / "audit" / "_run" / "conventions.md"
    artifact.write_text("# conventions\n", encoding="utf-8")
    cs.start_stage(root, "claims_b3c")
    cs.finish_stage(root, "claims_b3c", "done")
    manifest = read_manifest(root)
    manifest["stages"]["code_b3"]["status"] = "done"
    cs.write_manifest_atomic(root, manifest)
    monkeypatch.setattr(cs, "verify_done_stages", lambda *args, **kwargs: [])
    cs.verify_run(root)


def test_sabotage_cli_hand_flip_cannot_survive_verify_run(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    (root / "source.py").write_text("VALUE = 1\n", encoding="utf-8")
    write_intake(root)
    assert cli(root, "init").returncode == 0
    assert cli(root, "start", "--stage", "claims_b3c").returncode == 0
    (root / "audit" / "_run" / "conventions.md").write_text(
        "# conventions\n", encoding="utf-8"
    )
    assert cli(
        root, "finish", "--stage", "claims_b3c", "--outcome", "done"
    ).returncode == 0
    manifest = read_manifest(root)
    manifest["stages"]["code_b3"]["status"] = "done"
    path = root / "audit" / "_run" / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    before = path.read_bytes()
    result = cli(root, "verify-run")
    assert result.returncode != 0
    assert "code_b3" in result.stderr
    assert "artifact:code_error_register.md" in result.stderr
    assert "recorded passes still hold: claims_b3c" in result.stderr
    assert path.read_bytes() == before


def test_verify_refuses_missing_or_mismatched_schema_version(tmp_path):
    root = simple_run(tmp_path)
    for value in (None, "0.9.0"):
        manifest = read_manifest(root)
        if value is None:
            manifest["run_identity"].pop("mechanism_schema_version", None)
        else:
            manifest["run_identity"]["mechanism_schema_version"] = value
        cs.write_manifest_atomic(root, manifest)
        with pytest.raises(cs.CertificationError, match="schema changed.*restart"):
            cs.verify_run(root)


def test_resume_refuses_missing_mechanism_schema_version_without_manifest_write(tmp_path):
    root = simple_run(tmp_path)
    manifest = read_manifest(root)
    manifest["run_identity"].pop("mechanism_schema_version")
    cs.write_manifest_atomic(root, manifest)
    path = root / "audit" / "_run" / "manifest.json"
    before = path.read_bytes()
    with pytest.raises(cs.CertificationError, match="schema changed.*restart"):
        cs.resume_check(root, clear_stale_marker=True)
    assert path.read_bytes() == before


# --------------------------------------- Tier 1: resume fingerprint refusal


@pytest.mark.parametrize("mutation", ["edit", "add", "delete"])
def test_resume_bad_tree_mutations_refuse_without_manifest_write(tmp_path, mutation):
    root = simple_run(tmp_path)
    source = root / "source.py"
    if mutation == "edit":
        source.write_text("VALUE = 2\n", encoding="utf-8")
    elif mutation == "add":
        (root / "new.py").write_text("NEW = True\n", encoding="utf-8")
    else:
        source.unlink()
    path = root / "audit" / "_run" / "manifest.json"
    before = path.read_bytes()
    with pytest.raises(cs.CertificationError, match="only path forward"):
        cs.resume_check(root, clear_stale_marker=True)
    assert path.read_bytes() == before


def test_resume_good_untouched_tree_passes_and_refreshes_marker(tmp_path):
    root = simple_run(tmp_path)
    marker = root / "audit" / "_run" / "RUNNING"
    marker.write_text("stale marker\n", encoding="utf-8")
    # U16: the marker records the conductor PID it is given, and omits the
    # ``pid=`` line entirely when it is given none — so the refresh is asserted
    # on the exact recorded value rather than on the bare key.
    cs.resume_check(root, clear_stale_marker=True, conductor_pid=os.getpid())
    refreshed = marker.read_text(encoding="utf-8")
    assert "stale marker" not in refreshed
    assert f"pid={os.getpid()}\n" in refreshed
    assert refreshed.startswith("started_at=")


def test_resume_test_has_teeth_when_fingerprint_is_broken(tmp_path, monkeypatch):
    root = simple_run(tmp_path)
    (root / "source.py").write_text("VALUE = 999\n", encoding="utf-8")
    stored = read_manifest(root)["run_identity"]["tree_fingerprint"]
    monkeypatch.setattr(cs, "compute_tree_fingerprint", lambda *args, **kwargs: stored)
    cs.resume_check(root, clear_stale_marker=True)


def test_sabotage_cli_edited_tree_cannot_resume_after_pause(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    source = root / "source.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    write_intake(root)
    assert cli(root, "init").returncode == 0
    assert cli(root, "start", "--stage", "claims_b3c").returncode == 0
    source.write_text("VALUE = 2\n", encoding="utf-8")
    path = root / "audit" / "_run" / "manifest.json"
    before = path.read_bytes()
    result = cli(root, "resume-check", "--clear-stale-marker")
    assert result.returncode != 0
    assert "audited tree changed across the pause" in result.stderr
    assert "only path forward" in result.stderr
    assert path.read_bytes() == before


def test_resume_without_override_refuses_existing_marker(tmp_path):
    root = simple_run(tmp_path)
    with pytest.raises(cs.CertificationError, match="--clear-stale-marker"):
        cs.resume_check(root)


def test_fingerprint_ignores_audit_and_existing_declared_exclusions(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    (root / "source.py").write_text("VALUE = 1\n", encoding="utf-8")
    excluded = root / "scratch"
    excluded.mkdir()
    (excluded / "notes.txt").write_text("one\n", encoding="utf-8")
    write_intake(root, scope_exclusions=["scratch"], off_limits=["do not run network"])
    cs.init_run(root)
    (excluded / "notes.txt").write_text("two\n", encoding="utf-8")
    (root / "audit" / "transient.txt").write_text("changed\n", encoding="utf-8")
    cs.resume_check(root, clear_stale_marker=True)


def test_fingerprint_records_symlink_target_without_following_it(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("one\n", encoding="utf-8")
    os.symlink(outside, root / "linked.txt")
    write_intake(root)
    before = cs.compute_tree_fingerprint(root, read_manifest(root))
    outside.write_text("two\n", encoding="utf-8")
    after = cs.compute_tree_fingerprint(root, read_manifest(root))
    assert after == before
