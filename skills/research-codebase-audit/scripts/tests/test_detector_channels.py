"""U3a detector channels, b3d certification, mapping closure, and drills."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import regbuild as rb

bootstrap = rb.load_script("bootstrap_conda_oracle")
cs = rb.load_script("certify_stage")
dm = rb.load_script("build_detector_mapping")
du_emit = rb.load_script("emit_definition_use_bundles")
lint = rb.load_script("lint_registers")
mf = rb.load_script("check_manifests")
projection = rb.load_script("source_projection")

pytestmark = pytest.mark.u3

CERTIFY = rb.SCRIPTS_DIR / "certify_stage.py"


def _cli(root, command, *args):
    """Drive certify_stage.py through the production command line."""
    return subprocess.run(
        [sys.executable, str(CERTIFY), command, "--package-root", str(root),
         *[str(arg) for arg in args]],
        capture_output=True, text=True,
    )


def _manifest(root, **extra):
    data = {"mode": "code_errors_only", "ladder_level": 1,
            "scope_exclusions": [], "off_limits": [],
            "effort_map": dict(cs.dispatch_tracking.DEFAULT_EFFORT_MAP)}
    data.update(extra)
    path = root / "audit/_run/manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _detector_tree(tmp_path, initialize=False):
    root = tmp_path / "package"
    root.mkdir()
    a = rb.AuditDir(root)
    (root / "do").mkdir()
    (root / "do/build.do").write_text(
        "gen consent_ok = consent != \"\"\nkeep if consent_ok == 1 & wave == 1\n",
        encoding="utf-8",
    )
    (root / "pyproject.toml").write_text("[project\nname = 'broken'\n", encoding="utf-8")
    _manifest(root)
    a.write_register("code_error_register.md", rb.ERROR_COLS, [])
    if initialize:
        started = _cli(root, "init")
        assert started.returncode == 0, started.stdout + started.stderr
        started = _cli(root, "start", "--stage", "code_b3d")
        assert started.returncode == 0, started.stdout + started.stderr
    a.write_register("_run/snapshots/code_b3d/code_error_register.md", rb.ERROR_COLS, [])
    assert rb.run_script("emit_definition_use_bundles.py", root, "--audit-dir", a.audit).returncode == 0
    assert rb.run_script("check_manifests.py", root, "--audit-dir", a.audit).returncode == 0
    rb.emit_argument_contracts(a)
    rb.emit_path_derivations(a)
    sources = dm.parse_raw_sources(a.audit)
    keys = [(channel, source) for channel in ("DU", "MF") for source in sources[channel]]
    rows, decisions = [], []
    for index, (channel, source) in enumerate(keys):
        eid = f"E-{7000 + index:04d}"
        etype = "sample_filter_or_flag_error" if channel == "DU" else "version_or_dependency_error"
        rows.append(rb.error_row(eid, etype=etype, status="candidate", severity="2"))
        decisions.append([channel, source, eid, "new_candidate"])
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, rows)
    a.write(
        "_run/detector_mapping_decisions.md",
        "# Detector decisions\n\nDeclared detector Error-ID range: E-7000–E-7099\n\n"
        + rb.md_table(dm.DECISION_COLS, decisions),
    )
    return root, a, keys


def _complete_mapping(root, a):
    dm.emit(root, a.audit, a.audit / "_run/detector_mapping.md")


def test_projection_matches_fingerprint_scope_and_excludes_both_lists(tmp_path):
    root = tmp_path / "package"
    for rel in ("src/keep.py", "excluded/no.py", "secret/no.py", "audit/no.py"):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rel, encoding="utf-8")
    manifest = {"scope_exclusions": ["excluded"], "off_limits": ["secret"]}
    files = {p.relative_to(root).as_posix()
             for p in projection.audited_regular_files(root, manifest)}
    assert files == {"src/keep.py"}
    assert cs.compute_tree_fingerprint(root, manifest)["file_count"] == 1


def test_mf_ids_are_stable_and_invalid_toml_is_one_source(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    (root / "pyproject.toml").write_text("[project\nname='x'\n", encoding="utf-8")
    first = mf.check_package(root)
    second = mf.check_package(root)
    assert len({f["source_id"] for f in first["findings"]}) == 1
    assert [(f["source_id"], f["witness_id"]) for f in first["findings"]] == [
        (f["source_id"], f["witness_id"]) for f in second["findings"]]


@pytest.mark.parametrize("readme, expected", [
    ("", "undetermined"),
    ("Install with `pip install -r requirements.txt`.", "consumed"),
    ("Install with `pip install -r other.txt`.", "not_consumed"),
])
def test_consumer_discovery_is_tri_state(tmp_path, readme, expected):
    root = tmp_path / "package"
    root.mkdir()
    (root / "requirements.txt").write_text("numpy 1.2.3\n", encoding="utf-8")
    if readme:
        (root / "GUIDE.md").write_text(readme, encoding="utf-8")
    result = mf.check_package(root)
    assert result["findings"][0]["consumer_role"] == expected


def _fake_oracle(path, exit_code=0):
    path.write_text(f"#!/bin/sh\nexit {exit_code}\n", encoding="utf-8")
    path.chmod(0o755)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_conda_human_inventory_consolidates_full_witness_list(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    (root / "environment.yml").write_text(
        "name: inventory\nbad line one\nbad line two\n", encoding="utf-8")
    (root / "GUIDE.md").write_text("pip install -r requirements.txt\n", encoding="utf-8")
    oracle = tmp_path / "oracle"
    digest = _fake_oracle(oracle, 1)
    result = mf.check_package(root, oracle_path=oracle, oracle_sha256=digest)
    assert len({row["source_id"] for row in result["findings"]}) == 1
    assert len(result["findings"]) == 2
    assert {row["consumer_role"] for row in result["findings"]} == {"not_consumed"}


def test_conda_legal_file_is_quiet_when_oracle_accepts(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    (root / "environment.yml").write_text("name: valid\ndependencies: []\n", encoding="utf-8")
    oracle = tmp_path / "oracle"
    digest = _fake_oracle(oracle, 0)
    assert mf.check_package(root, oracle_path=oracle, oracle_sha256=digest)["findings"] == []


def test_conda_offline_solver_failure_is_not_a_finding(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    (root / "environment.yml").write_text(
        "name: t\ndependencies:\n  - numpy\n", encoding="utf-8")
    oracle = tmp_path / "oracle"
    oracle.write_text(
        f"#!/bin/sh\necho 'error    libmamba {mf.CONDA_SOLVE_FAILURE}' >&2\nexit 1\n",
        encoding="utf-8")
    oracle.chmod(0o755)
    digest = hashlib.sha256(oracle.read_bytes()).hexdigest()
    result = mf.check_package(root, oracle_path=oracle, oracle_sha256=digest)
    assert result["findings"] == []
    assert result["checked"] == [("environment.yml", "conda", 0, "filename")]


def test_conda_valid_uncached_dependencies_are_not_flagged(tmp_path):
    if not bootstrap.ORACLE_PATH.is_file():
        pytest.skip("pinned oracle not bootstrapped")
    root = tmp_path / "package"
    root.mkdir()
    (root / "environment.yml").write_text(
        "name: rca-real\nchannels:\n  - conda-forge\ndependencies:\n  - numpy\n",
        encoding="utf-8")
    result = mf.check_package(root)
    assert result["findings"] == []
    assert result["checked"] == [("environment.yml", "conda", 0, "filename")]


def test_oracle_bad_and_missing_fail_closed_without_artifact(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    (root / "environment.yml").write_text("name: test\ndependencies: []\n", encoding="utf-8")
    output = tmp_path / "manifest_check.md"
    bad = tmp_path / "oracle"
    _fake_oracle(bad)
    result = rb.run_script("check_manifests.py", root, "-o", output, "--oracle-path", bad)
    assert result.returncode == 1
    assert mf.ORACLE_SHA256 in result.stderr and hashlib.sha256(bad.read_bytes()).hexdigest() in result.stderr
    assert not output.exists()
    missing = rb.run_script("check_manifests.py", root, "-o", output,
                            "--oracle-path", tmp_path / "missing")
    assert missing.returncode == 1 and "missing" in missing.stderr
    assert not output.exists()


def test_oracle_good_preflight_and_test_has_teeth(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    (root / "environment.yml").write_text("name: test\ndependencies: []\n", encoding="utf-8")
    oracle = tmp_path / "oracle"
    digest = _fake_oracle(oracle)
    assert mf.check_package(root, oracle_path=oracle, oracle_sha256=digest)["findings"] == []
    oracle.write_bytes(oracle.read_bytes() + b"tamper")
    with pytest.raises(mf.OracleError):
        mf.check_package(root, oracle_path=oracle, oracle_sha256=digest)
    # Deliberately break the digest computation: the tampered oracle now passes.
    assert mf.check_package(root, oracle_path=oracle, oracle_sha256=digest,
                            digest_fn=lambda _path: digest)["findings"] == []


def test_real_pinned_oracle_constant_and_adapter_verdict(tmp_path):
    if not bootstrap.ORACLE_PATH.is_file():
        pytest.skip("pinned oracle not bootstrapped")
    assert bootstrap.sha256(bootstrap.ORACLE_PATH) == mf.ORACLE_SHA256
    root = tmp_path / "package"
    root.mkdir()
    (root / "environment.yml").write_text("name: rca-u3\ndependencies: []\n", encoding="utf-8")
    result = mf.check_package(root)
    assert result["checked"] == [("environment.yml", "conda", 0, "filename")]
    (root / "environment.yml").write_text(
        "name: broken\nbad line one\nbad line two\n", encoding="utf-8")
    flagged = mf.check_package(root)
    assert [f["rule_slug"] for f in flagged["findings"]] == ["conda-malformed-line"] * 2


def test_oracle_sabotage_cli_tamper_refuses_then_bootstrap_repairs(tmp_path):
    if not bootstrap.ORACLE_PATH.is_file():
        pytest.skip("pinned oracle not bootstrapped")
    root = tmp_path / "package"
    root.mkdir()
    (root / "environment.yml").write_text("name: rca-drill\ndependencies: []\n", encoding="utf-8")
    oracle = tmp_path / "micromamba-2.8.1-0"
    shutil.copy2(bootstrap.ORACLE_PATH, oracle)
    oracle.write_bytes(oracle.read_bytes() + b"x")
    output = tmp_path / "manifest_check.md"
    refused = rb.run_script(
        "check_manifests.py", root, "-o", output, "--oracle-path", oracle)
    assert refused.returncode == 1 and "digest mismatch" in refused.stderr
    assert not output.exists()
    bootstrap.install_oracle(
        path=oracle, url=bootstrap.ORACLE_PATH.as_uri(), expected=bootstrap.ORACLE_SHA256)
    passed = rb.run_script(
        "check_manifests.py", root, "-o", output, "--oracle-path", oracle)
    assert passed.returncode == 0 and output.is_file()


def test_mapping_emission_refuses_unmapped_unknown_duplicate_and_bad_new_candidate(tmp_path):
    root, a, keys = _detector_tree(tmp_path)
    decisions = a.audit / "_run/detector_mapping_decisions.md"
    original = decisions.read_text(encoding="utf-8")
    omitted = keys[-1][1]
    decisions.write_text("\n".join(line for line in original.splitlines() if omitted not in line))
    with pytest.raises(dm.MappingError, match=omitted):
        dm.emit(root, a.audit, a.audit / "_run/detector_mapping.md")
    decisions.write_text(original.replace(keys[-1][1], "MF-ffffffffffff"))
    with pytest.raises(dm.MappingError, match="unknown"):
        dm.emit(root, a.audit, a.audit / "_run/detector_mapping.md")
    row = next(line for line in original.splitlines() if keys[0][1] in line)
    decisions.write_text(original + row + "\n")
    with pytest.raises(dm.MappingError, match="duplicate"):
        dm.emit(root, a.audit, a.audit / "_run/detector_mapping.md")
    decisions.write_text(original.replace("| E-7000 |", "| E-7999 |", 1))
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [
        rb.error_row("E-7999", etype="sample_filter_or_flag_error", status="candidate", severity="2"),
        rb.error_row("E-7001", etype="version_or_dependency_error", status="candidate", severity="2"),
    ])
    with pytest.raises(dm.MappingError, match="outside declared range"):
        dm.emit(root, a.audit, a.audit / "_run/detector_mapping.md")


def test_mapping_emission_refuses_new_candidate_row_that_is_not_candidate(tmp_path):
    root, a, _keys = _detector_tree(tmp_path)
    staged = a.audit / "_staging/code_error_register.md"
    staged.write_text(staged.read_text().replace("| candidate |", "| confirmed |", 1))
    with pytest.raises(dm.MappingError, match="not candidate"):
        dm.emit(root, a.audit, a.audit / "_run/detector_mapping.md")


def test_mapping_good_emits_fixed_sections_and_expands_witnesses(tmp_path):
    root, a, keys = _detector_tree(tmp_path)
    _complete_mapping(root, a)
    text = (a.audit / "_run/detector_mapping.md").read_text(encoding="utf-8")
    assert [text.count(marker) for marker in dm.MARKERS] == [1] * len(dm.MARKERS)
    assert [text.index(marker) for marker in dm.MARKERS] == sorted(
        text.index(marker) for marker in dm.MARKERS)
    assert dm.CV_ZERO in text
    _declared, _display, rows = dm.load_mapping(a.audit / "_run/detector_mapping.md")
    assert {(row["Channel"], row["Source ID"]) for row in rows} == set(keys)


def test_mapping_explicit_zero_is_exact_and_missing_raw_is_not_zero(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    a = rb.AuditDir(root)
    _manifest(root)
    a.write_register("_run/snapshots/code_b3d/code_error_register.md", rb.ERROR_COLS, [])
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [])
    a.write("_run/detector_mapping_decisions.md",
            "Declared detector Error-ID range: E-7000–E-7099\n\n"
            + rb.md_table(dm.DECISION_COLS, []))
    assert rb.run_script("emit_definition_use_bundles.py", root, "--audit-dir", a.audit).returncode == 0
    assert rb.run_script("check_manifests.py", root, "--audit-dir", a.audit).returncode == 0
    rb.emit_argument_contracts(a)
    rb.emit_path_derivations(a)
    _complete_mapping(root, a)
    text = (a.audit / "_run/detector_mapping.md").read_text()
    assert dm.DU_ZERO in text and dm.MF_ZERO in text and dm.CV_ZERO in text
    (a.audit / "_run/manifest_check.md").unlink()
    with pytest.raises(dm.MappingError, match="missing raw detector artifact"):
        dm.emit(root, a.audit, a.audit / "_run/detector_mapping.md")


@pytest.mark.parametrize("mutation, token", [
    (lambda text: text.replace(dm.MARKERS[1], ""), "exactly once"),
    (lambda text: text.replace(dm.MARKERS[1], dm.MARKERS[0]), "exactly once"),
    (lambda text: text.replace(dm.MARKERS[0], "TEMP").replace(dm.MARKERS[1], dm.MARKERS[0]).replace("TEMP", dm.MARKERS[1]), "out of order"),
])
def test_mapping_marker_parser_rejects_missing_duplicate_and_reordered(tmp_path, mutation, token):
    root, a, _keys = _detector_tree(tmp_path)
    _complete_mapping(root, a)
    text = (a.audit / "_run/detector_mapping.md").read_text(encoding="utf-8")
    with pytest.raises(dm.MappingError, match=token):
        dm.parse_mapping_text(mutation(text))


def test_b3d_certifies_end_to_end_and_verify_run_catches_deleted_mapping_row(tmp_path):
    root, a, _keys = _detector_tree(tmp_path, initialize=True)
    emitted = rb.run_script("build_detector_mapping.py", root, "--audit-dir", a.audit)
    assert emitted.returncode == 0, emitted.stdout + emitted.stderr
    os.replace(a.audit / "_staging/code_error_register.md", a.audit / "code_error_register.md")
    finished = _cli(root, "finish", "--stage", "code_b3d", "--outcome", "done")
    assert finished.returncode == 0, finished.stdout + finished.stderr
    assert json.loads((a.audit / "_run/manifest.json").read_text())["stages"]["code_b3d"]["status"] == "done"
    # b6 legitimately resolves every candidate; verify-run must stay quiet.
    register = a.audit / "code_error_register.md"
    register.write_text(register.read_text().replace("| candidate |", "| confirmed |"))
    verified = _cli(root, "verify-run")
    assert verified.returncode == 0, verified.stdout + verified.stderr
    mapping = a.audit / "_run/detector_mapping.md"
    lines = mapping.read_text().splitlines()
    mapping.write_text("\n".join(line for line in lines if not (line.startswith("| DU |") or line.startswith("| MF |"))) + "\n")
    broken = _cli(root, "verify-run")
    assert broken.returncode != 0
    assert "detector mapping" in broken.stderr


def test_b3d_unmapped_cannot_certify_and_test_depends_on_validator(tmp_path, monkeypatch):
    root, a, keys = _detector_tree(tmp_path, initialize=True)
    decisions = a.audit / "_run/detector_mapping_decisions.md"
    omitted = keys[-1][1]
    decisions.write_text("\n".join(line for line in decisions.read_text().splitlines()
                                   if omitted not in line) + "\n")
    refused = rb.run_script("build_detector_mapping.py", root, "--audit-dir", a.audit)
    assert refused.returncode != 0 and omitted in refused.stderr
    assert not (a.audit / "_run/detector_mapping.md").exists()
    # Supply a nonempty artifact so refusal comes from the closure validator.
    (a.audit / "_run/detector_mapping.md").write_text("invalid mapping\n")
    os.replace(a.audit / "_staging/code_error_register.md", a.audit / "code_error_register.md")
    before = (a.audit / "_run/manifest.json").read_bytes()
    finish = _cli(root, "finish", "--stage", "code_b3d", "--outcome", "done")
    assert finish.returncode != 0 and omitted in finish.stderr
    assert (a.audit / "_run/manifest.json").read_bytes() == before
    monkeypatch.setattr(cs, "_run_validator", lambda *args: [])
    cs.finish_stage(root, "code_b3d", "done")


def test_reproducibility_check_rejects_edited_raw_artifact(tmp_path):
    root, a, _keys = _detector_tree(tmp_path)
    _complete_mapping(root, a)
    os.replace(a.audit / "_staging/code_error_register.md", a.audit / "code_error_register.md")
    dm.check(root, a.audit, a.audit / "_run/detector_mapping.md")
    path = a.audit / "_run/manifest_check.md"
    path.write_text(path.read_text() + "edited\n")
    with pytest.raises(dm.MappingError, match="stale or edited"):
        dm.check(root, a.audit, a.audit / "_run/detector_mapping.md")


def test_downstream_b4_and_b6_cover_du_and_mf_and_test_has_teeth(tmp_path, monkeypatch):
    mappings = [
        ("DU-aaa111", "E-0101", "new_candidate"),
        ("MF-bbb222", "E-0102", "new_candidate"),
    ]
    errors = [
        rb.error_row("E-0101", etype="sample_filter_or_flag_error", status="candidate", severity="2"),
        rb.error_row("E-0102", etype="version_or_dependency_error", status="candidate", severity="2"),
    ]
    a = rb.make_b4(
        tmp_path, "code", canon_errors=errors,
        inventory=[("E-0101", "detector", "DU-aaa111")],
        clusters=[("K1", "detector", "E-0101", "`audit/_code_error_recheck/k1.md`")],
        mappings=mappings,
    )
    result = rb.lint(a, "b4-code")
    assert result.returncode == 1 and "E-0102" in result.stdout
    checker = lint.Lint()
    plan, inventory, _clusters = lint.parse_recheck_plan(checker, a.audit, "code")
    monkeypatch.setattr(lint, "parse_detector_mappings", lambda *_args: [])
    lint.check_detector_mapping_b4(checker, a.audit, plan, inventory)
    assert not checker.errors


def test_downstream_b6_requires_each_du_and_mf_source_and_one_disposition(tmp_path):
    mappings = [
        ("DU-aaa111", "E-0101", "new_candidate"),
        ("MF-bbb222", "E-0102", "new_candidate"),
    ]
    before = [
        rb.error_row("E-0101", etype="sample_filter_or_flag_error", status="candidate", severity="2"),
        rb.error_row("E-0102", etype="version_or_dependency_error", status="candidate", severity="2"),
    ]
    final = [
        rb.error_row("E-0101", etype="sample_filter_or_flag_error", status="confirmed", severity="2"),
        rb.error_row("E-0102", etype="version_or_dependency_error", status="confirmed", severity="2"),
    ]
    inventory = [("E-0101", "detector", "DU-aaa111"),
                 ("E-0102", "detector", "MF-bbb222")]
    clusters = [("K1", "detectors", "E-0101; E-0102",
                 "`audit/_code_error_recheck/k1.md`")]
    a = rb.make_b6_code(
        tmp_path, before_rows=before, final_rows=final, inventory=inventory,
        clusters=clusters, mappings=mappings,
        ledger_rows=[rb.ledger_row("E-0101", evidence="DU-aaa111")],
    )
    missing = rb.lint(a, "b6-code")
    assert missing.returncode == 1 and "E-0102" in missing.stdout and "ledger" in missing.stdout
    a.write("_code_error_recheck/k1.md", rb.register_text(
        "Recheck ledger", rb.CODE_LEDGER_COLS,
        [rb.code_ledger_row("E-0101", evidence="DU-aaa111", witness_ids="DUW-000000000001"),
         rb.code_ledger_row("E-0102", evidence="MF-bbb222", witness_ids="MFW-000000000002"),
         rb.code_ledger_row("E-0102", evidence="MF-bbb222", witness_ids="MFW-000000000002")]))
    duplicate = rb.lint(a, "b6-code")
    assert duplicate.returncode == 1 and "E-0102 has 2 ledger rows" in duplicate.stdout


def test_b4_sabotage_drill_deleted_inventory_row_fails_production_lint(tmp_path):
    root, a, _keys = _detector_tree(tmp_path)
    _complete_mapping(root, a)
    os.replace(a.audit / "_staging/code_error_register.md", a.audit / "code_error_register.md")
    _declared, _display, rows = dm.load_mapping(a.audit / "_run/detector_mapping.md")
    by_error = {}
    for row in rows:
        by_error.setdefault(row["Error ID"], set()).add(row["Source ID"])
    inventory = [(eid, "detector", "; ".join(sorted(sources)))
                 for eid, sources in sorted(by_error.items())]
    clusters = [("K1", "detectors", "; ".join(sorted(by_error)),
                 "`audit/_code_error_recheck/k1.md`")]
    a.write("plans/code_error_recheck_plan.md",
            rb.recheck_plan_text("code", inventory, clusters))
    passing = rb.lint(a, "b4-code")
    assert passing.returncode == 0, passing.stdout + passing.stderr
    victim = inventory[0][0]
    plan = a.audit / "plans/code_error_recheck_plan.md"
    plan.write_text("\n".join(line for line in plan.read_text().splitlines()
                              if not line.startswith(f"| {victim} |")) + "\n")
    broken = rb.lint(a, "b4-code")
    assert broken.returncode == 1 and victim in broken.stdout


def test_b3b_detector_range_overlap_fails_and_disjoint_passes(tmp_path):
    a, _shard = rb.make_b3b_shard(tmp_path, "code", error_range="E-7000–E-7099")
    a.write("_run/detector_mapping.md", rb.detector_mapping_artifact([]))
    overlap = rb.lint(a, "b3b-code")
    assert overlap.returncode == 1
    assert "overlapping E- ID ranges" in overlap.stdout
    plan = a.audit / "plans/code_error_second_read_plan.md"
    plan.write_text(plan.read_text().replace("E-7000–E-7099", "E-2000–E-2099"))
    disjoint = rb.lint(a, "b3b-code")
    # The shard fixture is not fully green at b3b, so assert on the finding
    # itself rather than the exit code.
    assert "overlapping E- ID ranges" not in disjoint.stdout


def test_code_b3d_registration_and_missing_obligation_refuses(tmp_path, monkeypatch):
    assert cs.FULL_STAGES.index("code_b3d") == cs.FULL_STAGES.index("code_b3") + 1
    assert cs.CODE_ONLY_STAGES.index("code_b3d") == cs.CODE_ONLY_STAGES.index("code_b3") + 1
    table = cs.load_obligations()
    assert [item["type"] for item in table["code_b3d"]] == [
        "artifact", "artifact", "artifact", "artifact", "artifact", "validate"]
    root, _a, _keys = _detector_tree(tmp_path, initialize=True)
    monkeypatch.setattr(cs, "load_obligations", lambda: {})
    with pytest.raises(cs.CertificationError, match="no entry"):
        cs.finish_stage(root, "code_b3d", "done")
