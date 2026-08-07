"""U6a read-layer recall, deterministic sampler, and Tier-1 CLI drills."""

import json
import shutil
import subprocess
import sys

import pytest

import regbuild as rb


builder = rb.load_script("build_second_read_plan")
cs = rb.load_script("certify_stage")
dm = rb.load_script("build_detector_mapping")
score = rb.load_script("score_replay")
fixture_score = rb.load_script("score_fixture")

pytestmark = pytest.mark.u6
CERTIFY = rb.SCRIPTS_DIR / "certify_stage.py"


def cli(root, command, *args):
    return subprocess.run(
        [sys.executable, str(CERTIFY), command, "--package-root", str(root), *args],
        capture_output=True, text=True,
    )


def init_root(tmp_path, mode="replication"):
    root = tmp_path / "package"
    root.mkdir()
    (root / "source.py").write_text("VALUE = 1\n", encoding="utf-8")
    a = rb.AuditDir(root)
    extra = ({"allocation_override": {"purpose": "development", "allocation": []}}
             if mode == "replication" else {})
    a.write_manifest(
        mode=mode, scope_exclusions=[], off_limits=[], review_depth="standard",
        **extra)
    result = cli(root, "init")
    assert result.returncode == 0, result.stdout + result.stderr
    return root, a


def typed_footer(entries=()):
    return rb.md_table(
        ["Entry ID", "Kind", "Register IDs", "Observation", "Reason"],
        entries,
    )


def claims_b3_boundary(tmp_path):
    root, a = init_root(tmp_path)
    a.write_claims_plan()
    shard = rb.md_table(rb.CLAIMS_COLS, []) + "\n" + rb.md_table(rb.OUTPUT_COLS, [])
    shard += "\nCoverage: every assigned claim unit accounted for.\n\n"
    shard += typed_footer([["OBS-0001", "not_rowed_observation", "—",
                            "section overlap",
                            "scope: owned by adjacent section"]])
    a.write("_work/w1.md", shard)
    a.write_register("claims_register.md", rb.CLAIMS_COLS, [])
    a.write_register("output_register.md", rb.OUTPUT_COLS, [])
    a.write_register("_staging/claims_register.md", rb.CLAIMS_COLS, [])
    a.write_register("_staging/output_register.md", rb.OUTPUT_COLS, [])
    a.write("_run/merge_report_claims.json", json.dumps({
        "claims_register.md": {"shard_rows": 0, "dedup_removed": 0, "added": 0,
                               "conflicts": [], "coverage_gaps": [], "blocked_shards": []},
        "output_register.md": {"shard_rows": 0, "dedup_removed": 0, "added": 0,
                               "conflicts": [], "coverage_gaps": [], "blocked_shards": []},
        "footer_dispositions": [
            "audit/_work/w1.md#OBS-0001 | dismissed:adjacent section owns it"],
    }))
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    manifest["stages"]["claims_b2"] = {
        "status": "done", "retries": 0,
        "shards": {"audit/_work/w1.md": {"status": "done", "retries": 0}},
    }
    manifest["stages"]["claims_b3"]["status"] = "running"
    cs.write_manifest_atomic(root, manifest)
    return root, a


def code_b3_boundary(tmp_path, outcome="blocked: parser unavailable"):
    root, a = init_root(tmp_path, mode="code_errors_only")
    plan = (
        "# Code review plan\n\n"
        "| Script | Language | Pipeline role | ~Lines | Chunk |\n"
        "| --- | --- | --- | --- | --- |\n"
        "| `source.py` | Python | build | 1 | CE-01 |\n\n"
        "| Hygiene File | Chunk |\n| --- | --- |\n| `requirements.txt` | CE-01 |\n\n"
        "| Chunk ID | Script Scope | Likely Pipeline Stage/Outputs | Shard File | Error ID Range | Review Focus |\n"
        "| --- | --- | --- | --- | --- | --- |\n"
        "| CE-01 | `source.py`; `requirements.txt` | build | `audit/_code_errors/ce-01.md` | E-0100–E-0199 | all |\n\n"
        "Merge-coordinator range: E-0900–E-0949\n"
    )
    a.write("plans/code_error_review_plan.md", plan)
    shard = rb.md_table(rb.ERROR_COLS, []) + "\n" + rb.md_table(
        ["Script", "Outcome"], [
            ["source.py", outcome], ["requirements.txt", "clean"],
            ["@hygiene:data-and-log-lens", "clean"],
        ]) + "\n" + typed_footer()
    a.write("_code_errors/ce-01.md", shard)
    a.write_register("code_error_register.md", rb.ERROR_COLS, [])
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [])
    a.write("_run/merge_report_code.json", json.dumps({
        "code_error_register.md": {
            "shard_rows": 0, "dedup_removed": 0, "added": 0,
            "conflicts": [], "coverage_gaps": [], "blocked_shards": [],
        },
        "footer_dispositions": [], "unreviewed_files": [],
        "coverage_outcomes": {
            "@hygiene:data-and-log-lens": "clean",
            "requirements.txt": "clean", "source.py": outcome,
        },
    }))
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    manifest["stages"]["code_b2"] = {
        "status": "done", "retries": 0,
        "shards": {"audit/_code_errors/ce-01.md": {"status": "done", "retries": 0}},
    }
    manifest["stages"]["code_b3"]["status"] = "running"
    cs.write_manifest_atomic(root, manifest)
    return root, a


def test_tier1_footer_success_and_silent_failure(tmp_path):
    root, a = claims_b3_boundary(tmp_path)
    finished = cli(root, "finish", "--stage", "claims_b3", "--outcome", "done")
    assert finished.returncode == 0, finished.stdout + finished.stderr
    report = json.loads((a.audit / "_run/merge_report_claims.json").read_text())
    report["footer_dispositions"] = []
    (a.audit / "_run/merge_report_claims.json").write_text(json.dumps(report), encoding="utf-8")
    refused = cli(root, "verify-run")
    assert refused.returncode != 0
    assert "typed footer entry audit/_work/w1.md#OBS-0001 is undispositioned" in refused.stderr


def test_tier1_footer_check_has_teeth(tmp_path, monkeypatch):
    _root, a = claims_b3_boundary(tmp_path)
    report = json.loads((a.audit / "_run/merge_report_claims.json").read_text())
    report["footer_dispositions"] = []
    (a.audit / "_run/merge_report_claims.json").write_text(json.dumps(report), encoding="utf-8")
    lint = rb.load_script("lint_registers")
    live = lint.Lint()
    lint.stage_b3(live, a.audit, "claims", json.loads((a.audit / "_run/manifest.json").read_text()))
    assert any("undispositioned" in finding for finding in live.errors)
    monkeypatch.setattr(lint, "reconcile_footer_dispositions", lambda *_args: None)
    broken = lint.Lint()
    lint.stage_b3(broken, a.audit, "claims", json.loads((a.audit / "_run/manifest.json").read_text()))
    assert not any("undispositioned" in finding for finding in broken.errors)


def test_candidate_footer_entry_cannot_be_dismissed(tmp_path):
    _root, a = claims_b3_boundary(tmp_path)
    claim = rb.claims_row("C-0100", status="unclear")
    shard = rb.md_table(rb.CLAIMS_COLS, [claim]) + "\n" + rb.md_table(
        rb.OUTPUT_COLS, [])
    shard += "\nCoverage: every assigned claim unit accounted for.\n\n"
    shard += typed_footer(
        [["OBS-0001", "candidate", "C-0100", "uncertain claim", "—"]])
    a.write("_work/w1.md", shard)
    # Post-promotion evidence: the b3 rename has put the merged rows on canon.
    a.write_register("claims_register.md", rb.CLAIMS_COLS, [claim])
    report_path = a.audit / "_run/merge_report_claims.json"
    report = json.loads(report_path.read_text())
    report["claims_register.md"].update(shard_rows=1, added=1)
    report["footer_dispositions"] = [
        "audit/_work/w1.md#OBS-0001 | candidate:C-0100"]
    report_path.write_text(json.dumps(report), encoding="utf-8")
    assert rb.lint(a, "b3-claims").returncode == 0
    report["footer_dispositions"] = [
        "audit/_work/w1.md#OBS-0001 | dismissed:coordinator disagreed"]
    report_path.write_text(json.dumps(report), encoding="utf-8")
    refused = rb.lint(a, "b3-claims")
    assert refused.returncode == 1
    assert "candidate entry cannot be dismissed" in refused.stdout


def test_tier1_b3b_footer_entry_cannot_vanish(tmp_path):
    row = rb.error_row("E-2001", status="candidate", severity="2")
    a, shard = rb.make_b3b_shard(tmp_path, "code", error_rows=[row])
    a.write_register("_run/snapshots/code_b3b/code_error_register.md",
                     rb.ERROR_COLS, [])
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [row])
    a.write("_run/merge_report_code_b3b.json", json.dumps({
        "code_error_register.md": {
            "shard_rows": 1, "dedup_removed": 0, "added": 1},
        "footer_dispositions": [],
    }))
    a.write_manifest(stages={"code_b3b": {
        "status": "running", "retries": 0,
        "shards": {"audit/_code_errors_second_read/w1.md": {
            "status": "done", "retries": 0}},
    }})
    refused = rb.lint(a, "b3b-code")
    assert refused.returncode == 1
    assert "typed footer entry audit/_code_errors_second_read/w1.md#OBS-0001 is undispositioned" in refused.stdout


def test_tier1_coverage_tamper_refused_by_verify_run(tmp_path):
    root, a = code_b3_boundary(tmp_path)
    finished = cli(root, "finish", "--stage", "code_b3", "--outcome", "done")
    assert finished.returncode == 0, finished.stdout + finished.stderr
    shard = a.audit / "_code_errors/ce-01.md"
    shard.write_text(shard.read_text().replace(
        "blocked: parser unavailable", "clean"), encoding="utf-8")
    refused = cli(root, "verify-run")
    assert refused.returncode != 0
    assert "coverage_outcomes disagree with shard evidence" in refused.stderr


def test_tier1_coverage_check_has_teeth(tmp_path):
    _root, a = code_b3_boundary(tmp_path)
    shard = a.audit / "_code_errors/ce-01.md"
    shard.write_text(shard.read_text().replace(
        "blocked: parser unavailable", "clean"), encoding="utf-8")
    result = rb.lint(a, "b3-code")
    assert result.returncode == 1
    assert "coverage_outcomes disagree with shard evidence" in result.stdout


@pytest.mark.parametrize("mutation, expected", [
    (lambda text: text.replace("| requirements.txt | clean |\n", ""),
     "has 0 coverage rows"),
    (lambda text: text.replace(
        "| requirements.txt | clean |",
        "| requirements.txt | clean |\n| requirements.txt | blocked: unreadable |"),
     "conflicting outcomes"),
])
def test_tier1_missing_or_conflicting_coverage_refused(
        tmp_path, mutation, expected):
    _root, a = code_b3_boundary(tmp_path)
    shard = a.audit / "_code_errors/ce-01.md"
    shard.write_text(mutation(shard.read_text()), encoding="utf-8")
    refused = rb.lint(a, "b3-code")
    assert refused.returncode == 1
    assert expected in refused.stdout


def test_tier1_manifest_blocked_owner_is_unreviewed_not_clean(tmp_path):
    _root, a = code_b3_boundary(tmp_path)
    manifest_path = a.audit / "_run/manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["stages"]["code_b2"]["shards"][
        "audit/_code_errors/ce-01.md"]["status"] = "blocked"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    report_path = a.audit / "_run/merge_report_code.json"
    report = json.loads(report_path.read_text())
    report["unreviewed_files"] = [
        "@hygiene:data-and-log-lens", "requirements.txt", "source.py"]
    report["coverage_outcomes"] = {}
    report_path.write_text(json.dumps(report), encoding="utf-8")
    accepted = rb.lint(a, "b3-code")
    assert accepted.returncode == 0, accepted.stdout + accepted.stderr


def test_code_coverage_clean_cannot_hide_a_shard_finding(tmp_path):
    rows = [rb.error_row("E-2001", status="candidate", severity="2")]
    a, shard = rb.make_b3b_shard(tmp_path, "code", error_rows=rows)
    shard.write_text(shard.read_text().replace(
        "findings: E-2001", "clean"), encoding="utf-8")
    refused = rb.lint(a, "b3b-code", shard=shard)
    assert refused.returncode == 1
    assert "findings coverage IDs do not equal code-error row IDs" in refused.stdout


def test_tier1_coverage_decision_patch_removes_failure(tmp_path, monkeypatch):
    _root, a = code_b3_boundary(tmp_path)
    shard = a.audit / "_code_errors/ce-01.md"
    shard.write_text(shard.read_text().replace(
        "blocked: parser unavailable", "clean"), encoding="utf-8")
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    lint = rb.load_script("lint_registers")
    live = lint.Lint()
    lint.stage_b3(live, a.audit, "code", manifest)
    assert any("coverage_outcomes disagree" in finding for finding in live.errors)
    recorded = json.loads(
        (a.audit / "_run/merge_report_code.json").read_text()
    )["coverage_outcomes"]
    monkeypatch.setattr(
        lint, "reconcile_code_coverage",
        lambda *_args: ([], recorded),
    )
    broken = lint.Lint()
    lint.stage_b3(broken, a.audit, "code", manifest)
    assert not any("coverage_outcomes disagree" in finding for finding in broken.errors)


def test_sampler_two_pass_caps_credit_determinism_and_logs():
    clean = [f"py/f{i}.py" for i in range(15)] + ["config.yml", "bridge.py"]
    memberships = {path: {"language:python"} for path in clean}
    memberships["config.yml"] = {"ancillary"}
    memberships["bridge.py"] = {"language:python", "handoff", "ancillary"}
    first = builder.select_clean(clean, memberships, 2)
    second = builder.select_clean(list(reversed(clean)), memberships, 2)
    assert first == second
    selected, unserved, quotas = first
    assert len(selected) == 2
    assert "bridge.py" in selected
    assert quotas["language:python"] == 2
    assert not unserved
    assert "language:python" in builder.select_clean(clean, memberships, 1)[1]
    roomy, roomy_unserved, _ = builder.select_clean(clean, memberships, 20)
    assert not roomy_unserved
    assert all(any(path in roomy for path in paths) for paths in (
        {"bridge.py"}, {"config.yml", "bridge.py"}, set(clean) - {"config.yml"}))


def test_codemap_real_lineage_schema_and_manifest_names_form_strata(tmp_path):
    a = rb.AuditDir(tmp_path)
    inventory = ["py/producer.py", "do/consumer.do", "requirements-dev.txt"]
    a.write("CODEMAP.md", "# CODEMAP\n\n" + rb.md_table(
        ["ID", "Stage/order", "Script", "Called by", "Main role",
         "Key inputs/outputs if visible"],
        [["S-0001", "1", "py/producer.py", "master", "build", "panel"],
         ["S-0002", "2", "do/consumer.do", "master", "analyse", "table"]],
    ) + "\n" + rb.md_table(
        ["ID", "Dataset/path", "Type", "Stage", "Created by", "Inputs",
         "Consumed by", "Restricted/manual/external?", "Confidence", "Notes"],
        [["D-0001", "panel.dta", "intermediate dataset", "build", "S-0001",
          "raw", "S-0002", "no", "high", "cross-language"]],
    ))
    memberships = builder._codemap_strata(a.audit, inventory)
    assert "handoff" in memberships["py/producer.py"]
    assert "handoff" in memberships["do/consumer.do"]
    assert "ancillary" in memberships["requirements-dev.txt"]


def test_candidate_mode_exact_path_mechanism_status_severity_and_fp_ceiling():
    path = "do/create_supplier_distance_panel.do"
    row = dict(zip(rb.ERROR_COLS, rb.error_row(
        "E-7100", etype="stale_or_wrong_path", source=f"`{path}`",
        location=f"`{path}:33`", status="candidate", severity="1",
        desc="consumer reads firm panel _2km but producer writes no suffix",
    )))
    observed = {
        "id": "E-7100", "register": "code_errors", "path": path,
        "mechanism": score._candidate_mechanism("code_errors", row, path),
        "status": "candidate", "severity": 1, "text": " ".join(row.values()),
    }
    sheet = {
        "false_positive_ceiling": 0,
        "expected_candidates": [{
            "key": "E0500", "register": "code_errors", "path": path,
            "mechanism": observed["mechanism"], "status_family": "candidate",
            "benchmark_severity": 1, "anchors": ["_2km"],
        }],
    }
    assert score.score_candidates(sheet, [observed])["status"] == "score"
    wrong_path = {**observed, "path": "do/other.do"}
    red = score.score_candidates(sheet, [wrong_path])
    assert red["status"] == "red" and red["recoveries"][0]["mechanism_outcome"] == "absent"
    assert score.score_candidates(
        sheet, [{**observed, "status": "not_error"}])["status"] == "red"
    assert score.score_candidates(
        sheet, [{**observed, "severity": 4}])["status"] == "red"
    assert score.score_candidates(
        sheet, [observed, {**observed, "id": "E-7101",
                           "mechanism": score._candidate_mechanism(
                               "code_errors", {**row, "Error Type": "aggregation_or_unit_error"},
                               path)}])["status"] == "red"


def detector_chain(tmp_path):
    root = tmp_path / "chain"
    root.mkdir()
    a = rb.AuditDir(root)
    (root / "dummy.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "requirements-recall.txt").write_text(
        "numpy 2.0.0\npandas==2.2.2\npandas==1.5.3\nopenpyxl==3.1.5\n",
        encoding="utf-8",
    )
    plan = (
        "# Code plan\n\n"
        "| Script | Language | Pipeline role | ~Lines | Chunk |\n"
        "| --- | --- | --- | --- | --- |\n| `dummy.py` | Python | helper | 1 | CE-01 |\n\n"
        "| Hygiene File | Chunk |\n| --- | --- |\n| `requirements-recall.txt` | CE-01 |\n\n"
        "| Chunk ID | Script Scope | Shard File | Error ID Range |\n"
        "| --- | --- | --- | --- |\n"
        "| CE-01 | `dummy.py`; `requirements-recall.txt` | `audit/_code_errors/ce-01.md` | E-0100–E-0199 |\n\n"
        "Merge-coordinator range: E-0900–E-0949\n"
    )
    a.write("plans/code_error_review_plan.md", plan)
    a.write("CODEMAP.md", "# CODEMAP\n\nPRECONDITIONS: 5/5\n\n" + rb.md_table(
        ["ID", "Script", "Classification", "Reason", "Likely use"],
        [["S-0001", "dummy.py", "helper", "support", "tests"],
         ["S-0002", "requirements-recall.txt", "ancillary", "manifest", "install"]]))
    first_shard = rb.md_table(rb.ERROR_COLS, []) + "\n" + rb.md_table(
        ["Script", "Outcome"], [
            ["dummy.py", "clean"], ["requirements-recall.txt", "clean"],
            ["@hygiene:data-and-log-lens", "clean"],
        ]) + "\n" + typed_footer()
    a.write("_code_errors/ce-01.md", first_shard)
    a.write_manifest(
        mode="code_errors_only", review_depth="standard", scope_exclusions=[], off_limits=[],
    )
    cs.init_run(root)
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    manifest["stages"]["code_b2"] = {"status": "done", "retries": 0, "shards": {
        "audit/_code_errors/ce-01.md": {"status": "done", "retries": 0}}}
    manifest["stages"]["code_b3d"]["status"] = "done"
    manifest["stages"]["code_b3b"]["status"] = "running"
    cs.write_manifest_atomic(root, manifest)
    a.write("_run/definition_use_bundles.md", rb.definition_use_artifact([]))
    checked = rb.run_script("check_manifests.py", root, "--audit-dir", a.audit)
    assert checked.returncode == 0, checked.stdout + checked.stderr
    rb.emit_argument_contracts(a)
    rb.emit_path_derivations(a)
    sources = dm.parse_raw_sources(a.audit)
    source = next(iter(sources["MF"]))
    anchor = sources["MF"][source][0]["anchor"]
    plant_a = rb.error_row(
        "E-7000", etype="version_or_dependency_error",
        source="`requirements-recall.txt`", location=f"`{anchor}`",
        status="candidate", severity="1",
        desc="requirements-recall numpy pin uses invalid whitespace instead of an operator",
        why="dependency installation rejects the manifest",
    )
    a.write_register("_run/snapshots/code_b3d/code_error_register.md", rb.ERROR_COLS, [])
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [plant_a])
    a.write("_run/detector_mapping_decisions.md",
            "Declared detector Error-ID range: E-7000–E-7099\n\n" + rb.md_table(
                dm.DECISION_COLS, [["MF", source, "E-7000", "new_candidate"]]))
    mapped = rb.run_script("build_detector_mapping.py", root, "--audit-dir", a.audit)
    assert mapped.returncode == 0, mapped.stdout + mapped.stderr
    a.write_register("code_error_register.md", rb.ERROR_COLS, [plant_a])
    built = rb.run_script("build_second_read_plan.py", root, "--audit-dir", a.audit)
    assert built.returncode == 0, built.stdout + built.stderr
    return root, a


def test_sampler_excludes_and_logs_unreviewed_files(tmp_path):
    root, a = detector_chain(tmp_path)
    shard = a.audit / "_code_errors/ce-01.md"
    shard.write_text(shard.read_text().replace(
        "| dummy.py | clean |\n", ""), encoding="utf-8")
    rebuilt = rb.run_script("build_second_read_plan.py", root, "--audit-dir", a.audit)
    assert rebuilt.returncode == 0, rebuilt.stdout + rebuilt.stderr
    plan = (a.audit / "plans/code_error_second_read_plan.md").read_text()
    assert "Unreviewed files excluded: `dummy.py`" in plan
    assert not any("dummy.py" in line and "| clean_sample |" in line
                   for line in plan.splitlines())


def test_sampler_shallow_drops_clean_and_deep_duplicates_flagged(tmp_path):
    root, a = detector_chain(tmp_path)
    manifest_path = a.audit / "_run/manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["review_depth"] = "shallow"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    rebuilt = rb.run_script("build_second_read_plan.py", root, "--audit-dir", a.audit)
    assert rebuilt.returncode == 0, rebuilt.stdout + rebuilt.stderr
    shallow = (a.audit / "plans/code_error_second_read_plan.md").read_text()
    assert "| clean_sample |" not in shallow
    manifest["review_depth"] = "deep"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    rebuilt = rb.run_script("build_second_read_plan.py", root, "--audit-dir", a.audit)
    assert rebuilt.returncode == 0, rebuilt.stdout + rebuilt.stderr
    deep = (a.audit / "plans/code_error_second_read_plan.md").read_text()
    detector_rows = [line for line in deep.splitlines()
                     if "requirements-recall.txt" in line and "| detector |" in line]
    assert len(detector_rows) == 2


def test_u7_handoff_interface_reserved_but_assignment_empty(tmp_path):
    a, shard = rb.make_b3b_shard(tmp_path, "claims")
    plan = a.audit / "plans/claims_second_read_plan.md"
    plan.write_text(plan.read_text().replace(
        "| detector | C-0142 |  |", "| handoff | C-0142 | H-0001 |"),
        encoding="utf-8")
    refused = rb.lint(a, "b3b-claims", shard=shard)
    assert refused.returncode == 1
    assert "Assigned Handoff IDs must remain empty until U7" in refused.stdout


def test_register_identifier_exhaustion_is_loud(tmp_path):
    _root, a = code_b3_boundary(tmp_path)
    plan = a.audit / "plans/code_error_review_plan.md"
    assert rb.lint(a, "b1-code").returncode == 0
    plan.write_text(plan.read_text().replace(
        "E-0100–E-0199", "E-0100–E-9999"), encoding="utf-8")
    refused = rb.lint(a, "b1-code")
    assert refused.returncode == 1
    assert "code-error register identifier space exhausted at E-9999" in refused.stdout


def test_detector_identifier_exhaustion_is_loud():
    with pytest.raises(dm.MappingError, match=(
            "code-error register identifier space exhausted at E-9999")):
        dm._parse_range(
            "Declared detector Error-ID range: E-9900–E-9999\n",
            "detector decisions",
        )


def test_seeded_detector_to_second_read_to_merge_chain(tmp_path):
    root, a = detector_chain(tmp_path)
    mapping = (a.audit / "_run/detector_mapping.md").read_text()
    plan_text = (a.audit / "plans/code_error_second_read_plan.md").read_text()
    assert "requirements-recall.txt" in mapping
    assert "`detector`" not in plan_text  # Reason is an exact vocabulary cell, not decoration.
    assert "| detector |" in plan_text
    lint = rb.load_script("lint_registers")
    alloc, _ = lint.second_read_allocations(
        lint.Lint(), a.audit / "plans/code_error_second_read_plan.md", "code")
    owner = next(row for row in alloc if "requirements-recall.txt" in row["Script Scope"])
    error_id = lint.RANGE_RE.search(owner["Error ID Range"]).group(1)
    plant_b = rb.error_row(
        error_id, etype="version_or_dependency_error",
        source="`requirements-recall.txt`", location="`requirements-recall.txt:2-3`",
        status="candidate", severity="1",
        desc="pandas is pinned to incompatible exact versions 2.2.2 and 1.5.3",
        why="no environment can satisfy both pins",
    )
    shard = rb.md_table(rb.ERROR_COLS, [plant_b]) + "\n" + rb.md_table(
        ["Script", "Outcome"], [["requirements-recall.txt", f"findings: {error_id}"]]
    ) + "\n" + typed_footer(
        [["OBS-0001", "candidate", error_id, "incompatible pandas pins", "—"]])
    shard_path = a.audit.parent / owner["Shard File"].strip().strip("`")
    shard_path.parent.mkdir(parents=True, exist_ok=True)
    shard_path.write_text(shard, encoding="utf-8")
    base_rows = lint.load_register(
        lint.Lint(), a.audit / "code_error_register.md", rb.ERROR_COLS)[1]
    a.write_register("_run/snapshots/code_b3b/code_error_register.md", rb.ERROR_COLS,
                     base_rows)
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS,
                     base_rows + [plant_b])
    a.write("_run/merge_report_code_b3b.json", json.dumps({
        "code_error_register.md": {"shard_rows": 1, "dedup_removed": 0, "added": 1},
        "footer_dispositions": [
            f"{owner['Shard File'].strip().strip('`')}#OBS-0001 | candidate:{error_id}"],
    }))
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    shard_states = {
        owner["Shard File"].strip().strip("`"): {"status": "done", "retries": 0}}
    for other in alloc:
        if other is owner:
            continue
        other_path = a.audit.parent / other["Shard File"].strip().strip("`")
        other_path.parent.mkdir(parents=True, exist_ok=True)
        scope = other["Script Scope"].strip().strip("`")
        other_path.write_text(
            rb.md_table(rb.ERROR_COLS, []) + "\n" +
            rb.md_table(["Script", "Outcome"], [[scope, "clean"]]) + "\n" +
            typed_footer(), encoding="utf-8")
        shard_states[other["Shard File"].strip().strip("`")] = {
            "status": "done", "retries": 0}
    manifest["stages"]["code_b3b"]["shards"] = shard_states
    a.write("_run/manifest.json", json.dumps(manifest))
    # Promote first (rename-then-lint): the lint reads the promoted canon.
    a.write_register("code_error_register.md", rb.ERROR_COLS,
                     base_rows + [plant_b])
    result = rb.lint(a, "b3b-code")
    assert result.returncode == 0, result.stdout + result.stderr
    status, note = fixture_score.check_clean_recall_chain(a.audit)
    assert status == "PASS", note


def test_b3b_baseline_ordering_pinned_structurally(tmp_path):
    """Checklist pin: the b3b baseline is post-b3d by construction — the
    builder refuses to run before code_b3d is certified done, and --check
    reads only the frozen code_b3b snapshot (no runtime mtime machinery)."""
    root, a = detector_chain(tmp_path)
    manifest_path = a.audit / "_run/manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["stages"]["code_b3d"]["status"] = "running"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    premature = rb.run_script(
        "build_second_read_plan.py", root, "--audit-dir", a.audit)
    assert premature.returncode == 1
    assert "code_b3d must be certified done" in premature.stderr
    manifest["stages"]["code_b3d"]["status"] = "done"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    unfrozen = rb.run_script(
        "build_second_read_plan.py", root, "--audit-dir", a.audit, "--check")
    assert unfrozen.returncode == 1
    assert "missing frozen b3b baseline register snapshot" in unfrozen.stderr


def test_fixture_chain_accepts_first_pass_recovery_of_plant_b(tmp_path):
    _root, a = detector_chain(tmp_path)
    plant_b = rb.error_row(
        "E-0101", etype="version_or_dependency_error",
        source="`requirements-recall.txt`",
        location="`requirements-recall.txt:2-3`", status="candidate", severity="1",
        desc="pandas exact pins 2.2.2 and 1.5.3 are mutually incompatible",
        why="no environment can satisfy both pins",
    )
    a.write_register(
        "_run/snapshots/code_b3d/code_error_register.md", rb.ERROR_COLS, [plant_b])
    status, note = fixture_score.check_clean_recall_chain(a.audit)
    assert status == "PASS", note
    assert "provenance vacuous" in note


def test_tier1_empty_clean_sample_finish_refused(tmp_path):
    root, a = detector_chain(tmp_path)
    plan_path = a.audit / "plans/code_error_second_read_plan.md"
    text = plan_path.read_text()
    text = "\n".join(line for line in text.splitlines()
                     if "| clean_sample |" not in line) + "\n"
    plan_path.write_text(text, encoding="utf-8")
    lint = rb.load_script("lint_registers")
    base_rows = lint.load_register(
        lint.Lint(), a.audit / "code_error_register.md", rb.ERROR_COLS)[1]
    a.write_register("_run/snapshots/code_b3b/code_error_register.md", rb.ERROR_COLS,
                     base_rows)
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, base_rows)
    a.write("_run/merge_report_code_b3b.json", json.dumps({
        "code_error_register.md": {"shard_rows": 0, "dedup_removed": 0, "added": 0},
        "footer_dispositions": [],
    }))
    # Keep only the detector allocation manifest-free; the corrupted missing clean row is
    # rejected by recomputation before worker-evidence details can matter.
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    manifest["stages"]["code_b3b"]["status"] = "running"
    cs.write_manifest_atomic(root, manifest)
    refused = cli(root, "finish", "--stage", "code_b3b", "--outcome", "done")
    assert refused.returncode != 0
    assert "generated second-read allocation is stale or bypassed" in refused.stderr


def test_tier1_empty_clean_sample_decision_patch_removes_failure(
        tmp_path, monkeypatch):
    _root, a = detector_chain(tmp_path)
    lint = rb.load_script("lint_registers")
    base_rows = lint.load_register(
        lint.Lint(), a.audit / "code_error_register.md", rb.ERROR_COLS)[1]
    a.write_register("_run/snapshots/code_b3b/code_error_register.md",
                     rb.ERROR_COLS, base_rows)
    plan_path = a.audit / "plans/code_error_second_read_plan.md"
    plan_path.write_text(
        "\n".join(line for line in plan_path.read_text().splitlines()
                  if "| clean_sample |" not in line) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(builder.PlanError, match="stale or bypassed"):
        builder.run(a.audit.parent, a.audit, plan_path, True)
    current = plan_path.read_text(encoding="utf-8")
    generated = current[current.index(builder.BEGIN):
                        current.index(builder.END) + len(builder.END)]
    monkeypatch.setattr(builder, "_render", lambda *_args: (generated, True))
    builder.run(a.audit.parent, a.audit, plan_path, True)


def claims_b3b_promoted(tmp_path):
    """A fully promoted, staging-free claims b3b run driven to done via CLI."""
    root, a = claims_b3_boundary(tmp_path)
    finished = cli(root, "finish", "--stage", "claims_b3", "--outcome", "done")
    assert finished.returncode == 0, finished.stdout + finished.stderr
    plan = (
        "# Claims second-read plan\n\n"
        "| Worker ID | File/Section Scope | Shard File | Claim ID Range | "
        "Output ID Range | Reason | Known Findings | Assigned Handoff IDs |\n"
        "| --- | --- | --- | --- | --- | --- | --- | --- |\n"
        "| S1 | sec 2 | `audit/_work_second_read/s1.md` | C-2000\u2013C-2049 | "
        "O-2000\u2013O-2024 | flagged | \u2014 |  |\n"
    )
    a.write("plans/claims_second_read_plan.md", plan)
    new_claim = rb.claims_row("C-2000", status="unclear")
    shard = rb.md_table(rb.CLAIMS_COLS, [new_claim]) + "\n" + rb.md_table(
        rb.OUTPUT_COLS, [])
    shard += "\nCoverage: flagged section reread in full.\n\n"
    shard += typed_footer(
        [["OBS-0001", "candidate", "C-2000", "second-read find", "\u2014"]])
    a.write("_work_second_read/s1.md", shard)
    a.write_register("_run/snapshots/claims_b3b/claims_register.md",
                     rb.CLAIMS_COLS, [])
    a.write_register("_run/snapshots/claims_b3b/output_register.md",
                     rb.OUTPUT_COLS, [])
    a.write_register("claims_register.md", rb.CLAIMS_COLS, [new_claim])
    a.write_register("output_register.md", rb.OUTPUT_COLS, [])
    a.write("_run/merge_report_claims_b3b.json", json.dumps({
        "claims_register.md": {"shard_rows": 1, "dedup_removed": 0, "added": 1},
        "output_register.md": {"shard_rows": 0, "dedup_removed": 0, "added": 0},
        "footer_dispositions": [
            "audit/_work_second_read/s1.md#OBS-0001 | candidate:C-2000"],
    }))
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    manifest["stages"]["claims_b3b"] = {
        "status": "running", "retries": 0,
        "shards": {"audit/_work_second_read/s1.md": {
            "status": "done", "retries": 0}},
    }
    cs.write_manifest_atomic(root, manifest)
    # Production promotion renames staging over canon: no staging survives.
    shutil.rmtree(a.audit / "_staging", ignore_errors=True)
    finished = cli(root, "finish", "--stage", "claims_b3b", "--outcome", "done")
    assert finished.returncode == 0, finished.stdout + finished.stderr
    return root, a


def test_tier1_b3b_disposition_tamper_refused_by_verify_run(tmp_path):
    """Finding-5 drill: the b3b leg matches the b3 leg through the CLI."""
    root, a = claims_b3b_promoted(tmp_path)
    clean = cli(root, "verify-run")
    assert clean.returncode == 0, clean.stdout + clean.stderr
    report_path = a.audit / "_run/merge_report_claims_b3b.json"
    report = json.loads(report_path.read_text())
    report["footer_dispositions"] = []
    report_path.write_text(json.dumps(report), encoding="utf-8")
    refused = cli(root, "verify-run")
    assert refused.returncode != 0
    assert ("typed footer entry audit/_work_second_read/s1.md#OBS-0001 "
            "is undispositioned") in refused.stderr


def test_b3_and_b3b_obligations_survive_post_b6_register_evolution(tmp_path):
    """Finding-1 regression: once b6 freezes its pre-merge snapshot and
    mutates canon statuses, verify-run still holds on immutable evidence."""
    root, a = claims_b3b_promoted(tmp_path)
    claims = (a.audit / "claims_register.md").read_text()
    a.write("_run/snapshots/claims_b6/claims_register.md", claims)
    a.write("_run/snapshots/claims_b6/output_register.md",
            (a.audit / "output_register.md").read_text())
    mutated = claims.replace(" unclear ", " confirmed ")
    assert mutated != claims
    (a.audit / "claims_register.md").write_text(mutated, encoding="utf-8")
    still = cli(root, "verify-run")
    assert still.returncode == 0, still.stdout + still.stderr


def test_code_b3b_zero_work_skip_certifies_through_cli(tmp_path):
    root, a = code_b3_boundary(tmp_path)
    shard = a.audit / "_code_errors/ce-01.md"
    shard.write_text(shard.read_text().replace(
        "| requirements.txt | clean |", "| requirements.txt | blocked: raw |"),
        encoding="utf-8")
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    manifest["stages"]["code_b3"]["status"] = "pending"
    manifest["stages"]["code_b3d"] = {"status": "done", "retries": 0}
    manifest["stages"]["code_b3b"] = {"status": "running", "retries": 0}
    cs.write_manifest_atomic(root, manifest)
    a.write_register("_run/snapshots/code_b3d/code_error_register.md",
                     rb.ERROR_COLS, [])
    built = rb.run_script("build_second_read_plan.py", root, "--audit-dir", a.audit)
    assert built.returncode == 0, built.stdout + built.stderr
    plan = (a.audit / "plans/code_error_second_read_plan.md").read_text()
    assert "| clean_sample |" not in plan and "| detector |" not in plan
    a.write_register("_run/snapshots/code_b3b/code_error_register.md",
                     rb.ERROR_COLS, [])
    a.write("_run/merge_report_code_b3b.json", json.dumps({
        "code_error_register.md": {
            "shard_rows": 0, "dedup_removed": 0, "added": 0},
        "footer_dispositions": [],
    }))
    shutil.rmtree(a.audit / "_staging", ignore_errors=True)
    finished = cli(root, "finish", "--stage", "code_b3b", "--outcome", "done")
    assert finished.returncode == 0, finished.stdout + finished.stderr


def test_candidate_mode_fp_ceiling_counts_each_register_row_once():
    expected = [{"key": "K1", "register": "code_errors", "path": "a.do",
                 "mechanism": "m1", "status_family": "candidate",
                 "benchmark_severity": 2, "anchors": []}]
    sheet = {"false_positive_ceiling": 1, "expected_candidates": expected}
    hit = {"id": "E-0001", "register": "code_errors", "path": "a.do",
           "mechanism": "m1", "status": "candidate", "severity": 2, "text": ""}
    stray = {"id": "E-0002", "register": "code_errors", "path": "a.do",
             "mechanism": "m2", "status": "candidate", "severity": 2, "text": ""}
    result = score.score_candidates(
        sheet, [hit, stray, {**stray, "path": "b.do"}])
    assert result["false_positive_ids"] == ["E-0002"]
    assert result["status"] == "score"
    doubled = score.score_candidates(sheet, [hit, {**hit, "id": "E-0003"}])
    assert doubled["status"] == "red"
    assert doubled["false_positive_ids"] == []
