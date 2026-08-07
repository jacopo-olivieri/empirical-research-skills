"""U4 per-stage effort apparatus and conventions-channel activation."""

import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

import regbuild as rb


assembler = rb.load_script("assemble_boundary")
contracts = rb.load_script("build_worker_contracts")
cs = rb.load_script("certify_stage")
cv = rb.load_script("cv_scan")
dispatch = rb.load_script("dispatch_tracking")
dm = rb.load_script("build_detector_mapping")
lint = rb.load_script("lint_registers")

pytestmark = pytest.mark.u4

CERTIFY = rb.SCRIPTS_DIR / "certify_stage.py"
ROLE_DOCS = [
    rb.SKILL_DIR / "SKILL.md",
    rb.SKILL_DIR / "references/pipeline-claims.md",
    rb.SKILL_DIR / "references/pipeline-code-errors.md",
    rb.SKILL_DIR / "references/pipeline-finalize.md",
]

CONV_A = rb.conventions_row(
    "fiscal-year boundary",
    category="fiscal_year_or_sample_window_boundary",
    definition="fiscal year begins in July (C-0142)",
    sites="`paper/main.tex:40`; C-0142",
)
CONV_B = rb.conventions_row(
    "income components",
    category="enumerated_member_list",
    definition="crop; livestock; wages (C-0310)",
    sites="C-0310",
)


def _cli(root, command, *args):
    return subprocess.run(
        [sys.executable, str(CERTIFY), command, "--package-root", str(root),
         *[str(arg) for arg in args]],
        capture_output=True, text=True,
    )


def _base_tree(tmp_path, *, name="package", mode="replication", initialize=False):
    root = tmp_path / name
    root.mkdir()
    (root / "source.py").write_text("VALUE = 1\n", encoding="utf-8")
    a = rb.AuditDir(root)
    extra = ({"allocation_override": {"purpose": "development", "allocation": []}}
             if mode == "replication" else {})
    a.write_manifest(mode=mode, scope_exclusions=[], off_limits=[], **extra)
    a.write_register("code_error_register.md", rb.ERROR_COLS, [])
    if initialize:
        initialized = _cli(root, "init")
        assert initialized.returncode == 0, initialized.stdout + initialized.stderr
        started = _cli(root, "start", "--stage", "code_b3d")
        assert started.returncode == 0, started.stdout + started.stderr
    a.write_register(
        "_run/snapshots/code_b3d/code_error_register.md", rb.ERROR_COLS, [])
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [])
    du = rb.run_script("emit_definition_use_bundles.py", root, "--audit-dir", a.audit)
    mf = rb.run_script("check_manifests.py", root, "--audit-dir", a.audit)
    assert du.returncode == 0, du.stdout + du.stderr
    assert mf.returncode == 0, mf.stdout + mf.stderr
    rb.emit_argument_contracts(a)
    rb.emit_path_derivations(a)
    return root, a


def _write_conventions(a, rows):
    return a.write(
        "_run/conventions.md",
        rb.register_text("Shared conventions", cv.CONVENTION_COLS, list(rows)),
    )


def _scan_text(verdict_rows, witness_rows=()):
    return (
        "# Conventions scan\n\n"
        + cv.VERDICTS_MARKER + "\n\n"
        + rb.md_table(cv.VERDICT_COLS, list(verdict_rows)) + "\n"
        + cv.WITNESSES_MARKER + "\n\n"
        + rb.md_table(cv.WITNESS_COLS, list(witness_rows))
    )


def _scan_both():
    return _scan_text(
        [
            [CONV_A[0], CONV_A[1], "divergent", "—", "—"],
            [CONV_B[0], CONV_B[1], "not_divergent",
             "do/labels.do@members literal", "all three stated members are present"],
        ],
        [[CONV_A[0], CONV_A[1], "do/build.do", "line 12",
          "the code starts the fiscal year in June rather than July"]],
    )


def _freeze_scan(a, text):
    live = a.write("_run/cv_scan.md", text)
    frozen = a.write("_run/snapshots/code_b3d/cv_scan.md", text)
    return live, frozen


def _write_decisions(a, rows):
    return a.write(
        "_run/detector_mapping_decisions.md",
        "# Detector decisions\n\n"
        "Declared detector Error-ID range: E-7000–E-7099\n\n"
        + rb.md_table(dm.DECISION_COLS, list(rows)),
    )


def _configure_complete_cv(root, a, *, scan_text=None, verdict_override=None):
    _write_conventions(a, [CONV_A, CONV_B])
    _freeze_scan(a, scan_text or _scan_both())
    sources = dm.parse_cv_sources(a.audit)
    decisions, candidates = [], []
    for source_id, source in sorted(sources.items()):
        verdict = verdict_override or source["verdict"]
        if verdict == "divergent":
            decisions.append(["CV", source_id, "E-7000", "new_candidate"])
            if not candidates:
                candidates.append(rb.error_row(
                    "E-7000", status="candidate", severity="2",
                    source="`do/build.do`", location="`do/build.do:12`",
                ))
        else:
            decisions.append(["CV", source_id, "—", "reviewed_not_divergent"])
    _write_decisions(a, decisions)
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, candidates)
    return sources


def _promote(a):
    os.replace(
        a.audit / "_staging/code_error_register.md",
        a.audit / "code_error_register.md",
    )


def _inprocess_validator(identifier, package_root, audit, _stage_entry):
    if identifier != "detector:mapping":
        return [f"unexpected validator {identifier}"]
    try:
        dm.check(package_root, audit, audit / "_run/detector_mapping.md")
    except dm.MappingError as exc:
        return [str(exc)]
    return []


def test_cv_identity_is_order_independent_and_list_subcommand_uses_same_constructor(tmp_path):
    first = tmp_path / "first.md"
    second = tmp_path / "second.md"
    rows = [
        [CONV_A[0], CONV_A[1], "divergent", "—", "—"],
        [CONV_B[0], CONV_B[1], "not_divergent",
         "do/labels.do@members literal", "the stated members match"],
    ]
    witnesses = [
        [CONV_A[0], CONV_A[1], "do/a.do", "line 4", "June is used"],
        [CONV_A[0], CONV_A[1], "do/b.do", "cutoff literal", "June is used"],
    ]
    first.write_text(_scan_text(rows, witnesses), encoding="utf-8")
    second.write_text(_scan_text(list(reversed(rows)), list(reversed(witnesses))),
                      encoding="utf-8")
    identity = lambda sources: {
        source.source_id: tuple(sorted(w.witness_id for w in source.witnesses))
        for source in sources
    }
    assert identity(cv.parse_scan(first)) == identity(cv.parse_scan(second))

    root, a = _base_tree(tmp_path, name="listing")
    _write_conventions(a, [CONV_A, CONV_B])
    _freeze_scan(a, first.read_text(encoding="utf-8"))
    result = rb.run_script(
        "build_detector_mapping.py", root, "--audit-dir", a.audit,
        "--list-cv-sources",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    parsed = dm.parse_cv_sources(a.audit)
    assert all(source_id in result.stdout for source_id in parsed)
    assert "| Convention | Source ID | Witness IDs | Verdict |" in result.stdout


def test_cv_identity_collision_refuses(tmp_path, monkeypatch):
    path = tmp_path / "scan.md"
    path.write_text(_scan_text([
        ["first", "id_or_merge_key", "not_divergent", "do/a.do@line 1", "matches"],
        ["second", "id_or_merge_key", "not_divergent", "do/b.do@line 2", "matches"],
    ]), encoding="utf-8")
    monkeypatch.setattr(cv, "_short_hash", lambda _payload: "0" * 12)
    with pytest.raises(cv.CVScanError, match="source identity collision"):
        cv.parse_scan(path)


@pytest.mark.parametrize("mutation, token", [
    (lambda text: text.replace(cv.VERDICTS_MARKER, ""), "must appear exactly once"),
    (lambda text: text.replace(
        f"| {CONV_A[0]} | {CONV_A[1]} | divergent |",
        f"| {CONV_B[0]} | {CONV_B[1]} | divergent |", 1),
     "more than one terminal verdict"),
    (lambda text: text.replace("| do/build.do | line 12 |", "| — | line 12 |"),
     "empty File Path"),
])
def test_cv_scan_parser_refuses_malformed_terminal_records(tmp_path, mutation, token):
    path = tmp_path / "scan.md"
    path.write_text(mutation(_scan_both()), encoding="utf-8")
    with pytest.raises(cv.CVScanError, match=token):
        cv.parse_scan(path)


def test_populated_cv_mapping_emits_and_checks_both_verdict_shapes(tmp_path):
    root, a = _base_tree(tmp_path)
    sources = _configure_complete_cv(root, a)
    dm.emit(root, a.audit, a.audit / "_run/detector_mapping.md")
    _declared, _display, rows = dm.load_mapping(a.audit / "_run/detector_mapping.md")
    cv_rows = [row for row in rows if row["Channel"] == "CV"]
    assert {row["Mapping Kind"] for row in cv_rows} == {
        "new_candidate", "reviewed_not_divergent",
    }
    assert {row["Source ID"] for row in cv_rows} == set(sources)
    reviewed = next(row for row in cv_rows
                    if row["Mapping Kind"] == "reviewed_not_divergent")
    assert reviewed["Error ID"] == "—"
    assert reviewed["Site Anchor"].startswith("audit/_run/cv_scan.md:verdict:")
    _promote(a)
    dm.check(root, a.audit, a.audit / "_run/detector_mapping.md")


@pytest.mark.parametrize("mode", ["replication", "code_errors_only"])
def test_cv_explicit_zero_is_exact_in_both_modes(tmp_path, mode):
    root, a = _base_tree(tmp_path, mode=mode, initialize=True)
    if mode == "replication":
        _write_conventions(a, [])
    _write_decisions(a, [])
    dm.emit(root, a.audit, a.audit / "_run/detector_mapping.md")
    text = (a.audit / "_run/detector_mapping.md").read_text(encoding="utf-8")
    assert text.count(dm.CV_ZERO) == 1
    _promote(a)
    dm.check(root, a.audit, a.audit / "_run/detector_mapping.md")
    finished = _cli(root, "finish", "--stage", "code_b3d", "--outcome", "done")
    assert finished.returncode == 0, finished.stdout + finished.stderr


def test_replication_absent_conventions_refuses_with_b3c_dependency(tmp_path):
    root, a = _base_tree(tmp_path, initialize=True)
    _write_decisions(a, [])
    result = rb.run_script("build_detector_mapping.py", root, "--audit-dir", a.audit)
    assert result.returncode != 0
    assert "missing conventions artifact" in result.stderr
    assert "wait for claims_b3c" in result.stderr

    a.write("_run/detector_mapping.md", dm.render_mapping(
        "E-7000–E-7099", {"DU": [], "MF": [], "CV": []}))
    _promote(a)
    manifest = a.audit / "_run/manifest.json"
    before = manifest.read_bytes()
    finished = _cli(root, "finish", "--stage", "code_b3d", "--outcome", "done")
    assert finished.returncode != 0
    assert "missing conventions artifact" in finished.stderr
    assert "wait for claims_b3c" in finished.stderr
    assert manifest.read_bytes() == before


def test_code_only_refuses_stray_cv_artifacts_and_decisions(tmp_path):
    root, a = _base_tree(tmp_path, mode="code_errors_only")
    _write_conventions(a, [])
    _write_decisions(a, [["CV", "CV-aaaaaaaaaaaa", "—", "reviewed_not_divergent"]])
    result = rb.run_script("build_detector_mapping.py", root, "--audit-dir", a.audit)
    assert result.returncode != 0
    assert "code-errors-only mode refuses" in result.stderr


def test_cv_closure_refuses_uncovered_convention_and_code_b3d_manifest_is_unchanged(tmp_path):
    root, a = _base_tree(tmp_path, initialize=True)
    _write_conventions(a, [CONV_A, CONV_B])
    partial = _scan_text(
        [[CONV_A[0], CONV_A[1], "divergent", "—", "—"]],
        [[CONV_A[0], CONV_A[1], "do/build.do", "line 12", "June is used"]],
    )
    _freeze_scan(a, partial)
    source = cv.parse_scan(a.audit / "_run/cv_scan.md")[0]
    _write_decisions(a, [["CV", source.source_id, "E-7000", "new_candidate"]])
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [
        rb.error_row("E-7000", status="candidate", severity="2")])
    emitted = rb.run_script("build_detector_mapping.py", root, "--audit-dir", a.audit)
    assert emitted.returncode != 0
    assert CONV_B[0] in emitted.stderr

    a.write("_run/detector_mapping.md", dm.render_mapping(
        "E-7000–E-7099", {"DU": [], "MF": [], "CV": []}))
    _promote(a)
    manifest = a.audit / "_run/manifest.json"
    before = manifest.read_bytes()
    finished = _cli(root, "finish", "--stage", "code_b3d", "--outcome", "done")
    assert finished.returncode != 0
    assert CONV_B[0] in finished.stderr
    assert manifest.read_bytes() == before


@pytest.mark.parametrize("case, token", [
    ("missing_scan", "missing conventions scan artifact"),
    ("missing_decision", "unmapped detector source"),
    ("unknown_decision", "decision names unknown detector source"),
    ("empty_with_decision", "decision names unknown detector source"),
])
def test_cv_closure_refusal_variants(tmp_path, case, token):
    root, a = _base_tree(tmp_path)
    if case == "empty_with_decision":
        _write_conventions(a, [])
        _write_decisions(a, [["CV", "CV-aaaaaaaaaaaa", "—", "reviewed_not_divergent"]])
    else:
        _write_conventions(a, [CONV_B])
        if case != "missing_scan":
            scan = _scan_text([[CONV_B[0], CONV_B[1], "not_divergent",
                                "do/labels.do@line 4", "members match"]])
            _freeze_scan(a, scan)
        if case == "missing_decision" or case == "missing_scan":
            _write_decisions(a, [])
        else:
            source = cv.parse_scan(a.audit / "_run/cv_scan.md")[0]
            _write_decisions(a, [
                ["CV", source.source_id, "—", "reviewed_not_divergent"],
                ["CV", "CV-aaaaaaaaaaaa", "—", "reviewed_not_divergent"],
            ])
    with pytest.raises(dm.MappingError, match=token):
        dm.emit(root, a.audit, a.audit / "_run/detector_mapping.md")


def test_tier1_cv_closure_test_has_teeth(tmp_path, monkeypatch):
    root, a = _base_tree(tmp_path, initialize=True)
    _write_conventions(a, [CONV_A, CONV_B])
    partial = _scan_text(
        [[CONV_A[0], CONV_A[1], "divergent", "—", "—"]],
        [[CONV_A[0], CONV_A[1], "do/build.do", "line 12", "June is used"]],
    )
    _freeze_scan(a, partial)
    source = cv.parse_scan(a.audit / "_run/cv_scan.md")[0]
    _write_decisions(a, [["CV", source.source_id, "E-7000", "new_candidate"]])
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [
        rb.error_row("E-7000", status="candidate", severity="2")])
    monkeypatch.setattr(dm, "_validate_cv_closure", lambda *_args: None)
    dm.emit(root, a.audit, a.audit / "_run/detector_mapping.md")
    _promote(a)
    monkeypatch.setattr(cs, "_run_validator", _inprocess_validator)
    cs.finish_stage(root, "code_b3d", "done")
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    assert manifest["stages"]["code_b3d"]["status"] == "done"


def test_reviewed_not_divergent_requires_matching_evidence_and_good_receipt_passes(tmp_path):
    bad_root, bad = _base_tree(tmp_path, name="bad")
    _write_conventions(bad, [CONV_A])
    divergent = _scan_text(
        [[CONV_A[0], CONV_A[1], "divergent", "—", "—"]],
        [[CONV_A[0], CONV_A[1], "do/build.do", "line 12", "June is used"]],
    )
    _freeze_scan(bad, divergent)
    source = cv.parse_scan(bad.audit / "_run/cv_scan.md")[0]
    _write_decisions(bad, [["CV", source.source_id, "—", "reviewed_not_divergent"]])
    with pytest.raises(dm.MappingError, match="conflicts with divergent verdict"):
        dm.emit(bad_root, bad.audit, bad.audit / "_run/detector_mapping.md")

    good_root, good = _base_tree(tmp_path, name="good")
    _write_conventions(good, [CONV_B])
    conforming = _scan_text([[CONV_B[0], CONV_B[1], "not_divergent",
                              "do/labels.do@line 4", "all members match"]])
    _freeze_scan(good, conforming)
    source = cv.parse_scan(good.audit / "_run/cv_scan.md")[0]
    _write_decisions(good, [["CV", source.source_id, "—", "reviewed_not_divergent"]])
    dm.emit(good_root, good.audit, good.audit / "_run/detector_mapping.md")
    _promote(good)
    dm.check(good_root, good.audit, good.audit / "_run/detector_mapping.md")


def test_tier1_reviewed_not_divergent_test_has_teeth(tmp_path, monkeypatch):
    root, a = _base_tree(tmp_path, initialize=True)
    _write_conventions(a, [CONV_A])
    scan = _scan_text(
        [[CONV_A[0], CONV_A[1], "divergent", "—", "—"]],
        [[CONV_A[0], CONV_A[1], "do/build.do", "line 12", "June is used"]],
    )
    _freeze_scan(a, scan)
    source = cv.parse_scan(a.audit / "_run/cv_scan.md")[0]
    _write_decisions(a, [["CV", source.source_id, "—", "reviewed_not_divergent"]])
    monkeypatch.setattr(dm, "_validate_cv_decision", lambda *_args: None)
    dm.emit(root, a.audit, a.audit / "_run/detector_mapping.md")
    _promote(a)
    monkeypatch.setattr(cs, "_run_validator", _inprocess_validator)
    cs.finish_stage(root, "code_b3d", "done")
    assert json.loads((a.audit / "_run/manifest.json").read_text())[
        "stages"]["code_b3d"]["status"] == "done"


def test_verify_run_catches_promoted_cv_row_disguised_as_reviewed(tmp_path):
    root, a = _base_tree(tmp_path, initialize=True)
    _write_conventions(a, [CONV_A])
    scan = _scan_text(
        [[CONV_A[0], CONV_A[1], "divergent", "—", "—"]],
        [[CONV_A[0], CONV_A[1], "do/build.do", "line 12", "June is used"]],
    )
    _freeze_scan(a, scan)
    source = cv.parse_scan(a.audit / "_run/cv_scan.md")[0]
    _write_decisions(a, [["CV", source.source_id, "E-7000", "new_candidate"]])
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [
        rb.error_row("E-7000", status="candidate", severity="2")])
    dm.emit(root, a.audit, a.audit / "_run/detector_mapping.md")
    _promote(a)
    finished = _cli(root, "finish", "--stage", "code_b3d", "--outcome", "done")
    assert finished.returncode == 0, finished.stdout + finished.stderr

    mapping = a.audit / "_run/detector_mapping.md"
    mapping.write_text(
        mapping.read_text().replace(
            "| E-7000 | new_candidate |", "| — | reviewed_not_divergent |"
        ), encoding="utf-8")
    a.write_register("code_error_register.md", rb.ERROR_COLS, [])
    verified = _cli(root, "verify-run")
    assert verified.returncode != 0
    assert "code_b3d" in verified.stderr


def test_verify_run_catches_hand_deleted_cv_mapping_row(tmp_path):
    root, a = _base_tree(tmp_path, initialize=True)
    _write_conventions(a, [CONV_A])
    scan = _scan_text(
        [[CONV_A[0], CONV_A[1], "divergent", "—", "—"]],
        [[CONV_A[0], CONV_A[1], "do/build.do", "line 12", "June is used"]],
    )
    _freeze_scan(a, scan)
    source = cv.parse_scan(a.audit / "_run/cv_scan.md")[0]
    _write_decisions(a, [["CV", source.source_id, "E-7000", "new_candidate"]])
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [
        rb.error_row("E-7000", status="candidate", severity="2")])
    dm.emit(root, a.audit, a.audit / "_run/detector_mapping.md")
    _promote(a)
    finished = _cli(root, "finish", "--stage", "code_b3d", "--outcome", "done")
    assert finished.returncode == 0, finished.stdout + finished.stderr

    mapping = a.audit / "_run/detector_mapping.md"
    kept = [line for line in mapping.read_text(encoding="utf-8").splitlines()
            if "new_candidate" not in line]
    mapping.write_text("\n".join(kept) + "\n", encoding="utf-8")
    verified = _cli(root, "verify-run")
    assert verified.returncode != 0
    assert "code_b3d" in verified.stderr


def test_verify_run_binds_live_scan_and_cv_section_to_snapshot_bytes(tmp_path):
    root, a = _base_tree(tmp_path, initialize=True)
    _write_conventions(a, [CONV_B])
    scan = _scan_text([[CONV_B[0], CONV_B[1], "not_divergent",
                        "do/labels.do@line 4", "all members match"]])
    _freeze_scan(a, scan)
    source = cv.parse_scan(a.audit / "_run/cv_scan.md")[0]
    _write_decisions(a, [["CV", source.source_id, "—", "reviewed_not_divergent"]])
    dm.emit(root, a.audit, a.audit / "_run/detector_mapping.md")
    _promote(a)
    finished = _cli(root, "finish", "--stage", "code_b3d", "--outcome", "done")
    assert finished.returncode == 0, finished.stdout + finished.stderr

    live = a.audit / "_run/cv_scan.md"
    live.write_text(live.read_text().replace("not_divergent", "divergent"),
                    encoding="utf-8")
    verified = _cli(root, "verify-run")
    assert verified.returncode != 0
    assert "differs from frozen code_b3d snapshot" in verified.stderr

    live.write_bytes((a.audit / "_run/snapshots/code_b3d/cv_scan.md").read_bytes())
    mapping = a.audit / "_run/detector_mapping.md"
    mapping.write_text(
        mapping.read_text().replace(dm.MARKERS[3], "\n" + dm.MARKERS[3]),
        encoding="utf-8")
    with pytest.raises(dm.MappingError, match="CV section differs byte-for-byte"):
        dm.check(root, a.audit, mapping)


def _reviewed_filter_case(tmp_path, name, mappings):
    root = tmp_path / name
    root.mkdir()
    a = rb.AuditDir(root)
    a.write("_run/detector_mapping.md", rb.detector_mapping_artifact(mappings))
    a.write_register("code_error_register.md", rb.ERROR_COLS, [])
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [])
    (a.audit / "_code_error_recheck").mkdir(parents=True, exist_ok=True)
    a.write("_run/dismissal_receipts.md",
            "# Dismissal receipts\n\n" + assembler.verifier.ZERO_RECEIPTS + "\n")
    assembled = assembler.assemble(a.audit, a.audit / "_staging/code_error_register.md")
    checker = lint.Lint()
    lint.check_detector_mapping_b4(
        checker, a.audit, a.audit / "plans/code_error_recheck_plan.md", [])
    lint.check_detector_mapping_b6(checker, a.audit)
    return assembler.render(assembled[0], assembled[1]), checker.errors


def test_reviewed_not_divergent_is_filtered_from_assembler_and_b4_b6_lints(tmp_path):
    empty = _reviewed_filter_case(tmp_path, "empty", [])
    reviewed = _reviewed_filter_case(
        tmp_path, "reviewed",
        [("CV-aaaaaaaaaaaa", "—", "reviewed_not_divergent")],
    )
    assert reviewed == empty


def test_divergent_cv_mapping_flows_through_b6_like_other_mapped_rows(tmp_path):
    mappings = [("CV-aaaaaaaaaaaa", "E-0101", "new_candidate")]
    before = [rb.error_row("E-0101", status="candidate", severity="2")]
    final = [rb.error_row("E-0101", status="confirmed", severity="2")]
    inventory = [("E-0101", "detector", "CV-aaaaaaaaaaaa")]
    clusters = [("K1", "detector", "E-0101", "`audit/_code_error_recheck/k1.md`")]
    a = rb.make_b6_code(
        tmp_path, before_rows=before, final_rows=final,
        inventory=inventory, clusters=clusters, mappings=mappings,
        ledger_rows=[rb.ledger_row("E-0101", evidence="CV-aaaaaaaaaaaa")],
    )
    result = rb.lint(a, "b6-code")
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("mutation, token", [
    (lambda effort: effort.pop("codemap"), "missing role key"),
    (lambda effort: effort.__setitem__("not_a_role", "high"), "unknown role key"),
    (lambda effort: effort.__setitem__("codemap", "ultra"), "invalid effort tier"),
])
def test_init_refuses_incomplete_unknown_or_invalid_effort_map(tmp_path, mutation, token):
    root = tmp_path / "package"
    root.mkdir()
    (root / "source.py").write_text("VALUE = 1\n", encoding="utf-8")
    a = rb.AuditDir(root)
    effort = dict(dispatch.DEFAULT_EFFORT_MAP)
    mutation(effort)
    a.write_manifest(mode="code_errors_only", effort_map=effort,
                     scope_exclusions=[], off_limits=[])
    manifest = a.audit / "_run/manifest.json"
    before = manifest.read_bytes()
    with pytest.raises(cs.CertificationError, match=token):
        cs.init_run(root)
    assert manifest.read_bytes() == before
    assert not (a.audit / "_run/RUNNING").exists()


def test_init_accepts_and_preserves_complete_effort_exceptions(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    (root / "source.py").write_text("VALUE = 1\n", encoding="utf-8")
    a = rb.AuditDir(root)
    effort = dict(dispatch.DEFAULT_EFFORT_MAP)
    effort["codemap"] = "max"
    a.write_manifest(mode="code_errors_only", effort_map=effort,
                     scope_exclusions=[], off_limits=[])
    cs.init_run(root)
    assert json.loads((a.audit / "_run/manifest.json").read_text())[
        "effort_map"] == effort


def test_dispatch_role_table_defaults_and_carriers_cover_expected_stage_role_sites():
    expected_sites = Counter({
        ("b0", "codemap"): 1,
        ("claims_b1", "claims_b1_planner"): 1,
        ("claims_b2", "claims_b2_section"): 1,
        ("claims_b3", "claims_b3_merge"): 1,
        ("claims_b3c", "claims_b3c_conventions"): 1,
        ("claims_b3b", "claims_b3b_second_read"): 1,
        ("claims_b3b", "claims_b3b_merge"): 1,
        ("claims_adjudication", "claims_adjudication"): 1,
        ("claims_b5", "claims_b5_recheck_cluster"): 1,
        ("claims_b6a", "claims_b6_merge"): 1,
        ("claims_b5s", "claims_b5_recheck_cluster"): 1,
        ("claims_b6b", "claims_b6_merge"): 1,
        ("code_b1", "code_b1_planner"): 1,
        ("code_b2", "code_b2_chunk"): 1,
        ("code_b3", "code_b3_merge"): 1,
        ("code_b3d", "b3d_conventions_scan"): 1,
        ("code_b3b", "code_b3b_second_read"): 1,
        ("code_b3b", "code_b3b_merge"): 1,
        ("code_b5", "code_b5_recheck_cluster"): 1,
        ("code_b6a", "code_b6_merge"): 1,
        ("code_b5s", "code_b5_recheck_cluster"): 1,
        ("code_b6b", "code_b6_merge"): 1,
        ("b7", "b7_cross_linker"): 1,
        ("b7", "b7_claim_recheck"): 1,
        ("b8", "b8_rewriter"): 1,
        ("claims_adjudication_lineage", "claims_adjudication_lineage"): 1,
    })
    observed_sites = Counter()
    # SKILL.md declares only the b0 CODEMAP dispatch site; parse it rather
    # than seeding it, so a deleted or duplicated declaration is caught.
    skill_text = ROLE_DOCS[0].read_text(encoding="utf-8")
    for role in re.findall(r"role:\s*`([a-z0-9_]+)`", skill_text):
        observed_sites[("b0", role)] += 1
    for path, stream in (
        (ROLE_DOCS[1], "claims"),
        (ROLE_DOCS[2], "code"),
        (ROLE_DOCS[3], None),
    ):
        text = path.read_text(encoding="utf-8")
        headings = []
        for match in re.finditer(
                r"(?m)^## (b(?:\d+[a-z]?|C)|claims_adjudication(?:_lineage)?)\b", text):
            raw = match.group(1)
            headings.append((
                match.start(), raw if raw.startswith("claims_adjudication")
                else (f"{stream}_{raw}" if stream else raw),
            ))
        for match in re.finditer(r"role:\s*`([a-z0-9_]+)`", text):
            stage = next(value for position, value in reversed(headings)
                         if position < match.start())
            observed_sites[(stage, match.group(1))] += 1
    assert observed_sites == expected_sites
    dispatch_roles = [role for (_stage, role) in observed_sites]
    skill = (rb.SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
    table_pairs = re.findall(
        r"(?m)^\| `([a-z0-9_]+)` \| .* \| (low|medium|high|xhigh|max) \|$",
        skill,
    )
    table_roles = [role for role, _tier in table_pairs]
    assert set(dispatch_roles) == set(table_roles) == set(dispatch.ROLE_KEYS)
    assert set(dispatch.DEFAULT_EFFORT_MAP) == set(dispatch.ROLE_KEYS)
    assert set(dispatch.DEFAULT_EFFORT_MAP.values()) <= set(dispatch.EFFORT_TIERS)
    # U17: the role-key table's effort values are compared to the code map by
    # value, not just validated as legal tiers.
    assert dict(table_pairs) == dispatch.DEFAULT_EFFORT_MAP
    assert dispatch.DEFAULT_EFFORT_MAP["b8_rewriter"] == "low"
    assert all(tier == "medium" for role, tier in dispatch.DEFAULT_EFFORT_MAP.items()
               if role != "b8_rewriter")

    carriers = sorted((rb.SKILL_DIR / "agents/claude").glob("rca-carrier-*.md"))
    assert len(carriers) == len(dispatch.EFFORT_TIERS) == 5
    observed = {}
    for path in carriers:
        text = path.read_text(encoding="utf-8")
        tier = re.search(r"(?m)^effort: (\w+)$", text).group(1)
        observed[path.stem] = tier
        assert "  Stop:" in text
        assert "dispatch_tracking.py" in text
    assert observed == {f"rca-carrier-{tier}": tier for tier in dispatch.EFFORT_TIERS}
    linker = (rb.SKILL_DIR.parents[1] / "scripts/link-skills.sh").read_text()
    assert "*/agents/claude/*.md" in linker


@pytest.mark.u17
def test_skill_manifest_template_effort_values_match_default_map():
    """U17 lockstep extension: the SKILL.md manifest template's effort_map is
    compared to DEFAULT_EFFORT_MAP by value. Regex extraction of the braced
    block, not json.loads of the whole fence — the template is a documentation
    sketch and is not guaranteed to stay valid JSON. Exactly one effort_map
    block must exist: zero or two would let the extraction silently match
    nothing (or the wrong block)."""
    skill = (rb.SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
    blocks = re.findall(r"\"effort_map\"\s*:\s*\{([^{}]*)\}", skill)
    assert len(blocks) == 1, f"expected exactly one effort_map block, found {len(blocks)}"
    parsed = dict(re.findall(r"\"([a-z0-9_]+)\"\s*:\s*\"([a-z]+)\"", blocks[0]))
    assert parsed == dispatch.DEFAULT_EFFORT_MAP


def test_conventions_scan_worker_contract_is_generated(tmp_path):
    artifacts = contracts.build_artifacts(
        rb.SKILL_DIR / "references/registers.md", tmp_path / "audit")
    key = "_run/contracts/conventions_scan.md"
    assert key in artifacts
    text = artifacts[key].read_text(encoding="utf-8")
    assert "Untrusted content" in text and "Secret handling" in text


def test_dispatch_ledger_appends_rows_and_enforces_monotone_sequence(tmp_path):
    audit = tmp_path / "audit"
    path = dispatch.append_dispatch(
        audit, "codemap", "rca-carrier-high", "b0", "audit/CODEMAP.md", 1)
    before = path.read_text(encoding="utf-8")
    dispatch.append_dispatch(
        audit, "code_b2_chunk", "rca-carrier-high", "code_b2",
        "audit/_code_errors/k1.md", 2)
    after = path.read_text(encoding="utf-8")
    assert after.startswith(before)
    assert "| code_b2_chunk | rca-carrier-high | code_b2 |" in after
    with pytest.raises(dispatch.DispatchError, match="not greater"):
        dispatch.append_dispatch(
            audit, "b8_rewriter", "rca-carrier-medium", "b8",
            "audit/_staging/code_error_register.md", 2)


def test_hook_audit_root_resolution_prefers_flag_then_hook_cwd_then_project_dir(
        tmp_path, monkeypatch):
    explicit = tmp_path / "explicit"
    assert dispatch.resolve_audit_dir(explicit, {"cwd": str(tmp_path)}) == explicit
    assert dispatch.resolve_audit_dir(None, {"cwd": str(tmp_path)}) \
        == tmp_path / "audit"
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path / "project"))
    assert dispatch.resolve_audit_dir(None, {}) == tmp_path / "project" / "audit"
    monkeypatch.delenv("CLAUDE_PROJECT_DIR")
    assert dispatch.resolve_audit_dir(None, None) == Path("audit")


def test_hook_event_write_is_atomic_and_accounting_reports_aggregate_gaps(tmp_path):
    audit = tmp_path / "audit"
    dispatch.append_dispatch(
        audit, "codemap", "rca-carrier-high", "b0", "audit/CODEMAP.md", 1)
    transcript = tmp_path / "transcript.jsonl"
    transcript.write_text(
        '{"prompt":"RCA-DISPATCH role=codemap stage=b0 build the codemap"}\n',
        encoding="utf-8",
    )
    path = dispatch.write_event(audit, "rca-carrier-high", {
        "session_id": "session-1", "model": "model-x",
        "transcript_path": str(transcript),
    })
    event = json.loads(path.read_text(encoding="utf-8"))
    assert event["role_key"] == "codemap" and event["stage_key"] == "b0"
    assert event["carrier"] == "rca-carrier-high"
    assert not list(path.parent.glob(".*"))
    report = dispatch.accounting_report(audit)
    assert "| b0 | codemap | 1 | 1 | none |" in report

    dispatch.append_dispatch(
        audit, "b8_rewriter", "rca-carrier-medium", "b8",
        "audit/_staging/code_error_register.md", 2)
    report = dispatch.accounting_report(audit)
    assert "| b8 | b8_rewriter | 1 | 0 | ledger=1, events=0 |" in report
