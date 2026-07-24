"""U3b structured adjudication contract, receipts, boundary, and drills."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import regbuild as rb


assembler = rb.load_script("assemble_boundary")
bootstrap = rb.load_script("bootstrap_conda_oracle")
certify = rb.load_script("certify_stage")
dm = rb.load_script("build_detector_mapping")
lint = rb.load_script("lint_registers")
mechanism = rb.load_script("mechanism_schema")
manifests = rb.load_script("check_manifests")
scorer = rb.load_script("score_fixture")
verifier = rb.load_script("verify_dismissals")

pytestmark = pytest.mark.u3

CERTIFY = rb.SCRIPTS_DIR / "certify_stage.py"
DU_SOURCE = "DU-aaaaaaaaaaaa"
DU_WITNESS = "DUW-111111111111"
MF_SOURCE = "MF-bbbbbbbbbbbb"
MF_WITNESS = "MFW-222222222222"


def _cli(root, command, *args):
    return subprocess.run(
        [sys.executable, str(CERTIFY), command, "--package-root", str(root),
         *[str(arg) for arg in args]], capture_output=True, text=True,
    )


def _mapping(channel="DU", *, eid="E-7000", anchor="do/probe.do:1",
             source=None, witness=None):
    source = source or (DU_SOURCE if channel == "DU" else MF_SOURCE)
    witness = witness or (DU_WITNESS if channel == "DU" else MF_WITNESS)
    row = {
        "Channel": channel, "Source ID": source, "Witness ID": witness,
        "Error ID": eid, "Mapping Kind": "new_candidate", "Site Anchor": anchor,
    }
    return dm.render_mapping(
        "E-7000–E-7099",
        {"DU": [row] if channel == "DU" else [],
         "MF": [row] if channel == "MF" else []},
    ), row


def _shard_text(ledger_rows, outcome_rows=(), mf_records=(), probe_records=()):
    text = rb.register_text("Recheck ledger", rb.CODE_LEDGER_COLS, ledger_rows)
    text += "\n### Witness outcomes\n\n" + rb.md_table(
        rb.WITNESS_OUTCOME_COLS, list(outcome_rows))
    text += "\n### Verification records\n\n"
    if mf_records:
        text += rb.md_table(rb.MF_VERIFICATION_COLS, list(mf_records)) + "\n"
    if probe_records:
        text += rb.md_table(rb.PROBE_VERIFICATION_COLS, list(probe_records)) + "\n"
    if not mf_records and not probe_records:
        text += "No verification records.\n"
    text += "\n### Footer dispositions\n\n" + rb.md_table(rb._lint_mod.FOOTER_COLS, [])
    return text


def _probe_record(source=DU_SOURCE, witness=DU_WITNESS, record_id="VR-0001",
                  harness="probe.py"):
    return ["DU", record_id, source, witness, "probe exits successfully",
            harness, "accepted", "do/probe.do:1"]


def _mf_record(path, source=MF_SOURCE, witness=MF_WITNESS,
               record_id="VR-0001"):
    return ["MF", record_id, source, witness,
            hashlib.sha256(path.read_bytes()).hexdigest(), "micromamba",
            "pinned", "micromamba env create --offline", "accepted", "yes"]


def _case(tmp_path, *, channel="DU", verdict="confirmed_error",
          proposed_status=None, proposed_severity=None, outcome=True,
          records=True, eid="E-7000", anchor=None, final_status=None,
          final_severity=None):
    root = tmp_path / "package"
    root.mkdir()
    a = rb.AuditDir(root)
    anchor = anchor or ("do/probe.do:1" if channel == "DU" else "environment.yml:1")
    mapping_text, mapping = _mapping(channel, eid=eid, anchor=anchor)
    a.write("_run/detector_mapping.md", mapping_text)
    source, witness = mapping["Source ID"], mapping["Witness ID"]
    etype = ("sample_filter_or_flag_error" if channel == "DU"
             else "version_or_dependency_error")
    path = root / anchor.rsplit(":", 1)[0]
    path.parent.mkdir(parents=True, exist_ok=True)
    if channel == "DU":
        path.write_text("display 1\n", encoding="utf-8")
    elif not path.exists():
        path.write_text("name: legal\ndependencies: []\n", encoding="utf-8")
    a.write_manifest(stages={
        "code_b5": {"status": "done", "retries": 0,
                    "shards": {"audit/_code_error_recheck/k1.md":
                               {"status": "done", "retries": 0}}},
    })
    inventory = [(eid, "detector", source)]
    clusters = [("K1", "detector", eid, "`audit/_code_error_recheck/k1.md`")]
    a.write("plans/code_error_recheck_plan.md",
            rb.recheck_plan_text("code", inventory, clusters))
    a.write("plans/code_error_second_read_plan.md", "# Code second-read plan\n")
    a.write("plans/code_error_review_plan.md", rb._code_b1_plan())
    status_map = {
        "confirmed_error": "confirmed", "not_error": "not_error",
        "confirmation_needed": "confirmation_needed", "blocked": "blocked",
        "deferred": "blocked", "duplicate": "duplicate_of:E-7001",
    }
    severity = "—" if verdict in {"not_error", "duplicate"} else "2"
    ledger = rb.code_ledger_row(
        eid, evidence=source, verdict=verdict,
        proposed_status=proposed_status or status_map[verdict],
        proposed_severity=(severity if proposed_severity is None else proposed_severity),
        accepted_type=etype, witness_ids=(witness if outcome else "—"),
        duplicate_target=("E-7001" if verdict == "duplicate" else "—"),
        record_ids=("VR-0001" if verdict == "not_error" and records else "—"),
        note=("off-limits: restricted input" if verdict == "deferred"
              else "documented blocker or disposition"),
    )
    outcomes = []
    if outcome:
        outcomes.append(rb.witness_outcome_row(
            channel, source, witness, verdict=verdict,
            severity=("—" if verdict in {"not_error", "duplicate"} else "2"),
            duplicate_target=("E-7001" if verdict == "duplicate" else "—"),
        ))
    mf_records, probe_records = [], []
    if verdict == "not_error" and records:
        if channel == "MF":
            mf_records.append(_mf_record(path, source, witness))
        else:
            probe_records.append(_probe_record(source, witness))
    shard = a.write("_code_error_recheck/k1.md", _shard_text(
        [ledger], outcomes, mf_records, probe_records))
    if channel == "DU" and verdict == "not_error" and records:
        (shard.parent / "probe.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
    before = rb.error_row(eid, etype=etype, source=f"`{anchor.rsplit(':', 1)[0]}`",
                          location=f"`{anchor}`", status="candidate", severity="2")
    if final_status is None:
        final_status = status_map[verdict]
    if final_severity is None:
        final_severity = ("" if final_status in {"not_error", "duplicate_of:E-7001"}
                          else ("2" if final_status != "confirmation_needed" else "2"))
    final = rb.error_row(eid, etype=etype, source=f"`{anchor.rsplit(':', 1)[0]}`",
                         location=f"`{anchor}`", status=final_status,
                         severity=final_severity)
    a.write_register("code_error_register.md", rb.ERROR_COLS, [before],
                     title="Code-error register")
    a.write_register("_run/snapshots/code_b6/code_error_register.md",
                     rb.ERROR_COLS, [before], title="Code-error register")
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [final],
                     title="Code-error register")
    a.write_recheck_summary("code")
    summary = a.audit / "code_error_recheck_summary.md"
    summary.write_text(
        summary.read_text() + "Discoveries declared: C=0; O=0; E=0\n",
        encoding="utf-8")
    a.write(
        "plans/code_error_supplementary_recheck_plan.md",
        rb.recheck_plan_text("code", [], [])
        + "\nNo supplementary recheck inventory.\n")
    return root, a, shard, ledger, mapping


def test_code_ledger_schema_extends_only_code_stream():
    assert rb.CODE_LEDGER_COLS[:len(rb.LEDGER_COLS)] == rb.LEDGER_COLS
    assert len(rb.CODE_LEDGER_COLS) == len(rb.LEDGER_COLS) + 8
    assert lint.LEDGER_COLS == rb.LEDGER_COLS


def test_b5_confirmed_structured_shard_passes(tmp_path):
    _root, a, shard, _ledger, _mapping_row = _case(tmp_path)
    result = rb.lint(a, "b5-code", shard)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(("mutation", "token"), [
    (lambda text: text.replace("### Witness outcomes", "### Outcomes"),
     "Witness outcomes' marker"),
    (lambda text: text + "\n### Verification records\n", 
     "Verification records' marker"),
])
def test_b5_requires_exact_structured_subtable_markers(tmp_path, mutation, token):
    _root, a, shard, _ledger, _mapping_row = _case(tmp_path)
    shard.write_text(mutation(shard.read_text()), encoding="utf-8")
    result = rb.lint(a, "b5-code", shard)
    assert result.returncode == 1 and token in result.stdout


@pytest.mark.parametrize("verdict", ["blocked", "deferred", "confirmation_needed"])
def test_b5_undecided_dispositions_pass_without_witness_outcomes(tmp_path, verdict):
    _root, a, shard, _ledger, _mapping_row = _case(
        tmp_path, verdict=verdict, outcome=False)
    result = rb.lint(a, "b5-code", shard)
    assert result.returncode == 0, result.stdout + result.stderr


def test_b5_deferred_requires_off_limits_citation(tmp_path):
    _root, a, shard, ledger, _mapping_row = _case(
        tmp_path, verdict="deferred", outcome=False)
    ledger = list(ledger)
    ledger[rb.CODE_LEDGER_COLS.index("Proposed Note")] = "work postponed"
    shard.write_text(_shard_text([ledger], []), encoding="utf-8")
    result = rb.lint(a, "b5-code", shard)
    assert result.returncode == 1 and "off-limits citation" in result.stdout


@pytest.mark.parametrize(("verdict", "status", "severity", "token"), [
    ("confirmed_error", "not_error", "2", "Proposed Status"),
    ("confirmed_error", "confirmed", "—", "Proposed Severity"),
    ("not_error", "not_error", "1", "forbids Proposed Severity"),
    ("not_error", "confirmed", "—", "Proposed Status"),
    ("confirmation_needed", "confirmation_needed", "—", "Proposed Severity"),
    ("blocked", "confirmed", "2", "Proposed Status"),
    ("deferred", "blocked", "1", "carry forward"),
])
def test_b5_matrix_refuses_bad_field_patterns(tmp_path, verdict, status, severity, token):
    _root, a, shard, _ledger, _mapping_row = _case(
        tmp_path, verdict=verdict, proposed_status=status,
        proposed_severity=severity,
        outcome=verdict in {"confirmed_error", "not_error"},
        records=verdict == "not_error")
    result = rb.lint(a, "b5-code", shard)
    assert result.returncode == 1 and token in result.stdout


def test_b5_not_error_requires_composite_key_record_coverage(tmp_path):
    _root, a, shard, _ledger, _mapping_row = _case(
        tmp_path, verdict="not_error", records=False)
    result = rb.lint(a, "b5-code", shard)
    assert result.returncode == 1
    assert "verification records do not cover every mapped key" in result.stdout


def test_b5_refuses_raw_reserved_mechanism_cell(tmp_path):
    _root, a, shard, _ledger, _mapping_row = _case(tmp_path)
    shard.write_text(shard.read_text().replace("sample_ok", "sample%ok"),
                     encoding="utf-8")
    result = rb.lint(a, "b5-code", shard)
    assert result.returncode == 1 and "mechanism invalid" in result.stdout


@pytest.mark.parametrize("patch", ["Status := confirmed", "Severity := 1",
                                    "Unknown := text", "Code Location = x"])
def test_b5_field_patch_whitelist_and_grammar(tmp_path, patch):
    _root, a, shard, ledger, mapping_row = _case(tmp_path)
    ledger = list(ledger)
    ledger[rb.CODE_LEDGER_COLS.index("Proposed Field Patches")] = patch
    outcome = rb.witness_outcome_row(
        mapping_row["Channel"], mapping_row["Source ID"], mapping_row["Witness ID"])
    shard.write_text(_shard_text([ledger], [outcome]), encoding="utf-8")
    result = rb.lint(a, "b5-code", shard)
    assert result.returncode == 1 and "field patch" in result.stdout.lower()


def test_verifier_writes_exact_zero_when_no_dismissal(tmp_path):
    root, a, _shard, _ledger, _mapping_row = _case(tmp_path)
    result = rb.run_script("verify_dismissals.py", root, "--audit-dir", a.audit)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (a.audit / "_run/dismissal_receipts.md").read_text() == (
        "# Dismissal receipts\n\n" + verifier.ZERO_RECEIPTS + "\n")


def test_result_digest_uses_fixed_raw_preimage():
    expected = hashlib.sha256(b"exit=7\nstdout\0stderr\n").hexdigest()
    assert verifier.result_digest(7, b"stdout", b"stderr\n") == expected


@pytest.mark.parametrize(("exit_line", "accepted"), [
    ("raise SystemExit(0)\n", "yes"),
    ("raise SystemExit(3)\n", "no"),
])
def test_du_verifier_reruns_persisted_probe(tmp_path, exit_line, accepted):
    root, a, shard, _ledger, _mapping_row = _case(tmp_path, verdict="not_error")
    (shard.parent / "probe.py").write_text(exit_line, encoding="utf-8")
    result = rb.run_script("verify_dismissals.py", root, "--audit-dir", a.audit)
    assert result.returncode == 0, result.stdout + result.stderr
    rows = verifier._rows(a.audit / "_run/dismissal_receipts.md", verifier.RECEIPT_COLS)
    assert rows[0]["Accepted (yes/no)"] == accepted
    assert rows[0]["Input Digest (sha256)"] == hashlib.sha256(
        (shard.parent / "probe.py").read_bytes()).hexdigest()


def test_mf_verifier_uses_digest_verified_pinned_oracle(tmp_path):
    assert bootstrap.ORACLE_PATH.is_file(), "pinned oracle must already be installed"
    root, a, _shard, _ledger, _mapping_row = _case(
        tmp_path, channel="MF", verdict="not_error")
    result = rb.run_script("verify_dismissals.py", root, "--audit-dir", a.audit)
    assert result.returncode == 0, result.stdout + result.stderr
    rows = verifier._rows(a.audit / "_run/dismissal_receipts.md", verifier.RECEIPT_COLS)
    assert rows[0]["Tool"] == "micromamba"
    assert rows[0]["Accepted (yes/no)"] == "yes"


def test_assembler_is_sole_writer_of_receipted_not_error(tmp_path):
    root, a, _shard, _ledger, _mapping_row = _case(
        tmp_path, verdict="not_error", final_status="confirmed", final_severity="2")
    assert rb.run_script("verify_dismissals.py", root, "--audit-dir", a.audit).returncode == 0
    result = rb.run_script("assemble_boundary.py", root, "--audit-dir", a.audit)
    assert result.returncode == 0, result.stdout + result.stderr
    final = dm.parse_register(a.audit / "_staging/code_error_register.md")["E-7000"]
    assert final["Status"] == "not_error" and final["Severity"] == ""
    assert "| E-7000 |" in (a.audit / "_run/witness_outcomes.md").read_text()


def test_assembler_refuses_not_error_without_qualifying_receipt(tmp_path):
    root, a, _shard, _ledger, _mapping_row = _case(
        tmp_path, verdict="not_error", final_status="confirmed", final_severity="2")
    a.write("_run/dismissal_receipts.md",
            "# Dismissal receipts\n\n" + verifier.ZERO_RECEIPTS + "\n")
    result = rb.run_script("assemble_boundary.py", root, "--audit-dir", a.audit)
    assert result.returncode == 1 and "no qualifying receipt" in result.stderr


def test_assembler_check_rederives_and_checks_owned_status(tmp_path):
    root, a, _shard, _ledger, _mapping_row = _case(
        tmp_path, verdict="not_error", final_status="confirmed", final_severity="2")
    assert rb.run_script("verify_dismissals.py", root, "--audit-dir", a.audit).returncode == 0
    assert rb.run_script("assemble_boundary.py", root, "--audit-dir", a.audit).returncode == 0
    os.replace(a.audit / "_staging/code_error_register.md",
               a.audit / "code_error_register.md")
    good = rb.run_script("assemble_boundary.py", root, "--audit-dir", a.audit, "--check")
    assert good.returncode == 0, good.stdout + good.stderr
    canonical = a.audit / "code_error_register.md"
    canonical.write_text(canonical.read_text().replace("| not_error |", "| confirmed |")
                         .replace("|  | a description", "| 2 | a description"),
                         encoding="utf-8")
    bad = rb.run_script("assemble_boundary.py", root, "--audit-dir", a.audit, "--check")
    assert bad.returncode == 1
    assert "disagrees with its ledger disposition" in bad.stderr


def test_b6_good_receipted_dismissal_passes(tmp_path):
    root, a, _shard, _ledger, _mapping_row = _case(
        tmp_path, verdict="not_error", final_status="confirmed", final_severity="2")
    assert rb.run_script("verify_dismissals.py", root, "--audit-dir", a.audit).returncode == 0
    assert rb.run_script("assemble_boundary.py", root, "--audit-dir", a.audit).returncode == 0
    result = rb.lint(a, "b6-code")
    assert result.returncode == 0, result.stdout + result.stderr


def test_b6_missing_disposition_refuses_provenance_closure(tmp_path):
    root, a, shard, _ledger, _mapping_row = _case(tmp_path)
    a.write("_run/dismissal_receipts.md",
            "# Dismissal receipts\n\n" + verifier.ZERO_RECEIPTS + "\n")
    # Supply the boundary independently so the disposition finding is isolated.
    outcome = rb.witness_outcome_row("DU", DU_SOURCE, DU_WITNESS)
    canonical = mechanism.canonicalize_mechanism(
        *outcome[4:9], register="code_errors", anchor="do/probe.do:1",
        projection=mechanism.EMPTY_PROJECTION)
    post = [["DU", DU_SOURCE, DU_WITNESS, "confirmed_error", canonical.sidecar,
             "2", "—", "—"]]
    a.write("_run/witness_outcomes.md",
            "# Witness outcomes\n\n" + rb.md_table(rb._lint_mod.POST_WITNESS_COLS, post)
            + "\n### Assembled dismissals\n\n" + assembler.DISMISSAL_ZERO + "\n")
    shard.write_text(_shard_text([], []), encoding="utf-8")
    result = rb.lint(a, "b6-code")
    assert result.returncode == 1 and "0 ledger rows" in result.stdout


def _green_split_case(tmp_path):
    root, a, shard, _ledger, first = _case(tmp_path)
    second = dict(first)
    second["Witness ID"] = "DUW-333333333333"
    second["Site Anchor"] = "do/probe.do:2"
    a.write("_run/detector_mapping.md", dm.render_mapping(
        "E-7000–E-7099", {"DU": [first, second], "MF": []}))
    ledger = rb.code_ledger_row(
        "E-7000", evidence=DU_SOURCE, verdict="confirmed_error",
        proposed_status="confirmed", proposed_severity="2",
        witness_ids=f"{DU_WITNESS}; {second['Witness ID']}")
    outcomes = [
        rb.witness_outcome_row(
            "DU", DU_SOURCE, DU_WITNESS, mech_object="sample_one"),
        rb.witness_outcome_row(
            "DU", DU_SOURCE, second["Witness ID"], mech_object="sample_two"),
    ]
    shard.write_text(_shard_text([ledger], outcomes), encoding="utf-8")
    a.write("_run/dismissal_receipts.md",
            "# Dismissal receipts\n\n" + verifier.ZERO_RECEIPTS + "\n")
    before = rb.error_row(
        "E-7000", etype="sample_filter_or_flag_error", source="`do/probe.do`",
        location="`do/probe.do:1`", status="candidate", severity="2")
    original = rb.error_row(
        "E-7000", etype="sample_filter_or_flag_error", source="`do/probe.do`",
        location="`do/probe.do:1`", status="confirmed", severity="2")
    descendant = rb.error_row(
        "E-9000", etype="sample_filter_or_flag_error", source="`do/probe.do`",
        location="`do/probe.do:2`", status="confirmed", severity="2")
    a.write_register("_run/snapshots/code_b6/code_error_register.md",
                     rb.ERROR_COLS, [before], title="Code-error register")
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS,
                     [original, descendant], title="Code-error register")
    lineage = [
        ["E-7000", "E-7000", "DU", DU_SOURCE, DU_WITNESS],
        ["E-7000", "E-9000", "DU", DU_SOURCE, second["Witness ID"]],
    ]
    summary = (
        "# code recheck summary\n\nSplits declared: 1\nMerges declared: 0\n\n"
        "### Split lineage\n\n" + rb.md_table(dm.LINEAGE_COLS, lineage)
    )
    a.write("code_error_recheck_summary.md", summary)
    assembled = rb.run_script("assemble_boundary.py", root, "--audit-dir", a.audit)
    assert assembled.returncode == 0, assembled.stdout + assembled.stderr
    baseline = rb.lint(a, "b6-code")
    assert baseline.returncode == 0, baseline.stdout + baseline.stderr
    return root, a, summary, lineage


def test_tier1_provenance_lineage_drill_uses_production_lint(tmp_path, monkeypatch):
    _root, a, summary, lineage = _green_split_case(tmp_path)
    corrupted = summary.replace(
        "| " + " | ".join(lineage[1]) + " |\n", "")
    a.write("code_error_recheck_summary.md", corrupted)
    result = rb.lint(a, "b6-code")
    assert result.returncode == 1
    assert "split lineage for E-7000 does not exactly cover" in result.stdout

    checker = lint.Lint()
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    lint.stage_b6(checker, a.audit, "code", manifest)
    assert any("split lineage" in error for error in checker.errors)
    monkeypatch.setattr(lint, "check_detector_mapping_b6", lambda *_args: None)
    toothless = lint.Lint()
    lint.stage_b6(toothless, a.audit, "code", manifest)
    assert not toothless.errors


def _mapped_duplicate_case(tmp_path, mutation=None):
    root = tmp_path / "duplicates"
    root.mkdir()
    a = rb.AuditDir(root)
    source_key = ("DU", "DU-aaaaaaaaaaaa", "DUW-111111111111")
    target_key = ("DU", "DU-bbbbbbbbbbbb", "DUW-222222222222")
    rows = [
        {"Channel": source_key[0], "Source ID": source_key[1],
         "Witness ID": source_key[2], "Error ID": "E-7000",
         "Mapping Kind": "existing_row", "Site Anchor": "do/probe.do:1"},
        {"Channel": target_key[0], "Source ID": target_key[1],
         "Witness ID": target_key[2], "Error ID": "E-7001",
         "Mapping Kind": "existing_row", "Site Anchor": "do/probe.do:1"},
    ]
    a.write("_run/detector_mapping.md", dm.render_mapping(
        "E-7000–E-7099", {"DU": rows, "MF": []}))
    a.write_manifest(stages={
        "code_b5": {"status": "done", "retries": 0,
                    "shards": {"audit/_code_error_recheck/k1.md":
                               {"status": "done", "retries": 0}}},
    })
    a.write("plans/code_error_review_plan.md", rb._code_b1_plan())
    inventory = [("E-7000", "mapped", source_key[1]),
                 ("E-7001", "mapped", target_key[1])]
    clusters = [("K1", "duplicates", "E-7000; E-7001",
                 "`audit/_code_error_recheck/k1.md`")]
    a.write("plans/code_error_recheck_plan.md",
            rb.recheck_plan_text("code", inventory, clusters))
    target = "E-7999" if mutation == "unmapped_target" else "E-7001"
    ledgers = [
        rb.code_ledger_row(
            "E-7000", evidence=source_key[1], verdict="duplicate",
            proposed_status=f"duplicate_of:{target}", proposed_severity="—",
            witness_ids=source_key[2], duplicate_target=target),
        rb.code_ledger_row(
            "E-7001", status="confirmed", evidence=target_key[1],
            verdict="confirmed_error", proposed_status="confirmed",
            proposed_severity="2", witness_ids=target_key[2]),
    ]
    source_object = "different_sample" if mutation == "mechanism" else "sample_ok"
    outcomes = [
        rb.witness_outcome_row(
            *source_key, verdict="duplicate", severity="—",
            duplicate_target=target, mech_object=source_object),
        rb.witness_outcome_row(*target_key),
    ]
    a.write("_code_error_recheck/k1.md", _shard_text(ledgers, outcomes))
    a.write("_run/dismissal_receipts.md",
            "# Dismissal receipts\n\n" + verifier.ZERO_RECEIPTS + "\n")
    source_type = ("aggregation_or_unit_error" if mutation == "type"
                   else "sample_filter_or_flag_error")
    before = [
        rb.error_row("E-7000", etype=source_type, source="`do/probe.do`",
                     location="`do/probe.do:1`", status="candidate", severity="2"),
        rb.error_row("E-7001", etype="sample_filter_or_flag_error",
                     source="`do/probe.do`", location="`do/probe.do:1`",
                     status="confirmed", severity="2"),
    ]
    final = [
        rb.error_row("E-7000", etype=source_type, source="`do/probe.do`",
                     location="`do/probe.do:1`", status=f"duplicate_of:{target}",
                     severity=""),
        before[1],
    ]
    a.write_register("_run/snapshots/code_b6/code_error_register.md",
                     rb.ERROR_COLS, before, title="Code-error register")
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS,
                     final, title="Code-error register")
    a.write_recheck_summary("code")
    return root, a


def test_guarded_mapped_duplicate_passes_all_legs(tmp_path):
    root, a = _mapped_duplicate_case(tmp_path)
    assembled = rb.run_script("assemble_boundary.py", root, "--audit-dir", a.audit)
    assert assembled.returncode == 0, assembled.stdout + assembled.stderr
    result = rb.lint(a, "b6-code")
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(("mutation", "token"), [
    ("unmapped_target", "mechanically mapped target"),
    ("type", "error type differs"),
    ("mechanism", "mechanism differs"),
])
def test_guarded_mapped_duplicate_refuses_failed_leg(tmp_path, mutation, token):
    root, a = _mapped_duplicate_case(tmp_path, mutation)
    result = rb.run_script("assemble_boundary.py", root, "--audit-dir", a.audit)
    assert result.returncode == 1 and token in result.stderr


@pytest.mark.parametrize("kind", ["stray", "delete", "mutate"])
def test_b3d_emission_converse_refuses_staging_corruption(tmp_path, kind):
    root = tmp_path / "package"
    root.mkdir()
    a = rb.AuditDir(root)
    a.write_manifest(mode="code_errors_only")
    a.write("_run/definition_use_bundles.md", rb.definition_use_artifact([]))
    a.write("_run/manifest_check.md",
            "# Manifest\n\nNo candidate findings: every recognized manifest parsed clean.\n"
            "No standard MF rows: no manifest candidates were emitted.\n")
    rb.emit_argument_contracts(a)
    a.write("_run/detector_mapping_decisions.md",
            "Declared detector Error-ID range: E-7000–E-7099\n\n"
            + rb.md_table(dm.DECISION_COLS, []))
    base = rb.error_row("E-0101", status="confirmed", severity="2")
    staged = [list(base)]
    if kind == "stray":
        staged.append(rb.error_row("E-0202", status="not_error", severity=""))
    elif kind == "delete":
        staged = []
    else:
        staged[0][rb.ERROR_COLS.index("Why It Matters")] = "mutated"
    a.write_register("_run/snapshots/code_b3d/code_error_register.md",
                     rb.ERROR_COLS, [base])
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, staged)
    result = rb.run_script("build_detector_mapping.py", root, "--audit-dir", a.audit)
    assert result.returncode == 1
    assert {"stray": "stray staged", "delete": "missing staged",
            "mutate": "mutated pre-existing"}[kind] in result.stderr


def test_code_b5_blocked_shard_gets_conductor_fallback(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    a = rb.AuditDir(root)
    a.write_manifest(mode="code_errors_only")
    a.write_register("code_error_register.md", rb.ERROR_COLS,
                     [rb.error_row("E-0101", status="candidate", severity="2")])
    a.write("plans/code_error_recheck_plan.md", rb.recheck_plan_text(
        "code", [("E-0101", "candidate", "source")],
        [("K1", "one", "E-0101", "`audit/_code_error_recheck/k1.md`")]))
    assert _cli(root, "init").returncode == 0
    assert _cli(root, "start", "--stage", "code_b5").returncode == 0
    result = _cli(root, "set-shard", "--stage", "code_b5", "--shard",
                  "audit/_code_error_recheck/k1.md", "--status", "blocked",
                  "--reason", "tool unavailable after attempt")
    assert result.returncode == 0, result.stdout + result.stderr
    fallback = a.audit / "_code_error_recheck/k1.md"
    text = fallback.read_text()
    assert "| E-0101 | candidate | 2 |" in text
    assert "| blocked |" in text and "### Witness outcomes" in text


def test_code_b6a_obligations_register_boundary_replay():
    obligations = certify.load_obligations()["code_b6a"]
    assert obligations == [
        {"type": "artifact", "pattern": "code_error_register.md"},
        {"type": "artifact", "pattern": "plans/code_error_supplementary_recheck_plan.md"},
        {"type": "artifact", "pattern": "_run/code_b6a/witness_outcomes.md"},
        {"type": "validate", "validator": "boundary:assemble"},
        {"type": "validate", "validator": "lint:b6a-code"},
    ]


def test_b6_confirmation_needed_caps_proposed_four_at_two(tmp_path):
    root, a, _shard, _ledger, _mapping_row = _case(
        tmp_path, verdict="confirmation_needed", proposed_severity="4",
        outcome=False, final_status="confirmation_needed", final_severity="2")
    a.write("_run/dismissal_receipts.md",
            "# Dismissal receipts\n\n" + verifier.ZERO_RECEIPTS + "\n")
    assembled = rb.run_script("assemble_boundary.py", root, "--audit-dir", a.audit)
    assert assembled.returncode == 0, assembled.stdout + assembled.stderr
    result = rb.lint(a, "b6-code")
    assert result.returncode == 0, result.stdout + result.stderr


def test_b6_receipt_gate_rejoins_composite_key_not_assembled_list_alone(tmp_path):
    root, a, _shard, _ledger, _mapping_row = _case(
        tmp_path, verdict="not_error", final_status="not_error", final_severity="")
    # A hand-written list is not proof: the receipt artifact is explicit-zero.
    a.write("_run/dismissal_receipts.md",
            "# Dismissal receipts\n\n" + verifier.ZERO_RECEIPTS + "\n")
    outcome = rb.witness_outcome_row(
        "DU", DU_SOURCE, DU_WITNESS, verdict="not_error", severity="—")
    canonical = mechanism.canonicalize_mechanism(
        *outcome[4:9], register="code_errors", anchor="do/probe.do:1",
        projection=mechanism.EMPTY_PROJECTION)
    post = [["DU", DU_SOURCE, DU_WITNESS, "not_error", canonical.sidecar,
             "—", "—", "—"]]
    a.write("_run/witness_outcomes.md",
            "# Witness outcomes\n\n" + rb.md_table(rb._lint_mod.POST_WITNESS_COLS, post)
            + "\n### Assembled dismissals\n\n| Error ID |\n| --- |\n| E-7000 |\n")
    result = rb.lint(a, "b6-code")
    assert result.returncode == 1
    assert "lacks qualifying receipt coverage" in result.stdout


def test_tier1_receipt_check_has_teeth(tmp_path, monkeypatch):
    root, a, _shard, _ledger, _mapping_row = _case(
        tmp_path, verdict="not_error", final_status="not_error", final_severity="")
    a.write("_run/dismissal_receipts.md",
            "# Dismissal receipts\n\n" + verifier.ZERO_RECEIPTS + "\n")
    outcome = rb.witness_outcome_row(
        "DU", DU_SOURCE, DU_WITNESS, verdict="not_error", severity="—")
    canonical = mechanism.canonicalize_mechanism(
        *outcome[4:9], register="code_errors", anchor="do/probe.do:1",
        projection=mechanism.EMPTY_PROJECTION)
    a.write("_run/witness_outcomes.md",
            "# Witness outcomes\n\n" + rb.md_table(rb._lint_mod.POST_WITNESS_COLS, [[
                "DU", DU_SOURCE, DU_WITNESS, "not_error", canonical.sidecar,
                "—", "—", "—"]])
            + "\n### Assembled dismissals\n\n| Error ID |\n| --- |\n| E-7000 |\n")
    checker = lint.Lint()
    lint.stage_b6(checker, a.audit, "code", json.loads(
        (a.audit / "_run/manifest.json").read_text()))
    assert any("receipt coverage" in error for error in checker.errors)
    monkeypatch.setattr(lint, "check_detector_mapping_b6", lambda *_args: None)
    toothless = lint.Lint()
    lint.stage_b6(toothless, a.audit, "code", json.loads(
        (a.audit / "_run/manifest.json").read_text()))
    assert not any("receipt coverage" in error for error in toothless.errors)


def test_tier1_b3d_converse_check_has_teeth(tmp_path, monkeypatch):
    root = tmp_path / "package"
    root.mkdir()
    a = rb.AuditDir(root)
    a.write_manifest(mode="code_errors_only")
    a.write("_run/definition_use_bundles.md", rb.definition_use_artifact([]))
    a.write("_run/manifest_check.md",
            "# Manifest\n\nNo candidate findings: every recognized manifest parsed clean.\n"
            "No standard MF rows: no manifest candidates were emitted.\n")
    rb.emit_argument_contracts(a)
    a.write("_run/detector_mapping_decisions.md",
            "Declared detector Error-ID range: E-7000–E-7099\n\n"
            + rb.md_table(dm.DECISION_COLS, []))
    a.write_register("_run/snapshots/code_b3d/code_error_register.md",
                     rb.ERROR_COLS, [])
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS,
                     [rb.error_row("E-0202", status="not_error", severity="")])
    with pytest.raises(dm.MappingError, match="stray staged"):
        dm.validate_inputs(root, a.audit)
    monkeypatch.setattr(dm, "_validate_staging_converse", lambda *_args: None)
    _display, rows = dm.validate_inputs(root, a.audit)
    assert rows == {"DU": [], "MF": [], "CV": [], "AC": []}


def _completed_b3d_b6_run(tmp_path, verdict="not_error"):
    root = tmp_path / "completed"
    root.mkdir()
    a = rb.AuditDir(root)
    (root / "do").mkdir()
    (root / "do/build.do").write_text(
        "gen consent_ok = consent != \"\"\nkeep if consent_ok == 1 & wave == 1\n",
        encoding="utf-8")
    a.write_manifest(mode="code_errors_only", scope_exclusions=[], off_limits=[])
    a.write_register("code_error_register.md", rb.ERROR_COLS, [])
    initialized = _cli(root, "init")
    assert initialized.returncode == 0, initialized.stdout + initialized.stderr
    assert rb.run_script("emit_definition_use_bundles.py", root,
                         "--audit-dir", a.audit).returncode == 0
    assert rb.run_script("check_manifests.py", root,
                         "--audit-dir", a.audit).returncode == 0
    rb.emit_argument_contracts(a)
    sources = dm.parse_raw_sources(a.audit)
    source = next(iter(sources["DU"]))
    witness = sources["DU"][source][0]["witness_id"]
    anchor = sources["DU"][source][0]["anchor"]
    a.write_register("_run/snapshots/code_b3d/code_error_register.md",
                     rb.ERROR_COLS, [])
    candidate = rb.error_row(
        "E-7000", etype="sample_filter_or_flag_error", source="`do/build.do`",
        location=f"`{anchor}`", status="candidate", severity="2")
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [candidate])
    a.write("_run/detector_mapping_decisions.md",
            "Declared detector Error-ID range: E-7000–E-7099\n\n"
            + rb.md_table(dm.DECISION_COLS,
                          [["DU", source, "E-7000", "new_candidate"]]))
    emitted = rb.run_script("build_detector_mapping.py", root, "--audit-dir", a.audit)
    assert emitted.returncode == 0, emitted.stdout + emitted.stderr
    os.replace(a.audit / "_staging/code_error_register.md",
               a.audit / "code_error_register.md")
    inventory = [("E-7000", "detector", source)]
    clusters = [("K1", "detector", "E-7000", "`audit/_code_error_recheck/k1.md`")]
    a.write("plans/code_error_recheck_plan.md",
            rb.recheck_plan_text("code", inventory, clusters))
    a.write("plans/code_error_second_read_plan.md", "# Code second-read plan\n")
    a.write("plans/code_error_review_plan.md", rb._code_b1_plan())
    if verdict == "not_error":
        ledger = rb.code_ledger_row(
            "E-7000", evidence=source, verdict="not_error",
            proposed_status="not_error", proposed_severity="—",
            witness_ids=witness, record_ids="VR-0001")
        outcome = rb.witness_outcome_row(
            "DU", source, witness, verdict="not_error", severity="—")
        probe_records = [_probe_record(source, witness)]
        merged = candidate
    else:
        ledger = rb.code_ledger_row(
            "E-7000", evidence=source, verdict="confirmed_error",
            proposed_status="confirmed", proposed_severity="2",
            witness_ids=witness)
        outcome = rb.witness_outcome_row("DU", source, witness)
        probe_records = []
        merged = rb.error_row(
            "E-7000", etype="sample_filter_or_flag_error", source="`do/build.do`",
            location=f"`{anchor}`", status="confirmed", severity="2")
    shard = a.write("_code_error_recheck/k1.md",
                    _shard_text([ledger], [outcome], probe_records=probe_records))
    if probe_records:
        (shard.parent / "probe.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
    assert rb.run_script("verify_dismissals.py", root,
                         "--audit-dir", a.audit).returncode == 0
    a.write_register("_run/snapshots/code_b6/code_error_register.md",
                     rb.ERROR_COLS, [candidate])
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [merged])
    a.write_recheck_summary("code")
    summary = a.audit / "code_error_recheck_summary.md"
    summary.write_text(
        summary.read_text() + "Discoveries declared: C=0; O=0; E=0\n",
        encoding="utf-8")
    a.write(
        "plans/code_error_supplementary_recheck_plan.md",
        rb.recheck_plan_text("code", [], [])
        + "\nNo supplementary recheck inventory.\n")
    # Certify b5 through the production state transition before b6a promotes
    # its dispositions; the certifier owns the stage-era evidence binding.
    certify.start_stage(root, "code_b5")
    certify.set_shard(
        root, "code_b5", "audit/_code_error_recheck/k1.md", "done")
    certify.finish_stage(root, "code_b5", "done")
    assembled = rb.run_script("assemble_boundary.py", root, "--audit-dir", a.audit)
    assert assembled.returncode == 0, assembled.stdout + assembled.stderr
    os.replace(a.audit / "_staging/code_error_register.md",
               a.audit / "code_error_register.md")
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    manifest["stages"]["code_b3d"]["status"] = "done"
    manifest["stages"]["code_b6a"]["status"] = "done"
    certify.write_manifest_atomic(root, manifest)
    return root, a


def test_completed_verify_run_rederives_b3d_and_b6_then_catches_hand_flip(tmp_path):
    root, a = _completed_b3d_b6_run(tmp_path)
    passed = _cli(root, "verify-run")
    assert passed.returncode == 0, passed.stdout + passed.stderr
    assert "code_b3d" in passed.stdout and "code_b6a" in passed.stdout
    register = a.audit / "code_error_register.md"
    register.write_text(register.read_text().replace("| not_error |  |", "| confirmed | 2 |"),
                        encoding="utf-8")
    failed = _cli(root, "verify-run")
    assert failed.returncode != 0
    assert "boundary:assemble" in failed.stderr
    assert "disagrees with its ledger disposition" in failed.stderr


def test_tier1_b3d_post_promotion_stray_refuses_verify_run(tmp_path):
    root, a = _completed_b3d_b6_run(tmp_path)
    passed = _cli(root, "verify-run")
    assert passed.returncode == 0, passed.stdout + passed.stderr
    current = dm.parse_register(a.audit / "code_error_register.md")
    rows = [[current["E-7000"][column] for column in rb.ERROR_COLS]]
    rows.append(rb.error_row("E-7999", status="not_error", severity=""))
    a.write_register("code_error_register.md", rb.ERROR_COLS, rows,
                     title="Code-error register")
    failed = _cli(root, "verify-run")
    assert failed.returncode != 0
    assert "validate:detector:mapping" in failed.stderr
    assert "b3d replay key closure failed" in failed.stderr


def test_tier1_drill_confirmed_row_hand_flipped_to_not_error_fails_verify_run(tmp_path):
    root, a = _completed_b3d_b6_run(tmp_path, verdict="confirmed_error")
    passed = _cli(root, "verify-run")
    assert passed.returncode == 0, passed.stdout + passed.stderr
    register = a.audit / "code_error_register.md"
    register.write_text(
        register.read_text().replace("| confirmed | 2 |", "| not_error |  |"),
        encoding="utf-8")
    failed = _cli(root, "verify-run")
    assert failed.returncode != 0
    assert "boundary:assemble" in failed.stderr
    assert "disagrees with its ledger disposition" in failed.stderr


def test_tier1_disposition_check_has_teeth(tmp_path, monkeypatch):
    root, a = _completed_b3d_b6_run(tmp_path, verdict="confirmed_error")
    register = a.audit / "code_error_register.md"
    register.write_text(
        register.read_text().replace("| confirmed | 2 |", "| not_error |  |"),
        encoding="utf-8")
    with pytest.raises(assembler.BoundaryError,
                       match="disagrees with its ledger disposition"):
        assembler.check_boundary(a.audit)
    monkeypatch.setattr(assembler, "_check_dispositions", lambda *_args: None)
    assembler.check_boundary(a.audit)


def test_b6_mapped_blocked_fallback_passes_certification(tmp_path):
    root, a, shard, _ledger, _mapping_row = _case(
        tmp_path, verdict="blocked", outcome=False)
    certify._write_code_b5_blocked_fallback(
        root, shard, "tool unavailable after attempt")
    text = shard.read_text()
    assert DU_SOURCE in text and "blocked fallback" in text
    a.write("_run/dismissal_receipts.md",
            "# Dismissal receipts\n\n" + verifier.ZERO_RECEIPTS + "\n")
    assembled = rb.run_script("assemble_boundary.py", root, "--audit-dir", a.audit)
    assert assembled.returncode == 0, assembled.stdout + assembled.stderr
    result = rb.lint(a, "b6-code")
    assert result.returncode == 0, result.stdout + result.stderr


# --------------------- Tier-2 composite-key collision tests (one per join)

COLLIDE_WITNESS = "DUW-777777777777"
MF_COLLIDE_SOURCE = "MF-cccccccccccc"


def _collision_case(tmp_path, *, e7000_verdict="not_error",
                    omit_e7000_outcome=False):
    """Two mapped rows sharing one Witness ID across channels AND sources."""
    root = tmp_path / "collisions"
    root.mkdir()
    a = rb.AuditDir(root)
    du_row = {"Channel": "DU", "Source ID": DU_SOURCE,
              "Witness ID": COLLIDE_WITNESS, "Error ID": "E-7000",
              "Mapping Kind": "new_candidate", "Site Anchor": "do/probe.do:1"}
    mf_row = {"Channel": "MF", "Source ID": MF_COLLIDE_SOURCE,
              "Witness ID": COLLIDE_WITNESS, "Error ID": "E-7001",
              "Mapping Kind": "new_candidate", "Site Anchor": "environment.yml:1"}
    a.write("_run/detector_mapping.md", dm.render_mapping(
        "E-7000–E-7099", {"DU": [du_row], "MF": [mf_row]}))
    a.write_manifest(stages={
        "code_b5": {"status": "done", "retries": 0,
                    "shards": {"audit/_code_error_recheck/k1.md":
                               {"status": "done", "retries": 0}}},
    })
    a.write("plans/code_error_review_plan.md", rb._code_b1_plan())
    inventory = [("E-7000", "detector", DU_SOURCE),
                 ("E-7001", "detector", MF_COLLIDE_SOURCE)]
    clusters = [("K1", "collisions", "E-7000; E-7001",
                 "`audit/_code_error_recheck/k1.md`")]
    a.write("plans/code_error_recheck_plan.md",
            rb.recheck_plan_text("code", inventory, clusters))
    ledgers = [
        rb.code_ledger_row(
            "E-7000", evidence=DU_SOURCE, verdict=e7000_verdict,
            proposed_status=("not_error" if e7000_verdict == "not_error"
                             else "confirmed"),
            proposed_severity=("—" if e7000_verdict == "not_error" else "2"),
            witness_ids=COLLIDE_WITNESS,
            record_ids=("VR-0001" if e7000_verdict == "not_error" else "—")),
        rb.code_ledger_row(
            "E-7001", evidence=MF_COLLIDE_SOURCE, verdict="confirmed_error",
            proposed_status="confirmed", proposed_severity="2",
            witness_ids=COLLIDE_WITNESS),
    ]
    outcomes = []
    if not omit_e7000_outcome:
        outcomes.append(rb.witness_outcome_row(
            "DU", DU_SOURCE, COLLIDE_WITNESS, verdict=e7000_verdict,
            severity=("—" if e7000_verdict == "not_error" else "2")))
    outcomes.append(rb.witness_outcome_row(
        "MF", MF_COLLIDE_SOURCE, COLLIDE_WITNESS))
    # The only verification record binds the OTHER mapped key: same Witness
    # ID, different channel and source. No join may accept it for E-7000.
    mf_records = [["MF", "VR-0001", MF_COLLIDE_SOURCE, COLLIDE_WITNESS,
                   "0" * 64, "micromamba", "pinned",
                   "micromamba env create --offline", "accepted", "yes"]]
    shard = a.write("_code_error_recheck/k1.md",
                    _shard_text(ledgers, outcomes, mf_records))
    before = [
        rb.error_row("E-7000", etype="sample_filter_or_flag_error",
                     source="`do/probe.do`", location="`do/probe.do:1`",
                     status="candidate", severity="2"),
        rb.error_row("E-7001", etype="sample_filter_or_flag_error",
                     source="`environment.yml`", location="`environment.yml:1`",
                     status="candidate", severity="2"),
    ]
    final = [
        rb.error_row("E-7000", etype="sample_filter_or_flag_error",
                     source="`do/probe.do`", location="`do/probe.do:1`",
                     status=("not_error" if e7000_verdict == "not_error"
                             else "confirmed"),
                     severity=("" if e7000_verdict == "not_error" else "2")),
        rb.error_row("E-7001", etype="sample_filter_or_flag_error",
                     source="`environment.yml`", location="`environment.yml:1`",
                     status="confirmed", severity="2"),
    ]
    a.write_register("code_error_register.md", rb.ERROR_COLS, before,
                     title="Code-error register")
    a.write_register("_run/snapshots/code_b6/code_error_register.md",
                     rb.ERROR_COLS, before, title="Code-error register")
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, final,
                     title="Code-error register")
    a.write_recheck_summary("code")
    return root, a, shard


def test_b5_collision_verification_record_must_match_full_key(tmp_path):
    _root, a, shard, = _collision_case(tmp_path)
    result = rb.lint(a, "b5-code", shard)
    assert result.returncode == 1
    assert ("E-7000 not_error verification records do not cover every mapped key"
            in result.stdout)


def test_verifier_collision_record_must_match_full_key(tmp_path):
    root, a, _shard = _collision_case(tmp_path)
    result = rb.run_script("verify_dismissals.py", root, "--audit-dir", a.audit)
    assert result.returncode == 1
    assert "requires exactly one verification record" in result.stderr


def test_assembler_collision_outcome_join_uses_full_key(tmp_path):
    root, a, _shard = _collision_case(
        tmp_path, e7000_verdict="confirmed_error", omit_e7000_outcome=True)
    a.write("_run/dismissal_receipts.md",
            "# Dismissal receipts\n\n" + verifier.ZERO_RECEIPTS + "\n")
    result = rb.run_script("assemble_boundary.py", root, "--audit-dir", a.audit)
    assert result.returncode == 1
    assert (f"mapped witness DU/{DU_SOURCE}/{COLLIDE_WITNESS} has no worker outcome"
            in result.stderr)


def test_b6_collision_receipt_must_bind_full_key(tmp_path):
    _root, a, _shard = _collision_case(tmp_path)
    receipt = ["MF", "RCP-collide", MF_COLLIDE_SOURCE, COLLIDE_WITNESS,
               "VR-0001", "micromamba", "pinned", "0" * 64,
               "micromamba env create --offline", "0", "yes", "1" * 64]
    a.write("_run/dismissal_receipts.md",
            "# Dismissal receipts\n\n"
            + rb.md_table(verifier.RECEIPT_COLS, [receipt]))
    outcome_du = rb.witness_outcome_row(
        "DU", DU_SOURCE, COLLIDE_WITNESS, verdict="not_error", severity="—")
    canon_du = mechanism.canonicalize_mechanism(
        *outcome_du[4:9], register="code_errors", anchor="do/probe.do:1",
        projection=mechanism.EMPTY_PROJECTION)
    outcome_mf = rb.witness_outcome_row("MF", MF_COLLIDE_SOURCE, COLLIDE_WITNESS)
    canon_mf = mechanism.canonicalize_mechanism(
        *outcome_mf[4:9], register="code_errors", anchor="environment.yml:1",
        projection=mechanism.EMPTY_PROJECTION)
    post = [
        ["DU", DU_SOURCE, COLLIDE_WITNESS, "not_error", canon_du.sidecar,
         "—", "—", "—"],
        ["MF", MF_COLLIDE_SOURCE, COLLIDE_WITNESS, "confirmed_error",
         canon_mf.sidecar, "2", "—", "—"],
    ]
    a.write("_run/witness_outcomes.md",
            "# Witness outcomes\n\n"
            + rb.md_table(rb.POST_WITNESS_COLS, post)
            + "\n### Assembled dismissals\n\n| Error ID |\n| --- |\n| E-7000 |\n")
    result = rb.lint(a, "b6-code")
    assert result.returncode == 1
    assert "lacks qualifying receipt coverage" in result.stdout


def test_three_manifest_plants_score_green_end_to_end(tmp_path):
    assert bootstrap.ORACLE_PATH.is_file(), "pinned oracle must already be installed"
    root = tmp_path / "plants"
    root.mkdir()
    for relative in ("pyproject.toml", "conda-inventory/environment.yml",
                     "conda-legal/environment.yml"):
        source = rb.FIXTURE_DIR / "planted" / relative
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    a = rb.AuditDir(root)
    results = manifests.check_package(root)
    a.write("_run/manifest_check.md", manifests.render_artifact(results))
    grouped = {}
    for finding in results["findings"]:
        grouped.setdefault(finding["source_id"], []).append(finding)
    ids = {
        "pyproject.toml": "E-7000",
        "conda-inventory/environment.yml": "E-7001",
        "conda-legal/environment.yml": "E-7002",
    }
    mapping_rows, ledger_rows, outcome_rows, mf_records = [], [], [], []
    register_rows = []
    inventory = []
    for manifest, eid in ids.items():
        findings = next(rows for rows in grouped.values()
                        if rows[0]["manifest"] == manifest)
        source_id = findings[0]["source_id"]
        witness_ids, record_ids = [], []
        for finding_index, finding in enumerate(findings, start=1):
            witness = finding["witness_id"]
            witness_ids.append(witness)
            anchor = f"{manifest}:{finding['line']}" if finding["line"] else manifest
            mapping_rows.append({
                "Channel": "MF", "Source ID": source_id,
                "Witness ID": witness, "Error ID": eid,
                "Mapping Kind": "new_candidate", "Site Anchor": anchor,
            })
            verdict = "not_error" if eid == "E-7002" else "confirmed_error"
            outcome_rows.append(rb.witness_outcome_row(
                "MF", source_id, witness, verdict=verdict,
                severity="—" if verdict == "not_error" else (
                    "1" if eid == "E-7001" else "2"),
                mech_class="version_or_dependency_error",
                mech_object=manifest.replace("/", "-"), relation="wrong_value",
                expected="usable", actual="inventory" if eid == "E-7001" else "accepted",
            ))
            if finding["rule_slug"] == "conda-malformed-line":
                record_id = f"VR-{eid[2:]}-{finding_index:02d}"
                record_ids.append(record_id)
                mf_records.append(_mf_record(
                    root / manifest, source_id, witness, record_id))
        verdict = "not_error" if eid == "E-7002" else "confirmed_error"
        severity = "—" if verdict == "not_error" else ("1" if eid == "E-7001" else "2")
        ledger_rows.append(rb.code_ledger_row(
            eid, evidence=source_id, verdict=verdict,
            proposed_status="not_error" if verdict == "not_error" else "confirmed",
            proposed_severity=severity, accepted_type="version_or_dependency_error",
            accepted_mechanism="manifest usability adjudicated with authoritative consumer",
            witness_ids="; ".join(witness_ids),
            record_ids="; ".join(record_ids) if record_ids else "—",
        ))
        inventory.append((eid, "manifest detector", source_id))
        final_status = "confirmed"
        final_severity = "1" if eid in {"E-7001", "E-7002"} else "2"
        register_rows.append(rb.error_row(
            eid, etype="version_or_dependency_error", source=f"`{manifest}`",
            location=f"`{manifest}`", status=final_status,
            severity=final_severity,
            desc=("pyproject TOML parser rejection" if eid == "E-7000" else
                  "conda human inventory or accepted documentation line")))
    a.write("_run/detector_mapping.md", dm.render_mapping(
        "E-7000–E-7099", {"DU": [], "MF": mapping_rows}))
    clusters = [("K1", "manifest plants", "; ".join(ids.values()),
                 "`audit/_code_error_recheck/k1.md`")]
    a.write("plans/code_error_recheck_plan.md",
            rb.recheck_plan_text("code", inventory, clusters))
    shard = a.write("_code_error_recheck/k1.md",
                    _shard_text(ledger_rows, outcome_rows, mf_records))
    assert shard.is_file()
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS,
                     register_rows, title="Code-error register")
    assert rb.run_script("verify_dismissals.py", root,
                         "--audit-dir", a.audit).returncode == 0
    assembled = rb.run_script("assemble_boundary.py", root, "--audit-dir", a.audit)
    assert assembled.returncode == 0, assembled.stdout + assembled.stderr
    os.replace(a.audit / "_staging/code_error_register.md",
               a.audit / "code_error_register.md")
    a.write_register("claims_register.md", rb.CLAIMS_COLS, [])
    a.write_register("output_register.md", rb.OUTPUT_COLS, [])
    expected = {
        "adjudication_contract_plants": [
            {"id": "P-16", "manifest": "pyproject.toml",
             "verdict": "confirmed_error", "final_status": "confirmed",
             "min_severity": 2, "receipt_required": False},
            {"id": "P-22", "manifest": "conda-inventory/environment.yml",
             "verdict": "confirmed_error", "final_status": "confirmed",
             "exact_severity": 1, "receipt_required": False},
            {"id": "D-04", "manifest": "conda-legal/environment.yml",
             "verdict": "not_error", "final_status": "not_error",
             "receipt_required": True},
        ],
        "must_find": [], "must_not_find": [], "expected_status_conflicts": [],
    }
    expected_path = tmp_path / "u3b-expected.json"
    expected_path.write_text(json.dumps(expected), encoding="utf-8")
    scored = rb.run_script("score_fixture.py", "--audit-dir", a.audit,
                           "--expected", expected_path)
    assert scored.returncode == 0, scored.stdout + scored.stderr
    assert "U3b adjudication channel: PASS" in scored.stdout
    assert "GATE GREEN" in scored.stdout
