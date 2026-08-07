"""U9c diagnosed-fix cycle: register handoffs, bands, and replay parity."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import regbuild as rb
import test_replay_harness as replay_helpers
import test_u6_read_recall as u6read
import test_u6_supplementary as u6


ac = rb.load_script("check_argument_contracts")
certify = rb.load_script("certify_stage")
dm = rb.load_script("build_detector_mapping")
lintmod = rb.load_script("lint_registers")
mechanism = rb.load_script("mechanism_schema")
replay = rb.load_script("replay_stage")
rulings = rb.load_script("severity_token_rulings")
score_fixture = rb.load_script("score_fixture")
tokens = rb.load_script("severity_tokens")
verifier = rb.load_script("verify_dismissals")

pytestmark = pytest.mark.u9

AC_SOURCE_ID = ac.source_id("source.py", 1, 0)


def _ac_artifact(source_id=AC_SOURCE_ID, witnesses=("argpos:2",)):
    call = ac.CallSite(
        source_id, "source.py:1@call=0", "shell", "python", "source.py",
        "source.py", "direct", tuple(int(w.split(":")[1]) for w in witnesses),
        (1,), "contract_mismatch",
    )
    findings = tuple(
        ac.Finding(
            source_id, witness, "passed_but_unread", witness.split(":")[1],
            "source.py", "source.py:1@call=0",
        )
        for witness in witnesses
    )
    return ac.Artifact("a" * 64, (call,), findings)


def _mapping_row(channel, source_id, witness_id, error_id, anchor):
    return {
        "Channel": channel, "Source ID": source_id, "Witness ID": witness_id,
        "Error ID": error_id, "Mapping Kind": "new_candidate",
        "Site Anchor": anchor,
    }


def _write_mapping(a, rows):
    by_channel = {channel: [] for channel in dm.CHANNELS}
    for row in rows:
        by_channel[row["Channel"]].append(row)
    a.write("_run/detector_mapping.md", dm.render_mapping(
        "E-7000–E-7099", by_channel))


def _minimal_b6_case(tmp_path, *, channel, source_id, witness_id, verdict,
                     accepted, rule=None, stamp=None, severity="2",
                     pd_statement='open("../out.txt")'):
    root = tmp_path / "package"
    root.mkdir()
    (root / "source.py").write_text("value = 1\n", encoding="utf-8")
    (root / "environment.yml").write_text(
        "name: empty\nprefix: /tmp/example\n", encoding="utf-8")
    a = rb.AuditDir(root)
    a.write("_run/definition_use_bundles.md", rb.definition_use_artifact([]))
    rb.emit_path_derivations(a)
    error_id = "E-7000"
    anchor = {"AC": "source.py:1@call=0", "PD": "source.py:2"}.get(
        channel, "environment.yml:2")
    mapping = _mapping_row(channel, source_id, witness_id, error_id, anchor)
    _write_mapping(a, [mapping])
    if channel == "AC":
        artifact = _ac_artifact(source_id, (witness_id,))
        a.write("_run/argument_contracts.md", ac.render(artifact))
    if channel == "PD":
        # The stamp binding reads every raw detector artifact, so the AC one
        # has to exist even when the mapped channel is PD.
        a.write("_run/argument_contracts.md",
                ac.render(ac.Artifact("a" * 64, (), ())))
        a.write("_run/path_derivation_bundles.md", rb.path_derivation_artifact(
            "source.py", [(2, "path literal", pd_statement, "no_known_caller")]))
    if channel == "MF":
        a.write(
            "_run/manifest_check.md",
            "# Manifest check\n\n"
            + rb.md_table(
                ["Source ID", "Witness ID", "Site Anchor", "Rule Slug",
                 "Offending Text", "Problem"],
                [[source_id, witness_id, anchor, rule or "conda-malformed-line",
                  "prefix: /tmp/example", "oracle adjudication"]],
            ),
        )
    else:
        a.write(
            "_run/manifest_check.md",
            "# Manifest parseability check\n\n"
            + verifier.manifests.NO_FINDINGS_LINE + "\n"
            + verifier.manifests.MF_ZERO_LINE + "\n",
        )
    status = "not_error" if verdict == "not_error" else "confirmed"
    severity = "" if verdict == "not_error" else severity
    description = stamp or "detector candidate description"
    final = rb.error_row(
        error_id, etype="missing_input_or_output", source="`source.py`",
        location=anchor, status=status, severity=severity, desc=description,
    )
    a.write_register("code_error_register.md", rb.ERROR_COLS, [final])
    a.write_register(
        "_run/snapshots/code_b6a/code_error_register.md",
        rb.ERROR_COLS, [final],
    )
    record_id = "VR-0001"
    ledger = rb.code_ledger_row(
        error_id, evidence=source_id, verdict=verdict,
        proposed_status=status, proposed_severity=severity or "—",
        accepted_type="missing_input_or_output", witness_ids=witness_id,
        record_ids=record_id,
    )
    a.write(
        "_code_error_recheck/k1.md",
        rb.register_text("Recheck ledger", rb.CODE_LEDGER_COLS, [ledger]),
    )
    a.write("code_error_recheck_summary.md", "# Recheck summary\n")
    sidecar = mechanism.canonicalize_mechanism(
        "missing_input_or_output", "source.py", "omits", "[argument]", "-",
        register="code_errors", anchor=anchor,
        projection=mechanism.EMPTY_PROJECTION,
    ).sidecar
    a.write(
        "_run/code_b6a/witness_outcomes.md",
        "# Witness outcomes\n\n"
        + rb.md_table(rb.POST_WITNESS_COLS, [[
            channel, source_id, witness_id, verdict, sidecar,
            severity or "—", ("RCP-test" if accepted else "—"), "—",
        ]])
        + "\n### Assembled dismissals\n\n"
        + (rb.md_table(["Error ID"], [[error_id]])
           if verdict == "not_error"
           else "No mapped Error IDs were assembled as not_error.\n"),
    )
    receipt = [
        channel, "RCP-test", source_id, witness_id, record_id, "micromamba",
        "test", "a" * 64, "micromamba env create", "0" if accepted else "1",
        "yes" if accepted else "no", "b" * 64,
    ]
    a.write(
        "_run/code_b6a/dismissal_receipts.md",
        "# Dismissal receipts\n\n"
        + rb.md_table(verifier.RECEIPT_COLS, [receipt]),
    )
    return root, a


def test_p26_builder_stamps_every_argument_contract_witness(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    (root / "source.py").write_text("value = 1\n", encoding="utf-8")
    a = rb.AuditDir(root)
    source_id = AC_SOURCE_ID
    artifact = _ac_artifact(source_id, ("argpos:2", "argpos:3"))
    a.write("_run/argument_contracts.md", ac.render(artifact))
    a.write("_run/definition_use_bundles.md", rb.definition_use_artifact([]))
    rb.emit_path_derivations(a)
    a.write(
        "_run/manifest_check.md",
        "# Manifest parseability check\n\n"
        + verifier.manifests.NO_FINDINGS_LINE + "\n"
        + verifier.manifests.MF_ZERO_LINE + "\n",
    )
    a.write_manifest(mode="code_errors_only", scope_exclusions=[], off_limits=[])
    candidate = rb.error_row(
        "E-7000", etype="missing_input_or_output", source="`source.py`",
        location="source.py:1@call=0", status="candidate", severity="2",
    )
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [candidate])
    a.write_register(
        "_run/snapshots/code_b3d/code_error_register.md", rb.ERROR_COLS, [])
    a.write(
        "_run/detector_mapping_decisions.md",
        "# Decisions\n\nDeclared detector Error-ID range: E-7000–E-7099\n\n"
        + rb.md_table(dm.DECISION_COLS, [[
            "AC", source_id, "E-7000", "new_candidate",
        ]]),
    )
    result = rb.run_script(
        "build_detector_mapping.py", root, "--audit-dir", a.audit)
    assert result.returncode == 0, result.stdout + result.stderr
    row = dm.parse_register(a.audit / "_staging/code_error_register.md")["E-7000"]
    expected = [
        dm.argument_contract_stamp(
            finding.finding_kind, finding.witness_id, "source.py",
            finding.callee_path, finding.argument_position,
            finding.site_anchor,
        )
        for finding in artifact.findings
    ]
    assert all(sentence in row["Error Description"] for sentence in expected)
    assert row["Error Description"].count("Argument-contract finding") == 2


def test_p26_b6_binding_fires_on_stripped_stamp_and_is_quiet_when_preserved(
        tmp_path):
    source_id, witness_id = AC_SOURCE_ID, "argpos:2"
    stamp = dm.argument_contract_stamp(
        "passed_but_unread", witness_id, "source.py", "source.py", "2",
        "source.py:1@call=0")
    _root, a = _minimal_b6_case(
        tmp_path, channel="AC", source_id=source_id, witness_id=witness_id,
        verdict="confirmed_error", accepted=False, stamp=stamp,
    )
    clean = lintmod.Lint()
    lintmod.check_detector_mapping_b6(clean, a.audit)
    assert not any("machine-written stamp" in error for error in clean.errors)
    register = a.audit / "code_error_register.md"
    register.write_text(
        register.read_text(encoding="utf-8").replace(stamp, ""),
        encoding="utf-8",
    )
    stripped = lintmod.Lint()
    lintmod.check_detector_mapping_b6(stripped, a.audit)
    assert any("machine-written stamp" in error for error in stripped.errors)


def test_tier1_p26_survival_test_oracle_notices_disabled_binding(
        tmp_path, monkeypatch):
    source_id, witness_id = AC_SOURCE_ID, "argpos:2"
    stamp = dm.argument_contract_stamp(
        "passed_but_unread", witness_id, "source.py", "source.py", "2",
        "source.py:1@call=0")
    _root, a = _minimal_b6_case(
        tmp_path, channel="AC", source_id=source_id, witness_id=witness_id,
        verdict="confirmed_error", accepted=False, stamp=stamp,
    )
    register = a.audit / "code_error_register.md"
    register.write_text(
        register.read_text(encoding="utf-8").replace(stamp, ""),
        encoding="utf-8",
    )

    def negative_oracle():
        state = lintmod.Lint()
        lintmod.check_detector_mapping_b6(state, a.audit)
        assert any("machine-written stamp" in error for error in state.errors)

    negative_oracle()
    monkeypatch.setattr(
        lintmod.detector_mapping, "expected_candidate_stamps",
        lambda *_args, **_kwargs: {},
    )
    with pytest.raises(AssertionError):
        negative_oracle()


def test_tier1_p26_post_b6a_strip_fails_b6b_and_verify_run_clis(tmp_path):
    root, a, _shard = u6.make_wave(tmp_path, discovery=False)
    source_id, witness_id = AC_SOURCE_ID, "argpos:2"
    artifact = _ac_artifact(source_id, (witness_id,))
    a.write("_run/argument_contracts.md", ac.render(artifact))
    a.write("_run/definition_use_bundles.md", rb.definition_use_artifact([]))
    rb.emit_path_derivations(a)
    a.write(
        "_run/manifest_check.md",
        "# Manifest parseability check\n\n"
        + verifier.manifests.NO_FINDINGS_LINE + "\n"
        + verifier.manifests.MF_ZERO_LINE + "\n",
    )
    _write_mapping(a, [
        _mapping_row(
            "AC", source_id, witness_id, "E-0100",
            "source.py:1@call=0",
        ),
    ])
    stamp = dm.argument_contract_stamp(
        "passed_but_unread", witness_id, "source.py", "source.py", "2",
        "source.py:1@call=0")
    sidecar = mechanism.canonicalize_mechanism(
        "missing_input_or_output", "source.py", "omits", "[argument]", "-",
        register="code_errors", anchor="source.py:1@call=0",
        projection=mechanism.EMPTY_PROJECTION,
    ).sidecar
    ledger = rb.code_ledger_row(
        "E-0100", evidence=source_id, verdict="confirmed_error",
        proposed_status="confirmed", proposed_severity="2",
        accepted_type="missing_input_or_output",
        accepted_mechanism=sidecar, witness_ids=witness_id,
    )
    outcome = rb.witness_outcome_row(
        "AC", source_id, witness_id, verdict="confirmed_error",
        severity="2", mech_class="missing_input_or_output",
        mech_object="source.py", relation="omits",
        expected="[argument]", actual="-",
    )
    a.write(
        "_code_error_recheck/k1.md",
        rb.register_text("Recheck ledger", rb.CODE_LEDGER_COLS, [ledger])
        + "\n### Witness outcomes\n\n"
        + rb.md_table(rb.WITNESS_OUTCOME_COLS, [outcome])
        + "\n### Verification records\n\nNo verification records.\n"
        + u6.footer(),
    )
    stamped = rb.error_row(
        "E-0100", etype="missing_input_or_output", source="`source.py`",
        location="source.py:1@call=0", status="confirmed", severity="2",
        desc=stamp,
    )
    a.write_register(
        "_run/snapshots/code_b6b/code_error_register.md",
        rb.ERROR_COLS, [stamped],
    )
    a.write_register("code_error_register.md", rb.ERROR_COLS, [stamped])
    assembler_text = rb.md_table(rb.POST_WITNESS_COLS, [[
        "AC", source_id, witness_id, "confirmed_error", sidecar, "2",
        "—", "—",
    ]])
    a.write(
        "_run/code_b6a/witness_outcomes.md",
        "# Witness outcomes\n\n" + assembler_text
        + "\n### Assembled dismissals\n\n"
        "No mapped Error IDs were assembled as not_error.\n",
    )
    u6.certify_to_b5s(root, discovery=False)
    started = u6.cli(root, "start", "--stage", "code_b6b")
    assert started.returncode == 0, started.stdout + started.stderr
    register = a.audit / "code_error_register.md"
    register.write_text(
        register.read_text(encoding="utf-8").replace(stamp, ""),
        encoding="utf-8",
    )
    direct = rb.lint(a, "b6b-code")
    assert direct.returncode == 1
    assert "machine-written stamp" in direct.stdout
    refused = u6.cli(
        root, "finish", "--stage", "code_b6b", "--outcome", "done")
    assert refused.returncode == 1
    assert "machine-written stamp" in refused.stderr
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    manifest["stages"]["code_b6b"]["status"] = "done"
    u6.certify.write_manifest_atomic(root, manifest)
    verified = u6.cli(root, "verify-run")
    assert verified.returncode == 1
    assert "code_b6b" in verified.stderr


def test_b6b_proposal_equality_survives_lawful_later_severity_cap(
        tmp_path):
    stamp = dm.argument_contract_stamp(
        "passed_but_unread", "argpos:2", "source.py", "source.py", "2",
        "source.py:1@call=0")
    _root, a = _minimal_b6_case(
        tmp_path, channel="AC", source_id=AC_SOURCE_ID,
        witness_id="argpos:2", verdict="confirmed_error",
        accepted=False, stamp=stamp, severity="3",
    )
    proposal = a.audit / "_run/snapshots/post_b6b/code_error_register.md"
    proposal.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(a.audit / "code_error_register.md", proposal)
    final = rb.error_row(
        "E-7000", etype="missing_input_or_output", source="`source.py`",
        location="source.py:1@call=0", status="confirmed", severity="2",
        desc=stamp,
    )
    a.write_register("code_error_register.md", rb.ERROR_COLS, [final])

    lawful_cap = lintmod.Lint()
    lintmod.check_detector_mapping_b6(
        lawful_cap, a.audit, proposal_path=proposal,
        survival_path=a.audit / "code_error_register.md")
    assert not lawful_cap.errors

    a.write_register(
        "code_error_register.md", rb.ERROR_COLS,
        [rb.error_row(
            "E-7000", etype="missing_input_or_output",
            source="`source.py`", location="source.py:1@call=0",
            status="confirmed", severity="2", desc="stamp removed",
        )],
    )
    stripped = lintmod.Lint()
    lintmod.check_detector_mapping_b6(
        stripped, a.audit, proposal_path=proposal,
        survival_path=a.audit / "code_error_register.md")
    assert any("machine-written stamp" in error for error in stripped.errors)
    assert not any("disagrees with applied proposal" in error
                   for error in stripped.errors)


@pytest.mark.parametrize("form", ["multi", "single", "zero"])
def test_second_read_plan_accepts_sectioned_detector_mapping_forms(
        tmp_path, form):
    root, a = u6read.detector_chain(tmp_path)
    _declared, _display, existing = dm.load_mapping(
        a.audit / "_run/detector_mapping.md")
    channels = {channel: [] for channel in dm.CHANNELS}
    if form != "zero":
        channels[existing[0]["Channel"]].append(existing[0])
    if form == "multi":
        channels["DU"].append({
            "Channel": "DU", "Source ID": "DU-0123456789ab",
            "Witness ID": "DUW-0123456789ab", "Error ID": "E-7000",
            "Mapping Kind": "existing_row",
            "Site Anchor": "requirements-recall.txt:1",
        })
    a.write(
        "_run/detector_mapping.md",
        dm.render_mapping("E-7000–E-7099", channels),
    )
    current_rows = dm.parse_register(a.audit / "code_error_register.md")
    a.write_register(
        "_run/snapshots/code_b3b/code_error_register.md",
        rb.ERROR_COLS,
        [[row[column] for column in rb.ERROR_COLS]
         for row in current_rows.values()],
    )

    built = rb.run_script(
        "build_second_read_plan.py", root, "--audit-dir", a.audit)
    assert built.returncode == 0, built.stdout + built.stderr
    plan = a.audit / "plans/code_error_second_read_plan.md"
    first = plan.read_bytes()
    checked = rb.run_script(
        "build_second_read_plan.py", root, "--audit-dir", a.audit, "--check")
    assert checked.returncode == 0, checked.stdout + checked.stderr
    rebuilt = rb.run_script(
        "build_second_read_plan.py", root, "--audit-dir", a.audit)
    assert rebuilt.returncode == 0, rebuilt.stdout + rebuilt.stderr
    assert plan.read_bytes() == first


def _finish_b0_with_certified_evidence(tmp_path):
    a = rb.make_b0(tmp_path)
    a.write_manifest(
        allocation_override={"purpose": "development", "allocation": []})
    certify.init_run(a.root)
    certify.start_stage(a.root, "b0")
    certify.finish_stage(a.root, "b0", "done")
    return a


def test_tier1_stage_era_b0_survives_tail_and_tamper_refuses_both_commands(
        tmp_path):
    a = _finish_b0_with_certified_evidence(tmp_path)
    claim = rb.claims_row(
        "C-0001", status="unclear", severity="2",
        issue="candidate-era issue")
    a.write_register("claims_register.md", rb.CLAIMS_COLS, [claim])
    a.write_register("output_register.md", rb.OUTPUT_COLS, [])
    plan = rb.recheck_plan_text(
        "claims",
        [("C-0001", "issue-flagged", "static")],
        [("K1", "cluster one", "C-0001", "`audit/_recheck/k1.md`")],
    )
    a.write("plans/claims_recheck_plan.md", plan)
    shard = a.write(
        "_recheck/k1.md",
        rb.register_text(
            "Recheck ledger", rb.LEDGER_COLS,
            [rb.ledger_row(
                "C-0001", status="unclear", severity="2",
                verdict="substantiated")],
        )
        + rb._shard_footer_text([], include_phase=False),
    )
    certify.start_stage(a.root, "claims_b4")
    certify.finish_stage(a.root, "claims_b4", "done")
    certify.start_stage(a.root, "claims_b5")
    certify.set_shard(
        a.root, "claims_b5", f"audit/{shard.relative_to(a.audit)}", "done")
    certify.finish_stage(a.root, "claims_b5", "done")

    rewritten_columns, rewritten_rows = rb.rewrite_pass_cols(
        rb.CLAIMS_COLS,
        [rb.claims_row(
            "C-0001", status="confirmed", severity="2",
            issue="final author-facing issue")],
        ["Issue Description"],
    )
    a.write_register(
        "claims_register.md", rewritten_columns, rewritten_rows)
    a.write_register(
        "code_error_register.md", rb.ERROR_COLS,
        [rb.error_row("E-0001", severity="2")])

    certify.verify_run(a.root)
    certify.resume_check(a.root, clear_stale_marker=True)

    frozen = (
        a.audit / "_run/certified_stage_evidence/b0/"
        "code_error_register.md"
    )
    frozen.write_text(
        frozen.read_text(encoding="utf-8") + "\nhand-flipped\n",
        encoding="utf-8",
    )
    with pytest.raises(
            certify.CertificationError, match="edited after certification"):
        certify.verify_run(a.root)
    with pytest.raises(
            certify.CertificationError, match="edited after certification"):
        certify.resume_check(a.root, clear_stale_marker=True)


@pytest.mark.parametrize(
    ("stage", "filenames"),
    sorted(certify.CERTIFIED_REGISTER_EVIDENCE.items()),
)
def test_stage_era_evidence_missing_and_malformed_fail_closed(
        tmp_path, stage, filenames):
    a = rb.AuditDir(tmp_path)
    for filename in filenames:
        columns = {
            "claims_register.md": rb.CLAIMS_COLS,
            "output_register.md": rb.OUTPUT_COLS,
            "code_error_register.md": rb.ERROR_COLS,
        }[filename]
        a.write_register(filename, columns, [])
    entry = {}
    certify._capture_certified_stage_evidence(a.root, stage, entry)
    manifest = {
        "certified_stage_evidence_version":
            certify.CERTIFIED_EVIDENCE_VERSION,
    }
    assert not certify._certified_stage_evidence_failures(
        a.root, manifest, stage, entry)

    evidence_dir = certify._certified_evidence_dir(a.audit, stage)
    (evidence_dir / filenames[0]).unlink()
    failures = certify._certified_stage_evidence_failures(
        a.root, manifest, stage, entry)
    assert any("missing or malformed" in failure for failure in failures)

    malformed = {
        "certified_evidence": {
            "version": certify.CERTIFIED_EVIDENCE_VERSION,
            "registers": {},
        }
    }
    failures = certify._certified_stage_evidence_failures(
        a.root, manifest, stage, malformed)
    assert any("expected exactly" in failure for failure in failures)


@pytest.mark.parametrize(
    "deleted", ["root-marker", "stage-binding", "both"])
def test_stage_era_binding_deletions_refuse_verify_and_resume(
        tmp_path, deleted):
    a = _finish_b0_with_certified_evidence(tmp_path)
    manifest = certify.read_manifest(a.root)
    if deleted in {"root-marker", "both"}:
        manifest.pop("certified_stage_evidence_version")
    if deleted in {"stage-binding", "both"}:
        manifest["stages"]["b0"].pop("certified_evidence")
    certify.write_manifest_atomic(a.root, manifest)

    with pytest.raises(
            certify.CertificationError,
            match="missing certified stage-era evidence"):
        certify.verify_run(a.root)
    with pytest.raises(
            certify.CertificationError,
            match="missing certified stage-era evidence"):
        certify.resume_check(a.root, clear_stale_marker=True)


def test_pending_only_initialized_run_requires_root_evidence_version(
        tmp_path):
    a = rb.make_b0(tmp_path)
    a.write_manifest(
        allocation_override={"purpose": "development", "allocation": []})
    certify.init_run(a.root)
    manifest = certify.read_manifest(a.root)
    assert all(
        entry["status"] == "pending"
        for entry in manifest["stages"].values()
    )
    manifest.pop("certified_stage_evidence_version")
    certify.write_manifest_atomic(a.root, manifest)

    with pytest.raises(
            certify.CertificationError,
            match="missing certified stage-era evidence"):
        certify.verify_run(a.root)
    with pytest.raises(
            certify.CertificationError,
            match="missing certified stage-era evidence"):
        certify.resume_check(a.root, clear_stale_marker=True)


@pytest.mark.parametrize(
    "invalid_version", [True, 1.0],
    ids=["boolean", "float"],
)
def test_pending_only_initialized_run_rejects_type_wrong_root_version(
        tmp_path, invalid_version):
    a = rb.make_b0(tmp_path)
    a.write_manifest(
        allocation_override={"purpose": "development", "allocation": []})
    certify.init_run(a.root)
    manifest = certify.read_manifest(a.root)
    manifest["certified_stage_evidence_version"] = invalid_version
    certify.write_manifest_atomic(a.root, manifest)

    with pytest.raises(
            certify.CertificationError,
            match="missing certified stage-era evidence"):
        certify.verify_run(a.root)
    with pytest.raises(
            certify.CertificationError,
            match="missing certified stage-era evidence"):
        certify.resume_check(a.root, clear_stale_marker=True)


@pytest.mark.parametrize(
    "invalid_version", [True, 1.0],
    ids=["boolean", "float"],
)
def test_completed_stage_rejects_type_wrong_stage_evidence_version(
        tmp_path, invalid_version):
    a = _finish_b0_with_certified_evidence(tmp_path)
    manifest = certify.read_manifest(a.root)
    manifest["stages"]["b0"]["certified_evidence"][
        "version"] = invalid_version
    certify.write_manifest_atomic(a.root, manifest)

    with pytest.raises(
            certify.CertificationError,
            match="unsupported certified evidence version"):
        certify.verify_run(a.root)
    with pytest.raises(
            certify.CertificationError,
            match="unsupported certified evidence version"):
        certify.resume_check(a.root, clear_stale_marker=True)


def test_stage_era_test3_breaking_selector_makes_late_canon_fail(
        tmp_path, monkeypatch):
    a = _finish_b0_with_certified_evidence(tmp_path)
    a.write_register(
        "code_error_register.md", rb.ERROR_COLS,
        [rb.error_row("E-0001", severity="2")])
    monkeypatch.setattr(
        certify, "_certified_stage_evidence_failures",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        certify, "_certified_evidence_dir",
        lambda audit, _stage: audit,
    )
    with pytest.raises(
            certify.CertificationError, match="register must be empty at b0"):
        certify.verify_run(a.root)


def test_d03_matcher_stays_quiet_on_preserved_p18_row_and_keeps_plant_hits():
    # Verbatim from the preserved gate run 1 register
    # (~/scratch/rca-u9b-gate-run1-pkg/audit/code_error_register.md).
    preserved = {
        "Error ID": "E-0010",
        "Error Type": "sample_filter_or_flag_error",
        "Code/Data Source": "`py/build_income.py`",
        "Code Location": "`py/build_income.py:24-26`",
        "Status": "confirmed", "Severity": "2",
        "Error Description": (
            'Line 24 comment says "Flag households reporting wage earnings '
            'in any wave." Lines 25-26 loop over waves `(1, 2)` and assign '
            '`df["has_wages"] = (df["wave"] == wave) & '
            '(df["wage_earnings"] > 0)` each iteration. Each iteration '
            "overwrites the column entirely, so after the loop completes "
            "only wave 2 status is retained. Synthetic probe confirmed: a "
            "household with wage_earnings > 0 only in wave 1 is flagged "
            "False for both of its rows."),
        "Why It Matters": (
            "The has_wages diagnostic flag is incorrect for any household "
            "whose wage status differs between waves. The flag only "
            'reflects wave 2 status, not "any wave" as the comment '
            "documents."),
    }
    # Verbatim from the preserved invalid-config run register
    # (~/scratch/rca-u9b-invalid-config-run-20260722-pkg/audit/).
    preserved_e0051 = {
        "Error ID": "E-0051",
        "Error Type": "sample_filter_or_flag_error",
        "Code/Data Source": "`py/build_income.py`",
        "Code Location": "`py/build_income.py:25-26`",
        "Status": "confirmed", "Severity": "2",
        "Error Description": (
            'The comment on line 24 says "Flag households reporting wage '
            'earnings in any wave." The loop `for wave in (1, 2): '
            'df["has_wages"] = ...` overwrites `has_wages` on each '
            "iteration, so after the loop completes only the wave-2 "
            "condition survives. Households with wage earnings in wave 1 "
            "but not wave 2 are incorrectly flagged False. Synthetic probe "
            "confirmed: a household with wage_earnings > 0 only in wave 1 "
            "gets has_wages = False after the loop."),
        "Why It Matters": (
            "The has_wages flag in output/income_check.csv is incorrect "
            "for all wave-1-only wage earners; the diagnostic output does "
            "not match its stated intent."),
    }
    assert score_fixture.is_d03(preserved) is False
    assert score_fixture.is_d03(preserved_e0051) is False
    assert score_fixture.is_d03({
        **preserved, "Code/Data Source": "`do/analysis.do`",
        "Code Location": "`do/analysis.do:41`",
        "Error Description": (
            "The first-wave diagnostic restricts the analytic sample by "
            "dropping baseline observations."),
    }) is True
    assert score_fixture.is_d03({
        **preserved, "Code/Data Source": "`do/analysis.do`",
        "Code Location": "`do/analysis.do:13`",
    }) is True


@pytest.mark.parametrize(
    "accepted,verdict,expected_failure",
    [(True, "confirmed_error", True),
     (False, "confirmed_error", False),
     (True, "not_error", False)],
)
def test_d04_b6_oracle_accept_obligation(
        tmp_path, accepted, verdict, expected_failure):
    _root, a = _minimal_b6_case(
        tmp_path, channel="MF", source_id="MF-aaaaaaaaaaaa",
        witness_id="MFW-bbbbbbbbbbbb", verdict=verdict, accepted=accepted,
        rule="conda-malformed-line",
    )
    state = lintmod.Lint()
    lintmod.check_detector_mapping_b6(state, a.audit)
    failures = [
        error for error in state.errors
        if "required disposition is mechanical not_error" in error
    ]
    assert bool(failures) is expected_failure


def test_d04_receipt_obligation_skips_duplicate_verdict(tmp_path):
    # verify_dismissals mints pinned-oracle receipts only for not_error and
    # confirmed_error dispositions, so the b6 cardinality check must stay
    # quiet on a duplicate verdict — otherwise the failure is unsatisfiable.
    _root, a = _minimal_b6_case(
        tmp_path, channel="MF", source_id="MF-aaaaaaaaaaaa",
        witness_id="MFW-bbbbbbbbbbbb", verdict="confirmed_error",
        accepted=False, rule="conda-malformed-line",
    )
    shard = a.audit / "_code_error_recheck/k1.md"
    shard.write_text(
        shard.read_text(encoding="utf-8").replace(
            "| confirmed_error |", "| duplicate |"),
        encoding="utf-8",
    )
    a.write(
        "_run/code_b6a/dismissal_receipts.md",
        "# Dismissal receipts\n\n" + verifier.ZERO_RECEIPTS + "\n",
    )
    state = lintmod.Lint()
    lintmod.check_detector_mapping_b6(state, a.audit)
    assert not any("pinned-oracle receipt" in error for error in state.errors)
    assert not any(
        "required disposition is mechanical not_error" in error
        for error in state.errors
    )


def test_d04_verifier_receipts_confirmed_conda_candidate(
        tmp_path, monkeypatch):
    root, a = _minimal_b6_case(
        tmp_path, channel="MF", source_id="MF-aaaaaaaaaaaa",
        witness_id="MFW-bbbbbbbbbbbb", verdict="confirmed_error",
        accepted=True, rule="conda-malformed-line",
    )
    record = [
        "MF", "VR-0001", "MF-aaaaaaaaaaaa", "MFW-bbbbbbbbbbbb",
        "a" * 64, "micromamba", "test", "micromamba env create",
        "accepted", "yes",
    ]
    shard = a.audit / "_code_error_recheck/k1.md"
    shard.write_text(
        shard.read_text(encoding="utf-8")
        + "\n" + rb.md_table(verifier.MF_RECORD_COLS, [record]),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        verifier, "_manifest_run",
        lambda *_args: (
            "micromamba", "test", "micromamba env create",
            SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
        ),
    )
    receipts = verifier.verify(root, a.audit)
    assert len(receipts) == 1
    assert receipts[0]["Accepted (yes/no)"] == "yes"


def _p28_fixture(tmp_path, *, cv=True, covering=False, verdict="upheld"):
    root = tmp_path / "package"
    root.mkdir(parents=True)
    a = rb.AuditDir(root)
    a.write_manifest(mode="replication")
    py = root / "py"
    py.mkdir()
    capita = ["pass"] * 20
    capita[13] = 'income_pc = income / age_head'
    capita[16] = 'wage_pc = wage_earnings / age_head'
    capita[19] = 'crop_pc = crop_sales / age_head'
    (py / "build_capita.py").write_text("\n".join(capita) + "\n", encoding="utf-8")
    (py / "table.py").write_text("print(age_head)\n", encoding="utf-8")
    row = rb.error_row(
        "E-0011", etype="aggregation_or_unit_error",
        source="`py/build_capita.py`; `py/table.py`",
        location="py/build_capita.py:14", status="confirmed", severity="3",
        desc="wage_pc divides by age_head",
        why="reported output is affected output:O-0121",
    )
    a.write_register("code_error_register.md", rb.ERROR_COLS, [row])
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [row])
    a.write_register("claims_register.md", rb.CLAIMS_COLS, [])
    a.write_register("output_register.md", rb.OUTPUT_COLS, [
        rb.output_row(
            "O-0121", script="`py/table.py`",
            location="`paper/paper.tex:1`"),
    ])
    witness = "CVW-774f1d1f861f" if cv else "DUW-774f1d1f861f"
    channel = "CV" if cv else "DU"
    source_id = "CV-267217db96d3" if cv else "DU-267217db96d3"
    mapping = _mapping_row(
        channel, source_id, witness, "E-0011",
        ('py/build_capita.py:line 17: `wage_pc = wage_earnings / age_head`'
         if cv else "py/build_capita.py:17"),
    )
    _write_mapping(a, [mapping])
    sidecar = mechanism.canonicalize_mechanism(
        "variable_substitution", "age_head", "wrong_value", "hhsize",
        "age_head", register="code_errors", anchor="py/build_capita.py:17",
        projection=mechanism.EMPTY_PROJECTION,
    ).sidecar
    lineage = [{"anchor": "py/build_capita.py:14", "carries": "age_head"}]
    if covering:
        lineage.append({
            "anchor": "py/build_capita.py:17", "carries": "wage_pc"})
    lineage.append({"anchor": "py/table.py:1", "carries": "age_head"})
    digest = tokens.obligation_digest(
        "E-0011", "output:O-0121", sidecar, witness,
        "py/build_capita.py:14", "age_head",
    )
    record = {
        "Record Type": "token_verification", "Error ID": "E-0011",
        "Token": "output:O-0121", "Obligation Digest": digest,
        "Mechanism": sidecar, "Witness IDs": witness,
        "Error Location": "py/build_capita.py:14",
        "Flawed Identifier": "age_head", "Cited Target": "O-0121",
        "Lineage JSON": json.dumps(lineage, separators=(",", ":")),
        "Probe Path": "probe.py",
        "Probe Output SHA256": tokens.result_digest(0, b"", b""),
        "Verdict": "verified", "Derived From Receipt ID": "—",
    }
    ledger = rb.code_ledger_row(
        "E-0011", status="confirmed", severity="3",
        proposed_status="confirmed", proposed_severity="3",
        accepted_type="aggregation_or_unit_error",
        accepted_mechanism=sidecar, witness_ids=witness,
    )
    shard = a.audit / "_code_error_recheck/k1.md"
    shard.parent.mkdir(parents=True, exist_ok=True)
    (shard.parent / "probe.py").write_text("pass\n", encoding="utf-8")
    a.write(
        "_code_error_recheck/k1.md",
        rb.register_text("Recheck ledger", rb.CODE_LEDGER_COLS, [ledger])
        + "\n### Token verification records\n\n"
        + rb.md_table(tokens.TOKEN_RECORD_COLS, [[
            record[column] for column in tokens.TOKEN_RECORD_COLS
        ]]),
    )
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    receipts, failures = tokens.verify_token_records(
        root, a.audit, manifest, "code_b6b")
    assert failures == []
    tokens.write_atomic(
        tokens.receipt_path(a.audit, "code_b6b"),
        tokens.render_receipts(receipts),
    )
    a.write(
        "register_cross_link_summary.md",
        "# Cross-link summary\n\n## Severity-token adjudications\n\n"
        + rb.md_table(tokens.ADJUDICATION_COLS, [[
            "E-0011 output:O-0121", "O-0121", verdict, "py/table.py:1",
        ]]),
    )
    return root, a, manifest


def test_p28_b7_refuses_borrowed_tie_allows_covering_lineage_and_ignores_non_cv(
        tmp_path):
    root, a, manifest = _p28_fixture(tmp_path / "borrowed")
    _rejected, failures = rulings.validate_b7(root, a.audit, manifest)
    assert any("mapped CV witness-site mismatch cannot be upheld" in f
               for f in failures)
    root, a, manifest = _p28_fixture(tmp_path / "cover", covering=True)
    _rejected, failures = rulings.validate_b7(root, a.audit, manifest)
    assert not any("witness-site" in f for f in failures)
    root, a, manifest = _p28_fixture(tmp_path / "non-cv", cv=False)
    _rejected, failures = rulings.validate_b7(root, a.audit, manifest)
    assert not any("witness-site" in f for f in failures)


def test_tier1_p28_b7_to_rulings_cli_caps_borrowed_tie(tmp_path):
    root, a, _manifest = _p28_fixture(
        tmp_path, verdict="rejected")
    checked = rb.run_script(
        "severity_token_rulings.py", "check-b7", root,
        "--audit-dir", a.audit)
    assert checked.returncode == 0, checked.stdout + checked.stderr
    snap = rb.run_script(
        "severity_token_rulings.py", "snapshot", root,
        "--audit-dir", a.audit)
    assert snap.returncode == 0, snap.stdout + snap.stderr
    worklist = json.loads(
        (a.audit / rulings.WORKLIST_PATH).read_text(encoding="utf-8"))
    a.write("_run/severity_token_rulings.json", json.dumps({
        "schema": rulings.RULINGS_SCHEMA,
        "cycle": "main",
        "b7_certification_sha256": worklist["b7_certification_sha256"],
        "rulings": [{
            "error_id": "E-0011", "token": "output:O-0121",
            "b7_verdict": "rejected", "ruling": "cap",
            "resulting_status": "confirmed", "resulting_severity": 2,
            "rationale": "borrowed tie omits the wage_pc witness site",
            "decision_identity": "operator-test",
        }],
    }, indent=2) + "\n")
    applied = rb.run_script(
        "severity_token_rulings.py", "apply", root,
        "--audit-dir", a.audit)
    assert applied.returncode == 0, applied.stdout + applied.stderr
    checked = rb.run_script(
        "severity_token_rulings.py", "check", root,
        "--audit-dir", a.audit)
    assert checked.returncode == 0, checked.stdout + checked.stderr
    final = tokens._load_register_error_rows(a.audit)
    assert final["E-0011"]["Severity"] == "2"


def test_rulings_snapshot_tamper_refuses_finish_without_mutating_canon(
        tmp_path):
    root, a, _manifest = _p28_fixture(
        tmp_path, verdict="rejected")
    manifest = certify.read_manifest(root)
    manifest["allocation_override"] = {
        "purpose": "development", "allocation": []}
    certify.write_manifest_atomic(root, manifest)
    certify.init_run(root)
    manifest = certify.read_manifest(root)
    manifest["stages"]["b7"]["status"] = "done"
    certify.write_manifest_atomic(root, manifest)
    certify.start_stage(root, "severity_token_rulings")
    worklist = json.loads(
        (a.audit / rulings.WORKLIST_PATH).read_text(encoding="utf-8"))
    a.write("_run/severity_token_rulings.json", json.dumps({
        "schema": rulings.RULINGS_SCHEMA,
        "cycle": "main",
        "b7_certification_sha256": worklist["b7_certification_sha256"],
        "rulings": [{
            "error_id": "E-0011", "token": "output:O-0121",
            "b7_verdict": "rejected", "ruling": "cap",
            "resulting_status": "dismissed", "resulting_severity": 2,
            "rationale": "tampered snapshot launders an unauthorized status",
            "decision_identity": "operator-test",
        }],
    }, indent=2) + "\n")
    canonical = a.audit / "code_error_register.md"
    before = canonical.read_bytes()
    snapshot = a.audit / rulings.SNAPSHOT_REGISTER
    snapshot.write_text(
        snapshot.read_text(encoding="utf-8").replace(
            "| confirmed | 3 |", "| dismissed | 2 |", 1),
        encoding="utf-8",
    )

    with pytest.raises(
            certify.CertificationError, match="snapshot digest mismatch"):
        certify.finish_stage(root, "severity_token_rulings", "done")
    assert canonical.read_bytes() == before
    assert (
        certify.read_manifest(root)["stages"]["severity_token_rulings"]["status"]
        == "running"
    )


def _certify_public(root, stage, shard=None):
    certify.start_stage(root, stage)
    if shard is not None:
        certify.set_shard(root, stage, shard, "done")
    certify.finish_stage(root, stage, "done")


def _complete_stage_era_tail(tmp_path, ruling="cap", through_b8=True):
    """The lawful scenario composer's spine (SR-01/SR-02): a full-mode tail
    with one main-cycle row (E-0003) and one supplementary row (E-8000)
    evolved through the real production surfaces — public certifier, real
    staging -> canonical promotion, real snapshots."""
    root, a, _manifest = _p28_fixture(
        tmp_path, verdict="rejected")
    (root / "source.py").write_text("value = 1\n", encoding="utf-8")
    a.write("audit_readme.md", "# Audit readme\n\nVocabulary and rules.\n")
    a.write(
        "CODEMAP.md",
        "# CODEMAP\n\nS-0001 py/build_capita.py\n"
        "D-0001 data/input.csv\nB-0001 build\n\nPRECONDITIONS: 5/5\n",
    )
    saved_output = (a.audit / "output_register.md").read_bytes()
    a.write_register("claims_register.md", rb.CLAIMS_COLS, [])
    a.write_register("output_register.md", rb.OUTPUT_COLS, [])
    a.write_register("code_error_register.md", rb.ERROR_COLS, [])
    a.write_manifest(
        mode="replication", scope_exclusions=[], off_limits=[],
        allocation_override={"purpose": "development", "allocation": []},
    )
    certify.init_run(root)
    _certify_public(root, "b0")

    # Build and certify the lint-green claims input that full-mode code-b4
    # pins. The b3 merge carries the same row identities later dispositioned
    # by b4/b5, matching a production run rather than minting them afterward.
    claim_before = rb.claims_row(
        "C-0001", status="unclear", severity="2",
        issue="candidate-era issue")
    claim_final = rb.claims_row(
        "C-0001", status="inconsistent", severity="3",
        issue="confirmed issue", related="E-0003")
    output_rows = [
        rb.output_row(
            "O-0121", script="`py/table.py`",
            location="`paper/paper.tex:1`"),
    ]
    a.write(
        "plans/claims_review_plan.md",
        "# Claims review plan\n\n"
        "| Worker ID | Worker Scope | Claim ID Range | Output ID Range | Shard File |\n"
        "| --- | --- | --- | --- | --- |\n"
        "| W1 | full paper | C-0001–C-0099 | O-0001–O-0999 | `audit/_work/w1.md` |\n\n"
        "Merge-coordinator range: C-9000–C-9099\n"
        "Merge-coordinator range: O-9000–O-9099\n",
    )
    claims_worker = (
        rb.register_text("Claims", rb.CLAIMS_COLS, [claim_before])
        + "\n" + rb.register_text("Outputs", rb.OUTPUT_COLS, output_rows)
        + "\nCoverage: every assigned claim unit accounted for.\n"
        + u6.footer([
            ["OBS-0001", "candidate", "C-0001",
             "claim row retained", ""],
            ["OBS-0002", "candidate", "O-0121",
             "output row retained", ""],
        ])
        # U15: a first-pass shard carries the phase table as its third part.
        + "\n### Reading phase\n\n"
        + rb.phase_table_text(["C-0001"] + [row[0] for row in output_rows])
    )
    a.write("_work/w1.md", claims_worker)
    _certify_public(root, "claims_b2", "audit/_work/w1.md")
    a.write_register("claims_register.md", rb.CLAIMS_COLS, [claim_before])
    (a.audit / "output_register.md").write_bytes(saved_output)
    a.write_register(
        "_run/snapshots/claims_b3b/claims_register.md",
        rb.CLAIMS_COLS, [claim_before])
    shutil.copy2(
        a.audit / "output_register.md",
        a.audit / "_run/snapshots/claims_b3b/output_register.md")
    a.write("_run/merge_report_claims.json", json.dumps({
        "claims_register.md": {
            "shard_rows": 1, "dedup_removed": 0, "added": 1,
            "conflicts": [], "coverage_gaps": [], "blocked_shards": [],
        },
        "output_register.md": {
            "shard_rows": len(output_rows), "dedup_removed": 0,
            "added": len(output_rows),
            "conflicts": [], "coverage_gaps": [], "blocked_shards": [],
        },
        "footer_dispositions": [
            "audit/_work/w1.md#OBS-0001 | candidate:C-0001",
            "audit/_work/w1.md#OBS-0002 | candidate:O-0121",
        ],
        **rb.report_phase_fields(
            reading=["C-0001"] + [row[0] for row in output_rows]),
    }))
    _certify_public(root, "claims_b3")

    claims_plan = rb.recheck_plan_text(
        "claims", [("C-0001", "issue-flagged", "paper")],
        [("K1", "claims", "C-0001", "`audit/_recheck/k1.md`")])
    a.write("plans/claims_recheck_plan.md", claims_plan)
    a.write(
        "_recheck/k1.md",
        rb.register_text("Claims recheck", rb.LEDGER_COLS, [
            rb.ledger_row(
                "C-0001", status="unclear", severity="2",
                verdict="substantiated", change="set status=inconsistent",
                note="confirmed issue"),
        ]) + u6.footer(),
    )
    _certify_public(root, "claims_b4")
    _certify_public(root, "claims_b5", "audit/_recheck/k1.md")

    # E-0003 carries both the AC survival obligation and the borrowed CV tie.
    cv_source, cv_witness = "CV-267217db96d3", "CVW-774f1d1f861f"
    ac_source, ac_witness = AC_SOURCE_ID, "argpos:2"
    mapping_rows = [
        _mapping_row(
            "CV", cv_source, cv_witness, "E-0003",
            "py/build_capita.py:line 17: `wage_pc = wage_earnings / age_head`"),
        _mapping_row(
            "AC", ac_source, ac_witness, "E-0003",
            "source.py:1@call=0"),
    ]
    _write_mapping(a, mapping_rows)
    a.write(
        "_run/argument_contracts.md",
        ac.render(_ac_artifact(ac_source, (ac_witness,))),
    )
    a.write("_run/definition_use_bundles.md", rb.definition_use_artifact([]))
    rb.emit_path_derivations(a)
    a.write(
        "_run/manifest_check.md",
        "# Manifest parseability check\n\n"
        + verifier.manifests.NO_FINDINGS_LINE + "\n"
        + verifier.manifests.MF_ZERO_LINE + "\n",
    )
    stamp = dm.argument_contract_stamp(
        "passed_but_unread", ac_witness, "source.py", "source.py", "2",
        "source.py:1@call=0")
    sidecar = mechanism.canonicalize_mechanism(
        "variable_substitution", "age_head", "wrong_value", "hhsize",
        "age_head", register="code_errors", anchor="py/build_capita.py:17",
        projection=mechanism.EMPTY_PROJECTION,
    ).sidecar
    witness_ids = f"{cv_witness}; {ac_witness}"
    candidate = rb.error_row(
        "E-0003", etype="aggregation_or_unit_error",
        source="`py/build_capita.py`; `py/table.py`; `source.py`",
        location="py/build_capita.py:14", status="candidate", severity="3",
        desc=f"wage_pc divides by age_head. {stamp}",
        why="reported output is affected output:O-0121",
        related="C-0001",
    )
    proposal = list(candidate)
    proposal[rb.ERROR_COLS.index("Status")] = "confirmed"
    discovery_candidate = rb.error_row(
        "E-8000", etype="sample_filter_or_flag_error",
        source="`source.py`", location="source.py:1",
        status="candidate", severity="2",
        desc="supplementary candidate", why="secondary effect",
    )
    discovery_final = list(discovery_candidate)
    discovery_final[rb.ERROR_COLS.index("Status")] = "confirmed"
    digest = tokens.obligation_digest(
        "E-0003", "output:O-0121", sidecar, witness_ids,
        "py/build_capita.py:14", "age_head",
    )
    record = {
        "Record Type": "token_verification", "Error ID": "E-0003",
        "Token": "output:O-0121", "Obligation Digest": digest,
        "Mechanism": sidecar, "Witness IDs": witness_ids,
        "Error Location": "py/build_capita.py:14",
        "Flawed Identifier": "age_head", "Cited Target": "O-0121",
        "Lineage JSON": json.dumps([
            {"anchor": "py/build_capita.py:14", "carries": "age_head"},
            {"anchor": "py/table.py:1", "carries": "age_head"},
        ], separators=(",", ":")),
        "Probe Path": "probe.py",
        "Probe Output SHA256": tokens.result_digest(0, b"", b""),
        "Verdict": "verified", "Derived From Receipt ID": "—",
    }
    ledger = rb.code_ledger_row(
        "E-0003", status="candidate", severity="3",
        evidence=f"{cv_source}; {ac_source}",
        verdict="confirmed_error", proposed_status="confirmed",
        proposed_severity="3", accepted_type="aggregation_or_unit_error",
        accepted_mechanism=sidecar, witness_ids=witness_ids,
    )
    outcomes = [
        rb.witness_outcome_row(
            channel, source, witness, verdict="confirmed_error",
            severity="3", mech_class="variable_substitution",
            mech_object="age_head", relation="wrong_value",
            expected="hhsize", actual="age_head")
        for channel, source, witness in (
            ("CV", cv_source, cv_witness),
            ("AC", ac_source, ac_witness),
        )
    ]
    shard = a.write(
        "_code_error_recheck/k1.md",
        rb.register_text("Code recheck", rb.CODE_LEDGER_COLS, [ledger])
        + "\n### Witness outcomes\n\n"
        + rb.md_table(rb.WITNESS_OUTCOME_COLS, outcomes)
        + "\n### Verification records\n\n"
        + rb.md_table(tokens.TOKEN_RECORD_COLS, [[
            record[column] for column in tokens.TOKEN_RECORD_COLS
        ]])
        + u6.footer([[
            "OBS-0001", "candidate", "", "supplementary candidate", "",
        ]]),
    )
    (shard.parent / "probe.py").write_text("pass\n", encoding="utf-8")
    a.write_register("code_error_register.md", rb.ERROR_COLS, [candidate])
    a.write(
        "plans/code_error_recheck_plan.md",
        rb.recheck_plan_text(
            "code",
            [("E-0003", "detector", f"{cv_source}; {ac_source}")],
            [("K1", "code", "E-0003",
              "`audit/_code_error_recheck/k1.md`")],
        ),
    )
    a.write("plans/code_error_review_plan.md", rb._code_b1_plan())
    a.write("plans/code_error_second_read_plan.md", "# Code second-read plan\n")
    certify.start_stage(root, "code_b4")
    pinned = rb.run_script(
        "severity_tokens.py", "pin-dispatch-inputs", root,
        "--audit-dir", a.audit)
    assert pinned.returncode == 0, pinned.stdout + pinned.stderr
    certify.finish_stage(root, "code_b4", "done")
    _certify_public(root, "code_b5", "audit/_code_error_recheck/k1.md")

    # Claims b6 tail.
    a.write_register(
        "_run/snapshots/claims_b6a/claims_register.md",
        rb.CLAIMS_COLS, [claim_before])
    shutil.copy2(
        a.audit / "output_register.md",
        a.audit / "_run/snapshots/claims_b6a/output_register.md")
    a.write_register(
        "_run/snapshots/claims_b6b/claims_register.md",
        rb.CLAIMS_COLS, [claim_final])
    shutil.copy2(
        a.audit / "output_register.md",
        a.audit / "_run/snapshots/claims_b6b/output_register.md")
    a.write_register("claims_register.md", rb.CLAIMS_COLS, [claim_final])
    a.write(
        "claims_recheck_summary.md",
        "# Claims recheck summary\n\nSplits declared: 0\nMerges declared: 0\n"
        "Discoveries declared: C=0; O=0; E=0\n")
    a.write(
        "plans/claims_second_read_plan.md",
        "# Claims second-read plan\n")
    a.write(
        "plans/claims_supplementary_recheck_plan.md",
        rb.recheck_plan_text("claims", [], [])
        + f"\n{lintmod.SUPPLEMENTARY_EMPTY}\n")
    a.write(
        "claims_supplementary_recheck_summary.md",
        "# Supplementary recheck summary\n")
    a.write(
        "late_observations_claims.md",
        "# Late observations — claims\n\nNo late observations.\n\n"
        "## Dispositions\n\nNo dispositions.\n")
    _certify_public(root, "claims_b6a")
    _certify_public(root, "claims_b5s")
    _certify_public(root, "claims_b6b")

    # Code b6 tail and its immutable proposal-3 snapshot.
    a.write_register(
        "_run/snapshots/code_b6a/code_error_register.md",
        rb.ERROR_COLS, [candidate])
    a.write_register(
        "code_error_register.md", rb.ERROR_COLS,
        [proposal, discovery_candidate])
    a.write_register(
        "_staging/code_error_register.md", rb.ERROR_COLS,
        [proposal, discovery_candidate])
    a.write(
        "code_error_recheck_summary.md",
        "# Code recheck summary\n\nSplits declared: 0\nMerges declared: 0\n"
        "Discoveries declared: C=0; O=0; E=1\n\n"
        "audit/_code_error_recheck/k1.md#OBS-0001 | candidate:E-8000\n")
    a.write(
        "plans/code_error_supplementary_recheck_plan.md",
        "# code supplementary recheck plan\n\n## Inventory\n\n"
        + rb.md_table(tokens.SUPPLEMENTARY_TOKEN_COLS, [[
            "E-8000", "discovery", "—", "—", "—", "recheck_ledger",
        ]])
        + "\n## Clusters\n\n"
        + rb.md_table(
            ["Cluster ID", "Cluster Name", "Assigned IDs", "Shard File"],
            [[
                "KS1", "supplementary", "E-8000",
                "`audit/_code_error_recheck_supplementary/k1.md`",
            ]],
        )
        + "\nVerdict/evidence vocabulary: `audit/audit_readme.md`.\n"
        + "\nDeclared supplementary discovery range: E-8000–E-8000\n")
    assert rb.run_script(
        "verify_dismissals.py", root, "--audit-dir", a.audit).returncode == 0
    assert rb.run_script(
        "verify_dismissals.py", root, "--audit-dir", a.audit,
        "--tokens").returncode == 0
    assembled = rb.run_script(
        "assemble_boundary.py", root, "--audit-dir", a.audit)
    assert assembled.returncode == 0, assembled.stdout + assembled.stderr
    a.write(
        "_run/late_severity_residuals.md",
        "# Late severity residuals\n\n"
        + rb.md_table(tokens.RESIDUAL_COLS, []))
    _certify_public(root, "code_b6a")
    supplementary_ledger = rb.code_ledger_row(
        "E-8000", status="candidate", severity="2",
        evidence="source.py:1", verdict="confirmed_error",
        proposed_status="confirmed", proposed_severity="2",
        accepted_type="sample_filter_or_flag_error",
    )
    a.write(
        "_code_error_recheck_supplementary/k1.md",
        rb.register_text(
            "Supplementary code recheck",
            rb.CODE_LEDGER_COLS, [supplementary_ledger])
        + "\n### Witness outcomes\n\n"
        + rb.md_table(rb.WITNESS_OUTCOME_COLS, [])
        + "\n### Verification records\n\nNo verification records.\n"
        + u6.footer([[
            "OBS-0001", "candidate", "", "post-export severe defect", "",
        ]]),
    )
    _certify_public(
        root, "code_b5s",
        "audit/_code_error_recheck_supplementary/k1.md")
    a.write_register(
        "_run/snapshots/code_b6b/code_error_register.md",
        rb.ERROR_COLS, [proposal, discovery_candidate])
    a.write_register(
        "code_error_register.md", rb.ERROR_COLS,
        [proposal, discovery_final])
    a.write_register(
        "_staging/code_error_register.md", rb.ERROR_COLS,
        [proposal, discovery_final])
    a.write(
        "code_error_supplementary_recheck_summary.md",
        "# Supplementary recheck summary\n\n"
        "audit/_code_error_recheck_supplementary/k1.md#OBS-0001 | "
        "late_observation:LO-E-0001\n")
    a.write(
        "late_observations_code.md",
        u6.lo_artifact(
            [[
                "LO-E-0001",
                "audit/_code_error_recheck_supplementary/k1.md#OBS-0001",
                "source.py:1", "post-export severe defect",
            ]],
            [["LO-E-0001", "pending"]],
        ),
    )
    assert rb.run_script(
        "verify_dismissals.py", root, "--audit-dir", a.audit,
        "--supplementary").returncode == 0
    assert rb.run_script(
        "verify_dismissals.py", root, "--audit-dir", a.audit,
        "--supplementary", "--tokens").returncode == 0
    assembled = rb.run_script(
        "assemble_boundary.py", root, "--audit-dir", a.audit,
        "--supplementary")
    assert assembled.returncode == 0, assembled.stdout + assembled.stderr
    _certify_public(root, "code_b6b")

    # b7 rejects the borrowed CV tie; the rulings stage lawfully caps 3 -> 2.
    a.write_register(
        "_run/snapshots/b7/claims_register.md",
        rb.CLAIMS_COLS, [claim_final])
    a.write_register(
        "_run/snapshots/b7/code_error_register.md",
        rb.ERROR_COLS, [proposal, discovery_final])
    a.write_register(
        "_staging/claims_register.md", rb.CLAIMS_COLS, [claim_final])
    a.write_register(
        "_staging/code_error_register.md",
        rb.ERROR_COLS, [proposal, discovery_final])
    a.write(
        "register_cross_link_summary.md",
        "# Cross-link summary\n\n## Status conflicts\n\nnone\n\n"
        "## Escalated mapped claims\n\nnone\n\n"
        "## Severity divergences\n\nnone\n\n"
        "## Severity-token adjudications\n\n"
        + rb.md_table(tokens.ADJUDICATION_COLS, [[
            "E-0003 output:O-0121", "O-0121", "rejected",
            "py/table.py:1",
        ]]),
    )
    _certify_public(root, "b7")
    certify.start_stage(root, "severity_token_rulings")
    worklist = json.loads(
        (a.audit / rulings.WORKLIST_PATH).read_text(encoding="utf-8"))
    ruled_status, ruled_severity = {
        "cap": ("confirmed", 2),
        "uphold": ("confirmed", 3),
        "hold": ("confirmation_needed", 2),
    }[ruling]
    a.write("_run/severity_token_rulings.json", json.dumps({
        "schema": rulings.RULINGS_SCHEMA, "cycle": "main",
        "b7_certification_sha256": worklist["b7_certification_sha256"],
        "rulings": [{
            "error_id": "E-0003", "token": "output:O-0121",
            "b7_verdict": "rejected", "ruling": ruling,
            "resulting_status": ruled_status,
            "resulting_severity": ruled_severity,
            "rationale": "borrowed tie omits the wage_pc witness site",
            "decision_identity": "operator-test",
        }],
    }, indent=2) + "\n")
    certify.finish_stage(root, "severity_token_rulings", "done")
    assert tokens._load_register_error_rows(a.audit)["E-0003"]["Severity"] == str(
        ruled_severity)

    capped = list(proposal)
    capped[rb.ERROR_COLS.index("Status")] = ruled_status
    capped[rb.ERROR_COLS.index("Severity")] = str(ruled_severity)
    if not through_b8:
        return root, a
    # Faithful production b8 (pipeline-finalize b8 steps 1-4): snapshot canon
    # (the applied post-rulings register) byte-for-byte into the b8 boundary,
    # dispatch the author-facing rewrite into `_staging/`, then PROMOTE BY COPY
    # — the rewritten staging registers over canon. The earlier fixture omitted
    # this last promotion step, so the completed rulings stage's require_applied
    # replay still saw the un-rewritten canon and passed falsely; the honest
    # replay binds instead to b8's pre-rewrite snapshot.
    (a.audit / "_run/snapshots/b8").mkdir(parents=True, exist_ok=True)
    shutil.copy2(
        a.audit / "claims_register.md",
        a.audit / "_run/snapshots/b8/claims_register.md")
    shutil.copy2(
        a.audit / "code_error_register.md",
        a.audit / "_run/snapshots/b8/code_error_register.md")
    claims_cols, claims_rows = rb.rewrite_pass_cols(
        rb.CLAIMS_COLS, [claim_final], ["Issue Description"])
    error_cols, error_rows = rb.rewrite_pass_cols(
        rb.ERROR_COLS, [capped, discovery_final],
        ["Error Description", "Why It Matters"])
    a.write_register("_staging/claims_register.md", claims_cols, claims_rows)
    a.write_register("_staging/code_error_register.md", error_cols, error_rows)
    shutil.copy2(
        a.audit / "_staging/claims_register.md",
        a.audit / "claims_register.md")
    shutil.copy2(
        a.audit / "_staging/code_error_register.md",
        a.audit / "code_error_register.md")
    _certify_public(root, "b8")
    manifest = certify.read_manifest(root)
    required_done = {
        "b0", "claims_b4", "claims_b5", "code_b4", "code_b5",
        "claims_b6b", "code_b6b", "b7", "severity_token_rulings", "b8",
    }
    assert {
        stage for stage in required_done
        if manifest["stages"][stage]["status"] == "done"
    } == required_done
    return root, a


def _continue_complete_tail_through_bc(tmp_path, linked=False, co_patch=False):
    """Continue the composed tail through a lawful operator bC correction,
    the post-bC b7 replay-plus-extension, and the scoped b8 rerun.

    ``linked`` makes the new row E-8001 carry its payload-borne link
    ``Related Claim IDs: C-0001`` (SR-03: the existing claim's reciprocal
    cell is derived, never recorded); ``co_patch`` adds the lawful C<->O
    reciprocal patch pair with its companion claims edit (SR-04)."""
    root, a = _complete_stage_era_tail(tmp_path)
    certify.start_stage(root, "bC")
    bc_snapshot = a.audit / "_run/snapshots/bC"
    bc_snapshot.mkdir(parents=True, exist_ok=True)
    for filename in (
            "claims_register.md", "output_register.md",
            "code_error_register.md"):
        shutil.copy2(a.audit / filename, bc_snapshot / filename)
    shutil.copy2(
        a.audit / "late_observations_claims.md",
        bc_snapshot / "late_observations_claims.md")
    late_row = [[
        "LO-E-0001", "audit/_code_error_recheck_supplementary/k1.md#OBS-0001",
        "source.py:1", "post-export severe defect",
    ]]
    a.write(
        "_run/snapshots/bC/late_observations_code.md",
        u6.lo_artifact(late_row, [["LO-E-0001", "pending"]]),
    )
    a.write(
        "late_observations_code.md",
        u6.lo_artifact(
            late_row, [["LO-E-0001", "pending", "minted:BC-0001"]]),
    )

    parse_state = lintmod.Lint()
    current = lintmod.load_register(
        parse_state, a.audit / "code_error_register.md",
        rb.ERROR_COLS, allow_extra=True)
    assert current is not None and not parse_state.errors
    current_headers, current_rows = current
    bc_base = rb.error_row(
        "E-8001", etype="sample_filter_or_flag_error",
        source="`py/build_capita.py`; `py/table.py`",
        location="py/build_capita.py:14",
        status="confirmed", severity="3",
        desc="late correction detects a severe output defect",
        why="reported output is affected output:O-0121",
        related="C-0001" if linked else "",
    )
    bc_base_by_column = dict(zip(rb.ERROR_COLS, bc_base))
    bc_row = [bc_base_by_column.get(column, "") for column in current_headers]
    bc_row_by_column = dict(zip(current_headers, bc_row))
    for base, original in (
            ("Error Description", "Error Description Original"),
            ("Why It Matters", "Why It Matters Original")):
        if original in current_headers:
            bc_row_by_column[original] = bc_row_by_column[base]
    bc_row = [bc_row_by_column[column] for column in current_headers]
    payload = json.dumps(
        dict(zip(current_headers, bc_row)),
        sort_keys=True, separators=(",", ":"))

    plan_rows = [[
        "BC-0001", "LO-E-0001", "code_error", "new_row", "E-8001",
        payload, "—",
    ]]
    if co_patch:
        claims_snapshot = lintmod.load_register(
            lintmod.Lint(), bc_snapshot / "claims_register.md",
            rb.CLAIMS_COLS, allow_extra=True)
        outputs_snapshot = lintmod.load_register(
            lintmod.Lint(), bc_snapshot / "output_register.md",
            rb.OUTPUT_COLS)
        old_outputs_cell = dict(
            zip(claims_snapshot[0], claims_snapshot[1][0]))["Output IDs"]
        old_claims_cell = dict(
            zip(outputs_snapshot[0], outputs_snapshot[1][0]))["Claim IDs"]
        plan_rows.append([
            "BC-0001", "LO-E-0001", "claims", "patch", "C-0001",
            json.dumps({"field": "Output IDs", "new_value": "O-0121"},
                       separators=(",", ":")),
            lintmod.bc_old_value_hash(
                "claims", "C-0001", "Output IDs", old_outputs_cell),
        ])
        plan_rows.append([
            "BC-0001", "LO-E-0001", "output", "patch", "O-0121",
            json.dumps({"field": "Claim IDs", "new_value": "C-0001"},
                       separators=(",", ":")),
            lintmod.bc_old_value_hash(
                "output", "O-0121", "Claim IDs", old_claims_cell),
        ])

    bc_mechanism = mechanism.canonicalize_mechanism(
        "sample_filter_or_flag_error", "age_head", "wrong_value", "1", "0",
        register="code_errors", anchor="py/build_capita.py:14",
        projection=mechanism.EMPTY_PROJECTION,
    ).sidecar
    token = "output:O-0121"
    obligation = tokens.obligation_digest(
        "E-8001", token, bc_mechanism, "—",
        "py/build_capita.py:14", "age_head")
    token_record = {
        "Record Type": "token_verification", "Error ID": "E-8001",
        "Token": token, "Obligation Digest": obligation,
        "Mechanism": bc_mechanism, "Witness IDs": "—",
        "Error Location": "py/build_capita.py:14",
        "Flawed Identifier": "age_head",
        "Cited Target": "O-0121",
        "Lineage JSON": json.dumps([
            {"anchor": "py/build_capita.py:14", "carries": "age_head"},
            {"anchor": "py/table.py:1", "carries": "age_head"},
        ], separators=(",", ":")),
        "Probe Path": "bc_token_probe.py",
        "Probe Output SHA256": tokens.result_digest(0, b"", b""),
        "Verdict": "verified", "Derived From Receipt ID": "—",
    }
    a.write("plans/bc_token_probe.py", "pass\n")
    a.write(
        "plans/late_observation_corrections.md",
        "# Late-observation corrections\n\n"
        "Declared bC range: E-8001–E-8001\n\n"
        + rb.md_table(lintmod.BC_PLAN_COLS, plan_rows)
        + "\n### Token verification records\n\n"
        + rb.md_table(tokens.TOKEN_RECORD_COLS, [[
            token_record[column] for column in tokens.TOKEN_RECORD_COLS
        ]]),
    )
    a.write_register(
        "code_error_register.md", current_headers, current_rows + [bc_row])
    if co_patch:
        _apply_cell(a, "claims_register.md", rb.CLAIMS_COLS,
                    "C-0001", "Output IDs", "O-0121")
        _apply_cell(a, "output_register.md", rb.OUTPUT_COLS,
                    "O-0121", "Claim IDs", "C-0001")
    manifest = certify.read_manifest(root)
    receipts, failures = tokens.verify_token_records(
        root, a.audit, manifest, "bC")
    assert not failures, failures
    tokens.write_atomic(
        tokens.receipt_path(a.audit, "bC"),
        tokens.render_receipts(receipts))
    certify.finish_stage(root, "bC", "done")

    # The post-bC b7 replay-plus-extension: only the derived reciprocal
    # state may change — the new row's own link is payload-borne, and the
    # existing claim's cell gains exactly the plan-declared referrer.
    if linked:
        _apply_cell(a, "claims_register.md", rb.CLAIMS_COLS,
                    "C-0001", "Related Error IDs", "E-0003; E-8001")
    shutil.copy2(
        a.audit / "claims_register.md",
        a.audit / "_staging/claims_register.md")
    shutil.copy2(
        a.audit / "code_error_register.md",
        a.audit / "_staging/code_error_register.md")
    a.write(
        "register_cross_link_summary.md",
        "# Cross-link summary\n\n## Status conflicts\n\nnone\n\n"
        "## Escalated mapped claims\n\nnone\n\n"
        "## Severity divergences\n\nnone\n\n"
        "## Severity-token adjudications\n\n"
        + rb.md_table(tokens.ADJUDICATION_COLS, [[
            "E-8001 output:O-0121", "O-0121", "upheld",
            "py/build_capita.py:14 -> py/table.py:1",
        ]]),
    )
    certify.demote_stage(root, "b7", "post-bC extension replay")
    _certify_public(root, "b7")

    parse_state = lintmod.Lint()
    post_bc = lintmod.load_register(
        parse_state, a.audit / "_staging/code_error_register.md",
        rb.ERROR_COLS, allow_extra=True)
    assert post_bc is not None and not parse_state.errors
    post_bc_headers, post_bc_rows = post_bc
    rewritten_rows = []
    for raw in post_bc_rows:
        row = dict(zip(post_bc_headers, raw))
        if row["Error ID"] == "E-8001":
            row["Error Description Original"] = row["Error Description"]
            row["Error Description"] = "Late severe output defect."
            row["Why It Matters Original"] = row["Why It Matters"]
            row["Why It Matters"] = "A reported result may be incorrect."
        rewritten_rows.append([row[column] for column in post_bc_headers])
    a.write_register(
        "_staging/code_error_register.md",
        post_bc_headers, rewritten_rows)
    shutil.copy2(
        a.audit / "_staging/code_error_register.md",
        a.audit / "code_error_register.md")
    certify.demote_stage(root, "b8", "post-bC scoped rewrite")
    _certify_public(root, "b8")
    return root, a


def _apply_cell(a, register, cols, row_id, column, value, staging=False):
    """Set one cell of one register row, preserving extra columns."""
    rel = ("_staging/" + register) if staging else register
    state = lintmod.Lint()
    parsed = lintmod.load_register(
        state, a.audit / rel, cols, allow_extra=True)
    assert parsed is not None and not state.errors
    headers, rows = parsed
    id_col = {"claims_register.md": "Claim ID",
              "output_register.md": "Output ID",
              "code_error_register.md": "Error ID"}[register]
    updated = []
    for raw in rows:
        row = dict(zip(headers, raw))
        if row.get(id_col) == row_id:
            row[column] = value
        updated.append([row[c] for c in headers])
    a.write_register(rel, headers, updated)


def test_tier1_complete_stage_era_tail_verifies_then_refuses_tamper(tmp_path):
    root, a = _complete_stage_era_tail(tmp_path)
    certify.verify_run(root)
    certify.resume_check(root, clear_stale_marker=True)
    frozen = (
        a.audit / "_run/certified_stage_evidence/code_b5/"
        "code_error_register.md")
    frozen.write_text(
        frozen.read_text(encoding="utf-8") + "\nhand-flipped\n",
        encoding="utf-8")
    with pytest.raises(
            certify.CertificationError, match="edited after certification"):
        certify.verify_run(root)
    with pytest.raises(
            certify.CertificationError, match="edited after certification"):
        certify.resume_check(root, clear_stale_marker=True)


def test_sr01_composed_tail_replays_every_tail_lint_green(tmp_path):
    """SR-01: the main-cycle spine — proposal 3 -> b7 reject -> cap 2 -> b8;
    every tail lint, verify-run, and resume-check stay green."""
    root, a = _complete_stage_era_tail(tmp_path)
    for stage in ("b6b-claims", "b6b-code", "b7",
                  "severity_token_rulings", "b8"):
        replayed = rb.lint(a, stage)
        assert replayed.returncode == 0, (
            stage, replayed.stdout + replayed.stderr)
    certify.verify_run(root)
    certify.resume_check(root, clear_stale_marker=True)


def test_f1_duplicate_staging_row_id_refuses_b8(tmp_path):
    """F1 (review disposition 2026-08-01): a duplicated staging row ID must
    refuse at b8. The set-based ID comparison alone dict-collapses
    duplicates, so a divergent earlier copy would otherwise be shadowed by
    the later snapshot-matching copy and pass silently."""
    _root, a = _complete_stage_era_tail(tmp_path)
    state = lintmod.Lint()
    staged = lintmod.load_register(
        state, a.audit / "_staging/code_error_register.md",
        rb.ERROR_COLS, allow_extra=True)
    assert staged is not None and not state.errors
    headers, rows = staged
    duplicated = []
    for raw in rows:
        row = dict(zip(headers, raw))
        if row["Error ID"] == "E-0003":
            divergent = dict(row)
            divergent["Why It Matters"] = "divergent duplicate first copy"
            duplicated.append([divergent[column] for column in headers])
        duplicated.append([row[column] for column in headers])
    a.write_register("_staging/code_error_register.md", headers, duplicated)
    refused = rb.lint(a, "b8")
    assert refused.returncode == 1
    assert "duplicate register row IDs at rewrite" in refused.stdout


def test_sr02_b6b_replay_keeps_post_b6b_proposal_after_lawful_bc_boundary(
        tmp_path):
    """SR-02 (Tier 1, Finding 1): the supplementary row E-8000 flows through
    the same proposal equality against the same b6b_proposal view; a later
    bC boundary image never displaces the anchor."""
    root, a = _complete_stage_era_tail(tmp_path)
    bc_snapshot = a.audit / "_run/snapshots/bC/code_error_register.md"
    bc_snapshot.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(a.audit / "code_error_register.md", bc_snapshot)

    replayed = rb.lint(a, "b6b-code")
    assert replayed.returncode == 0, replayed.stdout + replayed.stderr
    certify.verify_run(root)


def test_tier1_sr02_proposal_evidence_tamper_refuses_b6b_and_verify(tmp_path):
    """SR-02 sabotage through the production CLIs: a hand-flipped severity in
    the frozen b6b_proposal image breaks the supplementary ledger binding."""
    root, a = _complete_stage_era_tail(tmp_path)
    proposal = a.audit / "_run/snapshots/b7/code_error_register.md"
    proposal.write_text(
        proposal.read_text(encoding="utf-8").replace(
            "| confirmed | 2 |", "| confirmed | 1 |", 1),
        encoding="utf-8")
    refused = rb.lint(a, "b6b-code")
    assert refused.returncode == 1
    assert "disagrees with its ledger" in refused.stdout
    with pytest.raises(certify.CertificationError):
        certify.verify_run(root)


def test_tier1_sr02_test_oracle_notices_disabled_disposition_binding(
        tmp_path, monkeypatch):
    _root, a = _complete_stage_era_tail(tmp_path)
    proposal = a.audit / "_run/snapshots/b7/code_error_register.md"
    proposal.write_text(
        proposal.read_text(encoding="utf-8").replace(
            "| confirmed | 2 |", "| confirmed | 1 |", 1),
        encoding="utf-8")
    manifest = json.loads(
        (a.audit / "_run/manifest.json").read_text(encoding="utf-8"))

    def negative_oracle():
        state = lintmod.Lint()
        lintmod.stage_b6b(state, a.audit, "code", manifest)
        assert any("disagrees with its ledger" in error
                   for error in state.errors)

    negative_oracle()
    monkeypatch.setattr(
        lintmod, "expected_code_disposition",
        lambda *_args, **_kwargs: ("confirmed", "1"))
    with pytest.raises(AssertionError):
        negative_oracle()


def test_sr03_linked_bc_addition_derives_reciprocal_state_and_verifies(
        tmp_path):
    """SR-03 (Tier 1, Finding 2): the new row's link is payload-borne, the
    existing claim's reciprocal cell is derived from the plan, and the whole
    tail — b7 replay-plus-extension, scoped b8, both verification commands —
    stays green.  The post-bC summary lawfully omits the capped E-0003 key
    (SR-07's omission half)."""
    root, a = _continue_complete_tail_through_bc(tmp_path, linked=True)
    certify.verify_run(root)
    certify.resume_check(root, clear_stale_marker=True)
    final = tokens._load_register_error_rows(a.audit)
    assert final["E-0003"]["Severity"] == "2"
    assert final["E-8001"]["Severity"] == "3"
    assert final["E-8001"]["Related Claim IDs"] == "C-0001"
    state = lintmod.Lint()
    claims = lintmod.load_register(
        state, a.audit / "claims_register.md", rb.CLAIMS_COLS,
        allow_extra=True)
    linked_cell = dict(zip(claims[0], claims[1][0]))["Related Error IDs"]
    assert set(lintmod.ids_in(linked_cell, "E")) == {"E-0003", "E-8001"}


def test_tier1_sr03_non_derived_link_refuses_b7_and_b8(tmp_path):
    _root, a = _continue_complete_tail_through_bc(tmp_path, linked=True)
    # Mutate the derived side: drop the plan-declared referrer.
    _apply_cell(a, "claims_register.md", rb.CLAIMS_COLS,
                "C-0001", "Related Error IDs", "E-0003", staging=True)
    for stage in ("b7", "b8"):
        refused = rb.lint(a, stage)
        assert refused.returncode == 1, stage
        assert "departs from the derived reciprocal state" in refused.stdout
    # Restore, then mutate the payload-borne side of the bC-added row.
    _apply_cell(a, "claims_register.md", rb.CLAIMS_COLS,
                "C-0001", "Related Error IDs", "E-0003; E-8001", staging=True)
    _apply_cell(a, "code_error_register.md", rb.ERROR_COLS,
                "E-8001", "Status", "blocked", staging=True)
    refused = rb.lint(a, "b7")
    assert refused.returncode == 1
    assert "does not match its correction-plan payload" in refused.stdout
    refused = rb.lint(a, "b8")
    assert refused.returncode == 1
    assert ("does not preserve its correction-plan payload through rewrite"
            in refused.stdout)


def test_tier1_sr03_test_oracle_notices_disabled_link_derivation(
        tmp_path, monkeypatch):
    _root, a = _continue_complete_tail_through_bc(tmp_path, linked=True)
    _apply_cell(a, "claims_register.md", rb.CLAIMS_COLS,
                "C-0001", "Related Error IDs", "E-0003", staging=True)
    manifest = json.loads(
        (a.audit / "_run/manifest.json").read_text(encoding="utf-8"))

    def negative_oracle():
        state = lintmod.Lint()
        lintmod.stage_b7(state, a.audit, manifest)
        assert any("departs from the derived reciprocal state" in error
                   for error in state.errors)

    negative_oracle()
    monkeypatch.setattr(
        lintmod, "non_link_identical", lambda *_args, **_kwargs: None)
    with pytest.raises(AssertionError):
        negative_oracle()


def test_tier1_sr03_test_oracle_notices_disabled_payload_binding(
        tmp_path, monkeypatch):
    _root, a = _continue_complete_tail_through_bc(tmp_path, linked=True)
    _apply_cell(a, "code_error_register.md", rb.ERROR_COLS,
                "E-8001", "Status", "blocked", staging=True)
    manifest = json.loads(
        (a.audit / "_run/manifest.json").read_text(encoding="utf-8"))

    def negative_oracle():
        state = lintmod.Lint()
        lintmod.stage_b8(state, a.audit, manifest)
        assert any("does not preserve its correction-plan payload" in error
                   for error in state.errors)

    negative_oracle()
    monkeypatch.setattr(
        lintmod.authorized_deltas, "payload_matches_row",
        lambda *_args, **_kwargs: True)
    with pytest.raises(AssertionError):
        negative_oracle()


def test_sr04_unlinked_bc_addition_with_co_patch_pair_verifies(tmp_path):
    """SR-04: unlinked bC addition plus the lawful C<->O reciprocal patch
    pair (with its companion claims edit) is green everywhere."""
    root, a = _continue_complete_tail_through_bc(tmp_path, co_patch=True)
    certify.verify_run(root)
    certify.resume_check(root, clear_stale_marker=True)


def test_sr04_undeclared_cell_edit_refuses_bc_replay(tmp_path):
    _root, a = _continue_complete_tail_through_bc(tmp_path, co_patch=True)
    _apply_cell(a, "claims_register.md", rb.CLAIMS_COLS,
                "C-0001", "Code/Data Source", "tampered.py:1")
    refused = rb.lint(a, "bC")
    assert refused.returncode == 1
    assert "undeclared bC cell change" in refused.stdout


def test_sr05_uphold_ruling_permits_no_cell_changes(tmp_path):
    """SR-05: an uphold ruling changes nothing; a drive-by edit on either a
    worklist row or a non-worklist row refuses."""
    root, a = _complete_stage_era_tail(tmp_path, ruling="uphold")
    certify.verify_run(root)
    _apply_cell(a, "code_error_register.md", rb.ERROR_COLS,
                "E-0003", "Severity", "1", staging=True)
    refused = rb.lint(a, "b7")
    assert refused.returncode == 1
    assert "departs from the authorized ruling value" in refused.stdout
    _apply_cell(a, "code_error_register.md", rb.ERROR_COLS,
                "E-0003", "Severity", "3", staging=True)
    _apply_cell(a, "code_error_register.md", rb.ERROR_COLS,
                "E-8000", "Severity", "1", staging=True)
    refused = rb.lint(a, "b7")
    assert refused.returncode == 1
    assert "changed at cross-link" in refused.stdout


def test_sr07_hold_ruling_tail_verifies(tmp_path):
    """SR-07: a hold ruling (confirmation_needed, severity capped) survives
    the full tail under both verification commands."""
    root, _a = _complete_stage_era_tail(tmp_path, ruling="hold")
    certify.verify_run(root)
    certify.resume_check(root, clear_stale_marker=True)


def test_sr07_new_rejected_key_on_post_bc_rerun_refuses(tmp_path):
    _root, a = _continue_complete_tail_through_bc(tmp_path)
    summary = a.audit / "register_cross_link_summary.md"
    summary.write_text(
        summary.read_text(encoding="utf-8").replace("upheld", "rejected"),
        encoding="utf-8")
    refused = rb.lint(a, "b7")
    assert refused.returncode == 1
    assert "introduced new rejected severity-token key" in refused.stdout


def test_tier1_sr08_b7_recertification_refuses_missing_classification_evidence(
        tmp_path):
    """SR-08 (Tier 1, Finding 3): with the pre-ruling register deleted and
    the summary laundered to match mutable capped state, the public
    demote-and-recertify of b7 refuses at its own certification — not merely
    at a later verify-run."""
    root, a = _complete_stage_era_tail(tmp_path)
    (a.audit / rulings.SNAPSHOT_REGISTER).unlink()
    a.write(
        "register_cross_link_summary.md",
        "# Cross-link summary\n\n## Status conflicts\n\nnone\n\n"
        "## Escalated mapped claims\n\nnone\n\n"
        "## Severity divergences\n\nnone\n\n"
        "## Severity-token adjudications\n\nnone\n")
    certify.demote_stage(root, "b7", "attempted mutable-canon recertification")
    certify.start_stage(root, "b7")
    with pytest.raises(
            certify.CertificationError,
            match="b7_classification evidence refused"):
        certify.finish_stage(root, "b7", "done")
    with pytest.raises(certify.CertificationError):
        certify.verify_run(root)


def test_tier1_sr08_test_oracle_notices_restored_fallback(
        tmp_path, monkeypatch):
    root, a = _complete_stage_era_tail(tmp_path)
    (a.audit / rulings.SNAPSHOT_REGISTER).unlink()
    a.write(
        "register_cross_link_summary.md",
        "# Cross-link summary\n\n## Status conflicts\n\nnone\n\n"
        "## Escalated mapped claims\n\nnone\n\n"
        "## Severity divergences\n\nnone\n\n"
        "## Severity-token adjudications\n\nnone\n")
    manifest = certify.read_manifest(root)

    def negative_oracle():
        _rejected, failures = rulings.validate_b7(root, a.audit, manifest)
        assert any("b7_classification evidence refused" in failure
                   for failure in failures)

    negative_oracle()
    monkeypatch.setitem(
        rulings.evidence_views._RESOLVERS, "b7_classification",
        lambda register, audit, _manifest:
        rulings.evidence_views._live_register(
            "b7_classification", register, audit, prefer_staging=True))
    with pytest.raises(AssertionError):
        negative_oracle()


def test_sr09_bytes_bound_tamper_refuses_asking_stage_and_both_commands(
        tmp_path):
    """SR-09: one representative post-certification byte flip in a
    bytes-bound view; the asking stage and both verification commands
    refuse.  Per-view tamper/malformed/absent behavior is proven at module
    level (test_u9_evidence_views.py)."""
    root, a = _complete_stage_era_tail(tmp_path)
    snapshot = a.audit / rulings.SNAPSHOT_REGISTER
    snapshot.write_text(
        snapshot.read_text(encoding="utf-8").replace(
            "| confirmed | 3 |", "| confirmed | 2 |", 1),
        encoding="utf-8")
    asking = rb.lint(a, "severity_token_rulings")
    assert asking.returncode == 1
    assert "snapshot digest mismatch" in asking.stdout
    with pytest.raises(
            certify.CertificationError, match="snapshot digest mismatch"):
        certify.verify_run(root)
    with pytest.raises(
            certify.CertificationError, match="snapshot digest mismatch"):
        certify.resume_check(root, clear_stale_marker=True)


def test_sr10_rulings_replay_green_before_and_after_b8_boundary(tmp_path):
    """SR-10: before b8 the rulings replay anchors live canon; after b8 it
    anchors the frozen rulings_applied image (the post-b8 half is the SR-01
    spine and the amendment-×7 refusal tests)."""
    root, a = _complete_stage_era_tail(tmp_path, through_b8=False)
    manifest = certify.read_manifest(root)
    _decisions, failures = rulings.validate_rulings(
        root, a.audit, manifest, require_applied=True)
    assert failures == []
    replayed = rb.lint(a, "severity_token_rulings")
    assert replayed.returncode == 0, replayed.stdout + replayed.stderr
    certify.verify_run(root)
    certify.resume_check(root, clear_stale_marker=True)


def test_complete_tail_refuses_post_certification_rulings_snapshot_tamper(
        tmp_path):
    root, a = _complete_stage_era_tail(tmp_path)
    snapshot = a.audit / rulings.SNAPSHOT_REGISTER
    snapshot.write_text(
        snapshot.read_text(encoding="utf-8").replace(
            "| confirmed | 3 |", "| confirmed | 2 |", 1),
        encoding="utf-8",
    )
    with pytest.raises(
            certify.CertificationError, match="snapshot digest mismatch"):
        certify.verify_run(root)
    with pytest.raises(
            certify.CertificationError, match="snapshot digest mismatch"):
        certify.resume_check(root, clear_stale_marker=True)


def test_rulings_replay_fails_closed_when_b8_applied_snapshot_absent(tmp_path):
    """Once b8 is done the rulings replay binds to b8's pre-rewrite snapshot;
    with that stage-era boundary gone it must refuse rather than fall back to
    the post-b8 canonical register (which no longer proves the apply)."""
    root, a = _complete_stage_era_tail(tmp_path)
    (a.audit / rulings.B8_SNAPSHOT_REGISTER).unlink()
    manifest = certify.read_manifest(root)
    _decisions, failures = rulings.validate_rulings(
        root, a.audit, manifest, require_applied=True)
    assert any(
        "pre-rewrite register snapshot is missing" in failure
        for failure in failures), failures
    with pytest.raises(certify.CertificationError):
        certify.verify_run(root)
    with pytest.raises(certify.CertificationError):
        certify.resume_check(root, clear_stale_marker=True)


def test_complete_tail_refuses_tampered_b8_applied_snapshot(tmp_path):
    """A byte edit to b8's frozen boundary that its own value-level rewrite
    lint cannot see (trailing content outside the table) must still be caught
    by the rulings stage-era byte comparison under both verify commands."""
    root, a = _complete_stage_era_tail(tmp_path)
    snapshot = a.audit / rulings.B8_SNAPSHOT_REGISTER
    snapshot.write_bytes(
        snapshot.read_bytes() + b"\n<!-- tampered applied evidence -->\n")
    with pytest.raises(
            certify.CertificationError, match="applied ruling bytes differ"):
        certify.verify_run(root)
    with pytest.raises(
            certify.CertificationError, match="applied ruling bytes differ"):
        certify.resume_check(root, clear_stale_marker=True)


def test_post_b8_ac_stamp_only_in_original_refuses_b6b_and_verification(
        tmp_path):
    root, a = _complete_stage_era_tail(tmp_path)
    stamp = dm.argument_contract_stamp(
        "passed_but_unread", "argpos:2", "source.py", "source.py", "2",
        "source.py:1@call=0")
    staging = a.audit / "_staging/code_error_register.md"
    rewritten = staging.read_text(encoding="utf-8")
    assert rewritten.count(stamp) == 2
    staging.write_text(
        rewritten.replace(stamp, "author-facing argument-contract finding", 1),
        encoding="utf-8",
    )
    shutil.copy2(staging, a.audit / "code_error_register.md")

    direct = rb.lint(a, "b6b-code")
    assert direct.returncode == 1
    assert "machine-written stamp" in direct.stdout
    with pytest.raises(
            certify.CertificationError, match="machine-written stamp"):
        certify.verify_run(root)
    with pytest.raises(
            certify.CertificationError, match="machine-written stamp"):
        certify.resume_check(root, clear_stale_marker=True)


def test_published_rulings_digest_contract_tracks_frozen_worklist():
    registers_reference = (
        rb.SKILL_DIR / "references/registers.md").read_text(encoding="utf-8")
    pipeline_reference = (
        rb.SKILL_DIR / "references/pipeline-finalize.md").read_text(
            encoding="utf-8")
    assert "canonical JSON" in registers_reference
    assert "`lines` and `b7_register_sha256`" in registers_reference
    assert (
        "`audit/_run/snapshots/severity_token_rulings/"
        "b7_rejected_worklist.json`"
    ) in pipeline_reference
    assert "copy its `b7_certification_sha256`" in pipeline_reference


def test_tier1_p28_test_oracle_notices_disabled_witness_binding(
        tmp_path, monkeypatch):
    root, a, manifest = _p28_fixture(tmp_path)

    def negative_oracle():
        _rejected, failures = rulings.validate_b7(root, a.audit, manifest)
        assert any(
            "mapped CV witness-site mismatch cannot be upheld" in failure
            for failure in failures
        )

    negative_oracle()
    monkeypatch.setattr(
        rulings, "_cv_witness_binding_failure",
        lambda *_args, **_kwargs: None,
    )
    with pytest.raises(AssertionError):
        negative_oracle()


def _b5_relation_case(tmp_path, relation, *, mapped=True):
    ledger = rb.code_ledger_row(
        "E-0100", witness_ids="DUW-000000000001",
        evidence="DU-aaaaaaaaaaaa",
    )
    a, shard = rb.make_b5(
        tmp_path, "code", ledger_rows=[ledger], assigned_ids=["E-0100"])
    mappings = ([("DU-aaaaaaaaaaaa", "E-0100", "new_candidate")]
                if mapped else [])
    a.write("_run/detector_mapping.md", rb.detector_mapping_artifact(mappings))
    outcome = rb.witness_outcome_row(
        "DU", "DU-aaaaaaaaaaaa", "DUW-000000000001",
        relation=relation,
    )
    shard.write_text(
        rb.register_text("Recheck ledger", rb.CODE_LEDGER_COLS, [ledger])
        + "\n### Witness outcomes\n\n"
        + rb.md_table(rb.WITNESS_OUTCOME_COLS, [outcome])
        + "\n### Verification records\n\nNo verification records.\n",
        encoding="utf-8",
    )
    return a, shard


def test_s702_relation_lint_names_closed_list_and_no_longer_skips_unmapped(
        tmp_path):
    a, shard = _b5_relation_case(
        tmp_path / "mapped", "present_in", mapped=True)
    failed = rb.lint(a, "b5-code", shard)
    assert failed.returncode == 1
    assert "outside the closed code_errors list" in failed.stdout
    assert "never_fires" in failed.stdout and "unresolved" in failed.stdout
    a, shard = _b5_relation_case(
        tmp_path / "unmapped", "missing_version_operator", mapped=False)
    failed = rb.lint(a, "b5-code", shard)
    assert "outside the closed code_errors list" in failed.stdout


def test_s702_canonical_relation_is_quiet(tmp_path):
    a, shard = _b5_relation_case(tmp_path, "wrong_value", mapped=True)
    result = rb.lint(a, "b5-code", shard)
    assert result.returncode == 0, result.stdout + result.stderr


def test_tier1_s702_relation_test_oracle_notices_reopened_vocabulary(
        tmp_path, monkeypatch):
    a, shard = _b5_relation_case(tmp_path, "present_in", mapped=True)
    text = shard.read_text(encoding="utf-8")
    rows = [
        row for headers, table_rows, _line in lintmod.parse_tables(text)
        if headers == rb.CODE_LEDGER_COLS for row in table_rows
    ]

    def negative_oracle():
        state = lintmod.Lint()
        lintmod._validate_code_adjudication_shard(
            state, a.audit, shard, text, rows, {"E-0100"})
        assert any("closed code_errors list" in error for error in state.errors)

    negative_oracle()
    monkeypatch.setattr(
        lintmod, "_check_code_relation",
        lambda *_args, **_kwargs: True,
    )
    with pytest.raises(AssertionError):
        negative_oracle()


def test_replay_retry_records_both_attempts_and_scores_second_failure_as_is(
        tmp_path, monkeypatch):
    sandbox = tmp_path / "sandbox"
    run_dir = tmp_path / "run"
    (sandbox / "audit/_code_error_recheck").mkdir(parents=True)
    run_dir.mkdir()
    scenario = {
        "stage": "code_b5", "route": "worker", "model": "fake",
        "effort": "high", "role_key": "code_b5_recheck_cluster",
        "owner": "audit/_code_error_recheck/k1.md",
        "promised_outputs": ["audit/_code_error_recheck/k1.md"],
        "downstream_exclusions": [],
    }
    monkeypatch.setattr(replay, "verify_declared_cut", lambda *_args: None)
    monkeypatch.setattr(
        replay, "_cut_sources", lambda *_args: {})
    monkeypatch.setattr(
        replay, "verify_deterministic_expectations",
        lambda *_args: "not-declared")
    monkeypatch.setattr(replay, "verify_no_downstream", lambda *_args: None)
    monkeypatch.setattr(
        replay, "render_worker_prompt",
        lambda *_args: "RCA-DISPATCH role=x stage=code_b5\n")
    monkeypatch.setattr(replay, "_claude_version", lambda: "fake")
    monkeypatch.setattr(replay, "_git_identity", lambda *_args: ("a" * 40, False))
    monkeypatch.setattr(replay, "_observed_effort", lambda *_args: "observed")
    attempts = []

    def fake_worker(*args):
        attempt = args[-1]
        attempts.append(attempt)
        return {"model": "fake"}, {
            "attempt": attempt, "argv": ["claude"], "cwd": str(sandbox),
            "returncode": 0, "prompt": f"worker-prompt-attempt-{attempt}.md",
            "prompt_sha256": "a" * 64,
            "response": f"worker-response-attempt-{attempt}.json",
        }

    monkeypatch.setattr(replay, "_run_worker_attempt", fake_worker)

    def failing_lint(_scenario, _sandbox, _run_dir, _skill_root, attempt):
        report = f"LINT FAIL attempt {attempt}\n"
        return SimpleNamespace(
            returncode=1, stdout=report, stderr=""), {
                "argv": ["lint"], "cwd": str(sandbox), "returncode": 1,
                "report": f"worker-lint-attempt-{attempt}.txt",
            }

    monkeypatch.setattr(replay, "_run_worker_shard_lint", failing_lint)
    monkeypatch.setattr(
        replay, "_promised_matches",
        lambda *_args: ["audit/_code_error_recheck/k1.md"])
    record = replay.execute_sandbox(
        tmp_path / "scenario.json", scenario, tmp_path, tmp_path, sandbox,
        run_dir, 1, rb.SKILL_DIR,
    )
    assert attempts == [1, 2]
    assert [
        item["returncode"] for item in record["route_commands"]
        if "report" in item
    ] == [1, 1]
    assert [
        item["attempt"] for item in record["route_commands"]
        if "prompt" in item
    ] == [1, 2]
    persisted = json.loads(
        (run_dir / "replay-record.json").read_text(encoding="utf-8"))
    assert len([
        item for item in persisted["route_commands"] if "prompt" in item
    ]) == 2
    # The record's top-level prompt sha must match the persisted final
    # prompt beside it (the retry prompt after a re-dispatch).
    assert record["prompt_sha256"] == hashlib.sha256(
        (run_dir / "worker-prompt.md").read_bytes()).hexdigest()
    assert (run_dir / "worker-prompt.md").read_text(
        encoding="utf-8") == (
        run_dir / "worker-prompt-attempt-2.md").read_text(encoding="utf-8")

    def negative_oracle():
        attempts.clear()
        record = replay.execute_sandbox(
            tmp_path / "scenario.json", scenario, tmp_path, tmp_path, sandbox,
            tmp_path / "reblinded-run", 2, rb.SKILL_DIR,
        )
        assert len([
            item for item in record["route_commands"] if "prompt" in item
        ]) == 2

    monkeypatch.setattr(
        replay, "_run_worker_shard_lint",
        lambda *_args: (
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            {
                "argv": ["lint"], "cwd": str(sandbox), "returncode": 0,
                "report": "worker-lint-attempt-1.txt",
            },
        ),
    )
    with pytest.raises(AssertionError):
        negative_oracle()


def test_tier1_s702_replay_driver_cli_redispatches_bad_worker_once(tmp_path):
    replay_root = tmp_path / "replay-cli"
    replay_root.mkdir()
    archive, archive_manifest, _manifest = replay_helpers._archive(replay_root)
    scenario_id = "opaque-u9c"
    data = replay_helpers._data_tree(
        replay_root, archive_manifest, scenario_id=scenario_id)
    base_root = tmp_path / "b5-base"
    a, shard = _b5_relation_case(base_root, "wrong_value", mapped=True)
    good_shard = tmp_path / "good-shard.md"
    bad_shard = tmp_path / "bad-shard.md"
    good_text = shard.read_text(encoding="utf-8")
    good_shard.write_text(good_text, encoding="utf-8")
    bad_shard.write_text(
        good_text.replace("wrong_value", "present_in"),
        encoding="utf-8",
    )
    shard.unlink()

    material = data / "scenario-material" / scenario_id
    cut = []
    for source in sorted(path for path in base_root.rglob("*") if path.is_file()):
        relative = source.relative_to(base_root).as_posix()
        authored = material / relative
        authored.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, authored)
        cut.append({
            "kind": "authored",
            "source": f"scenario-material/{scenario_id}/{relative}",
            "path": relative,
            "sha256": replay.sha256_file(authored),
            "classification": "conductor",
        })
    answer = data / "answers/sheet.json"
    answer.write_text("{}\n", encoding="utf-8")
    template = (
        rb.SKILL_DIR / "references/prompts/recheck-cluster-worker.md")
    skeleton = re.search(
        r"```md\n(.*?)\n```",
        template.read_text(encoding="utf-8"),
        re.DOTALL,
    ).group(1)
    slot_names = set(re.findall(
        r"\{([A-Z][A-Z0-9_]*)\}", skeleton))
    slots = {name: "synthetic" for name in slot_names}
    slots.update({
        "CONTRACT_PATH": "audit/_run/contracts/recheck_code.md",
        "RECHECK_PLAN_PATH": "audit/plans/code_error_recheck_plan.md",
        "SHARD_FILE": "audit/_code_error_recheck/k1.md",
        "REGISTER_FILES": "audit/code_error_register.md",
        "STREAM": "code-error",
        "ASSIGNED_IDS": "E-0100",
        "OFF_LIMITS": "none",
        "COMPUTE_BUDGET": "1",
    })
    scenario = {
        "format_version": 1, "stage": "code_b5", "route": "worker",
        "archive_manifest": "manifests/archive.json",
        "dependency_cut": cut,
        "promised_outputs": ["audit/_code_error_recheck/k1.md"],
        "downstream_exclusions": ["audit/_code_error_recheck/k1.md"],
        "deterministic_prefix": [],
        "prompt_template": "references/prompts/recheck-cluster-worker.md",
        "prompt_slots": slots, "model": "fake-u9c", "effort": "high",
        "role_key": "code_b5_recheck_cluster",
        "owner": "audit/_code_error_recheck/k1.md",
        "answer_sheet": "answers/sheet.json",
        "answer_sheet_sha256": replay.sha256_file(answer),
        "runs": 2,
    }
    scenario_path = data / "scenarios" / f"{scenario_id}.json"
    scenario_path.write_text(json.dumps(scenario, indent=2), encoding="utf-8")

    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    fake_claude = fake_bin / "claude"
    fake_claude.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "if '--version' in sys.argv:\n"
        "    print('fake-claude 1.0')\n"
        "    raise SystemExit(0)\n"
        "root = Path.cwd()\n"
        "counter = root / '.fake-claude-attempt'\n"
        "attempt = int(counter.read_text()) + 1 if counter.exists() else 1\n"
        "counter.write_text(str(attempt))\n"
        "source = Path(os.environ['FAKE_BAD_SHARD' if attempt == 1 "
        "else 'FAKE_GOOD_SHARD'])\n"
        "target = root / 'audit/_code_error_recheck/k1.md'\n"
        "target.parent.mkdir(parents=True, exist_ok=True)\n"
        "target.write_bytes(source.read_bytes())\n"
        "print(json.dumps({'model': 'fake-u9c'}))\n",
        encoding="utf-8",
    )
    fake_claude.chmod(0o755)
    sandbox = tmp_path / "replay-sandbox"
    run_dir = tmp_path / "replay-run"
    base_command = [
        sys.executable, str(rb.SCRIPTS_DIR / "replay_stage.py"),
        "--data-root", str(data), "--archive-root", str(archive),
    ]
    prepared = subprocess.run(
        base_command + [
            "prepare", str(scenario_path), "--sandbox", str(sandbox),
        ],
        capture_output=True, text=True,
    )
    assert prepared.returncode == 0, prepared.stdout + prepared.stderr
    env = {
        **os.environ,
        "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", ""),
        "FAKE_BAD_SHARD": str(bad_shard),
        "FAKE_GOOD_SHARD": str(good_shard),
    }
    executed = subprocess.run(
        base_command + [
            "execute", str(scenario_path), "--sandbox", str(sandbox),
            "--run-dir", str(run_dir), "--run-index", "1",
        ],
        capture_output=True, text=True, env=env,
    )
    assert executed.returncode == 0, executed.stdout + executed.stderr
    record = json.loads(
        (run_dir / "replay-record.json").read_text(encoding="utf-8"))
    assert [
        item["returncode"] for item in record["route_commands"]
        if "report" in item
    ] == [1, 0]
    assert [
        item["attempt"] for item in record["route_commands"]
        if "prompt" in item
    ] == [1, 2]
    retry_prompt = (
        run_dir / "worker-prompt-attempt-2.md").read_text(encoding="utf-8")
    assert "Production shard-lint report" in retry_prompt
    assert "outside the closed code_errors list" in retry_prompt
    assert (
        sandbox / "audit/_code_error_recheck/k1.md"
    ).read_text(encoding="utf-8") == good_text
