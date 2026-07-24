"""U8b severity-token, receipt, residual, and rulings contracts."""

import json
from pathlib import Path

import pytest

import regbuild as rb


tokens = rb.load_script("severity_tokens")
rulings = rb.load_script("severity_token_rulings")
mechanism = rb.load_script("mechanism_schema")
certify = rb.load_script("certify_stage")
lint = rb.load_script("lint_registers")
sf = rb.load_script("score_fixture")

pytestmark = pytest.mark.u8


def _mechanism():
    return mechanism.canonicalize_mechanism(
        "sample_filter_or_flag_error", "bad", "wrong_value", "1", "0",
        register="code_errors", anchor="py/source.py:1",
        projection=mechanism.EMPTY_PROJECTION,
    ).sidecar


def _token_fixture(tmp_path, *, token="output:O-0001", mode="replication"):
    root = tmp_path / "package"
    a = rb.AuditDir(root)
    a.write_manifest(mode=mode)
    (root / "py").mkdir(parents=True)
    (root / "py/source.py").write_text("bad = 0\n", encoding="utf-8")
    (root / "py/table.py").write_text("print(bad)\n", encoding="utf-8")
    (root / "py/other.py").write_text("print(other)\n", encoding="utf-8")
    row = rb.error_row(
        "E-0001", etype="sample_filter_or_flag_error",
        source="`py/source.py`; `py/table.py`", location="py/source.py:1",
        status="confirmed", severity="3", why=f"reported impact {token}",
    )
    a.write_register("code_error_register.md", rb.ERROR_COLS, [row])
    a.write_register("claims_register.md", rb.CLAIMS_COLS, [])
    outputs = [rb.output_row(
        "O-0001", script="`py/table.py`", location="`paper/paper.tex:1`")] \
        if mode == "replication" else []
    a.write_register("output_register.md", rb.OUTPUT_COLS, outputs)
    shard = a.audit / "_code_error_recheck/k1.md"
    probe = shard.parent / "token_probe.py"
    probe.parent.mkdir(parents=True, exist_ok=True)
    probe.write_text("pass\n", encoding="utf-8")
    sidecar = _mechanism()
    digest = tokens.obligation_digest(
        "E-0001", token, sidecar, "—", "py/source.py:1", "bad")
    ledger = rb.code_ledger_row(
        "E-0001", severity="3", proposed_severity="3",
        accepted_mechanism=sidecar, witness_ids="—")
    record = {
        "Record Type": "token_verification", "Error ID": "E-0001",
        "Token": token, "Obligation Digest": digest, "Mechanism": sidecar,
        "Witness IDs": "—", "Error Location": "py/source.py:1",
        "Flawed Identifier": "bad", "Cited Target": token.split(":", 1)[1],
        "Lineage JSON": json.dumps([
            {"anchor": "py/source.py:1", "carries": "bad"},
            {"anchor": "py/table.py:1", "carries": "bad"},
        ], separators=(",", ":")),
        "Probe Path": "token_probe.py",
        "Probe Output SHA256": tokens.result_digest(0, b"", b""),
        "Verdict": "verified", "Derived From Receipt ID": "—",
    }
    body = rb.register_text("Recheck ledger", rb.CODE_LEDGER_COLS, [ledger])
    body += "\n### Token verification records\n\n"
    body += rb.md_table(tokens.TOKEN_RECORD_COLS, [
        [record[column] for column in tokens.TOKEN_RECORD_COLS]])
    a.write("_code_error_recheck/k1.md", body)
    return root, a, row, record


def _issue_receipts(root, a, stage="code_b6a"):
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    receipts, failures = tokens.verify_token_records(
        root, a.audit, manifest, stage)
    assert failures == []
    tokens.write_atomic(
        tokens.receipt_path(a.audit, stage), tokens.render_receipts(receipts))
    return receipts


def test_token_vocabulary_is_mode_closed_and_duplicate_literal_is_refused():
    row = {"Why It Matters": "output:O-0001", "Error Type": "weighting_error",
           "Status": "confirmed", "Severity": "3", "Error ID": "E-0001"}
    assert tokens.row_token_state(row, "replication") == ("output:O-0001", None)
    row["Why It Matters"] = "reported impact (output:O-0001)."
    assert tokens.row_token_state(row, "replication") == ("output:O-0001", None)
    assert tokens.row_token_state(row, "code_errors_only")[0] is None
    row["Why It Matters"] = "output:O-0001 and output:O-0001"
    assert "exactly one" in tokens.row_token_state(row, "replication")[1]
    row["Why It Matters"] = "uses:py/x.py:2 build-abort:failed"
    assert tokens.row_token_state(row, "replication")[0] is None


def test_post_b8_gate_reads_why_it_matters_original():
    row = {"Why It Matters": "author prose", "Why It Matters Original": "claim:C-0001"}
    assert tokens.literal_tokens(tokens.why_text(row)) == ["claim:C-0001"]


def test_ra_inventory_derives_id_and_rejects_intermediate_dataset(tmp_path):
    root = tmp_path / "package"
    a = rb.AuditDir(root)
    (root / "master.do").write_text("* declares artifacts/table.csv\n", encoding="utf-8")
    (root / "py").mkdir()
    (root / "py/write.py").write_text("export table\n", encoding="utf-8")
    identity = {
        "Terminal Kind": "table", "Path/Pattern": "artifacts/table.csv",
        "Declaration Anchor": "master.do:1", "Writer Site": "py/write.py:1",
        "Availability": "generated_unshipped",
    }
    ra_id = tokens.reported_artifact_id(identity)
    row = [ra_id, *[identity[column] for column in tokens.RA_COLS[1:]]]
    codemap = (
        "# CODEMAP\n\n## Materials Inventory\n\n"
        + rb.md_table(["Material", "Path", "Notes"], [
            ["master script", "master.do", "master"],
            ["reported table", "artifacts/table.csv", "reported"],
        ])
        + "\n## Reported Artifact Token Inventory\n\n"
        + rb.md_table(tokens.RA_COLS, [row])
        + "\nPRECONDITIONS: 5/5 yes\n")
    a.write("CODEMAP.md", codemap)
    manifest = {"mode": "code_errors_only"}
    inventory, failures = tokens.validate_ra_inventory(root, a.audit, manifest)
    assert failures == []
    assert set(inventory) == {ra_id}
    a.write("CODEMAP.md", codemap.replace(
        "## Reported Artifact Token Inventory", "## Key Dataset Lineage\n\n"
        + rb.md_table([
            "ID", "Dataset/path", "Type", "Stage", "Created by", "Inputs",
            "Consumed by", "Restricted/manual/external?", "Confidence", "Notes",
        ], [["D-0001", "artifacts/table.csv", "intermediate dataset", "1", "x",
             "x", "x", "no", "high", "x"]])
        + "\n## Reported Artifact Token Inventory"))
    _inventory, failures = tokens.validate_ra_inventory(root, a.audit, manifest)
    assert any("intermediate/analysis-only" in failure for failure in failures)


def test_token_receipt_writer_uses_pinned_schema_id_and_zero_form():
    assert tokens.render_receipts([]) == (
        "Schema: token-receipts/v1\n\nNo token receipts.\n")
    digest = "a" * 64
    assert tokens.receipt_id("E-0001", "output:O-0001", digest) == (
        "TR-" + __import__("hashlib").sha256(
            ("token-receipt/v1\0E-0001\0output:O-0001\0" + digest).encode()).hexdigest()[:12])


def test_verifier_issues_receipt_and_gate_accepts_exact_composite(tmp_path):
    root, a, row, _record = _token_fixture(tmp_path)
    receipts = _issue_receipts(root, a)
    assert receipts[0]["Receipt ID"].startswith("TR-")
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    classifications, failures = tokens.gate_rows(
        root, a.audit, manifest, [dict(zip(rb.ERROR_COLS, row))], "code_b6a")
    assert failures == []
    assert classifications == {"E-0001": "live"}


def test_worker_record_without_verifier_receipt_satisfies_no_gate(tmp_path):
    root, a, row, _record = _token_fixture(tmp_path)
    tokens.write_atomic(tokens.receipt_path(a.audit, "code_b6a"),
                        tokens.render_receipts([]))
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    classifications, failures = tokens.gate_rows(
        root, a.audit, manifest, [dict(zip(rb.ERROR_COLS, row))], "code_b6a")
    assert classifications == {"E-0001": "invalid"}
    assert any("requires exactly one verifier token receipt" in failure
               for failure in failures)


def test_forged_receipt_without_matching_record_is_refused(tmp_path):
    root, a, row, record = _token_fixture(tmp_path)
    forged = {
        "Receipt ID": tokens.receipt_id("E-0001", record["Token"], "b" * 64),
        "Error ID": "E-0001", "Token": record["Token"],
        "Obligation Digest": "b" * 64, "Probe Path": "token_probe.py",
        "Probe Output SHA256": record["Probe Output SHA256"], "Verdict": "verified",
    }
    tokens.write_atomic(tokens.receipt_path(a.audit, "code_b6a"),
                        tokens.render_receipts([forged]))
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    _classifications, failures = tokens.gate_rows(
        root, a.audit, manifest, [dict(zip(rb.ERROR_COLS, row))], "code_b6a")
    assert any("no matching verifier record" in failure or "disagrees" in failure
               for failure in failures)


def test_laundered_real_output_id_fails_endpoint_anchoring(tmp_path):
    root, a, _row, record = _token_fixture(tmp_path, token="output:O-0002")
    a.write_register("output_register.md", rb.OUTPUT_COLS, [
        rb.output_row("O-0002", script="`py/other.py`"),
    ])
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    _receipts, failures = tokens.verify_token_records(
        root, a.audit, manifest, "code_b6a")
    assert any("output lineage endpoint" in failure for failure in failures)


def test_target_not_live_routes_across_b6_with_receipt(tmp_path):
    root, a, row, _record = _token_fixture(tmp_path)
    _issue_receipts(root, a)
    a.write_register("output_register.md", rb.OUTPUT_COLS, [])
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    classifications, failures = tokens.gate_rows(
        root, a.audit, manifest, [dict(zip(rb.ERROR_COLS, row))], "code_b6a")
    assert failures == []
    assert classifications == {"E-0001": "target_not_live"}


def test_nonterminal_output_id_cannot_launder_a_severe_token(tmp_path):
    root, a, _row, _record = _token_fixture(tmp_path)
    a.write_register("output_register.md", rb.OUTPUT_COLS, [
        rb.output_row("O-0001", script="`py/table.py`", location="—"),
    ])
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    _receipts, failures = tokens.verify_token_records(
        root, a.audit, manifest, "code_b6a")
    assert any("cited target is invalid" in failure for failure in failures)


def _rulings_fixture(tmp_path, verdict="rejected"):
    root, a, row, _record = _token_fixture(tmp_path)
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [row])
    a.write("register_cross_link_summary.md", (
        "# Cross-link summary\n\n## Status conflicts\n\nnone\n\n"
        "## Escalated mapped claims\n\nnone\n\n## Severity divergences\n\nnone\n\n"
        "## Severity-token adjudications\n\n"
        + rb.md_table(tokens.ADJUDICATION_COLS, [[
            "E-0001 output:O-0001", "O-0001", verdict, "py/table.py:1",
        ]])))
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    return root, a, manifest


def test_b7_rejects_upheld_non_live_target(tmp_path):
    root, a, manifest = _rulings_fixture(tmp_path, verdict="upheld")
    a.write_register("output_register.md", rb.OUTPUT_COLS, [])
    _rejected, failures = rulings.validate_b7(root, a.audit, manifest)
    assert any("recomputed-non-live" in failure for failure in failures)


def test_rulings_cap_applies_only_status_and_severity(tmp_path):
    root, a, manifest = _rulings_fixture(tmp_path)
    frozen = rulings.snapshot_stage(root, a.audit, manifest)
    authority = {
        "schema": "severity_token_rulings/v1", "cycle": "main",
        "b7_certification_sha256": frozen["b7_certification_sha256"],
        "rulings": [{
            "error_id": "E-0001", "token": "output:O-0001",
            "b7_verdict": "rejected", "ruling": "cap",
            "resulting_status": "confirmed", "resulting_severity": 2,
            "rationale": "downstream tie rejected", "decision_identity": "operator-1",
        }],
    }
    a.write("_run/severity_token_rulings.json", json.dumps(authority, indent=2) + "\n")
    rulings.apply_rulings(root, a.audit, manifest)
    _decisions, failures = rulings.validate_rulings(
        root, a.audit, manifest, require_applied=True)
    assert failures == []
    register = tokens._load_register_error_rows(a.audit)
    assert register["E-0001"]["Severity"] == "2"
    assert "output:O-0001" in register["E-0001"]["Why It Matters"]


def test_missing_ruling_and_doctored_uphold_get_zero_promotion(tmp_path):
    root, a, manifest = _rulings_fixture(tmp_path)
    frozen = rulings.snapshot_stage(root, a.audit, manifest)
    before = (a.audit / "code_error_register.md").read_bytes()
    a.write("_run/severity_token_rulings.json", json.dumps({
        "schema": "severity_token_rulings/v1", "cycle": "main",
        "b7_certification_sha256": frozen["b7_certification_sha256"],
        "rulings": [],
    }))
    with pytest.raises(rulings.RulingsError):
        rulings.apply_rulings(root, a.audit, manifest)
    assert (a.audit / "code_error_register.md").read_bytes() == before
    a.write_register("output_register.md", rb.OUTPUT_COLS, [])
    authority = {
        "schema": "severity_token_rulings/v1", "cycle": "main",
        "b7_certification_sha256": frozen["b7_certification_sha256"],
        "rulings": [{
            "error_id": "E-0001", "token": "output:O-0001",
            "b7_verdict": "rejected", "ruling": "uphold",
            "resulting_status": "confirmed", "resulting_severity": 3,
            "rationale": "keep", "decision_identity": "operator-1",
        }],
    }
    a.write("_run/severity_token_rulings.json", json.dumps(authority))
    with pytest.raises(rulings.RulingsError, match="non-live"):
        rulings.apply_rulings(root, a.audit, manifest)
    assert (a.audit / "code_error_register.md").read_bytes() == before


def test_zero_rejected_tokens_requires_exact_skip_form(tmp_path):
    root, a, manifest = _rulings_fixture(tmp_path, verdict="upheld")
    frozen = rulings.snapshot_stage(root, a.audit, manifest)
    a.write("_run/severity_token_rulings.json", json.dumps({
        "schema": "severity_token_rulings/v1", "cycle": "main",
        "b7_certification_sha256": frozen["b7_certification_sha256"],
        "skip_reason": "zero_rejected_severity_tokens", "rulings": [],
    }) + "\n")
    rulings.apply_rulings(root, a.audit, manifest)
    _decisions, failures = rulings.validate_rulings(
        root, a.audit, manifest, require_applied=True)
    assert failures == []


def test_post_bc_b7_rerun_refuses_any_new_rejected_key(tmp_path):
    root, a, manifest = _rulings_fixture(tmp_path)
    rulings.snapshot_stage(root, a.audit, manifest)
    second = rb.error_row(
        "E-0002", status="confirmed", severity="3",
        why="another impact output:O-0001")
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [
        rb.error_row("E-0001", etype="sample_filter_or_flag_error",
                     source="`py/source.py`; `py/table.py`",
                     location="py/source.py:1", status="confirmed", severity="3",
                     why="reported impact output:O-0001"),
        second,
    ])
    a.write("register_cross_link_summary.md", (
        "# Cross-link summary\n\n## Severity-token adjudications\n\n"
        + rb.md_table(tokens.ADJUDICATION_COLS, [
            ["E-0001 output:O-0001", "O-0001", "rejected", "py/table.py:1"],
            ["E-0002 output:O-0001", "O-0001", "rejected", "py/table.py:1"],
        ])))
    _rejected, failures = rulings.validate_b7(root, a.audit, manifest)
    assert any("introduced new rejected" in failure for failure in failures)


def test_stage_enumeration_places_rulings_between_b7_and_b8_only_in_full_mode():
    index = certify.FULL_STAGES.index("severity_token_rulings")
    assert certify.FULL_STAGES[index - 1:index + 2] == (
        "b7", "severity_token_rulings", "b8")
    assert "severity_token_rulings" not in certify.CODE_ONLY_STAGES


def test_close_run_refuses_activated_missing_rulings_stage(tmp_path):
    root = tmp_path / "package"
    a = rb.AuditDir(root)
    a.write_manifest(mode="replication", run_identity={
        "canonical_package_root": str(root.resolve()),
    }, stages={"severity_token_rulings": {"status": "pending", "retries": 0}})
    a.write("_run/RUNNING", "live\n")
    tokens.write_atomic(
        a.audit / "_run/code_b6b/token_receipts.md", tokens.render_receipts([]))
    with pytest.raises(certify.CertificationError, match="severity_token_rulings"):
        certify.close_run(root)


def test_b1_receipt_gate_has_teeth(tmp_path, monkeypatch):
    root, a, row, _record = _token_fixture(tmp_path)
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    classifications, failures = tokens.gate_rows(
        root, a.audit, manifest, [dict(zip(rb.ERROR_COLS, row))], "code_b6a")
    assert classifications == {"E-0001": "invalid"}
    assert any("requires exactly one verifier token receipt" in item for item in failures)

    verified, verify_failures = tokens.verify_token_records(
        root, a.audit, manifest, "code_b6a")
    assert verify_failures == []
    forged_loader = {
        (item["Error ID"], item["Token"], item["Obligation Digest"]): item
        for item in verified
    }
    monkeypatch.setattr(tokens, "load_receipts", lambda *_args, **_kwargs: (
        forged_loader, []))
    classifications, failures = tokens.gate_rows(
        root, a.audit, manifest, [dict(zip(rb.ERROR_COLS, row))], "code_b6a")
    assert classifications == {"E-0001": "live"}
    assert failures == []


def test_b2_endpoint_anchor_check_has_teeth(tmp_path, monkeypatch):
    root, a, _row, _record = _token_fixture(tmp_path, token="output:O-0002")
    a.write_register("output_register.md", rb.OUTPUT_COLS, [
        rb.output_row("O-0002", script="`py/other.py`"),
    ])
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    _verified, failures = tokens.verify_token_records(
        root, a.audit, manifest, "code_b6a")
    assert any("output lineage endpoint" in item for item in failures)
    monkeypatch.setattr(tokens, "validate_lineage", lambda *_args, **_kwargs: None)
    verified, failures = tokens.verify_token_records(
        root, a.audit, manifest, "code_b6a")
    assert len(verified) == 1 and failures == []


def test_production_token_verifier_cli_accepts_proof_and_refuses_drift(tmp_path):
    root, a, _row, _record = _token_fixture(tmp_path)
    issued = rb.run_script(
        "verify_dismissals.py", root, "--audit-dir", a.audit, "--tokens")
    assert issued.returncode == 0, issued.stdout + issued.stderr
    assert "wrote 1 token receipt" in issued.stdout
    shard = a.audit / "_code_error_recheck/k1.md"
    shard.write_text(shard.read_text().replace(
        "token_verification", "drifted_verification", 1), encoding="utf-8")
    refused = rb.run_script(
        "verify_dismissals.py", root, "--audit-dir", a.audit, "--tokens")
    assert refused.returncode == 1
    assert "Record Type must be token_verification" in refused.stderr


def test_b3_missing_ruling_refuses_certification_b8_and_close_clis(tmp_path):
    root, a, manifest = _rulings_fixture(tmp_path)
    rulings.snapshot_stage(root, a.audit, manifest)
    manifest["run_identity"] = {"canonical_package_root": str(root.resolve())}
    manifest["stages"] = {
        "b7": {"status": "done", "retries": 0},
        "severity_token_rulings": {"status": "running", "retries": 0},
    }
    tokens.write_atomic(
        a.audit / "_run/code_b6b/token_receipts.md", tokens.render_receipts([]))
    a.write("_run/RUNNING", "live\n")
    a.write("_run/manifest.json", json.dumps(manifest, indent=2) + "\n")

    uncertifiable = rb.run_script(
        "certify_stage.py", "finish", "--package-root", root,
        "--stage", "severity_token_rulings", "--outcome", "done")
    assert uncertifiable.returncode == 1
    assert "zero promotion" in uncertifiable.stderr

    manifest["stages"]["severity_token_rulings"]["status"] = "pending"
    a.write("_run/manifest.json", json.dumps(manifest, indent=2) + "\n")
    b8 = rb.run_script("lint_registers.py", "--stage", "b8", "--audit-dir", a.audit)
    assert b8.returncode == 1
    assert "b8 refuses while severity_token_rulings is not done" in b8.stdout
    close = rb.run_script("certify_stage.py", "close-run", "--package-root", root)
    assert close.returncode == 1
    assert "severity_token_rulings is not done" in close.stderr


def test_b3_nonlive_uphold_check_has_teeth(tmp_path, monkeypatch):
    root, a, manifest = _rulings_fixture(tmp_path)
    frozen = rulings.snapshot_stage(root, a.audit, manifest)
    a.write_register("output_register.md", rb.OUTPUT_COLS, [])
    a.write("_run/severity_token_rulings.json", json.dumps({
        "schema": "severity_token_rulings/v1", "cycle": "main",
        "b7_certification_sha256": frozen["b7_certification_sha256"],
        "rulings": [{
            "error_id": "E-0001", "token": "output:O-0001",
            "b7_verdict": "rejected", "ruling": "uphold",
            "resulting_status": "confirmed", "resulting_severity": 3,
            "rationale": "operator override", "decision_identity": "operator-1",
        }],
    }) + "\n")
    with pytest.raises(rulings.RulingsError, match="non-live"):
        rulings.apply_rulings(root, a.audit, manifest)
    monkeypatch.setattr(rulings.tokens, "resolve_target", lambda *_args: ("live", {}))
    rulings.apply_rulings(root, a.audit, manifest)


def _completed_severity_tail(tmp_path):
    root, a, row, _record = _token_fixture(tmp_path)
    _issue_receipts(root, a, "code_b6b")
    for name in ("claims_register.md", "output_register.md"):
        a.write(f"_run/snapshots/code_b5_dispatch/{name}",
                (a.audit / name).read_text(encoding="utf-8"))
    a.write("_run/late_severity_residuals.md",
            "# Late severity residuals\n\n" + rb.md_table(tokens.RESIDUAL_COLS, []))
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [row])
    a.write("register_cross_link_summary.md", (
        "# Cross-link summary\n\n## Status conflicts\n\nnone\n\n"
        "## Escalated mapped claims\n\nnone\n\n## Severity divergences\n\nnone\n\n"
        "## Severity-token adjudications\n\n"
        + rb.md_table(tokens.ADJUDICATION_COLS, [[
            "E-0001 output:O-0001", "O-0001", "upheld", "py/table.py:1",
        ]])))
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    frozen = rulings.snapshot_stage(root, a.audit, manifest)
    a.write("_run/severity_token_rulings.json", json.dumps({
        "schema": "severity_token_rulings/v1", "cycle": "main",
        "b7_certification_sha256": frozen["b7_certification_sha256"],
        "skip_reason": "zero_rejected_severity_tokens", "rulings": [],
    }, indent=2) + "\n")
    rulings.apply_rulings(root, a.audit, manifest)
    a.write_register("_run/snapshots/b8/claims_register.md", rb.CLAIMS_COLS, [])
    a.write_register("_run/snapshots/b8/code_error_register.md", rb.ERROR_COLS, [row])
    claims_cols, claims_rows = rb.rewrite_pass_cols(
        rb.CLAIMS_COLS, [], ["Issue Description"])
    error_cols, error_rows = rb.rewrite_pass_cols(
        rb.ERROR_COLS, [row], ["Error Description", "Why It Matters"])
    a.write_register("_staging/claims_register.md", claims_cols, claims_rows)
    a.write_register("_staging/code_error_register.md", error_cols, error_rows)
    manifest["stages"] = {
        "severity_token_rulings": {"status": "done", "retries": 0},
        "b8": {"status": "done", "retries": 0},
    }
    manifest["certified_stage_evidence_version"] = (
        certify.CERTIFIED_EVIDENCE_VERSION)
    manifest["run_identity"] = certify.make_run_identity(root.resolve(), manifest)
    a.write("_run/manifest.json", json.dumps(manifest, indent=2) + "\n")
    return root, a


def test_completed_tail_verify_run_rederives_token_gate_and_refuses_sabotage(tmp_path):
    root, a = _completed_severity_tail(tmp_path)
    verified = rb.run_script("certify_stage.py", "verify-run", "--package-root", root)
    assert verified.returncode == 0, verified.stdout + verified.stderr
    tokens.write_atomic(
        a.audit / "_run/code_b6b/token_receipts.md", tokens.render_receipts([]))
    refused = rb.run_script("certify_stage.py", "verify-run", "--package-root", root)
    assert refused.returncode == 1
    assert "token receipt set disagrees" in refused.stderr


def _install_bc_receipt_home(root, a):
    records, failures = tokens.load_token_records(a.audit, "code_b6b")
    assert failures == [] and len(records) == 1
    record = next(iter(records.values()))[1]
    a.write("plans/token_probe.py", (
        a.audit / "_code_error_recheck/token_probe.py").read_text(encoding="utf-8"))
    a.write("plans/late_observation_corrections.md", (
        "# Late-observation corrections\n\n### Token verification records\n\n"
        + rb.md_table(tokens.TOKEN_RECORD_COLS, [[
            record[column] for column in tokens.TOKEN_RECORD_COLS
        ]])
    ))
    _issue_receipts(root, a, "bC")
    (a.audit / "_run/code_b6b/token_receipts.md").unlink()


def _export_completed_tail(a):
    for stream in ("claims", "code"):
        a.write(f"late_observations_{stream}.md", (
            f"# Late observations — {stream}\n\nNo late observations.\n\n"
            "## Dispositions\n\nNo dispositions.\n"))
    exported = rb.run_script(
        "export_xlsx.py", "--audit-dir", a.audit, "--mode", "replication",
        "-o", a.audit / "code_review.xlsx")
    assert exported.returncode == 0, exported.stdout + exported.stderr


@pytest.mark.u9
def test_bc_receipt_home_union_passes_b8_and_b9_full_mode_clis(tmp_path):
    root, a = _completed_severity_tail(tmp_path)
    _install_bc_receipt_home(root, a)
    b8 = rb.lint(a, "b8")
    assert b8.returncode == 0, b8.stdout + b8.stderr
    _export_completed_tail(a)
    b9 = rb.lint(a, "b9")
    assert b9.returncode == 0, b9.stdout + b9.stderr


@pytest.mark.u9
def test_receiptless_severe_row_refuses_with_both_final_homes_present(tmp_path):
    _root, a = _completed_severity_tail(tmp_path)
    tokens.write_atomic(
        a.audit / "_run/code_b6b/token_receipts.md", tokens.render_receipts([]))
    tokens.write_atomic(
        a.audit / "_run/bC/token_receipts.md", tokens.render_receipts([]))
    b8 = rb.lint(a, "b8")
    assert b8.returncode == 1
    assert "severity-token gate" in b8.stdout
    _export_completed_tail(a)
    b9 = rb.lint(a, "b9")
    assert b9.returncode == 1
    assert "severity-token gate" in b9.stdout


@pytest.mark.u9
def test_b7_sweep_activates_from_bc_home_and_rows_without_spurious_firing(tmp_path):
    # Direction 1: a post-bC severe mint whose only receipt home is bC.  The
    # pre-fix b7 activation looked at the code_b6b home alone (and passed no
    # rows), so this exact state silently skipped the sweep; now the sweep
    # must activate and demand adjudication coverage through the b7 CLI.
    root, a, row, record = _token_fixture(tmp_path)
    a.write("plans/token_probe.py", (
        a.audit / "_code_error_recheck/token_probe.py").read_text(encoding="utf-8"))
    a.write("plans/late_observation_corrections.md", (
        "# Late-observation corrections\n\n### Token verification records\n\n"
        + rb.md_table(tokens.TOKEN_RECORD_COLS, [[
            record[column] for column in tokens.TOKEN_RECORD_COLS
        ]])
    ))
    _issue_receipts(root, a, "bC")
    a.write_register("_staging/claims_register.md", rb.CLAIMS_COLS, [])
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [row])
    a.snapshot("b7", ["claims_register.md", "code_error_register.md"])
    a.write("register_cross_link_summary.md", rb.CROSS_LINK_SUMMARY_STUB)
    activated = rb.lint(a, "b7")
    assert activated.returncode == 1, activated.stdout + activated.stderr
    assert "b7 severity-token sweep" in activated.stdout
    # Direction 2: no severe rows and no receipts in any home — the widened
    # activation (union homes + rows) must not fire spuriously.
    quiet = rb.make_b7(tmp_path / "quiet",
                       error_rows=[rb.error_row("E-0002", severity="2")])
    silent = rb.lint(quiet, "b7")
    assert silent.returncode == 0, silent.stdout + silent.stderr


# ---------------------------------------------------------------- F1: derived
# activation — a severe-eligible row makes the gate mandatory with no token
# artifact anywhere, so conductor omission fails instead of passing silently.


import test_u6_supplementary as u6  # noqa: E402  (shared wave/bC builders)


def test_tokenless_severe_row_drills_b6a_b6b_lint_clis_and_assembler(tmp_path):
    root, a, _shard = u6.make_wave(tmp_path, discovery=False)
    u6.certify_wave(root, a, discovery=False)
    severe = rb.error_row("E-0100", status="confirmed", severity="3")
    a.write_register("code_error_register.md", rb.ERROR_COLS, [severe])
    # the b6a lint reads the frozen post-b6a state when it exists
    a.write_register("_run/snapshots/code_b6b/code_error_register.md",
                     rb.ERROR_COLS, [severe])
    b6a = rb.lint(a, "b6a-code")
    assert b6a.returncode == 1
    assert "severity-token gate" in b6a.stdout
    b6b = rb.lint(a, "b6b-code")
    assert b6b.returncode == 1
    assert "severity-token gate" in b6b.stdout
    boundary = rb.run_script(
        "assemble_boundary.py", root, "--audit-dir", a.audit, "--check")
    assert boundary.returncode == 1
    assert "severity-token" in (boundary.stdout + boundary.stderr)


def test_severity2_wave_stays_quiet_without_token_artifacts(tmp_path):
    root, a, _shard = u6.make_wave(tmp_path, discovery=False)
    u6.certify_wave(root, a, discovery=False)
    res = rb.lint(a, "b6a-code")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "severity-token" not in res.stdout


def test_severe_bc_mint_gate_drills_through_lint_cli(tmp_path):
    root, a, before, _added = u6.make_bc(tmp_path)

    def install(mint_row):
        payload = json.dumps(dict(zip(rb.ERROR_COLS, mint_row)),
                             sort_keys=True, separators=(",", ":"))
        a.write("plans/late_observation_corrections.md", (
            "# Late-observation corrections\n\n"
            "Declared bC range: E-8001–E-8001\n\n"
            + rb.md_table(lint.BC_PLAN_COLS, [[
                "BC-0001", "LO-E-0001", "code_error", "new_row", "E-8001",
                payload, "—"]])))
        a.write_register("code_error_register.md", rb.ERROR_COLS,
                         before + [mint_row])

    install(rb.error_row("E-8001", status="confirmed", severity="3"))
    res = rb.lint(a, "bC")
    assert res.returncode == 1
    assert "severity-token gate" in res.stdout

    install(rb.error_row("E-8001", status="candidate", severity="3"))
    res = rb.lint(a, "bC")
    assert res.returncode == 1
    assert "token-governed final status" in res.stdout


def test_close_run_refuses_on_severe_rows_without_any_token_artifact(tmp_path):
    root = tmp_path / "package"
    a = rb.AuditDir(root)
    a.write_register("code_error_register.md", rb.ERROR_COLS,
                     [rb.error_row("E-0001", status="confirmed", severity="3")])
    a.write_manifest(mode="replication", run_identity={
        "canonical_package_root": str(root.resolve()),
    }, stages={"severity_token_rulings": {"status": "pending", "retries": 0}})
    a.write("_run/RUNNING", "live\n")
    with pytest.raises(certify.CertificationError, match="severity_token_rulings"):
        certify.close_run(root)


# ------------------------------------------------------- F3/F4: residual exit


def _residual_tail(tmp_path, *, target_in_dispatch=False, status="confirmation_needed",
                   why="late terminal impact", outcome="unavailable_blocked",
                   residual_rows=None):
    """A b8-lintable full-mode audit whose severe row is residual-covered."""
    root = tmp_path / "package"
    a = rb.AuditDir(root)
    (root / "py").mkdir(parents=True, exist_ok=True)
    (root / "py/source.py").write_text("bad = 0\n", encoding="utf-8")
    row = rb.error_row(
        "E-0001", etype="sample_filter_or_flag_error", source="`py/source.py`",
        location="py/source.py:1", status=status, severity="3", why=why)
    a.write_register("code_error_register.md", rb.ERROR_COLS, [row])
    a.write_register("claims_register.md", rb.CLAIMS_COLS, [])
    a.write_register("output_register.md", rb.OUTPUT_COLS,
                     [rb.output_row("O-0002")])
    a.write_register("_run/snapshots/code_b5_dispatch/claims_register.md",
                     rb.CLAIMS_COLS, [])
    a.write_register("_run/snapshots/code_b5_dispatch/output_register.md",
                     rb.OUTPUT_COLS,
                     [rb.output_row("O-0002")] if target_in_dispatch else [])
    head = tokens.dispatch_head(a.audit)
    a.write_register("_run/snapshots/claims_b6a/output_register.md",
                     rb.OUTPUT_COLS, [rb.output_row("O-0002")])
    intro = "claims_b6a:" + tokens.sha256_file(
        a.audit / "_run/snapshots/claims_b6a/output_register.md")
    if residual_rows is None:
        residual_rows = [["E-0001", "output", "O-0002", head, intro,
                          outcome, "EV-0001"]]
    a.write("_run/late_severity_residuals.md",
            "# Late severity residuals\n\n"
            + rb.md_table(tokens.RESIDUAL_COLS, residual_rows))
    tokens.write_atomic(a.audit / "_run/code_b6b/token_receipts.md",
                        tokens.render_receipts([]))
    a.write("register_cross_link_summary.md", (
        "# Cross-link summary\n\n## Status conflicts\n\nnone\n\n"
        "## Escalated mapped claims\n\nnone\n\n## Severity divergences\n\nnone\n\n"
        "## Severity-token adjudications\n\nnone\n"))
    a.write_register("_run/snapshots/b8/claims_register.md", rb.CLAIMS_COLS, [])
    a.write_register("_run/snapshots/b8/code_error_register.md",
                     rb.ERROR_COLS, [row])
    claims_cols, claims_rows = rb.rewrite_pass_cols(
        rb.CLAIMS_COLS, [], ["Issue Description"])
    error_cols, error_rows = rb.rewrite_pass_cols(
        rb.ERROR_COLS, [row], ["Error Description", "Why It Matters"])
    a.write_register("_staging/claims_register.md", claims_cols, claims_rows)
    a.write_register("_staging/code_error_register.md", error_cols, error_rows)
    a.write_manifest(mode="replication", stages={
        "claims_b6a": {"status": "done", "retries": 0},
        "code_b5s": {"status": "blocked", "retries": 0,
                     "reason": "claims stream interrupted before b5s"},
        "severity_token_rulings": {"status": "done", "retries": 0},
    })
    return root, a, row


def test_populated_residual_certifies_through_b8_cli(tmp_path):
    _root, a, _row = _residual_tail(tmp_path)
    res = rb.lint(a, "b8")
    assert res.returncode == 0, res.stdout + res.stderr


def test_fabricated_dispatch_time_residual_refused_through_b8_cli(tmp_path):
    _root, a, _row = _residual_tail(tmp_path, target_in_dispatch=True)
    res = rb.lint(a, "b8")
    assert res.returncode == 1
    assert "target existed in the dispatch-time register" in res.stdout


def test_confirmed_row_cannot_use_residual_through_b8_cli(tmp_path):
    _root, a, _row = _residual_tail(tmp_path, status="confirmed")
    res = rb.lint(a, "b8")
    assert res.returncode == 1
    assert "confirmed row E-0001 cannot use a residual" in res.stdout


def test_duplicate_literal_token_refused_through_b8_cli(tmp_path):
    _root, a, _row = _residual_tail(
        tmp_path, status="confirmed",
        why="dup output:O-0002 output:O-0002", residual_rows=[])
    res = rb.lint(a, "b8")
    assert res.returncode == 1
    assert "requires exactly one qualifying token (found 2)" in res.stdout


def test_exhausted_post_plan_ordering_check_has_both_directions(tmp_path):
    # Test 1: an introduction stage that was provably an input to the b6a
    # plan derivation cannot claim exhausted_post_plan.
    root, a, _row = _residual_tail(tmp_path, outcome="exhausted_post_plan")
    a.write_register("_run/snapshots/code_b6a/output_register.md",
                     rb.OUTPUT_COLS, [rb.output_row("O-0002")])
    intro = "code_b6a:" + tokens.sha256_file(
        a.audit / "_run/snapshots/code_b6a/output_register.md")
    head = tokens.dispatch_head(a.audit)
    a.write("_run/late_severity_residuals.md",
            "# Late severity residuals\n\n"
            + rb.md_table(tokens.RESIDUAL_COLS, [[
                "E-0001", "output", "O-0002", head, intro,
                "exhausted_post_plan", "EV-0001"]]))
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    manifest["stages"]["code_b6a"] = {"status": "done", "retries": 0}
    a.write("_run/manifest.json", json.dumps(manifest, indent=2) + "\n")
    loud = lint.Lint()
    lint._residual_rows(loud, a.audit, required=True)
    assert any("already an input to the b6a plan derivation" in e
               for e in loud.errors), loud.errors
    # Test 2: a wall-clock-parallel claims-wave introduction stays eligible.
    _root, a2, _row = _residual_tail(tmp_path / "ok", outcome="exhausted_post_plan")
    quiet = lint.Lint()
    lint._residual_rows(quiet, a2.audit, required=True)
    assert quiet.errors == [], quiet.errors


def _add_residual_snapshot(a, stage):
    a.write_register(
        f"_run/snapshots/{stage}/output_register.md", rb.OUTPUT_COLS,
        [rb.output_row("O-0002")])
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    manifest["stages"][stage] = {"status": "done", "retries": 0}
    a.write("_run/manifest.json", json.dumps(manifest, indent=2) + "\n")
    return f"{stage}:" + tokens.sha256_file(
        a.audit / f"_run/snapshots/{stage}/output_register.md")


def _set_residual_intro(a, intro):
    rows = tokens.rows_for_columns(
        a.audit / "_run/late_severity_residuals.md", tokens.RESIDUAL_COLS)
    rows[0]["Target Introduction Head"] = intro
    a.write("_run/late_severity_residuals.md", (
        "# Late severity residuals\n\n" + rb.md_table(
            tokens.RESIDUAL_COLS, [[row[column] for column in tokens.RESIDUAL_COLS]
                                   for row in rows])))


@pytest.mark.u9
def test_tier1_residual_firstness_drills_later_refusal_and_earliest_pass_cli(tmp_path):
    _root, a, _row = _residual_tail(tmp_path)
    earliest = _add_residual_snapshot(a, "claims_b4")
    later = rb.lint(a, "b8")
    assert later.returncode == 1
    assert "is not the first done snapshot containing O-0002; earliest is claims_b4" in later.stdout
    _set_residual_intro(a, earliest)
    first = rb.lint(a, "b8")
    assert first.returncode == 0, first.stdout + first.stderr


@pytest.mark.u9
def test_residual_firstness_claims_wave_code_b6a_exception(tmp_path):
    _root, a, _row = _residual_tail(tmp_path)
    _add_residual_snapshot(a, "claims_b4")
    code_intro = _add_residual_snapshot(a, "code_b6a")
    _set_residual_intro(a, code_intro)
    result = rb.lint(a, "b8")
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.u9
def test_tier1_residual_firstness_test_oracle_notices_disabled_check(
        tmp_path, monkeypatch):
    _root, a, _row = _residual_tail(tmp_path)
    _add_residual_snapshot(a, "claims_b4")

    def negative_oracle():
        probe = lint.Lint()
        lint._residual_rows(probe, a.audit, required=True)
        assert any("is not the first done snapshot" in error for error in probe.errors)

    negative_oracle()
    monkeypatch.setattr(
        lint, "_first_residual_introduction",
        lambda _lint, _audit, _stages, _filename, _cols, _target_col,
        _target_id, intro_stage: intro_stage)
    with pytest.raises(AssertionError):
        negative_oracle()


def test_residual_rows_branch_refusals(tmp_path):
    root, a, _row = _residual_tail(tmp_path)
    head = tokens.dispatch_head(a.audit)
    intro = "claims_b6a:" + tokens.sha256_file(
        a.audit / "_run/snapshots/claims_b6a/output_register.md")

    def failures(residual_row):
        a.write("_run/late_severity_residuals.md",
                "# Late severity residuals\n\n"
                + rb.md_table(tokens.RESIDUAL_COLS, [residual_row]))
        probe = lint.Lint()
        lint._residual_rows(probe, a.audit, required=True)
        return probe.errors

    assert any("Target Kind must be claim/output" in e for e in failures(
        ["E-0001", "artifact", "O-0002", head, intro, "unavailable_blocked", "EV-1"]))
    assert any("Target Kind/ID disagree" in e for e in failures(
        ["E-0001", "claim", "O-0002", head, intro, "unavailable_blocked", "EV-1"]))
    assert any("dispatch head disagrees" in e for e in failures(
        ["E-0001", "output", "O-0002", "claims:0;output:0", intro,
         "unavailable_blocked", "EV-1"]))
    assert any("exhausted_attempt was not attempted" in e for e in failures(
        ["E-0001", "output", "O-0002", head, intro, "exhausted_attempt", "EV-1"]))
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    manifest["stages"]["code_b5s"] = {"status": "done", "retries": 0}
    a.write("_run/manifest.json", json.dumps(manifest, indent=2) + "\n")
    assert any("lacks exact code_b5s blocker evidence" in e for e in failures(
        ["E-0001", "output", "O-0002", head, intro, "unavailable_blocked", "EV-1"]))
    a.write_register("output_register.md", rb.OUTPUT_COLS, [])
    assert any("residual target is not live" in e for e in failures(
        ["E-0001", "output", "O-0002", head, intro, "unavailable_blocked", "EV-1"]))


# ------------------------------------------------------------- B2 extra legs


def _ra_fixture(tmp_path, *, lineage=None):
    root = tmp_path / "package"
    a = rb.AuditDir(root)
    a.write_manifest(mode="code_errors_only")
    (root / "py").mkdir(parents=True, exist_ok=True)
    (root / "py/source.py").write_text("bad = 0\n", encoding="utf-8")
    (root / "py/write.py").write_text(
        "export table artifacts/table.csv\n", encoding="utf-8")
    (root / "py/other.py").write_text("print(other)\n", encoding="utf-8")
    (root / "master.do").write_text(
        "* declares artifacts/table.csv\n", encoding="utf-8")
    identity = {
        "Terminal Kind": "table", "Path/Pattern": "artifacts/table.csv",
        "Declaration Anchor": "master.do:1", "Writer Site": "py/write.py:1",
        "Availability": "generated_unshipped",
    }
    ra_id = tokens.reported_artifact_id(identity)
    a.write("CODEMAP.md", (
        "# CODEMAP\n\n## Materials Inventory\n\n"
        + rb.md_table(["Material", "Path", "Notes"], [
            ["master script", "master.do", "master"],
            ["reported table", "artifacts/table.csv", "reported"]])
        + "\n## Reported Artifact Token Inventory\n\n"
        + rb.md_table(tokens.RA_COLS,
                      [[ra_id, *[identity[c] for c in tokens.RA_COLS[1:]]]])
        + "\nPRECONDITIONS: 5/5 yes\n"))
    token = f"artifact:{ra_id}"
    row = rb.error_row(
        "E-0001", etype="sample_filter_or_flag_error", source="`py/source.py`",
        location="py/source.py:1", status="confirmed", severity="3",
        why=f"reported impact {token}")
    a.write_register("code_error_register.md", rb.ERROR_COLS, [row])
    shard = a.audit / "_code_error_recheck/k1.md"
    probe = shard.parent / "token_probe.py"
    probe.parent.mkdir(parents=True, exist_ok=True)
    probe.write_text("pass\n", encoding="utf-8")
    sidecar = _mechanism()
    digest = tokens.obligation_digest(
        "E-0001", token, sidecar, "—", "py/source.py:1", "bad")
    ledger = rb.code_ledger_row(
        "E-0001", severity="3", proposed_severity="3",
        accepted_mechanism=sidecar, witness_ids="—")
    hops = lineage or [
        {"anchor": "py/source.py:1", "carries": "bad"},
        {"anchor": "master.do:1", "carries": "artifacts/table.csv"},
        {"anchor": "py/write.py:1", "carries": "table"},
    ]
    record = {
        "Record Type": "token_verification", "Error ID": "E-0001",
        "Token": token, "Obligation Digest": digest, "Mechanism": sidecar,
        "Witness IDs": "—", "Error Location": "py/source.py:1",
        "Flawed Identifier": "bad", "Cited Target": ra_id,
        "Lineage JSON": json.dumps(hops, separators=(",", ":")),
        "Probe Path": "token_probe.py",
        "Probe Output SHA256": tokens.result_digest(0, b"", b""),
        "Verdict": "verified", "Derived From Receipt ID": "—",
    }
    body = rb.register_text("Recheck ledger", rb.CODE_LEDGER_COLS, [ledger])
    body += "\n### Token verification records\n\n"
    body += rb.md_table(tokens.TOKEN_RECORD_COLS, [
        [record[column] for column in tokens.TOKEN_RECORD_COLS]])
    a.write("_code_error_recheck/k1.md", body)
    return root, a, row, token


def test_ra_lineage_terminates_through_writer_and_declaration(tmp_path):
    root, a, _row, _token = _ra_fixture(tmp_path)
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    verified, failures = tokens.verify_token_records(
        root, a.audit, manifest, "code_b6a")
    assert failures == [] and len(verified) == 1


def test_ra_lineage_ending_at_bare_path_is_refused_and_gate_caps(tmp_path):
    root, a, row, _token = _ra_fixture(tmp_path, lineage=[
        {"anchor": "py/source.py:1", "carries": "bad"},
        {"anchor": "py/other.py:1", "carries": "other"},
    ])
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    _verified, failures = tokens.verify_token_records(
        root, a.audit, manifest, "code_b6a")
    assert any("RA lineage must terminate through writer and declaration"
               in f for f in failures)
    # continuation: with no issuable receipt the b6 gate is cap-or-fail
    tokens.write_atomic(tokens.receipt_path(a.audit, "code_b6a"),
                        tokens.render_receipts([]))
    classifications, gate_failures = tokens.gate_rows(
        root, a.audit, manifest, [dict(zip(rb.ERROR_COLS, row))], "code_b6a")
    assert classifications == {"E-0001": "invalid"}
    assert any("requires exactly one verifier token receipt" in f
               for f in gate_failures)


def test_claim_lineage_endpoint_must_be_recorded_location(tmp_path):
    root, a, _row, record = _token_fixture(tmp_path, token="claim:C-0001")
    a.write_register("claims_register.md", rb.CLAIMS_COLS,
                     [rb.claims_row("C-0001", source="`py/table.py`")])
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    verified, failures = tokens.verify_token_records(
        root, a.audit, manifest, "code_b6a")
    assert failures == [] and len(verified) == 1
    a.write_register("claims_register.md", rb.CLAIMS_COLS,
                     [rb.claims_row("C-0001", source="`py/other.py`")])
    _verified, failures = tokens.verify_token_records(
        root, a.audit, manifest, "code_b6a")
    assert any("claim lineage endpoint is not its recorded location" in f
               for f in failures)


# ----------------------------------------------------------- B3 hold + wiring


def test_hold_ruling_certifies_and_applies_only_status_severity(tmp_path):
    root, a, manifest = _rulings_fixture(tmp_path)
    frozen = rulings.snapshot_stage(root, a.audit, manifest)
    a.write("_run/severity_token_rulings.json", json.dumps({
        "schema": "severity_token_rulings/v1", "cycle": "main",
        "b7_certification_sha256": frozen["b7_certification_sha256"],
        "rulings": [{
            "error_id": "E-0001", "token": "output:O-0001",
            "b7_verdict": "rejected", "ruling": "hold",
            "resulting_status": "confirmation_needed", "resulting_severity": 2,
            "rationale": "await terminal evidence", "decision_identity": "operator-1",
        }],
    }, indent=2) + "\n")
    rulings.apply_rulings(root, a.audit, manifest)
    _decisions, failures = rulings.validate_rulings(
        root, a.audit, manifest, require_applied=True)
    assert failures == []
    register = tokens._load_register_error_rows(a.audit)
    assert register["E-0001"]["Status"] == "confirmation_needed"
    assert register["E-0001"]["Severity"] == "2"


# ----------------------------------------------- §8/§11 dispatch and worklist


def test_pin_dispatch_inputs_cli_and_b4_contract(tmp_path):
    root = tmp_path / "package"
    a = rb.AuditDir(root)
    a.write_manifest(mode="replication", stages={
        "code_b4": {"status": "running", "retries": 0},
        "claims_b3": {"status": "done", "retries": 0},
    })
    a.write_register("claims_register.md", rb.CLAIMS_COLS, [])
    a.write_register("output_register.md", rb.OUTPUT_COLS, [])
    plan = a.audit / "plans/code_error_recheck_plan.md"
    a.write("plans/code_error_recheck_plan.md", "# Code recheck plan\n")
    res = rb.run_script("severity_tokens.py", "pin-dispatch-inputs", root,
                        "--audit-dir", a.audit)
    assert res.returncode == 0, res.stdout + res.stderr
    head = tokens.dispatch_head(a.audit)
    assert f"Severity-token dispatch input head: {head}" in plan.read_text(
        encoding="utf-8")
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    quiet = lint.Lint()
    lint._token_dispatch_contract(quiet, a.audit, manifest, plan)
    assert quiet.errors == []
    manifest["stages"]["claims_b3"]["status"] = "running"
    loud = lint.Lint()
    lint._token_dispatch_contract(loud, a.audit, manifest, plan)
    assert any("lint-green claims_b3" in e for e in loud.errors)
    manifest["stages"]["claims_b3"]["status"] = "done"
    plan.write_text("# Code recheck plan\n", encoding="utf-8")
    missing = lint.Lint()
    lint._token_dispatch_contract(missing, a.audit, manifest, plan)
    assert any("missing exact digest-pinned line" in e for e in missing.errors)


def test_b3_warns_on_tokenless_severe_row_and_stays_quiet_with_token(tmp_path):
    def run(why):
        a = rb.AuditDir(tmp_path / why[:8].replace(":", "_"))
        a.write_manifest()
        a.write("plans/code_error_review_plan.md", rb._code_b1_plan())
        row = rb.error_row("E-0101", status="candidate", severity="3", why=why)
        a.write_register("code_error_register.md", rb.ERROR_COLS, [row],
                         title="Code-error register")
        a.write("_run/merge_report_code.json",
                '{"code_error_register.md": {"shard_rows": 1, "dedup_removed": 0, '
                '"added": 1, "conflicts": [], "coverage_gaps": [], '
                '"blocked_shards": []}}')
        a.write("_code_errors/k1.md",
                "| Script | Outcome |\n| --- | --- |\n"
                "| `py/x.py` | findings: E-0101 |\n")
        return rb.lint(a, "b3-code")

    warned = run("a consequence with no token")
    assert "severity-token: E-0101" in warned.stdout
    quiet = run("impact output:O-0001")
    assert "severity-token:" not in quiet.stdout


def test_expected_code_token_obligations_derives_discovery_late_split(tmp_path):
    root = tmp_path / "package"
    a = rb.AuditDir(root)
    a.write_manifest(mode="replication")
    a.write_register("claims_register.md", rb.CLAIMS_COLS, [])
    a.write_register("output_register.md", rb.OUTPUT_COLS,
                     [rb.output_row("O-0005")])
    a.write_register("code_error_register.md", rb.ERROR_COLS, [])
    a.write_register("_run/snapshots/code_b5_dispatch/claims_register.md",
                     rb.CLAIMS_COLS, [])
    a.write_register("_run/snapshots/code_b5_dispatch/output_register.md",
                     rb.OUTPUT_COLS, [])
    rows = [
        dict(zip(rb.ERROR_COLS, rb.error_row(
            "E-0010", status="confirmed", severity="3",
            why="late tie output:O-0005"))),
        dict(zip(rb.ERROR_COLS, rb.error_row(
            "E-0011", status="confirmed", severity="3",
            why="severe split descendant"))),
    ]
    summary_text = "# summary\n\n" + rb.md_table(
        lint.LINEAGE_COLS, [["E-0009", "E-0011", "DU", "S-1", "W-1"]])
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    reasons, parents = lint._expected_code_token_obligations(
        lint.Lint(), a.audit, manifest, rows, {"E-9000", "O-9000"},
        Path("summary.md"), summary_text)
    assert reasons == {"E-9000": {"discovery"}, "E-0010": {"late_token"},
                       "E-0011": {"split_token"}}
    assert parents == {"E-0011": "E-0009"}


# --------------------------------------------------- §14 plants and the scorer


def _severity_plant_audit(tmp_path, *, arm_b_severity="2",
                          arm_b_status="confirmed", with_receipt=True):
    root = tmp_path / "package"
    a = rb.AuditDir(root)
    a.write_manifest(mode="replication")
    token = "output:O-0300"
    rows = [
        rb.error_row("E-0301", status="confirmed", severity="3",
                     desc="income_pc divides by age_head, not household size",
                     why=f"feeds the reported Table 2 means {token}"),
        rb.error_row("E-0302", status=arm_b_status, severity=arm_b_severity,
                     desc="wage_pc divides by age_head and is never read"),
        rb.error_row("E-0303", status="confirmed", severity="2",
                     desc="crop_pc divides by age_head; village mean only printed"),
    ]
    a.write_register("code_error_register.md", rb.ERROR_COLS, rows)
    a.write_register("output_register.md", rb.OUTPUT_COLS,
                     [rb.output_row("O-0300", obj="Table 2",
                                    location="`paper/paper.tex:70`")])
    receipts = []
    if with_receipt:
        digest = "a" * 64
        receipts = [{
            "Receipt ID": tokens.receipt_id("E-0301", token, digest),
            "Error ID": "E-0301", "Token": token, "Obligation Digest": digest,
            "Probe Path": "token_probe.py",
            "Probe Output SHA256": "b" * 64, "Verdict": "verified",
        }]
    tokens.write_atomic(a.audit / "_run/code_b6b/token_receipts.md",
                        tokens.render_receipts(receipts))
    return a.audit


def test_scorer_severity_plants_pass_and_enforce_bands_and_receipt(tmp_path):
    expected = json.loads(sf.DEFAULT_EXPECTED.read_text(encoding="utf-8"))
    assert [item["id"] for item in expected["severity_token_plants"]] == [
        "P-27", "P-28", "P-29"]
    audit = _severity_plant_audit(tmp_path / "good")
    status, note = sf.check_severity_token_plants(audit, expected)
    assert status == "PASS", note
    # arm (b) band binds regardless of status: confirmation_needed at 3 fails
    audit = _severity_plant_audit(tmp_path / "band", arm_b_severity="3",
                                  arm_b_status="confirmation_needed")
    status, note = sf.check_severity_token_plants(audit, expected)
    assert status == "FAIL" and "regardless of status" in note
    # arm (a) without its verifier receipt fails
    audit = _severity_plant_audit(tmp_path / "receipt", with_receipt=False)
    status, note = sf.check_severity_token_plants(audit, expected)
    assert status == "FAIL" and "verifier token receipt" in note
