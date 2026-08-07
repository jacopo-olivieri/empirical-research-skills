"""U14 register lints and severity.

Two rules, one per issue:

* the closed reason-type vocabulary for `not_rowed_observation` typed-footer
  entries (issue #19) — a value rule on the existing `Reason` cell, enforced
  inside `typed_shard_footer` so every shard-lint call site inherits it;
* the severity-4 target-type join (issue #24) — one read-only join inside
  `severity_tokens.gate_rows`'s classification loop, so b6a, b6b, bC, b8 and
  b9 inherit it through the two existing wrappers.
"""

import json

import pytest

import regbuild as rb


lint = rb.load_script("lint_registers")
tokens = rb.load_script("severity_tokens")
mechanism = rb.load_script("mechanism_schema")
certify = rb.load_script("certify_stage")
rulings = rb.load_script("severity_token_rulings")

pytestmark = pytest.mark.u14


# --------------------------------------------------------------------------
# #19 — the closed reason-type vocabulary
# --------------------------------------------------------------------------

BAD_REASONS = [
    "the cull gate never fires for missing weights",   # label-less judgment
    "other: probe budget exhausted",                   # escape label
    "tooling:",                                        # empty payload
]
GOOD_REASONS = [
    "tooling: csvcut crashed on wide_ledger.csv",
    "scope: is legacy/ in my task?",
    "id_exhaustion: ID range exhausted",
]
NON_CANONICAL_EXHAUSTION = "id_exhaustion: ran out of IDs"
OLD_BARE_EXHAUSTION = "ID range exhausted"


def footer_table(entries):
    return rb.md_table(lint.FOOTER_COLS, entries)


def note_entry(reason, index=1):
    return [f"OBS-{index:04d}", "not_rowed_observation", "", "an observation",
            reason]


def footer_errors(reason, *, stream="claims", recheck=False):
    """Run the shared typed-footer check over one note entry."""
    state = lint.Lint()
    text = footer_table([note_entry(reason)])
    if stream == "code" and not recheck:
        text += "\n" + rb.md_table(lint.COVERAGE_COLS, [["`py/x.py`", "clean"]])
    if not recheck:
        # U15: the non-recheck footer carries the phase table as its third part.
        text += "\n" + rb.phase_table_text()
    lint.typed_shard_footer(state, "shard.md", text, stream, recheck=recheck)
    return state.errors


@pytest.mark.parametrize("reason", BAD_REASONS + [NON_CANONICAL_EXHAUSTION,
                                                  OLD_BARE_EXHAUSTION])
@pytest.mark.parametrize("stream", ["claims", "code"])
def test_illegal_note_reason_fails_the_typed_footer(reason, stream):
    errors = footer_errors(reason, stream=stream)
    assert errors, f"{reason!r} was accepted"
    assert any("OBS-0001" in error for error in errors)


def test_escape_label_and_judgment_note_name_the_three_legal_labels():
    for reason in ("the cull gate never fires for missing weights",
                   "other: probe budget exhausted"):
        message = " ".join(footer_errors(reason))
        assert "tooling: " in message
        assert "scope: " in message
        assert "id_exhaustion: " in message
        assert "candidate register row" in message


def test_non_canonical_exhaustion_payload_is_exact_matched():
    message = " ".join(footer_errors(NON_CANONICAL_EXHAUSTION))
    assert lint.ID_EXHAUSTION_REASON in message
    assert "exactly" in message


@pytest.mark.parametrize("reason", GOOD_REASONS)
@pytest.mark.parametrize("stream", ["claims", "code"])
def test_legal_note_reasons_pass(reason, stream):
    assert footer_errors(reason, stream=stream) == []


def test_all_three_labels_together_pass_beside_a_candidate():
    state = lint.Lint()
    entries = [note_entry(reason, index) for index, reason
               in enumerate(GOOD_REASONS, start=1)]
    entries.append(["OBS-0004", "candidate", "C-0801", "a defect", ""])
    lint.typed_shard_footer(
        state, "shard.md",
        footer_table(entries) + "\n" + rb.phase_table_text(["C-0801"]),
        "claims")
    assert state.errors == []


def test_recheck_context_footer_accepts_labeled_notes_beside_empty_candidate():
    state = lint.Lint()
    entries = [note_entry(reason, index) for index, reason
               in enumerate(GOOD_REASONS, start=1)]
    entries.append(["OBS-0004", "candidate", "", "a defect", ""])
    lint.typed_shard_footer(state, "shard.md", footer_table(entries), "code",
                            recheck=True)
    assert state.errors == []


def test_blank_reason_still_reports_the_one_line_rule_only():
    errors = footer_errors("")
    assert len(errors) == 1
    assert "requires a one-line Reason" in errors[0]


def _b2_code_shard(tmp_path, reason):
    """A synthetic b2 code shard whose only footer note carries *reason*."""
    a = rb.AuditDir(tmp_path)
    a.write_manifest()
    a.write("plans/code_error_review_plan.md", rb._code_b1_plan())
    text = rb.md_table(rb.ERROR_COLS, [])
    text += "\n### Coverage\n\n"
    text += rb.md_table(lint.COVERAGE_COLS, [["`py/x.py`", "clean"]])
    text += "\n### Footer dispositions\n\n" + footer_table([note_entry(reason)])
    text += "\n### Reading phase\n\n" + rb.phase_table_text()
    return a, a.write("_code_errors/k1.md", text)


def test_tier1_drill_b2_code_shard_lint_cli_stops_on_a_judgment_note(tmp_path):
    # The #19 operator-named drill: the judgment note the run-8 merge dismissed
    # in one line must now stop the production shard lint by name.
    a, shard = _b2_code_shard(tmp_path / "planted",
                              "the cull gate never fires for missing weights")
    planted = rb.lint(a, "b2-code", shard)
    assert planted.returncode == 1, planted.stdout + planted.stderr
    assert "OBS-0001" in planted.stdout
    assert "candidate register row" in planted.stdout
    clean, clean_shard = _b2_code_shard(tmp_path / "clean", GOOD_REASONS[0])
    passed = rb.lint(clean, "b2-code", clean_shard)
    assert passed.returncode == 0, passed.stdout + passed.stderr


def test_tier1_drill_test_oracle_notices_a_neutered_prefix_check(monkeypatch):
    # Test 3: with the prefix check neutered to "accept any non-empty Reason",
    # every Test-1 assertion above must fail.
    monkeypatch.setattr(lint, "footer_reason_failure",
                        lambda reason: None)
    for reason in BAD_REASONS + [NON_CANONICAL_EXHAUSTION,
                                 OLD_BARE_EXHAUSTION]:
        assert footer_errors(reason) == [], f"{reason!r} still refused"


def test_b3b_shard_lint_inherits_the_reason_rule(tmp_path):
    # A second call site of the single owner, through the production CLI.
    a, shard = rb.make_b3b_shard(tmp_path / "b3b", "code", error_rows=[])
    note = " | ".join(note_entry(OLD_BARE_EXHAUSTION))
    # Append the note row to the typed-observations table, which the U15
    # phase and block tables now follow.
    original = shard.read_text(encoding="utf-8")
    anchor = "| " + " | ".join(lint.FOOTER_COLS) + " |"
    head, sep, tail = original.partition(anchor)
    table_end = tail.index("\n\n") + 1
    shard.write_text(
        head + sep + tail[:table_end] + f"| {note} |\n" + tail[table_end:],
        encoding="utf-8")
    failed = rb.lint(a, "b3b-code", shard)
    assert failed.returncode == 1, failed.stdout + failed.stderr
    assert "OBS-0001" in failed.stdout
    assert "candidate register row" in failed.stdout


# --------------------------------------------------------------------------
# #24 — the severity-4 target-type join
# --------------------------------------------------------------------------

CLAIM_ROWS = [
    rb.claims_row("C-0801", ctype="quantitative_result", used="TRUE",
                  text="the training program raised certified-welder wages "
                       "by 14 percent",
                  source="`py/table.py`", outputs="O-0801"),
    rb.claims_row("C-0802", ctype="robustness", used="TRUE",
                  text="the wage effect is robust to dropping the smallest "
                       "cohort",
                  source="`py/table.py`", outputs="O-0802"),
    rb.claims_row("C-0803", ctype="quantitative_result", used="FALSE",
                  text="an appendix-only wage decomposition",
                  source="`py/table.py`", outputs="O-0804"),
    rb.claims_row("C-0804", ctype="quantitative_result", used="TRUE",
                  text="the certified-welder cohort grew by 320 trainees",
                  source="`py/table.py`", outputs="O-0805"),
    rb.claims_row("C-0805", ctype="robustness", used="TRUE",
                  text="the cohort count is stable across the two intake files",
                  source="`py/table.py`", outputs="O-0805"),
]
OUTPUT_ROWS = [
    rb.output_row("O-0801", script="`py/table.py`", claims="C-0801"),
    rb.output_row("O-0802", script="`py/table.py`", claims="C-0802"),
    rb.output_row("O-0803", script="`py/table.py`", claims=""),
    rb.output_row("O-0804", script="`py/table.py`", claims="C-0803"),
    rb.output_row("O-0805", script="`py/table.py`", claims="C-0804; C-0805"),
]


def _mechanism_sidecar():
    return mechanism.canonicalize_mechanism(
        "sample_filter_or_flag_error", "bad", "wrong_value", "1", "0",
        register="code_errors", anchor="py/source.py:1",
        projection=mechanism.EMPTY_PROJECTION,
    ).sidecar


def _full_mode_fixture(tmp_path, *, error_id, severity, token,
                       claim_rows=None, output_rows=None):
    """A full-mode audit dir with one severe-eligible row and a live receipt."""
    root = tmp_path / "package"
    a = rb.AuditDir(root)
    a.write_manifest(mode="replication")
    (root / "py").mkdir(parents=True, exist_ok=True)
    (root / "py/source.py").write_text("bad = 0\n", encoding="utf-8")
    (root / "py/table.py").write_text("print(bad)\n", encoding="utf-8")
    row = rb.error_row(
        error_id, etype="sample_filter_or_flag_error",
        source="`py/source.py`; `py/table.py`", location="py/source.py:1",
        status="confirmed", severity=severity,
        why=f"reported impact {token}")
    a.write_register("code_error_register.md", rb.ERROR_COLS, [row])
    a.write_register("claims_register.md", rb.CLAIMS_COLS,
                     list(CLAIM_ROWS if claim_rows is None else claim_rows))
    a.write_register("output_register.md", rb.OUTPUT_COLS,
                     list(OUTPUT_ROWS if output_rows is None else output_rows))
    probe = a.audit / "_code_error_recheck/token_probe.py"
    probe.parent.mkdir(parents=True, exist_ok=True)
    probe.write_text("pass\n", encoding="utf-8")
    sidecar = _mechanism_sidecar()
    digest = tokens.obligation_digest(
        error_id, token, sidecar, "—", "py/source.py:1", "bad")
    ledger = rb.code_ledger_row(
        error_id, severity=severity, proposed_severity=severity,
        accepted_mechanism=sidecar, witness_ids="—")
    record = {
        "Record Type": "token_verification", "Error ID": error_id,
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
    return root, a, row


def _issue_receipts(root, a, stage="code_b6a"):
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    receipts, failures = tokens.verify_token_records(
        root, a.audit, manifest, stage)
    assert failures == [], failures
    tokens.write_atomic(
        tokens.receipt_path(a.audit, stage), tokens.render_receipts(receipts))
    return receipts


def _gate(tmp_path, *, error_id, severity, token, stage="code_b6a",
          claim_rows=None, output_rows=None):
    root, a, row = _full_mode_fixture(
        tmp_path, error_id=error_id, severity=severity, token=token,
        claim_rows=claim_rows, output_rows=output_rows)
    _issue_receipts(root, a, stage)
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    return tokens.gate_rows(root, a.audit, manifest,
                            [dict(zip(rb.ERROR_COLS, row))], stage)


JOIN_FAILURES = [
    # (error id, severity, token, distinctive substring of the refusal)
    ("E-0802", "4", "claim:C-0802", "quantitative_result trace target"),
    ("E-0803", "4", "output:O-0802", "no live, reciprocal, text-used"),
    ("E-0804", "4", "output:O-0803", "cross-links to no claim"),
    ("E-0806", "4", "output:O-0804", "no live, reciprocal, text-used"),
]
JOIN_QUIET = [
    ("E-0801", "4", "claim:C-0801"),
    ("E-0805", "4", "output:O-0801"),
    ("E-0807", "4", "output:O-0805"),
    ("E-0808", "3", "claim:C-0802"),
]


@pytest.mark.parametrize("error_id,severity,token,detail", JOIN_FAILURES)
def test_severity_four_join_refuses_a_non_qualifying_target(
        tmp_path, error_id, severity, token, detail):
    classifications, failures = _gate(
        tmp_path, error_id=error_id, severity=severity, token=token)
    assert classifications == {error_id: "live"}
    matched = [failure for failure in failures
               if failure.startswith(f"{error_id}: {token} ")]
    assert matched, failures
    assert detail in matched[0]


@pytest.mark.parametrize("error_id,severity,token", JOIN_QUIET)
def test_severity_four_join_stays_quiet_on_a_qualifying_target(
        tmp_path, error_id, severity, token):
    classifications, failures = _gate(
        tmp_path, error_id=error_id, severity=severity, token=token)
    assert failures == [], failures
    assert classifications == {error_id: "live"}


def test_mixed_cross_link_set_needs_only_one_qualifying_claim(tmp_path):
    # O-0805 links C-0804 (quantitative_result) and C-0805 (robustness).  An
    # all-linked-claims-must-qualify implementation would refuse this row.
    _classifications, failures = _gate(
        tmp_path, error_id="E-0807", severity="4", token="output:O-0805")
    assert failures == []


def test_output_reciprocity_is_required_in_both_directions(tmp_path):
    # O-0801 still names C-0801, but C-0801 no longer names O-0801.
    one_way = [rb.claims_row("C-0801", ctype="quantitative_result",
                             used="TRUE", source="`py/table.py`", outputs="")]
    _classifications, failures = _gate(
        tmp_path, error_id="E-0805", severity="4", token="output:O-0801",
        claim_rows=one_way + list(CLAIM_ROWS[1:]))
    assert any("no live, reciprocal, text-used" in failure
               for failure in failures), failures


def test_duplicate_of_cross_linked_claim_does_not_qualify(tmp_path):
    tombstoned = [rb.claims_row(
        "C-0801", ctype="quantitative_result", used="TRUE",
        source="`py/table.py`", outputs="O-0801", status="duplicate_of:C-0804")]
    _classifications, failures = _gate(
        tmp_path, error_id="E-0805", severity="4", token="output:O-0801",
        claim_rows=tombstoned + list(CLAIM_ROWS[1:]))
    assert any("no live, reciprocal, text-used" in failure
               for failure in failures), failures


def test_target_not_live_severity_four_row_keeps_its_special_routing(tmp_path):
    root, a, row = _full_mode_fixture(
        tmp_path, error_id="E-0802", severity="4", token="claim:C-0802")
    _issue_receipts(root, a)
    # drop the target after the receipt was issued
    a.write_register("claims_register.md", rb.CLAIMS_COLS, list(CLAIM_ROWS[2:]))
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    classifications, failures = tokens.gate_rows(
        root, a.audit, manifest, [dict(zip(rb.ERROR_COLS, row))], "code_b6a")
    assert classifications == {"E-0802": "target_not_live"}
    assert failures == [], failures


def test_join_is_inherited_by_every_gate_stage(tmp_path):
    for index, stage in enumerate(("code_b6a", "code_b6b")):
        _classifications, failures = _gate(
            tmp_path / f"stage{index}", error_id="E-0802", severity="4",
            token="claim:C-0802", stage=stage)
        assert any("quantitative_result trace target" in failure
                   for failure in failures), (stage, failures)


def test_tier1_join_test_oracle_notices_a_disabled_severity_four_branch(
        tmp_path, monkeypatch):
    # Test 3: neuter the join (never return a failed condition).  One leg per
    # failure class — claim type, cross-link, and the code-errors-only cap.
    monkeypatch.setattr(tokens, "severity_four_target_failure",
                        lambda *args, **kwargs: None)
    for index, (error_id, severity, token, _detail) in enumerate(JOIN_FAILURES):
        _classifications, failures = _gate(
            tmp_path / f"neutered{index}", error_id=error_id,
            severity=severity, token=token)
        assert failures == [], (error_id, failures)
    root, a, row = _ra_fixture(tmp_path / "neutered-ra", severity="4")
    _issue_receipts(root, a)
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    _classifications, failures = tokens.gate_rows(
        root, a.audit, manifest, [dict(zip(rb.ERROR_COLS, row))], "code_b6a")
    assert failures == [], failures


# ------------------------------------------------ code-errors-only RA cap


def _ra_fixture(tmp_path, *, severity, error_id="E-0811"):
    root = tmp_path / "package"
    a = rb.AuditDir(root)
    a.write_manifest(mode="code_errors_only")
    (root / "py").mkdir(parents=True, exist_ok=True)
    (root / "py/source.py").write_text("bad = 0\n", encoding="utf-8")
    (root / "py/write.py").write_text(
        "export table artifacts/table.csv\n", encoding="utf-8")
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
        error_id, etype="sample_filter_or_flag_error", source="`py/source.py`",
        location="py/source.py:1", status="confirmed", severity=severity,
        why=f"reported impact {token}")
    a.write_register("code_error_register.md", rb.ERROR_COLS, [row])
    probe = a.audit / "_code_error_recheck/token_probe.py"
    probe.parent.mkdir(parents=True, exist_ok=True)
    probe.write_text("pass\n", encoding="utf-8")
    sidecar = _mechanism_sidecar()
    digest = tokens.obligation_digest(
        error_id, token, sidecar, "—", "py/source.py:1", "bad")
    ledger = rb.code_ledger_row(
        error_id, severity=severity, proposed_severity=severity,
        accepted_mechanism=sidecar, witness_ids="—")
    record = {
        "Record Type": "token_verification", "Error ID": error_id,
        "Token": token, "Obligation Digest": digest, "Mechanism": sidecar,
        "Witness IDs": "—", "Error Location": "py/source.py:1",
        "Flawed Identifier": "bad", "Cited Target": ra_id,
        "Lineage JSON": json.dumps([
            {"anchor": "py/source.py:1", "carries": "bad"},
            {"anchor": "master.do:1", "carries": "artifacts/table.csv"},
            {"anchor": "py/write.py:1", "carries": "table"},
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
    return root, a, row


def _ra_gate(tmp_path, severity, error_id):
    root, a, row = _ra_fixture(tmp_path, severity=severity, error_id=error_id)
    _issue_receipts(root, a)
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    return tokens.gate_rows(root, a.audit, manifest,
                            [dict(zip(rb.ERROR_COLS, row))], "code_b6a")


def test_severity_three_ra_receipt_stays_quiet(tmp_path):
    _classifications, failures = _ra_gate(tmp_path, "3", "E-0811")
    assert failures == [], failures


def test_severity_four_ra_receipt_is_capped(tmp_path):
    _classifications, failures = _ra_gate(tmp_path, "4", "E-0812")
    assert any("severity 4 is unavailable in code-errors-only mode" in failure
               for failure in failures), failures


# ------------------------------------------------------ production-CLI drills


def _severity_four_tail(tmp_path, token="output:O-0801", error_id="E-0801"):
    """A completed full-mode tail whose one severe row is Severity 4."""
    root, a, row = _full_mode_fixture(
        tmp_path, error_id=error_id, severity="4", token=token)
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
            f"{error_id} {token}", token.split(":", 1)[1], "upheld",
            "py/table.py:1",
        ]])))
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    frozen = rulings.snapshot_stage(root, a.audit, manifest)
    a.write("_run/severity_token_rulings.json", json.dumps({
        "schema": "severity_token_rulings/v1", "cycle": "main",
        "b7_certification_sha256": frozen["b7_certification_sha256"],
        "skip_reason": "zero_rejected_severity_tokens", "rulings": [],
    }, indent=2) + "\n")
    rulings.apply_rulings(root, a.audit, manifest)
    a.write_register("_run/snapshots/b8/claims_register.md", rb.CLAIMS_COLS,
                     list(CLAIM_ROWS))
    a.write_register("_run/snapshots/b8/code_error_register.md", rb.ERROR_COLS,
                     [row])
    claims_cols, claims_rows = rb.rewrite_pass_cols(
        rb.CLAIMS_COLS, list(CLAIM_ROWS), ["Issue Description"])
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


def _set_claim_type(a, claim_id, claim_type):
    """Retype one `Claim Type` cell in every copy of the claims register."""
    for path in a.audit.rglob("claims_register.md"):
        rows = []
        for line in path.read_text(encoding="utf-8").split("\n"):
            cells = line.split(" | ")
            if line.startswith(f"| {claim_id} |") and len(cells) > 4:
                cells[4] = claim_type
                line = " | ".join(cells)
            rows.append(line)
        path.write_text("\n".join(rows), encoding="utf-8")


def test_tier1_drill_final_partition_cli_flips_both_directions(tmp_path):
    # The join reaches final validation through `_final_token_partition`.
    # A severity-4 row whose claim target is `robustness` must stop the b8
    # production CLI; retyping the Claim Type cell must clear the stop; and
    # putting it back must return it.
    root, a = _severity_four_tail(tmp_path, token="output:O-0802",
                                  error_id="E-0803")
    stopped = rb.lint(a, "b8")
    assert stopped.returncode == 1, stopped.stdout + stopped.stderr
    assert "quantitative_result trace target" in stopped.stdout
    assert "output:O-0802" in stopped.stdout
    _set_claim_type(a, "C-0802", "quantitative_result")
    cleared = rb.lint(a, "b8")
    assert cleared.returncode == 0, cleared.stdout + cleared.stderr
    _set_claim_type(a, "C-0802", "robustness")
    returned = rb.lint(a, "b8")
    assert returned.returncode == 1
    assert "quantitative_result trace target" in returned.stdout


def test_tier1_drill_receipt_gate_home_stops_the_same_row(tmp_path):
    # The other wrapper: `_token_receipt_gate`.  The same severity-4 fixture
    # must stop there too, proving the join is not final-partition-only.
    root, a, row = _full_mode_fixture(
        tmp_path, error_id="E-0802", severity="4", token="claim:C-0802")
    _issue_receipts(root, a, "code_b6a")
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    state = lint.Lint()
    lint._token_receipt_gate(state, a.audit, manifest,
                             [dict(zip(rb.ERROR_COLS, row))], "code_b6a")
    assert any("quantitative_result trace target" in error
               for error in state.errors), state.errors
    quiet = lint.Lint()
    _set_claim_type(a, "C-0802", "quantitative_result")
    lint._token_receipt_gate(quiet, a.audit, manifest,
                             [dict(zip(rb.ERROR_COLS, row))], "code_b6a")
    assert quiet.errors == [], quiet.errors
