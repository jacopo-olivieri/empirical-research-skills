"""Tests for lint_registers.py.

Includes the failing-first contract test for the U1 advisory adjudication
heuristic (KTD-1). No committed fixture run artifacts exist (``fixture/``
holds only the planted package and scorecards), so lintable boundaries are
built synthetically via ``regbuild``.
"""

import json

import pytest

import regbuild as rb


def warning_lines(res, token):
    return [ln for ln in res.stdout.splitlines()
            if ln.startswith("WARNING") and token in ln]


# ------------------------------------------------------------ harness sanity


def test_b0_green_on_empty_registers(tmp_path):
    a = rb.make_b0(tmp_path)
    res = rb.lint(a, "b0")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "LINT PASS [b0]" in res.stdout


def test_b0_red_on_nonempty_register(tmp_path):
    a = rb.make_b0(tmp_path)
    a.write_register("claims_register.md", rb.CLAIMS_COLS,
                     [rb.claims_row("C-0101")])
    res = rb.lint(a, "b0")
    assert res.returncode == 1
    assert "must be empty at b0" in res.stdout


def test_b6_claims_green_on_clean_rows(tmp_path):
    """The b6-claims builder produces a boundary the current linter passes."""
    rows = [
        rb.claims_row("C-0101", status="confirmed"),
        rb.claims_row("C-0102", status="blocked",
                      blocked_check="The raw data is restricted-access."),
    ]
    a = rb.make_b6_claims(tmp_path, rows)
    res = rb.lint(a, "b6-claims")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "LINT PASS [b6-claims]" in res.stdout


def test_b6_claims_red_on_blocked_without_blocked_check(tmp_path):
    """Negative sanity: the harness surfaces a real lint failure."""
    rows = [rb.claims_row("C-0101", status="blocked", blocked_check="")]
    a = rb.make_b6_claims(tmp_path, rows)
    res = rb.lint(a, "b6-claims")
    assert res.returncode == 1
    assert "Blocked Check" in res.stdout


# ----------------------------- U3 manifest worker-shard integrity (R10)


def _b3b_manifest_boundary(tmp_path, stream, *, workers,
                           stage_present=True, stage_status="done",
                           shards_present=True, populated_shards=False):
    """A clean no-shard b3b merge with configurable manifest evidence."""
    a = rb.AuditDir(tmp_path)
    key = f"{stream}_b3b"
    entry = {"status": stage_status, "retries": 0}
    if shards_present:
        shard_path = ("audit/_work_second_read/w1.md" if stream == "claims"
                      else "audit/_code_errors_second_read/w1.md")
        entry["shards"] = ({shard_path: {"status": "done", "retries": 0}}
                           if populated_shards else {})
    a.write_manifest(stages={key: entry} if stage_present else {})
    if stream == "claims":
        plan = (
            "# Claims second-read plan\n\n"
            "| Worker ID | File/Section Scope | Shard File | Claim ID Range | Output ID Range | Reason | Known Findings | Assigned Handoff IDs |\n"
            "| --- | --- | --- | --- | --- | --- | --- | --- |\n"
        )
        if workers:
            plan += (
                f"| W1 | sec 4 — `{rb.CLAIMS_SPAN_PATH}:{rb.CLAIMS_SPAN[0]}–"
                f"{rb.CLAIMS_SPAN[1]}` | `audit/_work_second_read/w1.md` | "
                "C-2000–C-2099 | O-2000–O-2099 | flagged | C-0142 | — |\n"
            )
        a.write("plans/claims_second_read_plan.md", plan)
        a.write_claims_plan()
        files = ["claims_register.md", "output_register.md"]
        a.write_register("_staging/claims_register.md", rb.CLAIMS_COLS, [])
        a.write_register("_staging/output_register.md", rb.OUTPUT_COLS, [])
        # post-promotion canon: the b3b lint reads promoted evidence, not staging
        a.write_register("claims_register.md", rb.CLAIMS_COLS, [])
        a.write_register("output_register.md", rb.OUTPUT_COLS, [])
        report = {
            name: {"shard_rows": 0, "dedup_removed": 0, "added": 0}
            for name in files
        }
        report["footer_dispositions"] = []
        report.update(rb.report_phase_fields(
            blocks=(1, 1) if (workers and populated_shards) else (0, 0)))
        report_name = "merge_report_claims_b3b.json"
        if workers and populated_shards:
            shard_text = rb.md_table(rb.CLAIMS_COLS, []) + "\n" + rb.md_table(
                rb.OUTPUT_COLS, [])
            shard_text += (
                "\nCoverage: assigned section fully reread.\n\n"
                "| Entry ID | Kind | Register IDs | Observation | Reason |\n"
                "| --- | --- | --- | --- | --- |\n\n"
                + rb.phase_table_text()
                + "\n"
                + rb.block_table_text([
                    (f"`{rb.CLAIMS_SPAN_PATH}`",
                     f"{rb.CLAIMS_SPAN[0]}–{rb.CLAIMS_SPAN[1]}",
                     "assigned section", "clean")])
            )
            a.write("_work_second_read/w1.md", shard_text)
    else:
        plan = (
            "# Code-error second-read plan\n\n"
            "| Worker ID | Script Scope | Shard File | Error ID Range | Reason | Known Findings | Assigned Handoff IDs |\n"
            "| --- | --- | --- | --- | --- | --- | --- |\n"
        )
        if workers:
            plan += (
                "| W1 | `py/x.py` | `audit/_code_errors_second_read/w1.md` | "
                "E-2000–E-2099 | flagged | E-0142 | — |\n"
            )
        a.write("plans/code_error_second_read_plan.md", plan)
        a.write(
            "plans/code_error_review_plan.md",
            "# Code-error review plan\n\n"
            "| Chunk ID | Script Scope | Error ID Range | Shard File |\n"
            "| --- | --- | --- | --- |\n"
            "| K1 | `py/x.py` | E-0100–E-0999 | `audit/_code_errors/k1.md` |\n\n"
            "Merge-coordinator range: E-9000–E-9099\n",
        )
        files = ["code_error_register.md"]
        a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [])
        a.write_register("code_error_register.md", rb.ERROR_COLS, [])
        report = {
            "code_error_register.md": {
                "shard_rows": 0, "dedup_removed": 0, "added": 0,
            },
            "footer_dispositions": [],
        }
        report.update(rb.report_phase_fields(
            blocks=(1, 1) if (workers and populated_shards) else (0, 0)))
        report_name = "merge_report_code_b3b.json"
        if workers and populated_shards:
            rb.write_code_scope(a, rb.CODE_SCOPE_PATH, rb.CODE_SCOPE_LINES)
            shard_text = rb.md_table(rb.ERROR_COLS, [])
            shard_text += (
                "\n| Script | Outcome |\n| --- | --- |\n| `py/x.py` | clean |\n\n"
                "| Entry ID | Kind | Register IDs | Observation | Reason |\n"
                "| --- | --- | --- | --- | --- |\n\n"
                + rb.phase_table_text()
                + "\n"
                + rb.block_table_text([
                    (f"`{rb.CODE_SCOPE_PATH}`", f"1–{rb.CODE_SCOPE_LINES}",
                     "module body", "clean")])
            )
            a.write("_code_errors_second_read/w1.md", shard_text)
    a.snapshot(key, files)
    a.write(f"_run/{report_name}", json.dumps(report))
    return a


def _b6_manifest_boundary(tmp_path, stream, *, workers,
                          stage_present=True, stage_status="done",
                          shards_present=True, populated_shards=False):
    """A clean b6 merge whose recheck plan has zero or one cluster."""
    inventory = [("C-0101" if stream == "claims" else "E-0101",
                  "issue-flagged", "static")] if workers else []
    shard = ("`audit/_recheck/k1.md`" if stream == "claims"
             else "`audit/_code_error_recheck/k1.md`")
    clusters = [("K1", "cluster one", inventory[0][0], shard)] if workers else []
    if stream == "claims":
        a = rb.make_b6_claims(tmp_path, [])
        plan_name = "plans/claims_recheck_plan.md"
    else:
        a = rb.make_b6_code(
            tmp_path, before_rows=[], final_rows=[], inventory=inventory,
            clusters=clusters, mappings=[], ledger_rows=[],
        )
        plan_name = "plans/code_error_recheck_plan.md"
    a.write(plan_name, rb.recheck_plan_text(stream, inventory, clusters))
    key = f"{stream}_b5"
    entry = {"status": stage_status, "retries": 0}
    if shards_present:
        shard_path = ("audit/_recheck/k1.md" if stream == "claims"
                      else "audit/_code_error_recheck/k1.md")
        entry["shards"] = ({shard_path: {"status": "done", "retries": 0}}
                           if populated_shards else {})
    a.write_manifest(stages={key: entry} if stage_present else {})
    return a


@pytest.mark.parametrize("stage", [
    "b3b-code", "b3b-claims", "b6-code", "b6-claims",
])
@pytest.mark.parametrize("shards_present", [True, False], ids=["empty", "absent"])
def test_done_worker_stage_rejects_empty_manifest_shards(
        tmp_path, stage, shards_present):
    boundary, stream = stage.split("-")
    maker = _b3b_manifest_boundary if boundary == "b3b" else _b6_manifest_boundary
    a = maker(tmp_path, stream, workers=True, shards_present=shards_present)
    res = rb.lint(a, stage)

    assert res.returncode == 1
    manifest_key = f"{stream}_{'b3b' if boundary == 'b3b' else 'b5'}"
    assert manifest_key in res.stdout
    assert "1 planned worker" in res.stdout


@pytest.mark.parametrize("stage", [
    "b3b-code", "b3b-claims", "b6-code", "b6-claims",
])
def test_planned_worker_stage_requires_manifest_entry(tmp_path, stage):
    boundary, stream = stage.split("-")
    maker = _b3b_manifest_boundary if boundary == "b3b" else _b6_manifest_boundary
    a = maker(tmp_path, stream, workers=True, stage_present=False)

    res = rb.lint(a, stage)

    assert res.returncode == 1
    manifest_key = f"{stream}_{'b3b' if boundary == 'b3b' else 'b5'}"
    assert manifest_key in res.stdout
    assert "1 planned worker" in res.stdout


@pytest.mark.parametrize("stage", [
    "b3b-code", "b3b-claims", "b6-code", "b6-claims",
])
@pytest.mark.parametrize("shards_present", [True, False], ids=["empty", "absent"])
def test_running_worker_stage_rejects_empty_manifest_shards(
        tmp_path, stage, shards_present):
    boundary, stream = stage.split("-")
    maker = _b3b_manifest_boundary if boundary == "b3b" else _b6_manifest_boundary
    a = maker(
        tmp_path, stream, workers=True, stage_status="running",
        shards_present=shards_present,
    )

    res = rb.lint(a, stage)

    assert res.returncode == 1
    manifest_key = f"{stream}_{'b3b' if boundary == 'b3b' else 'b5'}"
    assert manifest_key in res.stdout
    assert "1 planned worker" in res.stdout


@pytest.mark.parametrize("stage", [
    "b3b-code", "b3b-claims", "b6-code", "b6-claims",
])
def test_running_worker_stage_accepts_populated_manifest_shards(tmp_path, stage):
    boundary, stream = stage.split("-")
    maker = _b3b_manifest_boundary if boundary == "b3b" else _b6_manifest_boundary
    a = maker(
        tmp_path, stream, workers=True, stage_status="running",
        populated_shards=True,
    )

    res = rb.lint(a, stage)

    assert res.returncode == 0, res.stdout + res.stderr


@pytest.mark.parametrize("stage", [
    "b3b-code", "b3b-claims", "b6-code", "b6-claims",
])
@pytest.mark.parametrize("manifest_shape", ["missing-stage", "absent", "empty"])
def test_worker_stage_allows_empty_shards_when_plan_has_no_workers(
        tmp_path, stage, manifest_shape):
    boundary, stream = stage.split("-")
    maker = _b3b_manifest_boundary if boundary == "b3b" else _b6_manifest_boundary
    a = maker(
        tmp_path, stream, workers=False,
        stage_present=manifest_shape != "missing-stage",
        shards_present=manifest_shape != "absent",
    )
    res = rb.lint(a, stage)

    assert res.returncode == 0, res.stdout + res.stderr


@pytest.mark.parametrize("stage", [
    "b3b-code", "b3b-claims", "b6-code", "b6-claims",
])
def test_done_worker_stage_accepts_populated_manifest_shards(tmp_path, stage):
    boundary, stream = stage.split("-")
    maker = _b3b_manifest_boundary if boundary == "b3b" else _b6_manifest_boundary
    a = maker(tmp_path, stream, workers=True, populated_shards=True)
    res = rb.lint(a, stage)

    assert res.returncode == 0, res.stdout + res.stderr


# ------------------------------------------- U1 advisory heuristic (pinned)


def test_adjudication_advisory_warning_contract(tmp_path):
    """CONTRACT pinned for U1 (remove the xfail marker when implementing).

    The recommendation-1 advisory heuristic (plan KTD-1 / U1):

    * Runs wherever a *final* claims register is linted — the recheck-merge
      and finalize boundaries, i.e. ``--stage b6-claims`` and ``--stage b8``
      (this test exercises b6-claims).
    * For every claims row whose Status is ``confirmed`` or ``blocked``, the
      linter scans that row's own Issue Description and Blocked Check text
      for contradiction language (a small token set documented inline in
      lint_registers.py, e.g. "whereas", "but the code", "instead",
      "does not match", "should be", "contradicts").
    * A negated mention must NOT fire: "nothing visible confirms or
      contradicts the claim" is a clean blocked row, not a flagged one.
    * The warning is ADVISORY — it never changes the exit code. It surfaces
      as one WARNING line per flagged row, in the linter's existing warning
      format, containing the literal token ``adjudication`` and the flagged
      Claim ID. Suggested shape:

        WARNING [b6-claims]: adjudication: C-0101 (blocked) — Blocked Check
        contains contradiction language ('whereas'); review against the
        escalation rule (registers.md)

      This test asserts only the stable parts: line starts with "WARNING",
      contains "adjudication" and the row ID.
    """
    rows = [
        # (a) blocked row whose Blocked Check records a paper-vs-code
        #     contradiction -> WARNING expected
        rb.claims_row(
            "C-0101", status="blocked",
            blocked_check=(
                "The paper states the estimates use a one-in-ten subsample "
                "whereas the shipped README shows households.csv is a "
                "1-in-20 subsample."
            ),
        ),
        # (b) cleanly-closed confirmed row, no discrepancy language -> silent
        rb.claims_row(
            "C-0102", status="confirmed",
            text="the sample contains 4,832 households",
        ),
        # (c) confirmed row whose Issue Description records a discrepancy
        #     -> WARNING expected
        rb.claims_row(
            "C-0103", status="confirmed", severity="2",
            issue=("The code does not match the stated definition of the "
                   "sample window."),
        ),
        # (d) blocked row whose Blocked Check states only a missing input,
        #     with a negated contradiction mention -> silent
        rb.claims_row(
            "C-0104", status="blocked",
            blocked_check=("The raw survey data is restricted-access; "
                           "nothing visible confirms or contradicts the "
                           "claim."),
        ),
    ]
    a = rb.make_b6_claims(tmp_path, rows)
    res = rb.lint(a, "b6-claims")

    # advisory: the stage still passes
    assert res.returncode == 0, res.stdout + res.stderr

    warns = warning_lines(res, "adjudication")
    assert any("C-0101" in ln for ln in warns), \
        f"no adjudication warning for C-0101 in:\n{res.stdout}"
    assert any("C-0103" in ln for ln in warns), \
        f"no adjudication warning for C-0103 in:\n{res.stdout}"
    assert not any("C-0102" in ln for ln in warns), \
        f"spurious adjudication warning for clean confirmed row C-0102:\n{res.stdout}"
    assert not any("C-0104" in ln for ln in warns), \
        f"spurious adjudication warning for clean blocked row C-0104:\n{res.stdout}"


# ------------------------------- U2 conventions artifact (advisory, b4-code)


def test_conventions_artifact_absent_is_silent(tmp_path):
    """No b3c artifact (a package with no multi-site convention) -> no
    conventions warning, and the check never contributes an error."""
    a = rb.make_conventions_b4_code(tmp_path, include_artifact=False)
    res = rb.lint(a, "b4-code")
    assert not warning_lines(res, "conventions.md"), res.stdout


def test_conventions_artifact_wellformed_is_silent(tmp_path):
    """A well-formed artifact with in-vocabulary categories warns about
    nothing."""
    rows = [
        rb.conventions_row("fiscal-year boundary"),
        rb.conventions_row(
            "household ID key", category="id_or_merge_key",
            definition="merge on hhid (C-0210)",
            sites="`do/merge.do`; C-0210; C-0233"),
    ]
    a = rb.make_conventions_b4_code(tmp_path, rows)
    res = rb.lint(a, "b4-code")
    assert not warning_lines(res, "conventions.md"), res.stdout


def test_conventions_artifact_enumerated_member_list_is_silent(tmp_path):
    """The U1 category `enumerated_member_list` is in-vocabulary: a row using
    it (even single-site, per the U1 carve-out) draws no warning."""
    rows = [
        rb.conventions_row(
            "income components list", category="enumerated_member_list",
            definition='members "crop sales; livestock sales; wages" (C-0310)',
            sites="C-0310"),
    ]
    a = rb.make_conventions_b4_code(tmp_path, rows)
    res = rb.lint(a, "b4-code")
    assert not warning_lines(res, "conventions.md"), res.stdout


def test_conventions_artifact_bad_category_warns(tmp_path):
    """An out-of-vocabulary Category draws an advisory warning, never a fail."""
    rows = [rb.conventions_row("mystery thing", category="not_a_real_category")]
    a = rb.make_conventions_b4_code(tmp_path, rows)
    res = rb.lint(a, "b4-code")
    warns = warning_lines(res, "conventions.md")
    assert any("out-of-vocabulary Category" in ln for ln in warns), res.stdout
    assert any("mystery thing" in ln for ln in warns), res.stdout


def test_conventions_artifact_wrong_header_warns(tmp_path):
    """A file present but not the expected table warns (advisory) so the grep
    step knows it may be skipped; still never a hard fail from this check."""
    a = rb.make_conventions_b4_code(tmp_path, include_artifact=False)
    a.write("_run/conventions.md",
            "# Conventions\n\n| Foo | Bar |\n| --- | --- |\n| x | y |\n")
    res = rb.lint(a, "b4-code")
    assert any("expected header" in ln for ln in warning_lines(res, "conventions.md")), \
        res.stdout


# ---------------------- U2 definition/use handoffs (b4-code and b6-code)


def _definition_use_b4(tmp_path, *, bundle_ids=("DU-aaa111",), mappings=None,
               evidence=None, include_artifact=True):
    mappings = mappings if mappings is not None else [
        (bid, "E-0101", "new_candidate") for bid in bundle_ids]
    evidence = evidence if evidence is not None else "; ".join(bundle_ids)
    errors = [rb.error_row("E-0101", status="candidate", severity="2",
                           etype="sample_filter_or_flag_error")]
    return rb.make_b4(
        tmp_path, "code", canon_errors=errors,
        inventory=[("E-0101", "definition/use candidate", evidence)],
        clusters=[("K1", "definition/use", "E-0101",
                   "`audit/_code_error_recheck/k1.md`")],
        bundle_ids=bundle_ids, mappings=mappings,
        include_definition_use_artifact=include_artifact,
    )


def test_b4_code_no_longer_reads_definition_use_artifact(tmp_path):
    a = _definition_use_b4(tmp_path, bundle_ids=(), mappings=[],
                   include_artifact=False)
    res = rb.lint(a, "b4-code")
    assert res.returncode == 0


def test_b4_code_explicit_empty_definition_use_artifact_passes(tmp_path):
    row = rb.error_row("E-0101", status="confirmed", severity="1")
    a = rb.make_b4(
        tmp_path, "code", canon_errors=[row],
        inventory=[("E-0101", "sampled", "static source")],
        clusters=[("K1", "sample", "E-0101",
                   "`audit/_code_error_recheck/k1.md`")],
        bundle_ids=[], mappings=[],
    )
    res = rb.lint(a, "b4-code")
    assert res.returncode == 0, res.stdout + res.stderr


def test_b4_code_leaves_raw_artifact_validation_to_b3d(tmp_path):
    a = _definition_use_b4(tmp_path)
    path = a.audit / "_run" / "definition_use_bundles.md"
    path.write_text(path.read_text().replace(
        "- Standard candidates: 1", "- Standard candidates: 2"))

    res = rb.lint(a, "b4-code")

    assert res.returncode == 0


def test_b4_code_accepts_real_zero_bundle_emitter_artifact(tmp_path):
    """Integration: b4 parses the committed emitter's actual empty artifact."""
    row = rb.error_row("E-0101", status="confirmed", severity="1")
    a = rb.make_b4(
        tmp_path, "code", canon_errors=[row],
        inventory=[("E-0101", "sampled", "static source")],
        clusters=[("K1", "sample", "E-0101",
                   "`audit/_code_error_recheck/k1.md`")],
    )
    package = tmp_path / "package"
    (package / "do").mkdir(parents=True)
    (package / "do" / "analysis.do").write_text("summarize wage\n")
    emitted = rb.run_script(
        "emit_definition_use_bundles.py", package, "--audit-dir", a.audit)
    assert emitted.returncode == 0, emitted.stdout + emitted.stderr
    res = rb.lint(a, "b4-code")
    assert res.returncode == 0, res.stdout + res.stderr


@pytest.mark.parametrize("mappings, evidence, token", [
    ([('DU-aaa111', 'E-0999', 'new_candidate')], "DU-aaa111", "absent from the b4 inventory"),
    ([('DU-aaa111', 'E-0101', 'new_candidate')], "static source", "Likely Evidence"),
])
def test_b4_code_rejects_broken_definition_use_handoff(tmp_path, mappings, evidence, token):
    a = _definition_use_b4(tmp_path, mappings=mappings, evidence=evidence)
    res = rb.lint(a, "b4-code")
    assert res.returncode == 1
    assert token in res.stdout


def test_b4_code_rejects_longer_prefix_in_inventory_evidence(tmp_path):
    a = _definition_use_b4(tmp_path, evidence="checked DU-aaa1114")
    res = rb.lint(a, "b4-code")
    assert res.returncode == 1
    assert "Likely Evidence" in res.stdout and "DU-aaa111" in res.stdout


@pytest.mark.parametrize("etype, status, token", [
    ("aggregation_or_unit_error", "candidate", "sample_filter_or_flag_error"),
    ("sample_filter_or_flag_error", "confirmed", "must be a candidate"),
])
def test_b4_code_new_candidate_mapping_enforces_row_shape(
        tmp_path, etype, status, token):
    a = _definition_use_b4(tmp_path)
    a.write_register(
        "code_error_register.md", rb.ERROR_COLS,
        [rb.error_row("E-0101", etype=etype, status=status, severity="2")])
    res = rb.lint(a, "b4-code")
    assert res.returncode == 1
    assert token in res.stdout


def _definition_use_b6(tmp_path, *, verdict="confirmed_error", final_status="confirmed",
               evidence="checked DU-aaa111 at do/build_panel.do:20",
               extra_ledger=(), bundle_ids=("DU-aaa111",)):
    before = [rb.error_row("E-0101", status="candidate", severity="2",
                           etype="sample_filter_or_flag_error")]
    final = [rb.error_row("E-0101", status=final_status,
                          severity="" if final_status == "not_error" else "2",
                          etype="sample_filter_or_flag_error")]
    ledger = rb.ledger_row("E-0101", evidence=evidence, verdict=verdict)
    return rb.make_b6_code(
        tmp_path, before_rows=before, final_rows=final,
        inventory=[("E-0101", "definition/use", "; ".join(bundle_ids))],
        clusters=[("K1", "definition/use", "E-0101",
                   "`audit/_code_error_recheck/k1.md`")],
        mappings=[(bid, "E-0101", "new_candidate") for bid in bundle_ids],
        ledger_rows=[ledger, *extra_ledger],
    )


def test_b6_code_accepts_complete_definition_use_handoff(tmp_path):
    a = _definition_use_b6(tmp_path)
    res = rb.lint(a, "b6-code")
    assert res.returncode == 0, res.stdout + res.stderr


@pytest.mark.parametrize("stage", ["b4-code", "b6-code"])
def test_many_definition_use_bundles_may_map_to_one_canonical_error(tmp_path, stage):
    bundle_ids = ("DU-aaa111", "DU-bbb222")
    evidence = "checked DU-aaa111 and DU-bbb222"
    if stage == "b4-code":
        a = _definition_use_b4(tmp_path, bundle_ids=bundle_ids, evidence=evidence)
    else:
        a = _definition_use_b6(tmp_path, bundle_ids=bundle_ids, evidence=evidence)

    res = rb.lint(a, stage)
    assert res.returncode == 0, res.stdout + res.stderr


@pytest.mark.parametrize("stage", ["b4-code", "b6-code"])
@pytest.mark.parametrize("omitted", ["DU-aaa111", "DU-bbb222"])
def test_many_to_one_definition_use_handoff_requires_every_bundle_in_evidence(
        tmp_path, stage, omitted):
    bundle_ids = ("DU-aaa111", "DU-bbb222")
    present = next(bid for bid in bundle_ids if bid != omitted)
    evidence = f"checked {present}"
    if stage == "b4-code":
        a = _definition_use_b4(tmp_path, bundle_ids=bundle_ids, evidence=evidence)
    else:
        a = _definition_use_b6(tmp_path, bundle_ids=bundle_ids, evidence=evidence)

    res = rb.lint(a, stage)
    assert res.returncode == 1
    assert omitted in res.stdout


def test_b6_code_requires_bundle_id_in_evidence_checked(tmp_path):
    a = _definition_use_b6(tmp_path, evidence="checked do/build_panel.do:20")
    res = rb.lint(a, "b6-code")
    assert res.returncode == 1
    assert "DU-aaa111" in res.stdout and "Evidence Checked" in res.stdout


def test_b6_code_rejects_longer_prefix_in_evidence_checked(tmp_path):
    a = _definition_use_b6(tmp_path, evidence="checked DU-aaa1114")
    res = rb.lint(a, "b6-code")
    assert res.returncode == 1
    assert "DU-aaa111" in res.stdout and "Evidence Checked" in res.stdout


def test_b6_code_requires_unique_disposition(tmp_path):
    duplicate = rb.ledger_row("E-0101", evidence="DU-aaa111",
                              verdict="confirmed_error")
    a = _definition_use_b6(tmp_path, extra_ledger=[duplicate])
    res = rb.lint(a, "b6-code")
    assert res.returncode == 1
    assert "exactly one disposition" in res.stdout


def test_b6_code_requires_ledger_final_status_agreement(tmp_path):
    a = _definition_use_b6(tmp_path, verdict="not_error", final_status="confirmed")
    res = rb.lint(a, "b6-code")
    assert res.returncode == 1
    assert "verdict 'not_error'" in res.stdout and "final status 'confirmed'" in res.stdout


@pytest.mark.parametrize("explicit", [True, False])
def test_b6_code_unmapped_target_is_not_a_guarded_derived_duplicate(tmp_path, explicit):
    before = [
        rb.error_row("E-0101", status="candidate", severity="2",
                     etype="sample_filter_or_flag_error"),
        rb.error_row("E-0102", status="confirmed", severity="2",
                     etype="sample_filter_or_flag_error"),
    ]
    final = [
        rb.error_row("E-0101", status="duplicate_of:E-0102", severity="",
                     etype="sample_filter_or_flag_error"),
        before[1],
    ]
    ledger = rb.ledger_row(
        "E-0101", evidence="DU-aaa111", verdict="confirmed_error",
        change=("set status=duplicate_of:E-0102" if explicit else "merge duplicate"))
    a = rb.make_b6_code(
        tmp_path, before_rows=before, final_rows=final,
        inventory=[("E-0101", "definition/use", "DU-aaa111")],
        clusters=[("K1", "definition/use", "E-0101",
                   "`audit/_code_error_recheck/k1.md`")],
        mappings=[("DU-aaa111", "E-0101", "existing_row")],
        ledger_rows=[ledger],
    )
    res = rb.lint(a, "b6-code")
    assert res.returncode == 1
    assert "verdict 'confirmed_error' requires final status 'confirmed'" in res.stdout


def test_b6_code_duplicate_rejects_not_error_verdict(tmp_path):
    before = [
        rb.error_row("E-0101", status="candidate", severity="2",
                     etype="sample_filter_or_flag_error"),
        rb.error_row("E-0102", status="confirmed", severity="2",
                     etype="sample_filter_or_flag_error"),
    ]
    final = [
        rb.error_row("E-0101", status="duplicate_of:E-0102", severity="",
                     etype="sample_filter_or_flag_error"),
        before[1],
    ]
    ledger = rb.ledger_row(
        "E-0101", evidence="DU-aaa111", verdict="not_error",
        change="set status=duplicate_of:E-0102")
    a = rb.make_b6_code(
        tmp_path, before_rows=before, final_rows=final,
        inventory=[("E-0101", "definition/use", "DU-aaa111")],
        clusters=[("K1", "definition/use", "E-0101",
                   "`audit/_code_error_recheck/k1.md`")],
        mappings=[("DU-aaa111", "E-0101", "existing_row")],
        ledger_rows=[ledger],
    )
    res = rb.lint(a, "b6-code")
    assert res.returncode == 1
    assert "verdict 'not_error' requires final status 'not_error'" in res.stdout
    assert "lacks qualifying receipt coverage" in res.stdout


# --------------------- U4 identifier-anchoring advisory (b5-claims ledger)
#
# KTD-3: the advisory reads the recheck ledger's `Evidence Checked` column,
# never the claims register's own row (a confirmed register row has no
# evidence column — comparing identifiers against it would fire on nearly
# every clean row). The claim's *text* comes from the canonical claims
# register at ``audit/claims_register.md``, keyed by the ledger row's ID.
# Advisory only: one WARNING per flagged row, exit status never changed.
# Fixture domain: an education-panel package (fresh, non-Floods surface).


def _anchoring_b5(tmp_path, *, claim_text, evidence,
                  verdict="not_substantiated",
                  change="set Status=confirmed",
                  note="", with_register=True):
    """A b5-claims boundary: one rechecked claim row closing `confirmed`."""
    row = rb.ledger_row(
        "C-0101", status="confirmed", severity="", evidence=evidence,
        verdict=verdict, change=change, impact="none", note=note)
    a, shard = rb.make_b5(tmp_path, "claims", ledger_rows=[row])
    if with_register:
        a.write_register(
            "claims_register.md", rb.CLAIMS_COLS,
            [rb.claims_row("C-0101", text=claim_text)],
            title="Claims register")
    return a, shard


def test_anchoring_named_identifier_in_evidence_is_silent(tmp_path):
    """A confirmed close whose evidence names the claimed identifier draws
    no anchoring warning."""
    a, shard = _anchoring_b5(
        tmp_path,
        claim_text=("the score index `test_score_std` is standardized to "
                    "mean zero within each cohort"),
        evidence=("`code/build_scores.R:41-44` standardizes test_score_std "
                  "within cohort; recomputed mean is 0 at shown precision"),
    )
    res = rb.lint(a, "b5-claims", shard=shard)
    assert res.returncode == 0, res.stdout + res.stderr
    assert not warning_lines(res, "anchoring"), res.stdout


def test_anchoring_named_identifier_absent_warns(tmp_path):
    """A confirmed close whose evidence never mentions the claimed identifier
    draws exactly one anchoring warning naming the row — and the warning is
    advisory (exit status unchanged)."""
    a, shard = _anchoring_b5(
        tmp_path,
        claim_text=("the panel drops teachers with `teacher_tenure_yrs` "
                    "below two years"),
        evidence=("verified the drop filter exists at `code/build_panel.R:88` "
                  "and covers the tenure block"),
    )
    res = rb.lint(a, "b5-claims", shard=shard)
    # advisory: never changes the stage exit status
    assert res.returncode == 0, res.stdout + res.stderr
    warns = warning_lines(res, "anchoring")
    assert len(warns) == 1, res.stdout
    assert "C-0101" in warns[0], res.stdout
    assert "teacher_tenure_yrs" in warns[0], res.stdout


def test_anchoring_line_number_only_evidence_warns(tmp_path):
    """PINNED DECISION — the main false-positive path.

    Evidence that cites only a file:line range without repeating the named
    identifier WARNS. Rationale: the evidence-discipline rule already
    requires exact anchors, and the anchoring norm requires each named
    identifier located *at its claimed role* — an anchor that names the
    identifier is the compliant form, so a line-number-only citation is
    exactly the case a human should re-read. Consistent with the U1 advisory
    philosophy: the lexical proxy over-matches by design; advisory noise is
    acceptable, a silent miss is not (the warning never fails the stage).
    """
    a, shard = _anchoring_b5(
        tmp_path,
        claim_text=("the panel drops teachers with `teacher_tenure_yrs` "
                    "below two years"),
        evidence=("`code/build_panel.R:88-93` applies the described drop "
                  "filter; output row count matches the paper"),
    )
    res = rb.lint(a, "b5-claims", shard=shard)
    assert res.returncode == 0, res.stdout + res.stderr
    warns = warning_lines(res, "anchoring")
    assert len(warns) == 1 and "C-0101" in warns[0], res.stdout


def test_anchoring_scoped_to_confirmed_closes_only(tmp_path):
    """A row NOT closing `confirmed` (here `confirmation_needed`) is out of
    scope even when its evidence omits the named identifier — this also pins
    that the 'confirmed' detector does not fire on 'confirmation_needed'."""
    a, shard = _anchoring_b5(
        tmp_path,
        claim_text=("the panel drops teachers with `teacher_tenure_yrs` "
                    "below two years"),
        evidence="static read of `code/build_panel.R:88` could not decide",
        verdict="confirmation_needed",
        change="set Status=confirmation_needed",
        note="cannot decide statically; needs the shipped panel",
    )
    res = rb.lint(a, "b5-claims", shard=shard)
    assert res.returncode == 0, res.stdout + res.stderr
    assert not warning_lines(res, "anchoring"), res.stdout


# ------------- U5 filename-parameter advisory (b8 finalize, blocked rows)
#
# KTD-4: the reconciliation lint is advisory, blocked-rows-only, and
# pattern-shaped, never magnitude-shaped — it compares only tokens of the
# SAME syntactic shape (a ratio composite against a ratio composite, a
# keyed parameter composite against one sharing the same alpha key). The
# crude any-numeric-mismatch version is explicitly rejected: filenames carry
# incidental years, versions, and resolutions, and claim text is dense with
# estimates and sample sizes. It attaches at finalize (``--stage b8``),
# alongside the U1 adjudication advisory; U4's anchoring advisory sits at
# b5 — this one reads the final claims register. Advisory only: WARNING
# lines carrying the literal token ``filename-parameter``, exit status
# never changed. Fixture domain: a customs-records / pollution-grid package
# (fresh, non-Floods surface).


def _fp_b8(tmp_path, *, claim_text, source, status="blocked",
           blocked_check=""):
    """A b8 boundary with one claims row for the filename-parameter check."""
    row = rb.claims_row("C-0101", status=status, text=claim_text,
                        source=source, blocked_check=blocked_check)
    a = rb.make_b8(tmp_path, claims_rows=[row])
    return a


def test_fp_builder_boundary_is_green(tmp_path):
    """Sanity: the make_b8 boundary itself lints green (so any warning the
    U5 scenarios observe comes from the advisory, not builder breakage)."""
    a = _fp_b8(
        tmp_path,
        claim_text="the sample contains 4,832 registered importers",
        source="`data/importers_panel.csv`",
        status="confirmed",
    )
    res = rb.lint(a, "b8")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "LINT PASS [b8]" in res.stdout


def test_fp_blocked_ratio_mismatch_warns(tmp_path):
    """A blocked row whose claim states a ratio parameter (spelled out) and
    whose cited filename encodes a DIFFERENT ratio of the same shape draws
    exactly one filename-parameter warning naming the row — and the warning
    is advisory (exit status unchanged)."""
    a = _fp_b8(
        tmp_path,
        claim_text=("the placebo estimates use a one-in-ten subsample of "
                    "the customs transaction records"),
        source="`data/customs_sample_1in20.csv`",
        blocked_check=("raw customs microdata is restricted-access; the "
                       "shipped filename `data/customs_sample_1in20.csv` "
                       "remains visible"),
    )
    res = rb.lint(a, "b8")
    assert res.returncode == 0, res.stdout + res.stderr
    warns = warning_lines(res, "filename-parameter")
    assert len(warns) == 1, res.stdout
    assert "C-0101" in warns[0], res.stdout


def test_fp_blocked_ratio_agreement_is_silent(tmp_path):
    """A blocked row whose claim and cited filename state the SAME ratio
    (spelled-out words normalized to digits before comparison) draws no
    warning — this also pins the number-word normalization."""
    a = _fp_b8(
        tmp_path,
        claim_text=("the placebo estimates use a one in twenty subsample "
                    "of the customs transaction records"),
        source="`data/customs_sample_1in20.csv`",
        blocked_check=("raw customs microdata is restricted-access; the "
                       "shipped filename `data/customs_sample_1in20.csv` "
                       "remains visible"),
    )
    res = rb.lint(a, "b8")
    assert res.returncode == 0, res.stdout + res.stderr
    assert not warning_lines(res, "filename-parameter"), res.stdout


def test_fp_incidental_year_and_version_are_silent(tmp_path):
    """GUARDS THE MAIN FALSE-POSITIVE PATH (KTD-4). A blocked row whose
    cited filename carries an incidental year and a version token unrelated
    to any claimed parameter draws no warning: a bare year has no syntactic
    key to compare, and a `v3` composite has no `v`-keyed counterpart in the
    claim — tokens of different shapes are never compared."""
    a = _fp_b8(
        tmp_path,
        claim_text=("the placebo estimates use a one-in-ten subsample of "
                    "the customs transaction records"),
        source="`data/customs_2019_v3.csv`",
        blocked_check=("raw customs microdata is restricted-access; the "
                       "shipped filename `data/customs_2019_v3.csv` "
                       "remains visible"),
    )
    res = rb.lint(a, "b8")
    assert res.returncode == 0, res.stdout + res.stderr
    assert not warning_lines(res, "filename-parameter"), res.stdout


def test_fp_non_blocked_row_is_never_examined(tmp_path):
    """A NON-blocked row is out of scope even when its claim and cited
    filename carry mismatching same-shape tokens (the sweep's reading-side
    rule handles open rows; the lint is a blocked-row tripwire only)."""
    a = _fp_b8(
        tmp_path,
        claim_text=("the placebo estimates use a one-in-ten subsample of "
                    "the customs transaction records"),
        source="`data/customs_sample_1in20.csv`",
        status="unclear",
    )
    res = rb.lint(a, "b8")
    assert res.returncode == 0, res.stdout + res.stderr
    assert not warning_lines(res, "filename-parameter"), res.stdout


def test_fp_keyed_composite_mismatch_warns(tmp_path):
    """A blocked row whose claim states a keyed parameter composite (`10km`)
    and whose cited filename encodes a different value under the SAME alpha
    key (`25km`) warns; the shared key is what licenses the comparison."""
    a = _fp_b8(
        tmp_path,
        claim_text=("monitor readings are gridded at a 10km resolution "
                    "before aggregation"),
        source="`data/pollution_grid_25km.csv`",
        blocked_check=("the gridding script is not shipped; the shipped "
                       "filename `data/pollution_grid_25km.csv` remains "
                       "visible"),
    )
    res = rb.lint(a, "b8")
    assert res.returncode == 0, res.stdout + res.stderr
    warns = warning_lines(res, "filename-parameter")
    assert len(warns) == 1 and "C-0101" in warns[0], res.stdout


# --------------- SC-01 overlap-conflict advisory (b7) — line-range parser
#
# Plan 2026-07-07-001 (SC-01), U5/U6: a deterministic advisory at b7 that
# warns when a confirmed claim's cited code location overlaps a confirmed
# error's cited Code Location without the pair being linked and listed as a
# status conflict. Ranged-only matching: a bare file citation contributes no
# range and never overlaps (whole-file coverage is the b7 worker rule's job).
# Advisory only: WARNING lines carrying the literal token ``overlap-conflict``,
# exit status never changed.

_lm = rb._lint_mod


def test_line_ranges_colon_form():
    assert _lm.code_line_ranges("`do/build_panel.do:21-23`") == [
        ("do/build_panel.do", (21, 23))]


def test_line_ranges_space_l_form():
    assert _lm.code_line_ranges("do/build_panel.do L21-23") == [
        ("do/build_panel.do", (21, 23))]


def test_line_ranges_multi_range_and_en_dash():
    assert _lm.code_line_ranges("`do/analysis.do:11,16–20`") == [
        ("do/analysis.do", (11, 11)), ("do/analysis.do", (16, 20))]


def test_line_ranges_bare_file_contributes_none():
    """Ranged-only matching (KTD-4): no line spec -> no range, never overlaps."""
    assert _lm.code_line_ranges("`README.md`") == []
    assert _lm.code_line_ranges("`do/build_panel.do`; see also the README") == []


def test_line_ranges_single_line_and_reversed():
    assert _lm.code_line_ranges("do/x.do:5") == [("do/x.do", (5, 5))]
    # reversed bounds are normalized, not treated as non-overlapping
    assert _lm.code_line_ranges("do/x.do:9-7") == [("do/x.do", (7, 9))]


def test_line_ranges_multiple_files_in_one_cell():
    assert _lm.code_line_ranges("`do/a.do:1-2`; `do/b.do:4`") == [
        ("do/a.do", (1, 2)), ("do/b.do", (4, 4))]


def test_line_ranges_prose_after_colon_is_not_a_citation():
    """A colon followed by prose (space before the number) is not a line spec;
    treating it as one would break ranged-only semantics on bare citations."""
    assert _lm.code_line_ranges("`do/clean.do`: 3 variables are dropped") == []
    assert _lm.code_line_ranges("do/clean.do: 3 variables are dropped") == []


def test_line_ranges_backticked_path_with_lines_outside():
    """Worker drift form: backticks around the path only, lines outside."""
    assert _lm.code_line_ranges("`do/x.do`:21-23") == [("do/x.do", (21, 23))]


# ------------- SC-01 overlap-conflict advisory — pure pair computation


def _oc(claim_source, err_location, *, claim_status="confirmed",
        err_status="confirmed"):
    claims = [rb.claims_row("C-0014", source=claim_source, status=claim_status)]
    errors = [rb.error_row("E-0151", location=err_location, status=err_status)]
    return _lm.overlapping_confirmed_pairs(claims, errors)


def test_overlap_pairs_positive_c0014_e0151():
    assert _oc("`do/build_panel.do:21-23`", "`do/build_panel.do:20-23`") == [
        ("C-0014", "E-0151")]


def test_overlap_pairs_same_file_disjoint_ranges_silent():
    assert _oc("`do/build_panel.do:21-23`", "`do/build_panel.do:30-35`") == []


def test_overlap_pairs_distinct_files_silent():
    assert _oc("`do/build_panel.do:21-23`", "`do/merge.do:21-23`") == []


def test_overlap_pairs_bare_file_never_matches():
    assert _oc("`do/build_panel.do`", "`do/build_panel.do:20-23`") == []


def test_overlap_pairs_requires_confirmed_on_both_sides():
    assert _oc("`do/build_panel.do:21-23`", "`do/build_panel.do:20-23`",
               claim_status="inconsistent") == []
    assert _oc("`do/build_panel.do:21-23`", "`do/build_panel.do:20-23`",
               err_status="candidate") == []


def test_overlap_pairs_read_error_code_location_not_source():
    """The error side parses the ranged Code Location column; the error
    Code/Data Source cell (a bare script path) must not silence the pair."""
    claims = [rb.claims_row("C-0014", source="`py/make_figures.py:4-6`")]
    errors = [rb.error_row("E-0151")]  # default: source bare, location `:5`
    assert _lm.overlapping_confirmed_pairs(claims, errors) == [
        ("C-0014", "E-0151")]


def test_overlap_pairs_cross_citation_forms():
    assert _oc("do/build_panel.do L21-23", "`do/build_panel.do:23`") == [
        ("C-0014", "E-0151")]


def test_overlap_pairs_skip_example_rows():
    claims = [rb.claims_row("C-0000", source="`do/x.do:1-2`")]
    errors = [rb.error_row("E-0151", location="`do/x.do:1-2`")]
    assert _lm.overlapping_confirmed_pairs(claims, errors) == []


# ------------- SC-01 overlap-conflict advisory — b7 boundary behavior


def _b7_conflict_rows(*, linked=False):
    claims = [rb.claims_row(
        "C-0014", source="`do/build_panel.do:21-23`",
        related="E-0151" if linked else "")]
    errors = [rb.error_row(
        "E-0151", etype="aggregation_or_unit_error",
        source="`do/build_panel.do`",
        location="`do/build_panel.do:20-23`",
        related="C-0014" if linked else "")]
    return claims, errors


def test_b7_unlinked_overlap_warns_and_stays_green(tmp_path):
    claims, errors = _b7_conflict_rows()
    a = rb.make_b7(tmp_path, claims_rows=claims, error_rows=errors)
    res = rb.lint(a, "b7")
    assert res.returncode == 0, res.stdout + res.stderr
    warns = warning_lines(res, "overlap-conflict")
    assert len(warns) == 1, res.stdout
    assert "C-0014" in warns[0] and "E-0151" in warns[0], res.stdout


def test_b7_linked_and_listed_pair_not_double_reported(tmp_path):
    """A confirmed pair that is linked and listed under '## Status conflicts'
    is covered by the existing hard check; the advisory must not re-report."""
    claims, errors = _b7_conflict_rows(linked=True)
    summary = (
        "# Cross-link summary\n\n## Status conflicts\n\n"
        "C-0014 <-> E-0151 — confirmed claim contradicted by confirmed error\n\n"
        "## Escalated mapped claims\n\nnone\n\n"
        "## Severity divergences\n\nnone\n"
    )
    a = rb.make_b7(tmp_path, claims_rows=claims, error_rows=errors,
                   summary=summary)
    res = rb.lint(a, "b7")
    assert res.returncode == 0, res.stdout + res.stderr
    assert not warning_lines(res, "overlap-conflict"), res.stdout


def test_b7_advisory_prints_even_when_summary_missing(tmp_path):
    """The conductor's pre-dispatch flow (pipeline-finalize b7 step 2) runs the
    b7 lint before the cross-link summary exists: the stage FAILS on the
    missing summary but the overlap-conflict WARNING lines still print — they
    are the pair list passed to the cross-linker."""
    claims, errors = _b7_conflict_rows()
    a = rb.make_b7(tmp_path, claims_rows=claims, error_rows=errors)
    (a.audit / "register_cross_link_summary.md").unlink()
    res = rb.lint(a, "b7")
    assert res.returncode == 1, res.stdout + res.stderr
    warns = warning_lines(res, "overlap-conflict")
    assert len(warns) == 1 and "C-0014" in warns[0], res.stdout


def test_b7_non_overlapping_citations_silent(tmp_path):
    claims = [rb.claims_row("C-0014", source="`do/build_panel.do:21-23`")]
    errors = [rb.error_row("E-0151", location="`do/build_panel.do:30-35`")]
    a = rb.make_b7(tmp_path, claims_rows=claims, error_rows=errors)
    res = rb.lint(a, "b7")
    assert res.returncode == 0, res.stdout + res.stderr
    assert not warning_lines(res, "overlap-conflict"), res.stdout


def test_anchoring_silent_without_claims_register(tmp_path):
    """No canonical claims register in the audit dir (as in these synthetic
    boundaries): the advisory skips silently — it never fails the stage and
    never crashes the linter."""
    a, shard = _anchoring_b5(
        tmp_path,
        claim_text="unused",
        evidence="verified the drop filter exists at `code/build_panel.R:88`",
        with_register=False,
    )
    res = rb.lint(a, "b5-claims", shard=shard)
    assert res.returncode == 0, res.stdout + res.stderr
    assert not warning_lines(res, "anchoring"), res.stdout
