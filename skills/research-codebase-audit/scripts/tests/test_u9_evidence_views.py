"""U9 module layer: the evidence resolver and the authorization projection.

Direct Test 1/Test 2 coverage per §9 layer 1 of the 2026-07-31 systemic
execution-tail checklist: each view resolves when produced, refuses on
absent/malformed/tampered evidence, and returns the typed ``premature``
caller error on a too-early ask; each supported transition accepts exactly
its permitted delta and names anything else.
"""

from __future__ import annotations

import hashlib
import json

import pytest

import regbuild as rb

deltas = rb.load_script("authorized_deltas")
views = rb.load_script("evidence_views")
tokens = rb.load_script("severity_tokens")

pytestmark = pytest.mark.u9

CODE = "code_error_register.md"
CLAIMS = "claims_register.md"
OUTPUT = "output_register.md"


def _manifest(mode="replication", **stages):
    return {
        "mode": mode,
        "stages": {name: {"status": status}
                   for name, status in stages.items()},
    }


def _row(severity="3", status="confirmed"):
    return rb.error_row("E-0001", status=status, severity=severity)


def _resolved(result):
    assert isinstance(result, views.ResolvedView), result
    return result


def _refused(result, reason):
    assert isinstance(result, views.ViewRefusal), result
    assert result.reason == reason, result
    return result


# --- b6b_proposal ---------------------------------------------------------

def test_b6b_proposal_binds_live_canon_before_any_boundary(tmp_path):
    a = rb.AuditDir(tmp_path)
    a.write_register(CODE, rb.ERROR_COLS, [_row()])
    result = _resolved(views.resolve("b6b_proposal", CODE, a.audit, _manifest()))
    assert result.source_path == a.audit / CODE


def test_b6b_proposal_binds_b7_start_image_once_boundary_minted(tmp_path):
    a = rb.AuditDir(tmp_path)
    a.write_register(CODE, rb.ERROR_COLS, [_row(severity="2")])
    a.write_register("_run/snapshots/b7/" + CODE, rb.ERROR_COLS, [_row()])
    for manifest in (_manifest(b7="running"), _manifest(b7="done"),
                     _manifest()):  # artifact mint alone also counts
        result = _resolved(
            views.resolve("b6b_proposal", CODE, a.audit, manifest))
        assert result.source_path == a.audit / "_run/snapshots/b7" / CODE


def test_b6b_proposal_refuses_when_boundary_recorded_but_image_gone(tmp_path):
    a = rb.AuditDir(tmp_path)
    a.write_register(CODE, rb.ERROR_COLS, [_row()])
    # Later boundary images exist, but a crossed b7 boundary is the sole
    # anchor: a deleted image refuses instead of sliding later.
    a.write_register("_run/snapshots/b8/" + CODE, rb.ERROR_COLS, [_row()])
    a.write_register("_run/snapshots/bC/" + CODE, rb.ERROR_COLS, [_row()])
    _refused(
        views.resolve("b6b_proposal", CODE, a.audit, _manifest(b7="done")),
        "absent")


def test_b6b_proposal_refuses_malformed_image(tmp_path):
    a = rb.AuditDir(tmp_path)
    a.write("_run/snapshots/b7/" + CODE, "no register table here\n")
    _refused(
        views.resolve("b6b_proposal", CODE, a.audit, _manifest(b7="done")),
        "malformed")


def test_b6b_proposal_output_register_owned_by_bc_start_image(tmp_path):
    a = rb.AuditDir(tmp_path)
    a.write_register(OUTPUT, rb.OUTPUT_COLS, [rb.output_row("O-0002")])
    live = _resolved(
        views.resolve("b6b_proposal", OUTPUT, a.audit, _manifest(b7="done")))
    assert live.source_path == a.audit / OUTPUT
    a.write_register("_run/snapshots/bC/" + OUTPUT, rb.OUTPUT_COLS,
                     [rb.output_row("O-0001")])
    frozen = _resolved(
        views.resolve("b6b_proposal", OUTPUT, a.audit, _manifest(bC="running")))
    assert frozen.source_path == a.audit / "_run/snapshots/bC" / OUTPUT


def test_b6b_proposal_code_errors_only_owned_by_b8_start_image(tmp_path):
    a = rb.AuditDir(tmp_path)
    a.write_register("_run/snapshots/b8/" + CODE, rb.ERROR_COLS, [_row()])
    result = _resolved(views.resolve(
        "b6b_proposal", CODE, a.audit,
        _manifest(mode="code_errors_only", b8="done")))
    assert result.source_path == a.audit / "_run/snapshots/b8" / CODE


# --- b7_classification ----------------------------------------------------

def test_b7_classification_prefers_staging_before_rulings_boundary(tmp_path):
    a = rb.AuditDir(tmp_path)
    a.write_register(CODE, rb.ERROR_COLS, [_row(severity="2")])
    a.write_register("_staging/" + CODE, rb.ERROR_COLS, [_row()])
    result = _resolved(
        views.resolve("b7_classification", CODE, a.audit, _manifest()))
    assert result.source_path == a.audit / "_staging" / CODE


def test_b7_classification_binds_frozen_register_and_fails_closed(tmp_path):
    a = rb.AuditDir(tmp_path)
    a.write_register(CODE, rb.ERROR_COLS, [_row()])
    a.write_register("_staging/" + CODE, rb.ERROR_COLS, [_row()])
    manifest = _manifest(severity_token_rulings="done")
    _refused(views.resolve("b7_classification", CODE, a.audit, manifest),
             "absent")
    a.write_register(views.PRE_RULING_REGISTER, rb.ERROR_COLS, [_row()])
    result = _resolved(
        views.resolve("b7_classification", CODE, a.audit, manifest))
    assert result.source_path == a.audit / views.PRE_RULING_REGISTER


def test_b7_classification_owns_only_the_code_register(tmp_path):
    a = rb.AuditDir(tmp_path)
    with pytest.raises(ValueError):
        views.resolve("b7_classification", CLAIMS, a.audit, _manifest())


# --- pre_ruling -----------------------------------------------------------

def _freeze_pre_ruling(a, lines=("E-0001 output:O-0001",)):
    register = a.write_register(views.PRE_RULING_REGISTER, rb.ERROR_COLS,
                                [_row()])
    sha = hashlib.sha256(register.read_bytes()).hexdigest()
    payload = {
        "schema": views.WORKLIST_SCHEMA,
        "lines": sorted(lines),
        "b7_register_sha256": sha,
        "b7_certification_sha256": views.worklist_digest(sorted(lines), sha),
    }
    a.write(views.WORKLIST_PATH, json.dumps(payload, indent=2) + "\n")
    return payload


def test_pre_ruling_premature_before_the_rulings_boundary(tmp_path):
    a = rb.AuditDir(tmp_path)
    result = views.resolve("pre_ruling", CODE, a.audit, _manifest())
    assert isinstance(result, views.PrematureAsk)


def test_pre_ruling_resolves_the_digest_bound_pair(tmp_path):
    a = rb.AuditDir(tmp_path)
    payload = _freeze_pre_ruling(a)
    result = _resolved(views.resolve(
        "pre_ruling", CODE, a.audit, _manifest(severity_token_rulings="done")))
    assert result.payload == payload
    assert result.rows


def test_pre_ruling_refuses_tampered_register_bytes(tmp_path):
    a = rb.AuditDir(tmp_path)
    _freeze_pre_ruling(a)
    snapshot = a.audit / views.PRE_RULING_REGISTER
    snapshot.write_bytes(snapshot.read_bytes() + b"flip\n")
    result = _refused(
        views.resolve("pre_ruling", CODE, a.audit,
                      _manifest(severity_token_rulings="done")),
        "tampered")
    assert "snapshot digest mismatch" in result.detail


def test_pre_ruling_refuses_tampered_worklist_lines(tmp_path):
    a = rb.AuditDir(tmp_path)
    payload = _freeze_pre_ruling(a)
    payload["lines"] = []
    a.write(views.WORKLIST_PATH, json.dumps(payload) + "\n")
    result = _refused(
        views.resolve("pre_ruling", CODE, a.audit,
                      _manifest(severity_token_rulings="done")),
        "tampered")
    assert "worklist digest mismatch" in result.detail


def test_pre_ruling_refuses_malformed_worklist(tmp_path):
    a = rb.AuditDir(tmp_path)
    _freeze_pre_ruling(a)
    a.write(views.WORKLIST_PATH, "not json\n")
    _refused(
        views.resolve("pre_ruling", CODE, a.audit,
                      _manifest(severity_token_rulings="done")),
        "malformed")
    a.write(views.WORKLIST_PATH, json.dumps({"schema": "x"}) + "\n")
    _refused(
        views.resolve("pre_ruling", CODE, a.audit,
                      _manifest(severity_token_rulings="done")),
        "malformed")


def test_pre_ruling_refuses_absent_register_snapshot(tmp_path):
    a = rb.AuditDir(tmp_path)
    _freeze_pre_ruling(a)
    (a.audit / views.PRE_RULING_REGISTER).unlink()
    _refused(
        views.resolve("pre_ruling", CODE, a.audit,
                      _manifest(severity_token_rulings="done")),
        "absent")


# --- rulings_applied ------------------------------------------------------

def test_rulings_applied_binds_live_canon_before_b8(tmp_path):
    a = rb.AuditDir(tmp_path)
    a.write_register(CODE, rb.ERROR_COLS, [_row()])
    result = _resolved(
        views.resolve("rulings_applied", CODE, a.audit, _manifest()))
    assert result.source_path == a.audit / CODE


def test_rulings_applied_binds_b8_start_image_and_fails_closed(tmp_path):
    a = rb.AuditDir(tmp_path)
    a.write_register(CODE, rb.ERROR_COLS, [_row(severity="2")])
    manifest = _manifest(b8="done")
    _refused(views.resolve("rulings_applied", CODE, a.audit, manifest),
             "absent")
    a.write_register("_run/snapshots/b8/" + CODE, rb.ERROR_COLS, [_row()])
    result = _resolved(views.resolve("rulings_applied", CODE, a.audit, manifest))
    assert result.source_path == a.audit / "_run/snapshots/b8" / CODE


# --- export_bound ---------------------------------------------------------

def test_export_bound_is_the_live_canonical_register(tmp_path):
    a = rb.AuditDir(tmp_path)
    _refused(views.resolve("export_bound", CODE, a.audit, _manifest()),
             "absent")
    a.write_register(CODE, rb.ERROR_COLS, [_row()])
    result = _resolved(views.resolve("export_bound", CODE, a.audit, _manifest()))
    assert result.source_path == a.audit / CODE


# --- bC_correction --------------------------------------------------------

def test_bc_correction_premature_then_resolves_then_fails_closed(tmp_path):
    a = rb.AuditDir(tmp_path)
    early = views.resolve("bC_correction", CODE, a.audit, _manifest())
    assert isinstance(early, views.PrematureAsk)
    _refused(views.resolve("bC_correction", CODE, a.audit, _manifest(bC="done")),
             "absent")
    a.write_register("_run/snapshots/bC/" + CODE, rb.ERROR_COLS, [_row()])
    result = _resolved(
        views.resolve("bC_correction", CODE, a.audit, _manifest(bC="done")))
    assert result.source_path == a.audit / "_run/snapshots/bC" / CODE
    # Non-register packet members (late-observation evidence) need no table.
    a.write("_run/snapshots/bC/late_observations_code.md", "# evidence\n")
    _resolved(views.resolve(
        "bC_correction", "late_observations_code.md", a.audit,
        _manifest(bC="done")))


def test_unknown_view_is_a_caller_error(tmp_path):
    a = rb.AuditDir(tmp_path)
    with pytest.raises(ValueError):
        views.resolve("latest_snapshot", CODE, a.audit, _manifest())


# --- authorization projection --------------------------------------------

def _freeze_rulings(a, rulings_payload):
    a.write(deltas.FROZEN_RULINGS, json.dumps({
        "schema": "severity_token_rulings/v1", "cycle": "main",
        "rulings": rulings_payload,
    }) + "\n")


def test_rulings_transition_permits_exactly_the_worklist_keyed_cells(tmp_path):
    a = rb.AuditDir(tmp_path)
    _freeze_pre_ruling(a)
    _freeze_rulings(a, [{
        "error_id": "E-0001", "token": "output:O-0001",
        "b7_verdict": "rejected", "ruling": "cap",
        "resulting_status": "confirmed", "resulting_severity": 2,
        "rationale": "r", "decision_identity": "operator",
    }])
    delta, failures = deltas.permitted_delta(
        "pre_ruling", "rulings_applied", CODE, a.audit,
        _manifest(severity_token_rulings="done"))
    assert failures == []
    assert delta.exact_cells == {
        ("E-0001", "Status"): "confirmed",
        ("E-0001", "Severity"): "2",
    }
    assert not delta.added_rows and not delta.link_additions


def test_rulings_transition_names_non_worklist_and_over_cap_rulings(tmp_path):
    a = rb.AuditDir(tmp_path)
    _freeze_pre_ruling(a)
    _freeze_rulings(a, [
        {"error_id": "E-0002", "token": "output:O-0001",
         "b7_verdict": "rejected", "ruling": "cap",
         "resulting_status": "confirmed", "resulting_severity": 2},
        {"error_id": "E-0001", "token": "output:O-0001",
         "b7_verdict": "rejected", "ruling": "cap",
         "resulting_status": "confirmed", "resulting_severity": 3},
    ])
    delta, failures = deltas.permitted_delta(
        "pre_ruling", "rulings_applied", CODE, a.audit,
        _manifest(severity_token_rulings="done"))
    assert any("non-worklist token" in failure for failure in failures)
    assert any("exceeds the severity cap" in failure for failure in failures)
    assert delta.exact_cells == {}


def test_rulings_transition_fails_closed_without_frozen_records(tmp_path):
    a = rb.AuditDir(tmp_path)
    _freeze_pre_ruling(a)
    _delta, failures = deltas.permitted_delta(
        "pre_ruling", "rulings_applied", CODE, a.audit,
        _manifest(severity_token_rulings="done"))
    assert any("frozen ruling artifact is missing" in failure
               for failure in failures)


def test_rewrite_transition_returns_only_the_rewrite_pairs(tmp_path):
    a = rb.AuditDir(tmp_path)
    delta, failures = deltas.permitted_delta(
        "rulings_applied", "export_bound", CODE, a.audit, _manifest())
    assert failures == []
    assert delta.rewrite_pairs == tuple(deltas.REWRITE_PAIRS[CODE])
    assert not delta.exact_cells and not delta.added_rows


def _write_bc_plan(a, rows):
    a.write(
        "plans/late_observation_corrections.md",
        "# Late-observation corrections\n\n"
        "Declared bC range: E-8001–E-8001\n\n"
        + rb.md_table(deltas.BC_PLAN_COLS, rows))


def test_bc_transition_absent_stage_means_no_deltas(tmp_path):
    a = rb.AuditDir(tmp_path)
    delta, failures = deltas.permitted_delta(
        "bC_correction", "export_bound", CODE, a.audit, _manifest())
    assert failures == [] and delta == deltas.EMPTY_DELTA


def test_bc_transition_fails_closed_when_done_without_plan(tmp_path):
    a = rb.AuditDir(tmp_path)
    _delta, failures = deltas.permitted_delta(
        "bC_correction", "export_bound", CODE, a.audit, _manifest(bC="done"))
    assert any("correction plan is absent" in failure for failure in failures)


def test_bc_transition_derives_reciprocal_links_from_payloads(tmp_path):
    a = rb.AuditDir(tmp_path)
    payload = dict(zip(rb.ERROR_COLS, rb.error_row(
        "E-8001", status="confirmed", severity="3", related="C-0001")))
    _write_bc_plan(a, [[
        "BC-0001", "LO-E-0001", "code_error", "new_row", "E-8001",
        json.dumps(payload, sort_keys=True, separators=(",", ":")), "—",
    ]])
    code_delta, code_failures = deltas.permitted_delta(
        "bC_correction", "export_bound", CODE, a.audit, _manifest(bC="done"))
    assert code_failures == []
    assert set(code_delta.added_rows) == {"E-8001"}
    assert not code_delta.link_additions
    claims_delta, claims_failures = deltas.permitted_delta(
        "bC_correction", "export_bound", CLAIMS, a.audit, _manifest(bC="done"))
    assert claims_failures == []
    assert claims_delta.link_additions == {
        ("C-0001", "Related Error IDs"): frozenset({"E-8001"})}
    assert not claims_delta.added_rows


def test_bc_transition_accepts_co_patches_and_names_illegal_fields(tmp_path):
    a = rb.AuditDir(tmp_path)
    _write_bc_plan(a, [
        ["BC-0001", "LO-E-0001", "claims", "patch", "C-0001",
         json.dumps({"field": "Output IDs", "new_value": "O-0121"}), "a" * 64],
        ["BC-0001", "LO-E-0001", "claims", "patch", "C-0002",
         json.dumps({"field": "Severity", "new_value": "4"}), "a" * 64],
    ])
    delta, failures = deltas.permitted_delta(
        "bC_correction", "export_bound", CLAIMS, a.audit, _manifest(bC="done"))
    assert delta.exact_cells == {("C-0001", "Output IDs"): "O-0121"}
    assert any("reciprocal C↔O link columns" in failure for failure in failures)


def test_unknown_transition_is_a_caller_error(tmp_path):
    a = rb.AuditDir(tmp_path)
    with pytest.raises(ValueError):
        deltas.permitted_delta(
            "b6b_proposal", "pre_ruling", CODE, a.audit, _manifest())


def test_compose_unions_link_additions_and_merges_cells():
    first = deltas.PermittedDelta(
        exact_cells={("E-0001", "Severity"): "2"},
        link_additions={("C-0001", "Related Error IDs"): frozenset({"E-8001"})})
    second = deltas.PermittedDelta(
        added_rows={"E-8001": {"Error ID": "E-8001"}},
        link_additions={("C-0001", "Related Error IDs"): frozenset({"E-8002"})})
    combined = deltas.compose(first, second)
    assert combined.exact_cells == {("E-0001", "Severity"): "2"}
    assert combined.added_rows == {"E-8001": {"Error ID": "E-8001"}}
    assert combined.link_additions == {
        ("C-0001", "Related Error IDs"): frozenset({"E-8001", "E-8002"})}
