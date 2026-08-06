"""Self-tests for score_fixture.py against synthetic final registers.

The HIT texts below double as documentation of the mechanism-signature
matching contract: each contains the signature terms a real run's rows have
carried in prior (hand-adjudicated) scorecards.
"""

import json
import re

import pytest

import regbuild as rb

sf = rb.load_script("score_fixture")

CLEAN_SUMMARY = (
    "# Register cross-link summary\n\n"
    "## Status conflicts\n\n(none)\n\n"
    "## Escalated mapped claims\n\n(none)\n\n"
    "## Severity divergences\n\n(none)\n"
)

# Minimal U2 parser artifact (audit/_run/manifest_check.md) naming the planted
# malformed manifest — what a real b4 run of check_manifests.py leaves behind.
MANIFEST_ARTIFACT = (
    "# Manifest parseability check\n\n"
    "## Manifests checked\n\n"
    "| Manifest | Format | Problem lines |\n| --- | --- | --- |\n"
    "| `pyproject.toml` | toml | 1 |\n\n"
    "## Candidate findings\n\n"
    "| Manifest | Format | Line | Offending Text | Problem |\n"
    "| --- | --- | --- | --- | --- |\n"
    "| pyproject.toml | toml | 4 |  | invalid TOML: Expected newline or end "
    "of document after a statement (at line 4, column 14) |\n"
)

# Same artifact shape but with every manifest parsing clean — the U2 plant
# missing from the candidate findings.
MANIFEST_ARTIFACT_CLEAN = (
    "# Manifest parseability check\n\n"
    "## Manifests checked\n\n"
    "| Manifest | Format | Problem lines |\n| --- | --- | --- |\n"
    "| `pyproject.toml` | toml | 0 |\n\n"
    "## Candidate findings\n\n"
    "No candidate findings: every recognized manifest parsed clean.\n"
)

# The plant's name appears ONLY in the `## Warnings` section that render_artifact
# writes AFTER the Candidate-findings section, with ZERO candidate findings —
# the shape a run leaves when the parser could not read the manifest (e.g. a
# permission error). The plant was never actually flagged, so the U2 check must
# FAIL: bounding the search to the Candidate-findings body is what catches it.
MANIFEST_ARTIFACT_PLANT_ONLY_IN_WARNINGS = (
    "# Manifest parseability check\n\n"
    "## Manifests checked\n\n"
    "| Manifest | Format | Problem lines |\n| --- | --- | --- |\n"
    "| `pyproject.toml` | toml | 0 |\n\n"
    "## Candidate findings\n\n"
    "No candidate findings: every recognized manifest parsed clean.\n\n"
    "## Warnings\n\n"
    "- could not read pyproject.toml: [Errno 13] Permission denied\n"
)

P21_DU = "DU-p21abc"
D03_DU = "DU-d03abc"


def channel_artifact(*, p21=True, d03=True):
    rows = []
    if p21:
        rows.append([
            f"`{P21_DU}`", "`DUW-p21abc`",
            "`(do/build_panel.do, 15, 18, consent_ok)`",
            "consent_ok", "boolean_gen", "`do/build_panel.do:15`",
            "`gen consent_ok = ...`", "`do/build_panel.do:18`",
            "`keep if consent_ok == 1 & consent == individual`",
            "`consent_ok == 1 & consent == individual`", "context", "review",
        ])
    if d03:
        rows.append([
            f"`{D03_DU}`", "`DUW-d03abc`",
            "`(do/analysis.do, 13, 14, baseline_diag_ok)`",
            "baseline_diag_ok", "boolean_gen", "`do/analysis.do:13`",
            "`gen baseline_diag_ok = (svy_weight != .)`", "`do/analysis.do:14`",
            "`keep if baseline_diag_ok == 1 & wave == 1`",
            "`baseline_diag_ok == 1 & wave == 1`", "intentional diagnostic", "review",
        ])
    return (
        "# Stata definition/use bundles\n\n## Scan summary\n\n"
        "- Stata files scanned: 2\n"
        "- Standard producer groups (file + gen line + variable): 2\n"
        f"- Standard candidates: {len(rows)}\n"
        "- Advisory candidates: 0\n\n## Candidate findings\n\n"
        + rb.md_table([
            "Bundle ID", "Witness ID", "Identity Tuple", "Variable", "Producer Shape",
            "Definition Site", "Producer Statement", "Consumer Site",
            "Consumer Statement", "Full Guard", "Code/Comment Context",
            "Obligation Question",
        ], rows)
        + "\n## Advisory candidates\n\n"
        + rb.md_table([
            "Bundle ID", "Witness ID", "Identity Tuple", "Variable", "Producer Shape",
            "Definition Site", "Producer Statement", "Consumer Site",
            "Consumer Statement", "Full Guard", "Code/Comment Context",
            "Obligation Question",
        ], [])
    )


def channel_plan(*, map_p21=True, map_d03=True, p21_evidence=True,
                 d03_evidence=True, p21_du=P21_DU, d03_du=D03_DU):
    inventory = [
        ("E-0021", "definition/use issue", p21_du if p21_evidence else "static"),
        ("E-0090", "definition/use diagnostic", d03_du if d03_evidence else "static"),
    ]
    mappings = []
    if map_p21:
        mappings.append((p21_du, "E-0021", "existing_row"))
    if map_d03:
        mappings.append((d03_du, "E-0090", "new_candidate"))
    clusters = [("K1", "definition/use", "E-0021; E-0090",
                 "`audit/_code_error_recheck/k1.md`")]
    return rb.recheck_plan_text("code", inventory, clusters, mappings)


def channel_ledgers(*, p21_evidence=True, d03_evidence=True,
                    p21_verdict="confirmed_error", d03_verdict="not_error",
                    p21_du=P21_DU, d03_du=D03_DU):
    return [
        rb.ledger_row("E-0021", evidence=(p21_du if p21_evidence else "source"),
                      verdict=p21_verdict),
        rb.ledger_row("E-0090", evidence=(d03_du if d03_evidence else "source"),
                      verdict=d03_verdict, change="set status=not_error"),
    ]


def hit_claims_rows(p14_branch="inconsistent", p19_branch="inconsistent",
                    p20_branch="inconsistent"):
    rows = [
        rb.claims_row(
            "C-0001", status="inconsistent", severity="4",
            ctype="transcription",
            issue=("The prose reports a coefficient of 0.083 but the shipped "
                   "table artifact tab1.tex shows -0.038."),
        ),
        rb.claims_row(
            "C-0013", status="inconsistent", severity="2",
            ctype="sample_count",
            issue=("The paper states 725 of 2,416 households (25 percent); "
                   "725/2,416 is 30 percent, an arithmetic slip."),
        ),
    ]
    if p19_branch == "inconsistent":
        rows.append(rb.claims_row(
            "C-0019", status="inconsistent", severity="2",
            ctype="estimation_specification",
            text=("wage earnings (`wage_earnings`) are winsorised at the "
                  "99th percentile before entering total income"),
            source="`py/build_income.py`",
            issue=("The paper says wage_earnings are winsorised at the 99th "
                   "percentile; build_income.py winsorises crop_sales "
                   "instead — the named variable is untouched."),
        ))
    elif p19_branch == "confirmed":
        rows.append(rb.claims_row(
            "C-0019", status="confirmed",
            ctype="estimation_specification",
            text=("wage earnings (`wage_earnings`) are winsorised at the "
                  "99th percentile before entering total income"),
            source="`py/build_income.py`",
        ))
    if p20_branch == "inconsistent":
        rows.append(rb.claims_row(
            "C-0020", status="inconsistent", severity="2",
            ctype="data_construction",
            text=("each village is matched to every rain gauge within a "
                  "15-km radius of its centroid"),
            source="`data/village_rain_radius_25km.csv`",
            issue=("Appendix A step 2 states a 15-km gauge radius; the "
                   "shipped file village_rain_radius_25km.csv encodes "
                   "25 km."),
        ))
    elif p20_branch == "blocked_with_note":
        rows.append(rb.claims_row(
            "C-0020", status="blocked",
            ctype="data_construction",
            text=("each village is matched to every rain gauge within a "
                  "15-km radius of its centroid"),
            source="`data/village_rain_radius_25km.csv`",
            blocked_check=("Gauge coordinates are not shipped, so the match "
                           "cannot be re-run; but the paper's 15-km radius "
                           "is contradicted by the shipped filename "
                           "village_rain_radius_25km.csv (25 km)."),
        ))
    elif p20_branch == "silent_block":
        rows.append(rb.claims_row(
            "C-0020", status="blocked",
            ctype="data_construction",
            text=("each village is matched to every rain gauge within a "
                  "15-km radius of its centroid; series shipped as "
                  "village_rain_radius_25km.csv"),
            source="`data/village_rain_radius_25km.csv`",
            blocked_check="Gauge coordinates are not distributed.",
        ))
    if p14_branch == "inconsistent":
        rows.append(rb.claims_row(
            "C-0014", status="inconsistent", severity="2",
            ctype="data_construction",
            issue=("The paper says a one-in-ten subsample; the README "
                   "describes households.csv as a 1-in-20 subsample."),
        ))
    elif p14_branch == "blocked_with_note":
        rows.append(rb.claims_row(
            "C-0014", status="blocked",
            text="estimates use the public one-in-ten subsample",
            blocked_check=("The full census is restricted-access, but the "
                           "README describes households.csv as a 1-in-20 "
                           "subsample whereas the paper says one-in-ten."),
        ))
    elif p14_branch == "silent_block":
        # mechanism visible in the row, but the Blocked Check does not record
        # the contradiction — the failure mode P-14 exists to catch
        rows.append(rb.claims_row(
            "C-0014", status="blocked",
            text=("estimates use the public one-in-ten subsample of the "
                  "1-in-20 census release"),
            blocked_check="The restricted census could not be inspected.",
        ))
    elif p14_branch == "empty_blocked_check":
        rows.append(rb.claims_row(
            "C-0014", status="blocked",
            text=("estimates use the public one-in-ten subsample of the "
                  "1-in-20 census release"),
            blocked_check="",
        ))
    return rows


def hit_error_rows():
    mk = rb.error_row
    return [
        mk("E-0002", etype="inference_or_se_specification", severity="3",
           desc=("The paper claims clustering at the village level; "
                 "analysis.do clusters at the household level.")),
        mk("E-0003", etype="weighting_error", severity="3",
           desc=("Regressions run unweighted although the paper claims "
                 "survey weights; svy_weight is never used.")),
        mk("E-0004", etype="randomness_or_seed_error", severity="2",
           desc="bootstrap with 200 replications and no set seed."),
        mk("E-0005", etype="sample_filter_or_flag_error", severity="4",
           desc=("keep if waves < 2 keeps exactly the households the paper "
                 "excludes (fewer than two waves).")),
        mk("E-0006", etype="stale_or_wrong_path", severity="2",
           desc="make_figures.py reads output/panel_v2.csv which no script writes."),
        mk("E-0007", etype="undefined_variable_or_global", severity="3",
           desc=("The $controls global is defined only in a commented-out "
                 "line; regressions run without controls.")),
        mk("E-0008", etype="aggregation_or_unit_error", severity="3",
           desc=("Income is divided by 100 although the paper says thousands "
                 "of local currency units — a factor-of-10 error.")),
        mk("E-0009", etype="readme_or_package_mismatch", severity="1",
           desc="The README lists data/rainfall_stations.csv, which does not exist."),
        mk("E-0010", etype="pii_or_disclosure_risk", severity="2",
           desc="head_name and gps_lat/gps_lon ship in the public data file."),
        mk("E-0011", etype="treatment_or_event_timing_error", severity="2",
           desc=("rain_mean is computed from the two in-sample waves, not "
                 "the 1991-2020 long-run climate normal the paper defines.")),
        mk("E-0012", etype="output_label_or_path_mismatch", severity="1",
           desc=("The figure legend is reversed: ax.legend(['Shocked', "
                 "'Non-shocked']) against the unstacked column order.")),
        mk("E-0015", etype="aggregation_or_unit_error", severity="2",
           desc=("build_income.py sums only crop_sales, livestock_sales and "
                 "wage_earnings, omitting the remittances component from the "
                 "paper's four-component income list.")),
        mk("E-0016", etype="version_or_dependency_error", severity="2",
           desc=("pyproject.toml is invalid TOML (version = 0.4.1 is "
                 "unquoted), so the documented pip install -e . cannot "
                 "parse the manifest.")),
        mk("E-0017", etype="sample_filter_or_flag_error", severity="2",
           desc=("The backfill comment says missing hhsize is filled, but "
                 "`if hhsize < .` acts only on non-missing rows, so the "
                 "missing wave-2 value is never filled.")),
        mk("E-0018", etype="sample_filter_or_flag_error", severity="2",
           desc=("has_wages is overwritten on each loop iteration, so the "
                 "wave-2 pass erases wave-1 matches and the flag reflects "
                 "the last wave only.")),
        mk("E-0021", etype="sample_filter_or_flag_error", severity="2",
           desc=("consent_ok is defined to cover both individual and "
                 "community consent, but keep if consent_ok == 1 & consent "
                 "== \"individual\" adds a conjunct that silently drops the "
                 "community-consent households from the estimation sample "
                 "feeding Table 1.")),
        mk("E-0090", etype="sample_filter_or_flag_error", status="not_error",
           severity="", source="`do/analysis.do`",
           location="`do/analysis.do:13-16`",
           desc=("baseline_diag_ok gates an intentional baseline-wave-only "
                 "diagnostic inside preserve/restore; reviewed and cleared.")),
    ]


def write_final_registers(tmp_path, claims_rows, error_rows,
                          summary=CLEAN_SUMMARY,
                          manifest_artifact=MANIFEST_ARTIFACT,
                          conventions=None, ledger_rows=None,
                          claims_original_cols=False,
                          definition_use_artifact="default", definition_use_plan="default",
                          definition_use_ledgers="default"):
    audit = tmp_path / "audit"
    audit.mkdir(parents=True)
    if claims_original_cols:
        # Post-b8 finalize promotes the rewriter's staging register, which
        # INSERTS an `Issue Description Original` column right after
        # `Issue Description` (not appended at the end) — the real shape of a
        # scored run's final claims register (mirrors regbuild.make_b8 via the
        # shared rewrite_pass_cols helper). The interleaved order is what a
        # prefix-match table finder trips on; the append-at-end shape used
        # previously hid that bug.
        c_cols, c_rows = rb.rewrite_pass_cols(
            rb.CLAIMS_COLS, claims_rows, ["Issue Description"])
        (audit / "claims_register.md").write_text(
            rb.register_text("Claims register", c_cols, c_rows))
    else:
        (audit / "claims_register.md").write_text(
            rb.register_text("Claims register", rb.CLAIMS_COLS, claims_rows))
    (audit / "code_error_register.md").write_text(
        rb.register_text("Code-error register", rb.ERROR_COLS, error_rows))
    (audit / "output_register.md").write_text(
        rb.register_text("Output register", rb.OUTPUT_COLS, []))
    (audit / "register_cross_link_summary.md").write_text(summary)
    if manifest_artifact is not None:
        (audit / "_run").mkdir(exist_ok=True)
        (audit / "_run" / "manifest_check.md").write_text(manifest_artifact)
    if definition_use_artifact == "default":
        definition_use_artifact = channel_artifact()
    if definition_use_artifact is not None:
        (audit / "_run").mkdir(exist_ok=True)
        (audit / "_run" / "definition_use_bundles.md").write_text(definition_use_artifact)
    if definition_use_plan == "default":
        definition_use_plan = channel_plan()
    if definition_use_plan is not None:
        (audit / "plans").mkdir(exist_ok=True)
        (audit / "plans" / "code_error_recheck_plan.md").write_text(definition_use_plan)
    if definition_use_ledgers == "default":
        definition_use_ledgers = channel_ledgers()
    if definition_use_ledgers is not None:
        (audit / "_code_error_recheck").mkdir(exist_ok=True)
        (audit / "_code_error_recheck" / "k1.md").write_text(
            rb.register_text("Recheck ledger", rb.LEDGER_COLS, definition_use_ledgers))
    if conventions is not None:
        (audit / "_run").mkdir(exist_ok=True)
        (audit / "_run" / "conventions.md").write_text(conventions)
    if ledger_rows is not None:
        (audit / "_recheck").mkdir(exist_ok=True)
        (audit / "_recheck" / "k1.md").write_text(
            rb.register_text("Recheck ledger", rb.LEDGER_COLS, ledger_rows))
    return audit


def run_scorer(audit):
    # These pre-U6 unit cases exercise the original 21-plant score surface.
    # U6's two plants have dedicated tests in test_u6_read_recall.py; U7a's
    # P-25/P-26 plants and their artifact scoring live in their unit suites,
    # as do U8b's P-27/P-28/P-29 severity plants (test_u8_severity_tokens.py).
    expected = json.loads(sf.DEFAULT_EXPECTED.read_text(encoding="utf-8"))
    expected["must_find"] = [
        plant for plant in expected["must_find"]
        if plant["id"] not in {"P-23", "P-24", "P-25", "P-26",
                               "P-27", "P-28", "P-29"}
    ]
    expected_path = audit / "_legacy_expected_findings.json"
    expected_path.write_text(json.dumps(expected), encoding="utf-8")
    return rb.run_script(
        "score_fixture.py", "--audit-dir", audit, "--expected", expected_path,
    )


def plant_line(res, pid):
    for ln in res.stdout.splitlines():
        if ln.startswith(f"{pid}:"):
            return ln
    raise AssertionError(f"no line for {pid} in:\n{res.stdout}")


def test_gate_green_on_full_hit_set(tmp_path):
    audit = write_final_registers(tmp_path, hit_claims_rows(), hit_error_rows())
    res = run_scorer(audit)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "GATE GREEN" in res.stdout
    assert "Recall: 21/21" in res.stdout
    assert "MISS" not in res.stdout


def test_new_plants_present_and_hit(tmp_path):
    """Each 2026-07-07 failure-class plant is in the key and scored must-find."""
    audit = write_final_registers(tmp_path, hit_claims_rows(), hit_error_rows())
    res = run_scorer(audit)
    for pid in ("P-15", "P-16", "P-17", "P-18", "P-19", "P-20", "P-21"):
        assert re.match(rf"{pid}: HIT", plant_line(res, pid)), plant_line(res, pid)


def test_per_class_tags_reported(tmp_path):
    audit = write_final_registers(tmp_path, hit_claims_rows(), hit_error_rows())
    res = run_scorer(audit)
    assert "[class=enumerated_member_list]" in plant_line(res, "P-15")
    assert "Per-class:" in res.stdout
    for cls in ("enumerated_member_list", "manifest_parseability",
                "empirical_verification", "identifier_anchoring",
                "step_parameter_filename", "definition_use_contract"):
        assert cls in res.stdout


def test_per_class_breakdown_lists_every_planted_class(tmp_path):
    """U10: the per-class breakdown alongside the aggregate lists EACH planted
    class with hit/miss counts — including the pre-2026-07-07 plants
    P-01..P-14, which carry no failure_class tag and roll up in an explicit
    unclassified_legacy bucket."""
    audit = write_final_registers(tmp_path, hit_claims_rows(), hit_error_rows())
    res = run_scorer(audit)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "Per-class:" in res.stdout
    for line in (
        "enumerated_member_list: 1/1 hit, 0 miss",
        "manifest_parseability: 1/1 hit, 0 miss",
        "empirical_verification: 2/2 hit, 0 miss",
        "identifier_anchoring: 1/1 hit, 0 miss",
        "step_parameter_filename: 1/1 hit, 0 miss",
        "definition_use_contract: 1/1 hit, 0 miss",
        "unclassified_legacy: 14/14 hit, 0 miss",
    ):
        assert line in res.stdout, f"missing per-class line {line!r} in:\n{res.stdout}"


def test_per_class_breakdown_counts_misses(tmp_path):
    """U10: a miss shows up in its class's hit/miss counts, and the legacy
    bucket is unaffected."""
    errors = [r for r in hit_error_rows() if r[0] != "E-0015"]  # drop P-15 hit
    audit = write_final_registers(tmp_path, hit_claims_rows(), errors)
    res = run_scorer(audit)
    assert res.returncode == 1
    assert "enumerated_member_list: 0/1 hit, 1 miss" in res.stdout
    assert "unclassified_legacy: 14/14 hit, 0 miss" in res.stdout


def test_p14_blocked_with_note_branch_is_hit(tmp_path):
    audit = write_final_registers(
        tmp_path, hit_claims_rows("blocked_with_note"), hit_error_rows())
    res = run_scorer(audit)
    assert res.returncode == 0, res.stdout + res.stderr
    assert re.match(r"P-14: HIT", plant_line(res, "P-14"))
    assert "blocked branch" in plant_line(res, "P-14")


def test_p14_silent_block_is_miss(tmp_path):
    audit = write_final_registers(
        tmp_path, hit_claims_rows("silent_block"), hit_error_rows())
    res = run_scorer(audit)
    assert res.returncode == 1
    assert re.match(r"P-14: MISS", plant_line(res, "P-14"))
    assert "silently-blocked" in plant_line(res, "P-14")
    assert "GATE RED" in res.stdout


def test_p14_empty_blocked_check_is_miss(tmp_path):
    audit = write_final_registers(
        tmp_path, hit_claims_rows("empty_blocked_check"), hit_error_rows())
    res = run_scorer(audit)
    assert res.returncode == 1
    assert re.match(r"P-14: MISS", plant_line(res, "P-14"))


def test_decoy_presence_turns_gate_red(tmp_path):
    errors = hit_error_rows() + [rb.error_row(
        "E-0099", etype="missing_input_or_output", severity="1",
        desc="artifacts/fig_placebo.pdf referenced by a placebo figure block "
             "is not produced by any script.")]
    audit = write_final_registers(tmp_path, hit_claims_rows(), errors)
    res = run_scorer(audit)
    assert res.returncode == 1
    assert "D-01 decoy: PRESENT" in res.stdout
    assert "GATE RED" in res.stdout
    assert "Recall: 21/21" in res.stdout  # decoy alone flips the gate


def test_cleared_decoy_row_does_not_turn_gate_red(tmp_path):
    errors = hit_error_rows() + [rb.error_row(
        "E-0099", etype="missing_input_or_output", status="not_error",
        severity="",
        desc=("artifacts/fig_placebo.pdf was reviewed and cleared because "
              "the placebo figure block is intentionally commented out."))]
    audit = write_final_registers(tmp_path, hit_claims_rows(), errors)
    res = run_scorer(audit)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "D-01 decoy: ABSENT" in res.stdout


@pytest.mark.parametrize("status", ["not_error", "duplicate_of:E-0002"])
@pytest.mark.parametrize("description", [
    ("artifacts/fig_placebo.pdf is missing even though the placebo figure "
     "block references it."),
    ("farm_components wrongly omits remittances from the four-component "
     "income list."),
])
def test_cleared_or_duplicate_decoy_rows_do_not_turn_gate_red(
        tmp_path, status, description):
    errors = hit_error_rows() + [rb.error_row(
        "E-0099", etype="sample_filter_or_flag_error", status=status,
        severity="", desc=description)]
    audit = write_final_registers(tmp_path, hit_claims_rows(), errors)

    res = run_scorer(audit)

    assert res.returncode == 0, res.stdout + res.stderr
    assert "D-01 decoy: ABSENT" in res.stdout
    assert "D-02 decoy: ABSENT" in res.stdout


def test_p18_wage_indicator_loop_overwrite_description_hits(tmp_path):
    errors = [row for row in hit_error_rows() if row[0] != "E-0018"]
    errors.append(rb.error_row(
        "E-0018", etype="sample_filter_or_flag_error", severity="2",
        source="`py/prepare_panel.py`", location="`py/prepare_panel.py:24-26`",
        desc=("The wage indicator is reset on each wave iteration instead "
              "of accumulating prior matches, so the final wave overwrites "
              "earlier true values.")))
    audit = write_final_registers(tmp_path, hit_claims_rows(), errors)
    res = run_scorer(audit)
    assert res.returncode == 0, res.stdout + res.stderr
    assert re.match(r"P-18: HIT", plant_line(res, "P-18"))


def test_p18_source_file_cannot_substitute_for_wage_mechanism(tmp_path):
    errors = [row for row in hit_error_rows() if row[0] != "E-0018"]
    errors.append(rb.error_row(
        "E-0018", etype="sample_filter_or_flag_error", severity="2",
        source="`py/build_income.py`", location="`py/build_income.py:24-26`",
        desc=("The loop assigns an eligibility indicator anew on each "
              "iteration, so the final iteration overwrites earlier true "
              "values.")))
    audit = write_final_registers(tmp_path, hit_claims_rows(), errors)

    res = run_scorer(audit)

    assert res.returncode == 1
    assert re.match(r"P-18: MISS", plant_line(res, "P-18"))


def test_intentional_subset_decoy_turns_gate_red(tmp_path):
    """The U1 intentional-subset decoy (D-02): a finding about the
    farm-components subset is a false positive and flips the gate."""
    errors = hit_error_rows() + [rb.error_row(
        "E-0098", etype="sample_filter_or_flag_error", severity="2",
        desc=("farm_components in build_income.py lists only crop_sales and "
              "livestock_sales, diverging from the paper's four-component "
              "income list."))]
    audit = write_final_registers(tmp_path, hit_claims_rows(), errors)
    res = run_scorer(audit)
    assert res.returncode == 1
    assert "D-02 decoy: PRESENT" in res.stdout
    assert "GATE RED" in res.stdout


def test_p15_row_quoting_signpost_comment_is_not_decoy(tmp_path):
    """D-02 narrowed again 2026-07-08: a legitimate P-15 recovery row that
    QUOTES the farm_components signpost comment as evidence (and records the
    subset reviewed-not-divergent) must not trip the decoy — only flagging
    the intentional subset AS the error is the planted bait."""
    errors = [r for r in hit_error_rows() if r[0] != "E-0015"]
    errors.append(rb.error_row(
        "E-0015", etype="aggregation_or_unit_error", severity="2",
        desc=("The income aggregate sums three components and omits "
              "remittances from the paper's four-component income list. "
              "The file's own later comment states the farm share is "
              "'deliberately a subset of the four income components'; the "
              "farm_components subset is explicitly local and recorded "
              "reviewed-not-divergent, but the total-income list at line 14 "
              "has no such signpost and under-counts the aggregate.")))
    audit = write_final_registers(tmp_path, hit_claims_rows(), errors)
    res = run_scorer(audit)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "D-02 decoy: ABSENT" in res.stdout
    assert re.match(r"P-15: HIT", plant_line(res, "P-15"))


def test_farm_subset_flagged_as_error_still_trips_decoy(tmp_path):
    """The exculpation override must not defuse a genuine decoy hit: a row
    whose tripping sentence flags farm_components as wrongly subsetting the
    income list (no exculpatory language in that sentence) still trips D-02
    even when a neighbouring sentence contains exculpatory vocabulary."""
    errors = hit_error_rows() + [rb.error_row(
        "E-0097", etype="sample_filter_or_flag_error", severity="2",
        desc=("The farm_share diagnostic was reviewed. farm_components "
              "wrongly omits wage earnings and remittances from the "
              "four-component income list, biasing the farm share."))]
    audit = write_final_registers(tmp_path, hit_claims_rows(), errors)
    res = run_scorer(audit)
    assert res.returncode == 1
    assert "D-02 decoy: PRESENT" in res.stdout
    assert "GATE RED" in res.stdout


def test_non_omission_finding_in_subset_block_is_not_decoy(tmp_path):
    """D-02 narrowed 2026-07-08: only subset-omission complaints trip the
    decoy. A distinct true observation inside the signposted block (here a
    zero-income division guard) is scored on its own merits."""
    errors = hit_error_rows() + [rb.error_row(
        "E-0099", etype="aggregation_or_unit_error", severity="1",
        desc=("farm_share divides by the raw income column with no guard "
              "against income == 0, yielding inf for a zero-income row."))]
    audit = write_final_registers(tmp_path, hit_claims_rows(), errors)
    res = run_scorer(audit)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "D-02 decoy: ABSENT" in res.stdout


def test_descriptive_subset_noun_in_ratio_finding_is_not_decoy(tmp_path):
    """D-02 narrowed 2026-07-09 (defuse gate run 2, E-0283): a ratio-basis
    finding that merely NAMES the block descriptively ("the farm subset's
    share") while flagging an unrelated denominator/guard defect must not trip.
    Bare "subset" is the signpost's own descriptive noun, not the omission
    grievance; the row makes no claim the list omits/diverges from the four
    components, so it is scored on its own merits."""
    errors = hit_error_rows() + [rb.error_row(
        "E-0096", etype="aggregation_or_unit_error", severity="1",
        desc=("The comment frames farm_share as the farm subset's share of "
              "the income components, but the denominator is the reported "
              "survey total income, not the component sum, so numerator and "
              "denominator are on different bases and the share can exceed 1."))]
    audit = write_final_registers(tmp_path, hit_claims_rows(), errors)
    res = run_scorer(audit)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "D-02 decoy: ABSENT" in res.stdout


def test_decoy_in_summary_turns_gate_red(tmp_path):
    summary = CLEAN_SUMMARY + "\nNote: fig_placebo.pdf was inspected.\n"
    audit = write_final_registers(tmp_path, hit_claims_rows(),
                                  hit_error_rows(), summary=summary)
    res = run_scorer(audit)
    assert res.returncode == 1
    assert "D-01 decoy: PRESENT" in res.stdout


def test_sc01_unresolved_status_conflict_turns_gate_red(tmp_path):
    claims = hit_claims_rows() + [rb.claims_row(
        "C-0021", status="confirmed", ctype="treatment_definition",
        text=("the rainfall shock is the deviation from the village's "
              "long-run historical mean (the 1991-2020 climate normal)"))]
    audit = write_final_registers(tmp_path, claims, hit_error_rows())
    res = run_scorer(audit)
    assert res.returncode == 1
    assert "SC-01: FAIL" in res.stdout


def test_p21_definition_use_contract_miss_when_absent(tmp_path):
    """Miss path: registers without a qualifying P-21 row report P-21 MISS and
    red the gate, and the definition_use_contract class shows the miss."""
    errors = [r for r in hit_error_rows() if r[0] != "E-0021"]
    audit = write_final_registers(tmp_path, hit_claims_rows(), errors)
    res = run_scorer(audit)
    assert res.returncode == 1
    assert re.match(r"P-21: MISS", plant_line(res, "P-21"))
    assert "definition_use_contract: 0/1 hit, 1 miss" in res.stdout
    assert "GATE RED" in res.stdout


def test_p21_below_min_severity_is_miss(tmp_path):
    """Severity floor: a P-21 row at severity 1 matches the mechanism but does
    not clear the floor of 2, so it is a MISS."""
    errors = [r for r in hit_error_rows() if r[0] != "E-0021"]
    errors.append(rb.error_row(
        "E-0021", etype="sample_filter_or_flag_error", severity="1",
        desc=("consent_ok is defined to cover both individual and community "
              "consent, but keep if consent_ok == 1 & consent == "
              "\"individual\" adds a conjunct that silently drops the "
              "community-consent households from the estimation sample.")))
    audit = write_final_registers(tmp_path, hit_claims_rows(), errors)
    res = run_scorer(audit)
    assert res.returncode == 1
    assert re.match(r"P-21: MISS", plant_line(res, "P-21"))
    assert "severity >= 2" in plant_line(res, "P-21")


# ------------------------------------ U2 definition/use channel attribution


def test_definition_use_channel_passes_for_p21_and_d03(tmp_path):
    audit = write_final_registers(tmp_path, hit_claims_rows(), hit_error_rows())
    status, note = sf.check_channel_definition_use(audit)
    assert status == "PASS", note
    assert P21_DU in note and D03_DU in note


def test_definition_use_channel_accepts_real_fixture_emitter_artifact(tmp_path):
    """Integration: score the committed emitter's real P-21/D-03 artifact."""
    audit = write_final_registers(tmp_path, hit_claims_rows(), hit_error_rows())
    emitted = rb.run_script(
        "emit_definition_use_bundles.py", rb.FIXTURE_DIR / "planted",
        "--audit-dir", audit)
    assert emitted.returncode == 0, emitted.stdout + emitted.stderr
    text = (audit / "_run" / "definition_use_bundles.md").read_text()
    section = text.partition("## Candidate findings")[2].split("\n## ", 1)[0]
    headers, rows = sf._table_with_headers(
        section, ["Bundle ID", "Variable", "Definition Site", "Consumer Site"])
    found = {dict(zip(headers, row))["Variable"]:
             dict(zip(headers, row))["Bundle ID"].strip("`") for row in rows}
    p21_du, d03_du = found["consent_ok"], found["baseline_diag_ok"]
    (audit / "plans" / "code_error_recheck_plan.md").write_text(
        channel_plan(p21_du=p21_du, d03_du=d03_du))
    (audit / "_code_error_recheck" / "k1.md").write_text(
        rb.register_text(
            "Recheck ledger", rb.LEDGER_COLS,
            channel_ledgers(p21_du=p21_du, d03_du=d03_du)))
    status, note = sf.check_channel_definition_use(audit)
    assert status == "PASS", note


def test_definition_use_channel_rejects_longer_prefix_inventory_evidence(tmp_path):
    plan = channel_plan().replace(
        f"| E-0021 | definition/use issue | {P21_DU} |",
        f"| E-0021 | definition/use issue | {P21_DU}4 |",
    )
    audit = write_final_registers(
        tmp_path, hit_claims_rows(), hit_error_rows(), definition_use_plan=plan)
    status, note = sf.check_channel_definition_use(audit)
    assert status == "FAIL"
    assert "Likely Evidence" in note and P21_DU in note


def test_definition_use_channel_rejects_longer_prefix_ledger_evidence(tmp_path):
    ledgers = channel_ledgers()
    ledgers[0][3] = P21_DU + "4"
    audit = write_final_registers(
        tmp_path, hit_claims_rows(), hit_error_rows(), definition_use_ledgers=ledgers)
    status, note = sf.check_channel_definition_use(audit)
    assert status == "FAIL"
    assert "Evidence Checked" in note and P21_DU in note


@pytest.mark.parametrize("kwargs, expected", [
    ({"definition_use_artifact": None}, "artifact"),
    ({"definition_use_artifact": channel_artifact(p21=False)}, "P-21"),
    ({"definition_use_plan": channel_plan(map_p21=False)}, "mapping"),
    ({"definition_use_plan": channel_plan(p21_evidence=False)}, "Likely Evidence"),
    ({"definition_use_ledgers": channel_ledgers(p21_evidence=False)}, "Evidence Checked"),
    ({"definition_use_ledgers": channel_ledgers(p21_verdict="not_error")}, "confirmed_error"),
    ({"definition_use_ledgers": channel_ledgers(d03_verdict="confirmed_error")}, "not_error"),
])
def test_definition_use_channel_rejects_broken_handoff_or_verdict(tmp_path, kwargs, expected):
    audit = write_final_registers(
        tmp_path, hit_claims_rows(), hit_error_rows(), **kwargs)
    status, note = sf.check_channel_definition_use(audit)
    assert status == "FAIL"
    assert expected in note


def test_definition_use_channel_reports_malformed_artifact(tmp_path):
    malformed = channel_artifact().replace(
        "- Standard candidates: 2", "- Standard candidates: 3")
    audit = write_final_registers(
        tmp_path, hit_claims_rows(), hit_error_rows(),
        definition_use_artifact=malformed)

    status, note = sf.check_channel_definition_use(audit)

    assert status == "FAIL"
    assert "malformed" in note and "Standard candidates count" in note


def test_definition_use_channel_rejects_d03_issue_final_status(tmp_path):
    errors = [r for r in hit_error_rows() if r[0] != "E-0090"]
    errors.append(rb.error_row(
        "E-0090", etype="sample_filter_or_flag_error", status="confirmed",
        severity="2", source="`do/analysis.do`", location="`do/analysis.do:13-16`",
        desc="baseline_diag_ok baseline-wave diagnostic is an error"))
    audit = write_final_registers(tmp_path, hit_claims_rows(), errors)
    status, note = sf.check_channel_definition_use(audit)
    assert status == "FAIL"
    assert "D-03" in note and "not_error" in note


def test_definition_use_channel_rejects_d03_claim_issue_row(tmp_path):
    claims = hit_claims_rows() + [rb.claims_row(
        "C-0090", status="inconsistent", severity="2",
        ctype="data_construction",
        issue=("baseline_diag_ok baseline-wave-only diagnostic wrongly "
               "narrows the estimation sample"))]
    audit = write_final_registers(tmp_path, claims, hit_error_rows())
    status, note = sf.check_channel_definition_use(audit)
    assert status == "FAIL"
    assert "D-03" in note and "issue row" in note


def test_definition_use_channel_rejects_d03_semantic_paraphrase(tmp_path):
    claims = hit_claims_rows() + [rb.claims_row(
        "C-0090", status="inconsistent", severity="2",
        ctype="data_construction",
        issue="The wave 1 diagnostic wrongly narrows the estimation sample.")]
    audit = write_final_registers(tmp_path, claims, hit_error_rows())

    status, note = sf.check_channel_definition_use(audit)

    assert status == "FAIL"
    assert "D-03" in note and "issue row" in note


def test_definition_use_channel_ignores_benign_wave1_diagnostic_issue(tmp_path):
    claims = hit_claims_rows() + [rb.claims_row(
        "C-0090", status="inconsistent", severity="2",
        ctype="transcription",
        issue=("The wave 1 diagnostic label is stale, but the estimation "
               "sample remains unchanged."))]
    audit = write_final_registers(tmp_path, claims, hit_error_rows())

    status, note = sf.check_channel_definition_use(audit)

    assert status == "PASS", note


def test_definition_use_channel_rejects_d03_issue_at_source_location(tmp_path):
    errors = hit_error_rows() + [rb.error_row(
        "E-0091", etype="sample_filter_or_flag_error", status="confirmed",
        severity="2", source="`do/analysis.do`", location="`do/analysis.do:13`",
        desc="A temporary marker is incorrectly reported as narrowing the sample")]
    audit = write_final_registers(tmp_path, hit_claims_rows(), errors)
    status, note = sf.check_channel_definition_use(audit)
    assert status == "FAIL"
    assert "D-03" in note and "issue row" in note


def test_definition_use_channel_rejects_p21_nonissue_final_status(tmp_path):
    errors = [r for r in hit_error_rows() if r[0] != "E-0021"]
    errors.append(rb.error_row(
        "E-0021", etype="sample_filter_or_flag_error", status="not_error",
        severity="", desc="consent_ok reviewed and cleared"))
    audit = write_final_registers(tmp_path, hit_claims_rows(), errors)
    status, note = sf.check_channel_definition_use(audit)
    assert status == "FAIL"
    assert "P-21" in note and "confirmed" in note


def test_definition_use_channel_accepts_explicit_duplicate_to_equivalent_issue(tmp_path):
    errors = [r for r in hit_error_rows() if r[0] != "E-0021"]
    errors.extend([
        rb.error_row("E-0021", etype="sample_filter_or_flag_error",
                     status="duplicate_of:E-0022", severity="",
                     desc="duplicate consent filter row"),
        rb.error_row(
            "E-0022", etype="sample_filter_or_flag_error", severity="2",
            desc=("consent_ok covers individual and community consent, but "
                  "keep if adds an individual-only conjunct that excludes "
                  "community households from Table 1.")),
    ])
    ledgers = channel_ledgers()
    ledgers[0] = rb.ledger_row(
        "E-0021", evidence=P21_DU, verdict="confirmed_error",
        change="set status=duplicate_of:E-0022")
    audit = write_final_registers(
        tmp_path, hit_claims_rows(), errors, definition_use_ledgers=ledgers)
    status, note = sf.check_channel_definition_use(audit)
    assert status == "PASS", note


def test_definition_use_channel_duplicate_rejects_not_error_verdict(tmp_path):
    errors = [r for r in hit_error_rows() if r[0] != "E-0021"]
    errors.extend([
        rb.error_row("E-0021", etype="sample_filter_or_flag_error",
                     status="duplicate_of:E-0022", severity=""),
        rb.error_row(
            "E-0022", etype="sample_filter_or_flag_error", severity="2",
            desc=("consent_ok covers individual and community consent, but "
                  "keep if excludes community households from Table 1.")),
    ])
    ledgers = channel_ledgers(p21_verdict="not_error")
    ledgers[0][6] = "set status=duplicate_of:E-0022"
    audit = write_final_registers(
        tmp_path, hit_claims_rows(), errors, definition_use_ledgers=ledgers)
    status, note = sf.check_channel_definition_use(audit)
    assert status == "FAIL"
    assert "confirmed_error" in note


def test_broken_definition_use_channel_turns_integrated_gate_red(tmp_path):
    audit = write_final_registers(
        tmp_path, hit_claims_rows(), hit_error_rows(),
        definition_use_plan=channel_plan(map_d03=False))
    res = run_scorer(audit)
    assert res.returncode == 1
    assert "Definition/use channel: FAIL" in res.stdout
    assert "GATE RED" in res.stdout


def test_below_min_severity_is_miss(tmp_path):
    """P-05 requires severity >= 4; a sev-2 row matches but does not score."""
    errors = [r for r in hit_error_rows() if r[0] != "E-0005"]
    errors.append(rb.error_row(
        "E-0005", etype="sample_filter_or_flag_error", severity="2",
        desc=("keep if waves < 2 keeps exactly the households the paper "
              "excludes (fewer than two waves).")))
    audit = write_final_registers(tmp_path, hit_claims_rows(), errors)
    res = run_scorer(audit)
    assert res.returncode == 1
    assert re.match(r"P-05: MISS", plant_line(res, "P-05"))
    assert "severity >= 4" in plant_line(res, "P-05")


def test_missing_register_is_usage_error(tmp_path):
    audit = tmp_path / "audit"
    audit.mkdir()
    res = run_scorer(audit)
    assert res.returncode == 2
    assert "not found" in res.stderr


# ------------------------------------------------- artifact-layer checks (U9)


def test_missing_manifest_artifact_turns_gate_red(tmp_path):
    audit = write_final_registers(tmp_path, hit_claims_rows(),
                                  hit_error_rows(), manifest_artifact=None)
    res = run_scorer(audit)
    assert res.returncode == 1
    assert "U2 manifest artifact: FAIL" in res.stdout
    assert "GATE RED" in res.stdout


def test_manifest_artifact_without_plant_turns_gate_red(tmp_path):
    audit = write_final_registers(tmp_path, hit_claims_rows(),
                                  hit_error_rows(),
                                  manifest_artifact=MANIFEST_ARTIFACT_CLEAN)
    res = run_scorer(audit)
    assert res.returncode == 1
    assert "U2 manifest artifact: FAIL" in res.stdout


def test_u4_u5_artifact_checks_vacuous_when_claims_flagged(tmp_path):
    audit = write_final_registers(tmp_path, hit_claims_rows(), hit_error_rows())
    res = run_scorer(audit)
    assert res.returncode == 0
    assert "U4 anchoring advisory: PASS" in res.stdout
    assert "U5 filename-parameter advisory: PASS" in res.stdout


def test_u4_advisory_fired_on_confirmed_unanchored_close(tmp_path):
    """P-19 wrongly closed confirmed with evidence that never names
    wage_earnings: register layer scores MISS, and the artifact layer records
    that the U4 tripwire fired."""
    ledger = [rb.ledger_row(
        "C-0019", status="confirmed", severity="",
        evidence=("`py/build_income.py:18` applies a 99th-percentile "
                  "winsorisation via clip"),
        verdict="substantiated", change="set status=confirmed")]
    audit = write_final_registers(
        tmp_path, hit_claims_rows(p19_branch="confirmed"), hit_error_rows(),
        ledger_rows=ledger)
    res = run_scorer(audit)
    assert res.returncode == 1  # P-19 register MISS reds the gate
    assert re.match(r"P-19: MISS", plant_line(res, "P-19"))
    assert "U4 anchoring advisory: PASS" in res.stdout
    assert "tripwire fired" in res.stdout


def test_u4_advisory_silent_on_confirmed_close_is_fail(tmp_path):
    """P-19 closed confirmed with evidence that DOES name wage_earnings: the
    lexical advisory stays silent, so the artifact check records FAIL."""
    ledger = [rb.ledger_row(
        "C-0019", status="confirmed", severity="",
        evidence=("wage_earnings winsorisation verified at "
                  "`py/build_income.py:18`"),
        verdict="substantiated", change="set status=confirmed")]
    audit = write_final_registers(
        tmp_path, hit_claims_rows(p19_branch="confirmed"), hit_error_rows(),
        ledger_rows=ledger)
    res = run_scorer(audit)
    assert res.returncode == 1
    assert "U4 anchoring advisory: FAIL" in res.stdout


def test_u5_blocked_with_note_branch_hit_and_advisory_fires(tmp_path):
    """P-20 dual-accept blocked branch: register HIT, advisory fires, gate can
    stay GREEN."""
    audit = write_final_registers(
        tmp_path, hit_claims_rows(p20_branch="blocked_with_note"),
        hit_error_rows())
    res = run_scorer(audit)
    assert res.returncode == 0, res.stdout + res.stderr
    assert re.match(r"P-20: HIT", plant_line(res, "P-20"))
    assert "blocked branch" in plant_line(res, "P-20")
    assert "U5 filename-parameter advisory: PASS" in res.stdout
    assert "tripwire fired" in res.stdout


def test_u5_silent_block_is_register_miss(tmp_path):
    audit = write_final_registers(
        tmp_path, hit_claims_rows(p20_branch="silent_block"), hit_error_rows())
    res = run_scorer(audit)
    assert res.returncode == 1
    assert re.match(r"P-20: MISS", plant_line(res, "P-20"))
    assert "silently-blocked" in plant_line(res, "P-20")


def test_u1_conventions_check_is_informative_only(tmp_path):
    """The U1 conventions-artifact check reports INFO and never settles the
    gate (worker-dependent per KTD-8) — the gate stays GREEN whether the
    artifact is present or absent."""
    conventions = (
        "# Shared conventions\n\n"
        "| Convention | Category | Stated Definition | Sites Already Seen |\n"
        "| --- | --- | --- | --- |\n"
        "| income components | enumerated_member_list | crop sales; "
        "livestock sales; wage earnings; remittances (C-0015) | "
        "`paper/paper.tex`; C-0015 |\n")
    with_artifact = write_final_registers(
        tmp_path / "a", hit_claims_rows(), hit_error_rows(),
        conventions=conventions)
    res = run_scorer(with_artifact)
    assert res.returncode == 0
    assert "U1 conventions artifact: INFO" in res.stdout
    assert "enumerated_member_list convention PRESENT" in res.stdout
    without_artifact = write_final_registers(
        tmp_path / "b", hit_claims_rows(), hit_error_rows())
    res = run_scorer(without_artifact)
    assert res.returncode == 0  # absence never reds the gate
    assert "U1 conventions artifact: INFO" in res.stdout


def test_manifest_plant_only_in_warnings_turns_gate_red(tmp_path):
    """Finding-5 regression: the plant's name appears only in the `## Warnings`
    section (zero candidate findings) — it was never actually flagged, so the
    U2 check must FAIL and red the gate rather than falsely pass on the warning
    line that names pyproject.toml outside the Candidate-findings body."""
    audit = write_final_registers(
        tmp_path, hit_claims_rows(), hit_error_rows(),
        manifest_artifact=MANIFEST_ARTIFACT_PLANT_ONLY_IN_WARNINGS)
    res = run_scorer(audit)
    assert res.returncode == 1
    assert "U2 manifest artifact: FAIL" in res.stdout
    assert "GATE RED" in res.stdout


def test_u4_advisory_tolerates_post_b8_original_columns(tmp_path):
    """Finding-1 regression: the finalized claims register carries the post-b8
    `Issue Description Original` extra column (the rewriter's staging register is
    promoted at finalize). The U4 anchoring advisory must still locate the claims
    table and fire on a confirmed-but-unanchored P-19 close. Fails before the
    header-tolerance fix (the advisory silently no-ops against the exact-header
    match -> U4 reports FAIL); passes after (the tripwire fires -> PASS)."""
    ledger = [rb.ledger_row(
        "C-0019", status="confirmed", severity="",
        evidence=("`py/build_income.py:18` applies a 99th-percentile "
                  "winsorisation via clip"),
        verdict="substantiated", change="set status=confirmed")]
    audit = write_final_registers(
        tmp_path, hit_claims_rows(p19_branch="confirmed"), hit_error_rows(),
        ledger_rows=ledger, claims_original_cols=True)
    res = run_scorer(audit)
    assert "U4 anchoring advisory: PASS" in res.stdout, res.stdout
    assert "tripwire fired" in res.stdout


def test_u4_anchoring_not_covered_when_confirmed_close_has_no_ledger_row(tmp_path):
    """NOT COVERED branch: the P-19 claim is closed confirmed but no recheck
    ledger row covers it, so the tripwire never saw it. The line reads NOT
    COVERED and contributes no red reason of its own (the register layer's P-19
    MISS is what reds the gate)."""
    audit = write_final_registers(
        tmp_path, hit_claims_rows(p19_branch="confirmed"), hit_error_rows())
    res = run_scorer(audit)
    assert "U4 anchoring advisory: NOT COVERED" in res.stdout
    assert "U4 anchoring advisory check failed" not in res.stdout
    assert re.match(r"P-19: MISS", plant_line(res, "P-19"))


def test_u5_filename_parameter_not_covered_when_row_misses_locator(tmp_path):
    """NOT COVERED branch: a blocked P-20-family row whose text does not match
    the U5 claim locator leaves the advisory with nothing to key on. The line
    reads NOT COVERED and adds no red reason of its own."""
    claims = [r for r in hit_claims_rows() if r[0] != "C-0020"]
    claims.append(rb.claims_row(
        "C-0020", status="blocked", ctype="data_construction",
        text="each village is matched to nearby rain gauges by centroid",
        source="`data/village_rain.csv`",
        blocked_check="Gauge coordinates are not shipped, so the match cannot "
                      "be re-run."))
    audit = write_final_registers(tmp_path, claims, hit_error_rows())
    res = run_scorer(audit)
    assert "U5 filename-parameter advisory: NOT COVERED" in res.stdout
    assert "U5 filename-parameter advisory check failed" not in res.stdout


def test_artifact_checks_fail_when_claims_register_unparsable(tmp_path):
    """FAIL branch: the claims register exists but carries no parsable claims
    table, so both conditional artifact checks report FAIL and red the gate."""
    audit = write_final_registers(tmp_path, hit_claims_rows(), hit_error_rows())
    (audit / "claims_register.md").write_text(
        "# Claims register\n\n| Foo | Bar |\n| --- | --- |\n| a | b |\n")
    res = run_scorer(audit)
    assert res.returncode == 1
    assert ("U4 anchoring advisory: FAIL — claims register missing or "
            "unparsable") in res.stdout
    assert ("U5 filename-parameter advisory: FAIL — claims register missing or "
            "unparsable") in res.stdout
