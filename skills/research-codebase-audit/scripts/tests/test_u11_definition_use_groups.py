"""U11 DU producer-group extension: formation, overwrite and narrowing bundles.

Tier-1 for this unit is the producer-group emitter — group formation plus both
bundle kinds it feeds.  Tests 1-3 plus the production-CLI sabotage drills live
here; every plant is freshly invented synthetic Stata.
"""

import json
import os
import subprocess
import sys

import pytest

import regbuild as rb

cs = rb.load_script("certify_stage")
dm = rb.load_script("build_detector_mapping")
du = rb.load_script("definition_use")
emitter = rb.load_script("emit_definition_use_bundles")

pytestmark = pytest.mark.u11

FILE = "do/build_flags.do"

# body, variable, producer statement, member replace, guard, rendered label.
# The rendered label is stated explicitly: Stata's abbreviations of
# ``forvalues`` all report the canonical spelling in the loop-context cell.
LOOP_PLANTS = {
    "foreach": (
        "gen enroll_ok = 0\n"
        "foreach g in alpha beta gamma {\n"
        "replace enroll_ok = 1 if cohort == \"alpha\"\n"
        "}\n",
        "enroll_ok", "gen enroll_ok = 0",
        "replace enroll_ok = 1 if cohort == \"alpha\"", "cohort == \"alpha\"",
        "foreach",
    ),
    "forvalues": (
        "gen visit_ok = .\n"
        "forvalues w = 1/3 {\n"
        "replace visit_ok = 1 if wave == 2\n"
        "}\n",
        "visit_ok", "gen visit_ok = .",
        "replace visit_ok = 1 if wave == 2", "wave == 2",
        "forvalues",
    ),
    "forval": (
        "gen route_ok = 0\n"
        "forval k = 1/4 {\n"
        "replace route_ok = 1 if leg == 2\n"
        "}\n",
        "route_ok", "gen route_ok = 0",
        "replace route_ok = 1 if leg == 2", "leg == 2",
        "forvalues",
    ),
    "forv": (
        "gen tally_ok = 0\n"
        "forv j = 1/2 {\n"
        "replace tally_ok = 1 if bin == 1\n"
        "}\n",
        "tally_ok", "gen tally_ok = 0",
        "replace tally_ok = 1 if bin == 1", "bin == 1",
        "forvalues",
    ),
    "while": (
        "gen scan_ok = 0\n"
        "while r(N) > 0 {\n"
        "replace scan_ok = 1 if batch == r(N)\n"
        "}\n",
        "scan_ok", "gen scan_ok = 0",
        "replace scan_ok = 1 if batch == r(N)", "batch == r(N)",
        "while",
    ),
}

SEQUENCE_PLANT = (
    "gen price_ok = .\n"
    "replace price_ok = 1 if unit == \"kg\"\n"
    "replace price_ok = 0\n"
)
OVERLAP_PLANT = (
    "gen stock_ok = 0\n"
    "foreach s in north south {\n"
    "replace stock_ok = 1 if depot == \"north\"\n"
    "}\n"
    "replace stock_ok = 0\n"
)
WIDENING_PLANT = (
    "gen link_ok = 0\n"
    "replace link_ok = 1\n"
    "replace link_ok = 2\n"
    "drop if site == \"\" & link_ok == 0\n"
)
CASE_ANALYSIS_TWIN = (
    "gen ration_ok = 0\n"
    "replace ration_ok = 1 if channel == \"shop\"\n"
    "replace ration_ok = 2 if channel == \"market\"\n"
)
BOOLEAN_TWIN = (
    "gen intake_ok = inlist(source, \"farm\", \"depot\")\n"
    "keep if intake_ok == 1 & round == 1\n"
)
RECREATION_TWIN = (
    "gen span_ok = 0\n"
    "replace span_ok = 1 if grade == 2\n"
    "gen span_ok = .\n"
    "replace span_ok = 2\n"
    "keep if span_ok == 1 & wave == 1\n"
)


def _package(tmp_path, body):
    root = tmp_path / "pkg"
    path = root / FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return root


def _standard_rows(tmp_path, body):
    """Emit the artifact in-process and return its parsed standard rows."""
    artifact = emitter.render_artifact(emitter.scan_package(_package(tmp_path, body)))
    return du.parse_artifact(artifact).standard_rows


def _overwrite_row(*, gen_line, variable, producer, anchor_line, consumer,
                   guard, context, member_lines):
    identity = (FILE, gen_line, variable, "overwrite")
    witness = identity + (";".join(str(line) for line in sorted(member_lines)),)
    return {
        "Bundle ID": f"DU-{emitter.short_hash(identity)}",
        "Witness ID": f"DUW-{emitter.short_hash(witness)}",
        "Identity Tuple": f"({FILE}, {gen_line}, {variable}, overwrite)",
        "Variable": variable,
        "Producer Shape": "producer_group",
        "Definition Site": f"{FILE}:{gen_line}",
        "Producer Statement": producer,
        "Consumer Site": f"{FILE}:{anchor_line}",
        "Consumer Statement": consumer,
        "Full Guard": guard,
        "Code/Comment Context": context,
        "Obligation Question": emitter.OVERWRITE_QUESTION,
    }


def _narrowing_row(*, gen_line, variable, producer, consumer_line, consumer,
                   guard, context, shape="producer_group"):
    identity = (FILE, gen_line, consumer_line, variable)
    return {
        "Bundle ID": f"DU-{emitter.short_hash(identity)}",
        "Witness ID": f"DUW-{emitter.short_hash(identity + (guard,))}",
        "Identity Tuple": f"({FILE}, {gen_line}, {consumer_line}, {variable})",
        "Variable": variable,
        "Producer Shape": shape,
        "Definition Site": f"{FILE}:{gen_line}",
        "Producer Statement": producer,
        "Consumer Site": f"{FILE}:{consumer_line}",
        "Consumer Statement": consumer,
        "Full Guard": guard,
        "Code/Comment Context": context,
        "Obligation Question": emitter.NARROWING_QUESTION,
    }


# --- Test 1: the plants fire, with exact rows -------------------------------

def _check_loop_arm(tmp_path, command):
    body, variable, producer, consumer, guard, label = LOOP_PLANTS[command]
    rows = _standard_rows(tmp_path, body)
    assert rows == [_overwrite_row(
        gen_line=1, variable=variable, producer=producer, anchor_line=3,
        consumer=consumer, guard=guard, member_lines=[3],
        context=(f"L1: {producer} / L2: {body.splitlines()[1]} / "
                 f"L3: {consumer} / L4: }} / "
                 f"L3 [loop: {label}]: {consumer}"),
    )]


@pytest.mark.parametrize("command", sorted(LOOP_PLANTS))
def test_1_loop_member_replace_emits_one_overwrite_bundle(tmp_path, command):
    _check_loop_arm(tmp_path, command)


def _labels(text):
    return emitter._loop_labels(emitter._logical_lines(text.splitlines()))


@pytest.mark.parametrize("head", [
    "forv", "forva", "forval", "forvalu", "forvalue", "forvalues", "FORVAL"])
def test_1_forvalues_abbreviations_open_a_loop_frame_as_forvalues(head):
    """Every legal abbreviation reports the canonical spelling, not its own."""
    # The head line reports its enclosing context; the body and the closing
    # brace read the frame the head pushed.
    assert _labels(f"{head} i = 1/3 {{\nreplace ok = 1\n}}\n") == [
        None, "forvalues", "forvalues"]


@pytest.mark.parametrize("head", [
    "forvx", "forvarlist", "forvaluesx", "format", "forva_ok"])
def test_2_commands_that_merely_start_with_forv_open_no_loop_frame(head):
    assert _labels(f"{head} thing {{\nreplace ok = 1\n}}\n") == [
        None, None, None]


def _check_sequence_arm(tmp_path):
    rows = _standard_rows(tmp_path, SEQUENCE_PLANT)
    assert rows == [_overwrite_row(
        gen_line=1, variable="price_ok", producer="gen price_ok = .",
        anchor_line=3, consumer="replace price_ok = 0", guard="—",
        member_lines=[2, 3],
        context=("L1: gen price_ok = . / "
                 "L2: replace price_ok = 1 if unit == \"kg\" / "
                 "L3: replace price_ok = 0 / "
                 "L2 [loop: none]: replace price_ok = 1 if unit == \"kg\" / "
                 "L3 [loop: none]: replace price_ok = 0"),
    )]


def test_1_unfiltered_later_replace_emits_one_overwrite_bundle(tmp_path):
    _check_sequence_arm(tmp_path)


def _check_overlap_arm(tmp_path):
    rows = _standard_rows(tmp_path, OVERLAP_PLANT)
    assert rows == [_overwrite_row(
        gen_line=1, variable="stock_ok", producer="gen stock_ok = 0",
        anchor_line=3, consumer="replace stock_ok = 1 if depot == \"north\"",
        guard="depot == \"north\"", member_lines=[3, 5],
        context=("L1: gen stock_ok = 0 / "
                 "L2: foreach s in north south { / "
                 "L3: replace stock_ok = 1 if depot == \"north\" / "
                 "L4: } / "
                 "L5: replace stock_ok = 0 / "
                 "L3 [loop: foreach]: replace stock_ok = 1 if depot == \"north\" / "
                 "L5 [loop: none]: replace stock_ok = 0"),
    )]


def test_1_both_triggers_still_emit_exactly_one_overwrite_bundle(tmp_path):
    _check_overlap_arm(tmp_path)


WIDENING_CONTEXT = ("L1: gen link_ok = 0 / L2: replace link_ok = 1 / "
                    "L3: replace link_ok = 2 / "
                    "L4: drop if site == \"\" & link_ok == 0")


def _check_widening_overwrite(tmp_path):
    rows = _standard_rows(tmp_path, WIDENING_PLANT)
    assert rows[:1] == [_overwrite_row(
        gen_line=1, variable="link_ok", producer="gen link_ok = 0",
        anchor_line=3, consumer="replace link_ok = 2", guard="—",
        member_lines=[2, 3],
        context=(WIDENING_CONTEXT + " / L2 [loop: none]: replace link_ok = 1"
                 " / L3 [loop: none]: replace link_ok = 2"),
    )]


def _check_widening_narrowing(tmp_path):
    rows = _standard_rows(tmp_path, WIDENING_PLANT)
    assert rows[-1:] == [_narrowing_row(
        gen_line=1, variable="link_ok", producer="gen link_ok = 0",
        consumer_line=4, consumer="drop if site == \"\" & link_ok == 0",
        guard="site == \"\" & link_ok == 0", context=WIDENING_CONTEXT,
    )]


def test_1_all_unguarded_group_feeds_both_bundle_kinds(tmp_path):
    """The widening the retired constant_then_replace shape missed."""
    assert len(_standard_rows(tmp_path, WIDENING_PLANT)) == 2
    _check_widening_overwrite(tmp_path / "a")
    _check_widening_narrowing(tmp_path / "b")


# --- Test 2: the planted good twins stay quiet ------------------------------

@pytest.mark.parametrize("body,expected", [
    (CASE_ANALYSIS_TWIN, 0),
    (BOOLEAN_TWIN, 1),
    (RECREATION_TWIN, 1),
])
def test_2_good_twins_emit_no_overwrite_bundle(tmp_path, body, expected):
    rows = _standard_rows(tmp_path, body)
    assert len(rows) == expected
    assert [row for row in rows if "overwrite" in row["Identity Tuple"]] == []


def test_2_boolean_twin_keeps_its_shape_and_eof_scan(tmp_path):
    assert _standard_rows(tmp_path, BOOLEAN_TWIN) == [_narrowing_row(
        gen_line=1, variable="intake_ok", shape="boolean_gen",
        producer="gen intake_ok = inlist(source, \"farm\", \"depot\")",
        consumer_line=2, consumer="keep if intake_ok == 1 & round == 1",
        guard="intake_ok == 1 & round == 1",
        context=("L1: gen intake_ok = inlist(source, \"farm\", \"depot\") / "
                 "L2: keep if intake_ok == 1 & round == 1"),
    )]


def test_2_recreated_variable_binds_the_consumer_to_the_second_group(tmp_path):
    rows = _standard_rows(tmp_path, RECREATION_TWIN)
    assert rows[0]["Definition Site"] == f"{FILE}:3"
    assert rows[0]["Identity Tuple"] == f"({FILE}, 3, 5, span_ok)"


# --- Test 3: the test of the test, three independent legs -------------------

def test_3_neutered_group_formation_breaks_both_bundle_kinds(tmp_path, monkeypatch):
    monkeypatch.setattr(emitter, "_group_members", lambda *_a, **_k: [])
    with pytest.raises(AssertionError):
        _check_sequence_arm(tmp_path / "overwrite")
    with pytest.raises(AssertionError):
        _check_widening_narrowing(tmp_path / "narrowing")


@pytest.mark.parametrize("command", sorted(LOOP_PLANTS))
def test_3_neutered_loop_trigger_breaks_the_loop_arm(tmp_path, monkeypatch, command):
    monkeypatch.setattr(emitter, "_loop_triggered", lambda _member: False)
    with pytest.raises(AssertionError):
        _check_loop_arm(tmp_path, command)


def test_3_neutered_loop_trigger_also_moves_the_overlap_anchor(tmp_path, monkeypatch):
    monkeypatch.setattr(emitter, "_loop_triggered", lambda _member: False)
    with pytest.raises(AssertionError):
        _check_overlap_arm(tmp_path)


def test_3_neutered_sequence_trigger_breaks_the_sequence_arms(tmp_path, monkeypatch):
    monkeypatch.setattr(emitter, "_sequence_triggered",
                        lambda _member, _position: False)
    with pytest.raises(AssertionError):
        _check_sequence_arm(tmp_path / "sequence")
    with pytest.raises(AssertionError):
        _check_widening_overwrite(tmp_path / "widening")


# --- Tier-2: stability, lifetime, witness identity, relabel -----------------

def test_previously_constant_then_replace_bundle_ids_are_unchanged(tmp_path):
    body = ("gen release_ok = 0\n"
            "replace release_ok = 1 if consent == \"individual\"\n"
            "keep if release_ok == 1 & wave == 1\n")
    rows = _standard_rows(tmp_path, body)
    identity = (FILE, 1, 3, "release_ok")
    assert [row["Bundle ID"] for row in rows] == [
        f"DU-{emitter.short_hash(identity)}"]
    assert rows[0]["Producer Shape"] == "producer_group"
    assert rows[0]["Identity Tuple"] == f"({FILE}, 1, 3, release_ok)"


def test_lifetime_boundary_ends_the_group_consumer_scan_at_recreation(tmp_path):
    body = ("gen cover_ok = 0\n"
            "replace cover_ok = 1 if zone == 2\n"
            "gen cover_ok = 0\n"
            "replace cover_ok = 1 if zone == 3\n"
            "keep if cover_ok == 1 & wave == 1\n")
    rows = _standard_rows(tmp_path, body)
    assert [row["Definition Site"] for row in rows] == [f"{FILE}:3"]


def test_changed_write_set_mints_a_new_witness_id(tmp_path):
    before = _standard_rows(tmp_path / "before", SEQUENCE_PLANT)
    after = _standard_rows(
        tmp_path / "after",
        SEQUENCE_PLANT + "replace price_ok = 1 if unit == \"lb\"\n")
    assert before[0]["Bundle ID"] == after[0]["Bundle ID"]
    assert before[0]["Witness ID"] != after[0]["Witness ID"]


def test_each_row_carries_its_own_obligation_question(tmp_path):
    rows = _standard_rows(tmp_path, WIDENING_PLANT)
    assert [row["Obligation Question"] for row in rows] == [
        emitter.OVERWRITE_QUESTION, emitter.NARROWING_QUESTION]
    assert emitter.OVERWRITE_QUESTION == (
        "Can a later write erase an earlier assignment that should persist?")


def test_count_line_is_relabelled_and_counts_gen_keyed_groups(tmp_path):
    root = _package(tmp_path, WIDENING_PLANT + RECREATION_TWIN)
    audit = root / "review-output"
    result = rb.run_script("emit_definition_use_bundles.py", root,
                           "--audit-dir", audit)
    assert result.returncode == 0, result.stdout + result.stderr
    text = (audit / "_run/definition_use_bundles.md").read_text(encoding="utf-8")
    assert "- Standard producer groups (file + gen line + variable): 2" in text
    assert "(file + variable)" not in text
    assert du.parse_artifact(text).standard_producer_groups == 2


def test_retired_shape_name_is_gone_from_the_artifact(tmp_path):
    rows = _standard_rows(tmp_path, WIDENING_PLANT)
    assert {row["Producer Shape"] for row in rows} == {"producer_group"}


# --- Production-CLI sabotage drills -----------------------------------------

CERTIFY = rb.SCRIPTS_DIR / "certify_stage.py"


def _certify(root, command, *args):
    return subprocess.run(
        [sys.executable, str(CERTIFY), command, "--package-root", str(root),
         *[str(arg) for arg in args]],
        capture_output=True, text=True,
    )


def _drill_tree(tmp_path, *, decide=True, initialize=False):
    """A real b3d chain over a package whose only DU source is an overwrite."""
    root = _package(tmp_path, SEQUENCE_PLANT)
    a = rb.AuditDir(root)
    (a.audit / "_run").mkdir(parents=True, exist_ok=True)
    (a.audit / "_run/manifest.json").write_text(json.dumps({
        "mode": "code_errors_only", "ladder_level": 1, "scope_exclusions": [],
        "off_limits": [],
        "effort_map": dict(cs.dispatch_tracking.DEFAULT_EFFORT_MAP),
    }), encoding="utf-8")
    a.write_register("code_error_register.md", rb.ERROR_COLS, [])
    if initialize:
        assert _certify(root, "init").returncode == 0
        assert _certify(root, "start", "--stage", "code_b3d").returncode == 0
    a.write_register("_run/snapshots/code_b3d/code_error_register.md",
                     rb.ERROR_COLS, [])
    assert rb.run_script("emit_definition_use_bundles.py", root,
                         "--audit-dir", a.audit).returncode == 0
    assert rb.run_script("check_manifests.py", root,
                         "--audit-dir", a.audit).returncode == 0
    rb.emit_argument_contracts(a)
    sources = dm.parse_raw_sources(a.audit)
    assert len(sources["DU"]) == 1, sources["DU"]
    source_id = next(iter(sources["DU"]))
    assert sources["DU"][source_id][0]["anchor"] == f"{FILE}:3"
    decisions = [["DU", source_id, "E-7000", "new_candidate"]] if decide else []
    rows = [rb.error_row("E-7000", etype="sample_filter_or_flag_error",
                         status="candidate", severity="2")] if decide else []
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, rows)
    a.write("_run/detector_mapping_decisions.md",
            "# Detector decisions\n\nDeclared detector Error-ID range: "
            "E-7000–E-7099\n\n" + rb.md_table(dm.DECISION_COLS, decisions))
    return root, a, source_id


def test_drill_undecided_overwrite_source_is_refused_by_the_mapping_builder(tmp_path):
    root, a, source_id = _drill_tree(tmp_path, decide=False)
    refused = rb.run_script("build_detector_mapping.py", root,
                            "--audit-dir", a.audit)
    assert refused.returncode == 1
    assert "unmapped detector source" in refused.stderr
    assert source_id in refused.stderr
    assert not (a.audit / "_run/detector_mapping.md").exists()


def _certified_drill_tree(tmp_path):
    root, a, source_id = _drill_tree(tmp_path, initialize=True)
    emitted = rb.run_script("build_detector_mapping.py", root,
                            "--audit-dir", a.audit)
    assert emitted.returncode == 0, emitted.stdout + emitted.stderr
    os.replace(a.audit / "_staging/code_error_register.md",
               a.audit / "code_error_register.md")
    finished = _certify(root, "finish", "--stage", "code_b3d",
                        "--outcome", "done")
    assert finished.returncode == 0, finished.stdout + finished.stderr
    checked = rb.run_script("build_detector_mapping.py", root,
                            "--audit-dir", a.audit, "--check")
    assert checked.returncode == 0, checked.stdout + checked.stderr
    return root, a, source_id


def test_drill_deleted_overwrite_mapping_row_is_refused_by_check(tmp_path):
    root, a, _source_id = _certified_drill_tree(tmp_path)
    mapping = a.audit / "_run/detector_mapping.md"
    mapping.write_text("\n".join(
        line for line in mapping.read_text(encoding="utf-8").splitlines()
        if not line.startswith("| DU |")) + "\n", encoding="utf-8")
    checked = rb.run_script("build_detector_mapping.py", root,
                            "--audit-dir", a.audit, "--check")
    assert checked.returncode == 1 and "exactly close" in checked.stderr


def test_drill_hand_edited_overwrite_artifact_row_is_refused_by_check(tmp_path):
    root, a, _source_id = _certified_drill_tree(tmp_path)
    artifact = a.audit / "_run/definition_use_bundles.md"
    original = artifact.read_text(encoding="utf-8")
    edited = "\n".join(line for line in original.splitlines()
                       if not line.startswith("| `DU-"))
    artifact.write_text(edited.replace("- Standard candidates: 1",
                                       "- Standard candidates: 0") + "\n",
                        encoding="utf-8")
    checked = rb.run_script("build_detector_mapping.py", root,
                            "--audit-dir", a.audit, "--check")
    assert checked.returncode == 1
    assert "decision names unknown detector source" in checked.stderr
