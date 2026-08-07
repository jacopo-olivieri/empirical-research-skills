"""U12 the path/import idiom-closure channel.

Tier-1 here is the closure guarantee and every verdict path that can emit a
``verified`` or suppress an instance: Check-A chain arithmetic, the Check-B
existence resolver with its anchor table, and each language parser's instance
recognition -- per language, with the planted-twin sabotage drill run through
the real b3d CLIs.  Everything else is Tier-2.
"""

import json

import pytest

import regbuild as rb

import emit_path_derivation_bundles as pdb

import test_u3_adjudication as u3
import test_u9c_fix_cycle as u9c

dm = rb.load_script("build_detector_mapping")

pytestmark = pytest.mark.u12


# ------------------------------------------------------------------ fixtures


def _package(tmp_path, name, files):
    root = tmp_path / name
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (root / "audit/_run").mkdir(parents=True, exist_ok=True)
    (root / "audit/_run/manifest.json").write_text(json.dumps({
        "mode": "code_errors_only", "scope_exclusions": [], "off_limits": [],
    }), encoding="utf-8")
    return root


GRID_BAD = (
    "import os\n"
    "import sys\n"
    "\n"
    "base_dir = os.path.dirname(os.path.dirname(os.path.dirname("
    "os.path.abspath(__file__))))\n"
    "sys.path.append(base_dir)\n"
    "import settings\n"
)
GRID_GOOD = GRID_BAD.replace(
    "os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))",
    "os.path.dirname(os.path.dirname(os.path.abspath(__file__)))")
AXIS_GOOD = GRID_GOOD

PY_ARM = {
    "py/run_all.py": '"""py-arm entry script."""\n\n\ndef main():\n    return 0\n',
    "py/settings.py": "pass\n",
    "py/graphs/draw_grid.py": GRID_BAD,
    "py/graphs/draw_axis.py": AXIS_GOOD,
    "py/box/__init__.py": "pass\n",
    "py/box/shapes.py": "pass\n",
    "py/box/loader.py": "from . import shapes\nfrom . import lenses\n",
    "py/tools/pack_out.py": (
        "import os\n"
        "import sys\n"
        "\n"
        "os.chdir(sys.argv[1])\n"
        'hop = getattr(os.path, "dirname")\n'
        'with open("../staging/notes.txt") as handle:\n'
        "    data = handle.read()\n"
    ),
    "py/legacy/old_export.py":
        "import os\n\nbase = os.path.dirname(__file__\nvalue = 1\n",
    "py/legacy/new_export.py": "import os\n\nbase = 1\nvalue = 1\n",
}
PY_ENTRIES = ("py/run_all.py@.",)

# The append-less config-named import: `sys.path[0]` is the ENTRY script's
# directory, never the importing module's, so a module beside the importer is
# not importable and a module beside the entry script is.
PY_IMPORT_ARM = {
    "py/__init__.py": "pass\n",
    "py/run_all.py": "from .tools import helper\nfrom .tools import twin\n",
    "py/shared_cfg.py": "pass\n",
    "py/tools/__init__.py": "pass\n",
    "py/tools/helper.py": "import settings\n",
    "py/tools/settings.py": "pass\n",
    "py/tools/twin.py": "import shared_cfg\n",
}
PY_IMPORT_ENTRIES = ("py/run_all.py@.",)

ST_ARM = {
    "do/run_chain.do": (
        "cd do\n"
        "do fold_step.do\n"
        "do roam_step.do\n"
        "do tools/join_step.do\n"
        'local lib_root "../../base_kit"\n'
        "do \"`lib_root'/load_kit.do\"\n"
        'local kit_dir "../misc"\n'
        "do \"`kit_dir'/join_step.do\"\n"
    ),
    "do/alt_chain.do": (
        "do do/fold_step.do\n"
        "#delimit ;\n"
        "do misc/join_step.do ;\n"
        "#delimit cr\n"
    ),
    "do/fold_step.do": "do helpers/tag_vars.do\n",
    "do/helpers/tag_vars.do": 'display "ok"\n',
    "do/roam_step.do": "cd \"`workpath'\"\ndo next_leg.do\n",
    "misc/join_step.do": 'display "ok"\n',
}
ST_ENTRIES = ("do/run_chain.do@.", "do/alt_chain.do@.")

R_ARM = {
    ".here": "",
    "inputs/roster.csv": "id,value\n1,2\n",
    "R/main_flow.R": (
        'source("R/plots/spark_line.R")\n'
        'source("R/plots/bar_stack.R")\n'
        'source("R/fetch_leg.R")\n'
        'roster <- here("inputs", "roster.csv")\n'
        'ledger <- here("inputs", "ledger.csv")\n'
    ),
    "R/plots/spark_line.R": 'source("../lib/palette_fns.R")\n',
    "R/plots/bar_stack.R": 'source("R/lib/palette_fns.R")\n',
    "R/lib/palette_fns.R": "invisible(NULL)\n",
    "R/fetch_leg.R": (
        'setwd(Sys.getenv("RUN_DIR"))\n'
        'source("side_calc.R")\n'
        'run_src <- do.call("source", list(leg_file))\n'
    ),
}
R_ENTRIES = ("R/main_flow.R@.",)

MIX_ARM = {
    "py/tri_run.py": (
        "import os\n"
        "import sys\n"
        "\n"
        "sys.path.append(os.path.dirname(os.path.abspath(__file__)))\n"
        "import tri_cfg\n"
    ),
    "py/tri_cfg.py": "pass\n",
    "do/tri_step.do": "cd do\ndo tri_leaf.do\n",
    "do/tri_leaf.do": 'display "ok"\n',
    "R/tri_plot.R": 'source("R/tri_leaf.R")\n',
    "R/tri_leaf.R": "invisible(NULL)\n",
    "m/glue_maps.m": 'aux = "../maps_dir";\n',
    "run_glue": "#!/bin/sh\nexit 0\n",
    "data/tri_rows.csv": "id,value\n1,2\n",
}
MIX_ENTRIES = ("py/tri_run.py@.", "do/tri_step.do@.", "R/tri_plot.R@.")

DRILL_ENTRIES = ("py/graphs/draw_grid.py@.", "do/run_chain.do@.",
                 "R/main_flow.R@.")


def drill_files(planted=("py", "do", "R")):
    """The pinned production-drill union; one broken twin per planted arm."""
    chain = "cd do\n"
    if "do" in planted:
        chain += "do tools/join_step.do\n"
    chain += 'local kit_dir "../misc"\n' + "do \"`kit_dir'/join_step.do\"\n"
    return {
        "py/graphs/draw_grid.py": GRID_BAD if "py" in planted else GRID_GOOD,
        "py/graphs/draw_axis.py": AXIS_GOOD,
        "py/settings.py": "pass\n",
        "do/run_chain.do": chain,
        "do/fold_step.do": 'display "ok"\n',
        "misc/join_step.do": 'display "ok"\n',
        "R/main_flow.R": ('source("R/plots/spark_line.R")\n'
                          'source("R/plots/bar_stack.R")\n'),
        "R/plots/spark_line.R": ('source("../lib/palette_fns.R")\n'
                                 if "R" in planted else
                                 'source("R/lib/palette_fns.R")\n'),
        "R/plots/bar_stack.R": 'source("R/lib/palette_fns.R")\n',
        "R/lib/palette_fns.R": "invisible(NULL)\n",
    }


# ------------------------------------------------------------------- helpers


def _seed(*entries):
    if not entries:
        return pdb.SeedRecord((), True)
    return pdb.SeedRecord([pdb.parse_entry_flag(entry) for entry in entries],
                          False)


def _sweep(root, *entries):
    """Render and re-parse a sweep; returns (text, parsed artifact)."""
    text = pdb.render_artifact(pdb.scan_package(root, _seed(*entries)))
    return text, pdb.parse_artifact(text)


def _failed(artifact):
    return {(source.file, source.witnesses[0].line): source
            for source in artifact.sources if source.kind == "failed"}


def _groups(artifact):
    return {source.file: source for source in artifact.sources
            if source.kind == "unchecked"}


def _reasons(artifact, relative):
    group = _groups(artifact)[relative]
    return {witness.witness_id: witness.reason for witness in group.witnesses}


def _verified(artifact):
    return {(row["File"], int(row["Line"])): row for row in artifact.verified}


def _counts(artifact):
    return artifact.counts


# =========================================================== Tier-1: closure


def test_tier1_closure_denominator_is_parsed_plus_unparsed_exactly(tmp_path):
    """(a) Every projected source file is parsed or listed unparsed."""
    root = _package(tmp_path, "mix-arm", MIX_ARM)
    report = pdb.scan_package(root, _seed(*MIX_ENTRIES))
    projection = pdb.Projection(root)
    source_files = set(projection.parsed) | {rel for rel, _ in projection.unparsed}
    assert source_files == {
        "py/tri_run.py", "py/tri_cfg.py", "do/tri_step.do", "do/tri_leaf.do",
        "R/tri_plot.R", "R/tri_leaf.R", "m/glue_maps.m", "run_glue",
    }
    parsed = set(report.parsed_files)
    unparsed = {rel for rel, _ in report.unparsed}
    assert parsed | unparsed == source_files
    assert not parsed & unparsed
    assert dict(report.unparsed) == {"m/glue_maps.m": "unsupported_language",
                                     "run_glue": "shebang_script"}


def test_tier1_closure_mix_arm_three_verified_and_no_candidate(tmp_path):
    """(a) Every instance carries exactly one of the three results."""
    root = _package(tmp_path, "mix-arm", MIX_ARM)
    text, artifact = _sweep(root, *MIX_ENTRIES)
    assert _counts(artifact) == {
        "Files parsed": 6, "Files unparsed (listed below)": 2,
        "Instances verified": 3, "Failed candidates": 0,
        "Unchecked candidate groups (files)": 0, "Unchecked lines": 0,
    }
    assert artifact.sources == []
    assert set(_verified(artifact)) == {
        ("py/tri_run.py", 4), ("do/tri_step.do", 2), ("R/tri_plot.R", 1)}
    assert artifact.unparsed == [("m/glue_maps.m", "unsupported_language"),
                                 ("run_glue", "shebang_script")]
    assert "data/tri_rows.csv" not in text
    assert pdb.CANDIDATE_ZERO in text


# ================================================ Tier-1: Python verdict paths


def test_tier1_python_test1_plants_fire_with_exact_cells(tmp_path):
    root = _package(tmp_path, "py-arm", PY_ARM)
    _text, artifact = _sweep(root, *PY_ENTRIES)

    chain = _failed(artifact)[("py/graphs/draw_grid.py", 4)]
    assert chain.witnesses[0].witness_id == "site"
    assert chain.witnesses[0].check == "A"
    assert chain.witnesses[0].idiom == "os.path.dirname"
    assert chain.witnesses[0].machine == "steps=3; depth=2; resolved=."
    assert chain.witnesses[0].question == pdb.FAILED_QUESTION

    relative_import = _failed(artifact)[("py/box/loader.py", 2)]
    assert relative_import.witnesses[0].check == "B"
    assert relative_import.witnesses[0].idiom == "relative import"
    assert relative_import.witnesses[0].machine == \
        "steps=—; depth=—; resolved=py/box/lenses.py"

    assert _reasons(artifact, "py/tools/pack_out.py") == {
        "line:4": "runtime_cwd", "line:5": "unrecognized_form",
        "line:6": "no_known_caller"}
    group = _groups(artifact)["py/tools/pack_out.py"]
    assert {witness.question for witness in group.witnesses} == \
        {pdb.UNCHECKED_QUESTION}

    failure = _groups(artifact)["py/legacy/old_export.py"]
    assert [witness.witness_id for witness in failure.witnesses] == ["file"]
    assert failure.witnesses[0].reason == "parse_failure"
    assert ("py/legacy/old_export.py", "parse_failure") in artifact.unparsed


def test_tier1_python_good_twins_stay_quiet_with_exact_counts(tmp_path):
    root = _package(tmp_path, "py-arm", PY_ARM)
    _text, artifact = _sweep(root, *PY_ENTRIES)
    assert _counts(artifact) == {
        "Files parsed": 9, "Files unparsed (listed below)": 1,
        "Instances verified": 2, "Failed candidates": 2,
        "Unchecked candidate groups (files)": 2, "Unchecked lines": 4,
    }
    verified = _verified(artifact)
    assert set(verified) == {("py/graphs/draw_axis.py", 4),
                             ("py/box/loader.py", 1)}
    axis = verified[("py/graphs/draw_axis.py", 4)]
    assert (axis["Check"], axis["Steps Counted"], axis["True Depth"],
            axis["Resolved Target"]) == ("A", "2", "2", "py")
    assert verified[("py/box/loader.py", 1)]["Resolved Target"] == \
        "py/box/shapes.py"
    assert "new_export.py" not in {source.file for source in artifact.sources}


def test_tier1_config_import_anchors_on_the_entry_script_directory(tmp_path):
    """Test 1 + 2 for the append-less config-named import (`sys.path[0]`)."""
    root = _package(tmp_path, "py-import-arm", PY_IMPORT_ARM)
    _text, artifact = _sweep(root, *PY_IMPORT_ENTRIES)
    # `settings.py` sits beside the importer, which the interpreter never sees.
    bad = _failed(artifact)[("py/tools/helper.py", 1)]
    assert bad.witnesses[0].check == "B"
    assert bad.witnesses[0].idiom == "import"
    assert bad.witnesses[0].machine == "steps=—; depth=—; resolved=py/settings.py"
    # `shared_cfg.py` sits beside the entry script, which the interpreter does.
    assert _verified(artifact)[("py/tools/twin.py", 1)]["Resolved Target"] == \
        "py/shared_cfg.py"
    assert _counts(artifact) == {
        "Files parsed": 7, "Files unparsed (listed below)": 0,
        "Instances verified": 3, "Failed candidates": 1,
        "Unchecked candidate groups (files)": 0, "Unchecked lines": 0,
    }


@pytest.mark.parametrize("entries,reason", [
    ((), "no_known_caller"),
    (("py/run_all.py@unknown",), "unresolved_anchor"),
])
def test_tier1_config_import_demotes_when_the_seed_cannot_place_it(
        tmp_path, entries, reason):
    """No entry chain, or an unknown seed, is an unchecked candidate."""
    root = _package(tmp_path, "py-import-arm", PY_IMPORT_ARM)
    _text, artifact = _sweep(root, *entries)
    # The package-anchored relative imports are seed-independent and keep their
    # verdicts; only the sys.path-anchored config imports are demoted.
    assert artifact.counts["Instances verified"] == 2
    assert artifact.counts["Failed candidates"] == 0
    assert _reason_of(artifact, "py/tools/helper.py", "line:1") == reason
    assert _reason_of(artifact, "py/tools/twin.py", "line:1") == reason


# ================================================ Tier-1: Stata verdict paths


def test_tier1_stata_test1_plants_fire_with_exact_cells(tmp_path):
    root = _package(tmp_path, "st-arm", ST_ARM)
    _text, artifact = _sweep(root, *ST_ENTRIES)
    failed = _failed(artifact)

    broken_call = failed[("do/run_chain.do", 4)]
    assert broken_call.witnesses[0].check == "B"
    assert broken_call.witnesses[0].machine == \
        "steps=—; depth=—; resolved=do/tools/join_step.do"

    up_steps = failed[("do/run_chain.do", 6)]
    assert up_steps.witnesses[0].machine == \
        "steps=2; depth=1; resolved=../base_kit/load_kit.do"

    multi_caller = failed[("do/fold_step.do", 1)]
    assert multi_caller.witnesses[0].machine == \
        "steps=—; depth=—; resolved=helpers/tag_vars.do"

    assert _reasons(artifact, "do/roam_step.do") == {
        "line:1": "runtime_cwd", "line:2": "runtime_cwd"}
    assert _reasons(artifact, "do/alt_chain.do") == {"line:3": "unrecognized_form"}
    assert _groups(artifact)["do/alt_chain.do"].witnesses[0].statement == \
        "do misc/join_step.do ;"


def test_tier1_stata_good_twins_stay_quiet_with_exact_counts(tmp_path):
    root = _package(tmp_path, "st-arm", ST_ARM)
    _text, artifact = _sweep(root, *ST_ENTRIES)
    assert _counts(artifact) == {
        "Files parsed": 6, "Files unparsed (listed below)": 0,
        "Instances verified": 4, "Failed candidates": 3,
        "Unchecked candidate groups (files)": 2, "Unchecked lines": 3,
    }
    verified = _verified(artifact)
    assert set(verified) == {("do/run_chain.do", 2), ("do/run_chain.do", 3),
                             ("do/run_chain.do", 8), ("do/alt_chain.do", 1)}
    good_twin = verified[("do/run_chain.do", 8)]
    assert (good_twin["Check"], good_twin["Steps Counted"],
            good_twin["True Depth"], good_twin["Resolved Target"]) == \
        ("B", "1", "1", "misc/join_step.do")
    assert verified[("do/run_chain.do", 2)]["Resolved Target"] == \
        "do/fold_step.do"


# ==================================================== Tier-1: R verdict paths


def test_tier1_r_test1_plants_fire_with_exact_cells(tmp_path):
    root = _package(tmp_path, "r-arm", R_ARM)
    _text, artifact = _sweep(root, *R_ENTRIES)
    failed = _failed(artifact)

    source_chain = failed[("R/plots/spark_line.R", 1)]
    assert source_chain.witnesses[0].check == "B"
    assert source_chain.witnesses[0].machine == \
        "steps=1; depth=0; resolved=../lib/palette_fns.R"

    here_miss = failed[("R/main_flow.R", 5)]
    assert here_miss.witnesses[0].idiom == "here"
    # here() walks up to the `.here` marker, never the tracked cwd.
    assert here_miss.witnesses[0].machine == \
        "steps=—; depth=—; resolved=inputs/ledger.csv"

    assert _reasons(artifact, "R/fetch_leg.R") == {
        "line:1": "runtime_cwd", "line:2": "runtime_cwd",
        "line:3": "unrecognized_form"}


def test_tier1_r_good_twins_stay_quiet_with_exact_counts(tmp_path):
    root = _package(tmp_path, "r-arm", R_ARM)
    _text, artifact = _sweep(root, *R_ENTRIES)
    assert _counts(artifact) == {
        "Files parsed": 5, "Files unparsed (listed below)": 0,
        "Instances verified": 5, "Failed candidates": 2,
        "Unchecked candidate groups (files)": 1, "Unchecked lines": 3,
    }
    verified = _verified(artifact)
    assert verified[("R/main_flow.R", 4)]["Resolved Target"] == \
        "inputs/roster.csv"
    assert verified[("R/plots/bar_stack.R", 1)]["Resolved Target"] == \
        "R/lib/palette_fns.R"


def test_tier1_here_anchor_is_the_walk_up_root_not_the_cwd(tmp_path):
    """The anchor table entry for here(): remove the marker, lose the anchor."""
    root = _package(tmp_path, "r-arm", R_ARM)
    _text, artifact = _sweep(root, *R_ENTRIES)
    assert pdb.Projection(root).here_anchor("R/main_flow.R") == "."
    (root / ".here").unlink()
    _text, artifact = _sweep(root, *R_ENTRIES)
    assert _reasons(artifact, "R/main_flow.R") == {
        "line:4": "unresolved_anchor", "line:5": "unresolved_anchor"}


# ================================================ Tier-1: Test 3, the matrix


def _neuter_parser(monkeypatch, suffix, language):
    monkeypatch.setitem(
        pdb.PARSERS, suffix,
        (language, lambda relative, _text, _projection:
         pdb.ParsedFile(relative, language)))


def _neuter_check_a(monkeypatch):
    monkeypatch.setattr(
        pdb, "_decide_check_a",
        lambda parsed_file, event, projection: pdb.Outcome("verified"))


def _neuter_check_b(monkeypatch):
    monkeypatch.setattr(pdb.Projection, "has_file", lambda self, parts: True)


def _neuter_markers(monkeypatch):
    monkeypatch.setattr(pdb, "_markers_in", lambda *_a, **_k: [])


def _neuter_parse_failure(monkeypatch):
    monkeypatch.setattr(pdb, "_parse_failure_group", lambda relative: None)


def _machine_of(artifact, relative, line):
    """The machine-numbers cell of one failed source, or None if it vanished."""
    source = _failed(artifact).get((relative, line))
    return None if source is None else source.witnesses[0].machine


def _reason_of(artifact, relative, witness_id):
    """The reason of one unchecked witness, or None if it vanished."""
    group = _groups(artifact).get(relative)
    if group is None:
        return None
    return next((witness.reason for witness in group.witnesses
                 if witness.witness_id == witness_id), None)


def _python_parser_assertion(artifact):
    assert ("py/graphs/draw_grid.py", 4) in _failed(artifact)


def _python_check_a_assertion(artifact):
    assert _machine_of(artifact, "py/graphs/draw_grid.py", 4) == \
        "steps=3; depth=2; resolved=."


def _python_check_b_assertion(artifact):
    assert ("py/box/loader.py", 2) in _failed(artifact)


def _neuter_syspath(monkeypatch):
    monkeypatch.setattr(
        pdb, "_decide_syspath",
        lambda parsed_file, event, projection, cwd, entry:
        pdb.Outcome("verified", None, None, "anywhere.py"))


def _python_syspath_assertion(artifact):
    assert _machine_of(artifact, "py/tools/helper.py", 1) == \
        "steps=—; depth=—; resolved=py/settings.py"


def _python_marker_assertion(artifact):
    assert _reason_of(artifact, "py/tools/pack_out.py", "line:5") == \
        "unrecognized_form"


def _python_parse_failure_assertion(artifact):
    assert _reason_of(artifact, "py/legacy/old_export.py", "file") == \
        "parse_failure"


def _stata_parser_assertion(artifact):
    assert ("do/run_chain.do", 4) in _failed(artifact)


def _stata_check_b_assertion(artifact):
    assert _machine_of(artifact, "do/run_chain.do", 6) == \
        "steps=2; depth=1; resolved=../base_kit/load_kit.do"


def _stata_marker_assertion(artifact):
    assert _reason_of(artifact, "do/alt_chain.do", "line:3") == \
        "unrecognized_form"


def _r_parser_assertion(artifact):
    assert ("R/plots/spark_line.R", 1) in _failed(artifact)


def _r_check_b_assertion(artifact):
    assert ("R/main_flow.R", 5) in _failed(artifact)


def _r_marker_assertion(artifact):
    assert _reason_of(artifact, "R/fetch_leg.R", "line:3") == "unrecognized_form"


VERDICT_PATH_LEGS = [
    ("python-parser", "py-arm", PY_ARM, PY_ENTRIES,
     lambda mp: _neuter_parser(mp, ".py", "Python"), _python_parser_assertion),
    ("python-check-a", "py-arm", PY_ARM, PY_ENTRIES,
     _neuter_check_a, _python_check_a_assertion),
    ("python-check-b", "py-arm", PY_ARM, PY_ENTRIES,
     _neuter_check_b, _python_check_b_assertion),
    ("python-syspath-anchor", "py-import-arm", PY_IMPORT_ARM, PY_IMPORT_ENTRIES,
     _neuter_syspath, _python_syspath_assertion),
    ("python-syspath-existence", "py-import-arm", PY_IMPORT_ARM,
     PY_IMPORT_ENTRIES, _neuter_check_b, _python_syspath_assertion),
    ("python-marker", "py-arm", PY_ARM, PY_ENTRIES,
     _neuter_markers, _python_marker_assertion),
    ("python-parse-failure", "py-arm", PY_ARM, PY_ENTRIES,
     _neuter_parse_failure, _python_parse_failure_assertion),
    ("stata-parser", "st-arm", ST_ARM, ST_ENTRIES,
     lambda mp: _neuter_parser(mp, ".do", "Stata"), _stata_parser_assertion),
    ("stata-check-b", "st-arm", ST_ARM, ST_ENTRIES,
     _neuter_check_b, _stata_check_b_assertion),
    ("stata-marker", "st-arm", ST_ARM, ST_ENTRIES,
     _neuter_markers, _stata_marker_assertion),
    ("r-parser", "r-arm", R_ARM, R_ENTRIES,
     lambda mp: _neuter_parser(mp, ".r", "R"), _r_parser_assertion),
    ("r-check-b", "r-arm", R_ARM, R_ENTRIES,
     _neuter_check_b, _r_check_b_assertion),
    ("r-marker", "r-arm", R_ARM, R_ENTRIES,
     _neuter_markers, _r_marker_assertion),
]


@pytest.mark.parametrize(
    "leg,name,files,entries,neuter,assertion",
    VERDICT_PATH_LEGS, ids=[leg[0] for leg in VERDICT_PATH_LEGS])
def test_tier1_test3_verdict_path_leg_observes_its_neuter(
        tmp_path, monkeypatch, leg, name, files, entries, neuter, assertion):
    root = _package(tmp_path, name, files)
    _text, artifact = _sweep(root, *entries)
    assertion(artifact)                      # the Test-1 assertion holds
    neuter(monkeypatch)
    _text, broken = _sweep(root, *entries)
    with pytest.raises(AssertionError):      # ... and notices the neuter
        assertion(broken)


def test_tier1_test3_closure_saboteur_file_classification(tmp_path, monkeypatch):
    root = _package(tmp_path, "mix-arm", MIX_ARM)

    def denominator_assertion():
        projection = pdb.Projection(root)
        assert set(projection.parsed) | {rel for rel, _ in projection.unparsed} == {
            "py/tri_run.py", "py/tri_cfg.py", "do/tri_step.do", "do/tri_leaf.do",
            "R/tri_plot.R", "R/tri_leaf.R", "m/glue_maps.m", "run_glue",
        }

    denominator_assertion()
    monkeypatch.setattr(pdb, "PARSED_SUFFIXES", {".py", ".r"})
    with pytest.raises(AssertionError):
        denominator_assertion()


def test_tier1_test3_closure_saboteur_unparsed_rendering(tmp_path, monkeypatch):
    root = _package(tmp_path, "mix-arm", MIX_ARM)

    def listing_assertion():
        text = pdb.render_artifact(pdb.scan_package(root, _seed(*MIX_ENTRIES)))
        assert "`m/glue_maps.m` — unsupported_language" in text

    listing_assertion()
    monkeypatch.setattr(
        pdb, "_render_unparsed",
        lambda report: ["## Unparsed files", "", pdb.UNPARSED_ZERO, ""])
    with pytest.raises(AssertionError):
        listing_assertion()


# ==================================== Tier-1: production-CLI sabotage drills


def _b3d_tree(tmp_path, name, files):
    root = _package(tmp_path, name, files)
    a = rb.AuditDir(root)
    a.write_register("code_error_register.md", rb.ERROR_COLS, [])
    a.write_register("_run/snapshots/code_b3d/code_error_register.md",
                     rb.ERROR_COLS, [])
    assert rb.run_script("emit_definition_use_bundles.py", root,
                         "--audit-dir", a.audit).returncode == 0
    assert rb.run_script("check_manifests.py", root,
                         "--audit-dir", a.audit).returncode == 0
    rb.emit_argument_contracts(a)
    emitted = rb.run_script(
        "emit_path_derivation_bundles.py", root, "--audit-dir", a.audit,
        *[flag for entry in DRILL_ENTRIES for flag in ("--entry", entry)])
    assert emitted.returncode == 0, emitted.stdout + emitted.stderr
    return root, a


ETYPES = {
    "DU": "sample_filter_or_flag_error",
    "MF": "version_or_dependency_error",
    "AC": "missing_input_or_output",
    "PD": "stale_or_wrong_path",
}


def _decide_every_source(root, a, *, skip=()):
    """Write the conductor decisions and the staged register for every source."""
    sources = dm.parse_raw_sources(a.audit)
    keys = sorted((channel, source_id) for channel in ("DU", "MF", "AC", "PD")
                  for source_id in sources[channel] if source_id not in skip)
    rows, decisions = [], []
    for index, (channel, source_id) in enumerate(keys):
        error_id = f"E-{7000 + index:04d}"
        source = sources[channel][source_id]
        if channel == "AC":
            cell = "`" + source["caller"] + "`"
            if source.get("callee"):
                cell += "; `" + source["callee"] + "`"
        elif channel == "PD":
            cell = "`" + source["file"] + "`"
        else:
            cell = "`unused.txt`"
        rows.append(rb.error_row(
            error_id, etype=ETYPES[channel], source=cell,
            location="`" + source_id + "`", status="candidate", severity="2"))
        decisions.append([channel, source_id, error_id, "new_candidate"])
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, rows)
    a.write("_run/detector_mapping_decisions.md",
            "# Detector decisions\n\nDeclared detector Error-ID range: "
            "E-7000–E-7099\n\n" + rb.md_table(dm.DECISION_COLS, decisions))
    return keys


def _run_b3d_chain(root, a):
    mapped = rb.run_script("build_detector_mapping.py", root,
                           "--audit-dir", a.audit)
    assert mapped.returncode == 0, mapped.stdout + mapped.stderr
    (a.audit / "code_error_register.md").write_text(
        (a.audit / "_staging/code_error_register.md").read_text(encoding="utf-8"),
        encoding="utf-8")
    checked = rb.run_script("build_detector_mapping.py", root,
                            "--audit-dir", a.audit, "--check")
    assert checked.returncode == 0, checked.stdout + checked.stderr
    return (a.audit / "_run/detector_mapping.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("language,plant_file", [
    ("py", "py/graphs/draw_grid.py"),
    ("do", "do/run_chain.do"),
    ("R", "R/plots/spark_line.R"),
])
def test_tier1_drill_planted_twin_reaches_mapping_and_register(
        tmp_path, language, plant_file):
    root, a = _b3d_tree(tmp_path / language, "drill", drill_files((language,)))
    _decide_every_source(root, a)
    mapping = _run_b3d_chain(root, a)
    _declared, _display, rows = dm.parse_mapping_text(mapping)
    pd_rows = [row for row in rows if row["Channel"] == "PD"]
    assert len(pd_rows) == 1
    assert pd_rows[0]["Witness ID"] == "site"
    assert pd_rows[0]["Site Anchor"].startswith(plant_file + ":")
    register = (a.audit / "code_error_register.md").read_text(encoding="utf-8")
    assert "Path-derivation finding `failed`" in register
    assert plant_file in register

    quiet_root, quiet_a = _b3d_tree(
        tmp_path / (language + "-quiet"), "drill", drill_files(()))
    _decide_every_source(quiet_root, quiet_a)
    quiet_mapping = _run_b3d_chain(quiet_root, quiet_a)
    assert dm.PD_ZERO in quiet_mapping
    assert "Path-derivation finding" not in (
        quiet_a.audit / "code_error_register.md").read_text(encoding="utf-8")


def test_tier1_drill_undecided_pd_source_refuses(tmp_path):
    root, a = _b3d_tree(tmp_path, "drill", drill_files())
    sources = dm.parse_raw_sources(a.audit)
    skipped = sorted(sources["PD"])[0]
    _decide_every_source(root, a, skip=(skipped,))
    refused = rb.run_script("build_detector_mapping.py", root,
                            "--audit-dir", a.audit)
    assert refused.returncode == 1
    assert "unmapped detector source" in refused.stderr
    assert skipped in refused.stderr


def test_tier1_drill_deleted_pd_mapping_row_refuses(tmp_path):
    root, a = _b3d_tree(tmp_path, "drill", drill_files())
    _decide_every_source(root, a)
    _run_b3d_chain(root, a)
    mapping = a.audit / "_run/detector_mapping.md"
    text = mapping.read_text(encoding="utf-8")
    kept = [line for line in text.splitlines() if not line.startswith("| PD |")]
    mapping.write_text("\n".join(kept) + "\n", encoding="utf-8")
    refused = rb.run_script("build_detector_mapping.py", root,
                            "--audit-dir", a.audit, "--check")
    assert refused.returncode == 1 and "exactly close" in refused.stderr


def test_tier1_drill_edited_pd_artifact_refuses_on_replay(tmp_path):
    """The seeded `--check` replay, reached end-to-end.

    The edit has to *survive* parse_artifact and row closure, otherwise one of
    those refuses first and the replay is never reached. So the plant is a
    lie in a Verified-instances cell: counts, candidate rows, and source IDs
    are all untouched, and only re-running the emitter can notice.
    """
    root, a = _b3d_tree(tmp_path, "drill", drill_files())
    _decide_every_source(root, a)
    _run_b3d_chain(root, a)
    raw = a.audit / "_run/path_derivation_bundles.md"
    text = raw.read_text(encoding="utf-8")
    tampered = text.replace("| py/graphs/draw_axis.py | 4 | os.path.dirname | A | 2 | 2 | py |",
                            "| py/graphs/draw_axis.py | 4 | os.path.dirname | A | 3 | 2 | py |")
    assert tampered != text
    raw.write_text(tampered, encoding="utf-8")
    # The tampered artifact still parses and still closes every mapped row.
    pdb.parse_artifact(tampered)
    dm.parse_raw_sources(a.audit)
    refused = rb.run_script("build_detector_mapping.py", root,
                            "--audit-dir", a.audit, "--check")
    assert refused.returncode == 1
    assert "detector artifact is stale or edited" in refused.stderr
    assert "path_derivation_bundles.md" in refused.stderr


def test_tier1_reordered_pd_section_trips_the_byte_check(tmp_path):
    """Row closure compares sorted tuples; only the byte check sees order."""
    root, a = _b3d_tree(tmp_path, "drill", drill_files())
    _decide_every_source(root, a)
    _run_b3d_chain(root, a)
    mapping = a.audit / "_run/detector_mapping.md"
    lines = mapping.read_text(encoding="utf-8").splitlines(keepends=True)
    pd_indexes = [index for index, line in enumerate(lines)
                  if line.startswith("| PD |")]
    assert len(pd_indexes) >= 2
    first, last = pd_indexes[0], pd_indexes[-1]
    lines[first], lines[last] = lines[last], lines[first]
    mapping.write_text("".join(lines), encoding="utf-8")
    refused = rb.run_script("build_detector_mapping.py", root,
                            "--audit-dir", a.audit, "--check")
    assert refused.returncode == 1
    assert "emitted PD section differs byte-for-byte" in refused.stderr


# ============================================================= Tier-2: seeds


def test_seed_refuses_when_neither_form_is_given(tmp_path):
    root = _package(tmp_path, "py-arm", PY_ARM)
    refused = rb.run_script("emit_path_derivation_bundles.py", root,
                            "--audit-dir", root / "audit")
    assert refused.returncode == 2 and "no invocation seed" in refused.stderr
    both = rb.run_script(
        "emit_path_derivation_bundles.py", root, "--audit-dir", root / "audit",
        "--entry", "py/run_all.py@.", "--no-documented-invocation")
    assert both.returncode == 2 and "mutually exclusive" in both.stderr


def test_seed_no_documented_invocation_demotes_cwd_anchored_check_b(tmp_path):
    root = _package(tmp_path, "st-arm", ST_ARM)
    _text, seeded = _sweep(root, *ST_ENTRIES)
    text, artifact = _sweep(root)
    assert artifact.seed == pdb.SeedRecord((), True)
    assert "- No documented invocation." in text
    assert artifact.counts["Failed candidates"] == 0
    assert artifact.counts["Instances verified"] == 0
    assert seeded.counts["Failed candidates"] == 3
    assert _reasons(artifact, "do/run_chain.do")["line:2"] == "no_known_caller"


def test_seed_unknown_cwd_demotes_check_b_but_keeps_check_a(tmp_path):
    root = _package(tmp_path, "py-arm", PY_ARM)
    text, artifact = _sweep(root, "py/run_all.py@unknown")
    assert artifact.seed.entries == (("py/run_all.py", "unknown"),)
    assert "- Entry: `py/run_all.py` @ `unknown`" in text
    # Check A is anchor-independent and keeps its verdict under an unknown seed.
    assert ("py/graphs/draw_grid.py", 4) in _failed(artifact)
    assert ("py/graphs/draw_axis.py", 4) in _verified(artifact)


def test_seed_record_round_trips_into_replay_flags(tmp_path):
    root = _package(tmp_path, "mix-arm", MIX_ARM)
    _text, artifact = _sweep(root, *MIX_ENTRIES)
    assert artifact.seed.flags() == [
        "--entry", "py/tri_run.py@.", "--entry", "do/tri_step.do@.",
        "--entry", "R/tri_plot.R@."]
    assert pdb.SeedRecord((), True).flags() == ["--no-documented-invocation"]


def test_seed_replay_reproduces_the_artifact_byte_for_byte(tmp_path):
    root = _package(tmp_path, "st-arm", ST_ARM)
    audit = root / "audit"
    first = rb.run_script(
        "emit_path_derivation_bundles.py", root, "--audit-dir", audit,
        *[flag for entry in ST_ENTRIES for flag in ("--entry", entry)])
    assert first.returncode == 0, first.stdout + first.stderr
    payload = (audit / "_run/path_derivation_bundles.md").read_bytes()
    seed = dm.path_derivation_seed(audit)
    replay = rb.run_script(
        "emit_path_derivation_bundles.py", root, "--audit-dir", audit,
        *seed.flags(), "-o", root / "replay.md")
    assert replay.returncode == 0, replay.stdout + replay.stderr
    assert (root / "replay.md").read_bytes() == payload


def test_seed_malformed_header_is_a_parse_failure(tmp_path):
    root = _package(tmp_path, "mix-arm", MIX_ARM)
    text, _artifact = _sweep(root, *MIX_ENTRIES)
    broken = text.replace("- Entry: `py/tri_run.py` @ `.`", "- Entry: py/tri_run.py")
    with pytest.raises(pdb.PathDerivationError, match="seed record"):
        pdb.parse_artifact(broken)
    with pytest.raises(pdb.PathDerivationError, match="invocation seed"):
        pdb.parse_artifact(text.replace("## Invocation seed", "## Seed"))
    with pytest.raises(pdb.PathDerivationError, match="relative path"):
        pdb.parse_entry_flag("../outside.py@.")


# ================================================== Tier-2: artifact parsing


def test_parse_artifact_enforces_counts_and_closed_vocabulary(tmp_path):
    root = _package(tmp_path, "py-arm", PY_ARM)
    text, _artifact = _sweep(root, *PY_ENTRIES)
    with pytest.raises(pdb.PathDerivationError, match="verified count"):
        pdb.parse_artifact(text.replace("- Instances verified: 2",
                                        "- Instances verified: 3"))
    with pytest.raises(pdb.PathDerivationError, match="unchecked line count"):
        pdb.parse_artifact(text.replace("- Unchecked lines: 4",
                                        "- Unchecked lines: 5"))
    with pytest.raises(pdb.PathDerivationError, match="invalid reason"):
        pdb.parse_artifact(text.replace("reason=runtime_cwd", "reason=vibes"))
    with pytest.raises(pdb.PathDerivationError, match="parse-failure witness rule"):
        pdb.parse_artifact(text.replace("reason=parse_failure",
                                        "reason=unresolved_target"))
    with pytest.raises(pdb.PathDerivationError, match="witness ID site"):
        pdb.parse_artifact(text.replace("| PD-001 | site |", "| PD-001 | line:2 |"))
    with pytest.raises(pdb.PathDerivationError, match="unparsed file"):
        pdb.parse_artifact(text.replace("— parse_failure", "— gremlins"))


def test_parse_artifact_enforces_sequential_source_ids(tmp_path):
    root = _package(tmp_path, "py-arm", PY_ARM)
    text, artifact = _sweep(root, *PY_ENTRIES)
    assert [source.source_id for source in artifact.sources] == [
        "PD-001", "PD-002", "PD-003", "PD-004"]
    with pytest.raises(pdb.PathDerivationError, match="sequential"):
        pdb.parse_artifact(text.replace("PD-002", "PD-007"))


def test_render_is_deterministic_across_reruns(tmp_path):
    root = _package(tmp_path, "st-arm", ST_ARM)
    first, _a = _sweep(root, *ST_ENTRIES)
    second, _b = _sweep(root, *ST_ENTRIES)
    assert first == second


def test_zero_case_renders_every_explicit_zero(tmp_path):
    root = _package(tmp_path, "empty", {"notes.txt": "nothing here\n"})
    text, artifact = _sweep(root)
    assert pdb.VERIFIED_ZERO in text and pdb.CANDIDATE_ZERO in text
    assert pdb.UNPARSED_ZERO in text
    assert artifact.counts["Files parsed"] == 0


# ============================================= Tier-2: mapping-builder wiring


def test_pd_is_the_fifth_channel_appended_last(tmp_path):
    assert dm.MARKERS[4] == "<!-- GENERATED:PD -->"
    assert dm.CHANNELS == ("DU", "MF", "CV", "AC", "PD")
    root, a = _b3d_tree(tmp_path, "drill", drill_files())
    _decide_every_source(root, a)
    mapping = _run_b3d_chain(root, a)
    positions = [mapping.index(marker) for marker in dm.MARKERS]
    assert positions == sorted(positions)
    assert dm.DU_ZERO in mapping and dm.MF_ZERO in mapping
    _declared, _display, rows = dm.parse_mapping_text(mapping)
    assert {row["Mapping Kind"] for row in rows if row["Channel"] == "PD"} == \
        {"new_candidate"}


def test_pd_decision_rejects_existing_row_and_unknown_channel(tmp_path):
    root, a = _b3d_tree(tmp_path, "drill", drill_files())
    _decide_every_source(root, a)
    path = a.audit / "_run/detector_mapping_decisions.md"
    text = path.read_text(encoding="utf-8")
    pd_line = next(line for line in text.splitlines()
                   if line.startswith("| PD |"))
    path.write_text(
        text.replace(pd_line, pd_line.replace("new_candidate", "existing_row")),
        encoding="utf-8")
    with pytest.raises(dm.MappingError, match="must use Mapping Kind new_candidate"):
        dm.parse_decisions(path)
    path.write_text(text.replace("| PD |", "| XX |"), encoding="utf-8")
    with pytest.raises(dm.MappingError, match="unsupported channel"):
        dm.parse_decisions(path)


def test_pd_row_must_carry_the_pinned_error_type_and_source_file(tmp_path):
    root, a = _b3d_tree(tmp_path, "drill", drill_files())
    _decide_every_source(root, a)
    staged = a.audit / "_staging/code_error_register.md"
    text = staged.read_text(encoding="utf-8")
    staged.write_text(text.replace("stale_or_wrong_path", "weighting_error"),
                      encoding="utf-8")
    refused = rb.run_script("build_detector_mapping.py", root,
                            "--audit-dir", a.audit)
    assert refused.returncode == 1 and "stale_or_wrong_path" in refused.stderr

    staged.write_text(
        text.replace("`R/plots/spark_line.R`", "`somewhere/else.R`"),
        encoding="utf-8")
    missing = rb.run_script("build_detector_mapping.py", root,
                            "--audit-dir", a.audit)
    assert missing.returncode == 1 and "Code/Data Source omits" in missing.stderr


def test_pd_stamp_is_written_once_and_must_survive(tmp_path):
    root, a = _b3d_tree(tmp_path, "drill", drill_files())
    _decide_every_source(root, a)
    _run_b3d_chain(root, a)
    staged = (a.audit / "_staging/code_error_register.md").read_text(
        encoding="utf-8")
    stamp = dm.path_derivation_stamp(
        "failed", "site", "py/graphs/draw_grid.py", 4, "os.path.dirname", "A",
        "base_dir = os.path.dirname(os.path.dirname(os.path.dirname("
        "os.path.abspath(__file__))))", "steps=3; depth=2; resolved=.", None)
    assert staged.count(stamp) == 1
    # The emit-time pass is idempotent: a second run appends nothing.
    assert rb.run_script("build_detector_mapping.py", root,
                         "--audit-dir", a.audit).returncode == 0
    assert (a.audit / "_staging/code_error_register.md").read_text(
        encoding="utf-8").count(stamp) == 1

    # A worker that strips a complete machine-written sentence is caught by
    # the certification re-run, which never re-stamps.
    stripped = (a.audit / "code_error_register.md").read_text(
        encoding="utf-8").replace(stamp, "")
    (a.audit / "code_error_register.md").write_text(stripped, encoding="utf-8")
    refused = rb.run_script("build_detector_mapping.py", root,
                            "--audit-dir", a.audit, "--check")
    assert refused.returncode == 1
    assert "machine-written witness stamp" in refused.stderr


def test_unchecked_pd_source_fans_out_one_witness_per_line(tmp_path):
    root, a = _b3d_tree(tmp_path, "grouped", dict(
        drill_files(()), **{"py/tools/pack_out.py": PY_ARM["py/tools/pack_out.py"]}))
    sources = dm.parse_raw_sources(a.audit)
    group = sources["PD"][sorted(sources["PD"])[0]]
    assert group["kind"] == "unchecked"
    assert [witness["witness_id"] for witness in group["witnesses"]] == [
        "line:4", "line:5", "line:6"]
    assert [witness["anchor"] for witness in group["witnesses"]] == [
        "py/tools/pack_out.py:4", "py/tools/pack_out.py:5",
        "py/tools/pack_out.py:6"]


PIPE_STATEMENT = "keep if source==1 | source==2"


def test_pipe_in_a_stamped_statement_survives_the_register_round_trip(tmp_path):
    """A boolean-or in audited source must not corrupt the staged register."""
    files = dict(drill_files(()))
    files["do/pipe_step.do"] = PIPE_STATEMENT + "\n"
    root, a = _b3d_tree(tmp_path, "piped", files)
    raw = pdb.parse_artifact(
        (a.audit / "_run/path_derivation_bundles.md").read_text(encoding="utf-8"))
    witness = _groups(raw)["do/pipe_step.do"].witnesses[0]
    assert witness.statement == PIPE_STATEMENT
    _decide_every_source(root, a)
    _run_b3d_chain(root, a)

    staged = (a.audit / "_staging/code_error_register.md").read_text(
        encoding="utf-8")
    stamp = dm.path_derivation_stamp(
        "unchecked", witness.witness_id, "do/pipe_step.do", witness.line,
        witness.idiom, witness.check, PIPE_STATEMENT, witness.machine,
        witness.reason)
    assert stamp not in staged                       # it is stored escaped
    assert dm.unescape_cell(staged).count(stamp) == 1
    # Every register row still has exactly the canonical cell count.
    rows = dm.parse_register(a.audit / "_staging/code_error_register.md")
    assert rows
    # Re-running emit is idempotent: no second copy of the stamp.
    assert rb.run_script("build_detector_mapping.py", root,
                         "--audit-dir", a.audit).returncode == 0
    assert dm.unescape_cell(
        (a.audit / "_staging/code_error_register.md").read_text(
            encoding="utf-8")).count(stamp) == 1
    checked = rb.run_script("build_detector_mapping.py", root,
                            "--audit-dir", a.audit, "--check")
    assert checked.returncode == 0, checked.stdout + checked.stderr


def test_escape_cell_is_idempotent_and_round_trips():
    assert dm.escape_cell("a | b") == "a \\| b"
    assert dm.escape_cell(dm.escape_cell("a | b")) == "a \\| b"
    assert dm.unescape_cell(dm.escape_cell("a | b")) == "a | b"


def test_missing_pd_artifact_is_a_refusal_never_zero(tmp_path):
    root, a = _b3d_tree(tmp_path, "drill", drill_files())
    (a.audit / "_run/path_derivation_bundles.md").unlink()
    with pytest.raises(dm.MappingError, match="missing raw detector artifact"):
        dm.parse_raw_sources(a.audit)


def test_stage_obligation_lists_the_pd_artifact_before_the_mapping(tmp_path):
    cs = rb.load_script("certify_stage")
    patterns = [item.get("pattern") for item in cs.load_obligations()["code_b3d"]]
    assert patterns.index("_run/path_derivation_bundles.md") < \
        patterns.index("_run/detector_mapping.md")


def test_pd_dismissal_uses_the_digest_typed_record_schema():
    lintmod = rb.load_script("lint_registers")
    assert lintmod.DIGEST_RECORD_CHANNELS == {"MF", "PD"}
    assert dm.STAMP_CHANNELS == ("AC", "PD")


# ============================ the two sanctioned lint extensions, behaviourally


def _pd_stamp_case(tmp_path, *, stamped=True):
    """A b6 case whose single mapped row is PD, stamped or stripped."""
    witness_id = "line:2"
    statement = 'open("../out.txt")'
    stamp = dm.path_derivation_stamp(
        "unchecked", witness_id, "source.py", 2, "path literal", pdb.DASH,
        statement, "reason=no_known_caller", "no_known_caller")
    root, a = u9c._minimal_b6_case(
        tmp_path, channel="PD", source_id="PD-001", witness_id=witness_id,
        verdict="confirmed_error", accepted=False,
        stamp=(stamp if stamped else "detector candidate description"),
        pd_statement=statement,
    )
    return root, a, stamp


def _b6_errors(a):
    lintmod = rb.load_script("lint_registers")
    state = lintmod.Lint()
    lintmod.check_detector_mapping_b6(state, a.audit)
    return state.errors


def test_tier1_b6_stamp_survival_lint_fires_on_a_stripped_pd_stamp(tmp_path):
    """Test 1 for the channel-keyed b6 stamp-survival extension."""
    _root, a, _stamp = _pd_stamp_case(tmp_path, stamped=False)
    errors = _b6_errors(a)
    assert any("PD-mapped Error ID E-7000 stripped the complete "
               "machine-written stamp for witness line:2" in error
               for error in errors), errors


def test_tier1_b6_stamp_survival_lint_stays_quiet_when_the_pd_stamp_survives(
        tmp_path):
    """Test 2: a preserved stamp raises nothing about stamps."""
    _root, a, _stamp = _pd_stamp_case(tmp_path, stamped=True)
    assert not [error for error in _b6_errors(a) if "stamp" in error]


def test_tier1_b6_stamp_survival_lint_test3_reverting_the_guard_goes_silent(
        tmp_path, monkeypatch):
    """Test 3: narrow the channel guard back to AC and the lint stops seeing."""
    _root, a, _stamp = _pd_stamp_case(tmp_path, stamped=False)
    lintmod = rb.load_script("lint_registers")
    monkeypatch.setattr(lintmod.detector_mapping, "STAMP_CHANNELS", ("AC",))
    state = lintmod.Lint()
    lintmod.check_detector_mapping_b6(state, a.audit)
    assert not [error for error in state.errors if "stamp" in error]


def _pd_dismissal_case(tmp_path, name):
    directory = tmp_path / name
    directory.mkdir(parents=True, exist_ok=True)
    return u3._case(directory, channel="PD", verdict="not_error")


def _b5_code_errors(a, shard):
    """Run the b5-code shard validation in-process so it can be monkeypatched."""
    lintmod = rb.load_script("lint_registers")
    state = lintmod.Lint()
    manifest = json.loads(
        (a.audit / "_run/manifest.json").read_text(encoding="utf-8"))
    lintmod.stage_b5(state, a.audit, "code", shard, manifest)
    return lintmod, state


def test_tier1_record_schema_xor_accepts_digest_and_rejects_probe_for_pd(
        tmp_path):
    """Tests 1 and 2 for the widened verification-record schema XOR."""
    _root, a, shard, _ledger, _mapping = _pd_dismissal_case(tmp_path, "good")
    result = rb.lint(a, "b5-code", shard)
    assert result.returncode == 0, result.stdout + result.stderr

    _root, a, shard, _ledger, _mapping = _pd_dismissal_case(tmp_path, "bad")
    text = shard.read_text(encoding="utf-8")
    probe = rb.md_table(rb.PROBE_VERIFICATION_COLS, [[
        "PD", "VR-0001", u3.PD_SOURCE, u3.PD_WITNESS,
        "the path resolves", "probe.py", "accepted", "py/pack_out.py:6",
        "na"]])
    digest_header = "| " + " | ".join(rb.MF_VERIFICATION_COLS) + " |"
    keep, dropping = [], False
    for line in text.splitlines(keepends=True):
        if line.rstrip("\n") == digest_header:
            dropping = True
            keep.append(probe)
            continue
        if dropping:
            if line.lstrip().startswith("|"):
                continue
            dropping = False
        keep.append(line)
    shard.write_text("".join(keep), encoding="utf-8")
    refused = rb.lint(a, "b5-code", shard)
    assert refused.returncode == 1
    assert "wrong channel-typed schema" in refused.stdout + refused.stderr


def test_tier1_record_schema_xor_test3_reverting_it_goes_silent(
        tmp_path, monkeypatch):
    """Test 3: narrow the XOR back to MF-only and the digest PD record trips."""
    _root, a, shard, _ledger, _mapping = _pd_dismissal_case(tmp_path, "case")
    lintmod, state = _b5_code_errors(a, shard)
    assert not [error for error in state.errors
                if "wrong channel-typed schema" in error], state.errors
    monkeypatch.setattr(lintmod, "DIGEST_RECORD_CHANNELS", {"MF"})
    narrowed = lintmod.Lint()
    manifest = json.loads(
        (a.audit / "_run/manifest.json").read_text(encoding="utf-8"))
    lintmod.stage_b5(narrowed, a.audit, "code", shard, manifest)
    assert [error for error in narrowed.errors
            if "wrong channel-typed schema" in error]


def test_instruction_files_name_the_pd_channel():
    skill = (rb.SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
    assert "scripts/emit_path_derivation_bundles.py" in skill
    assert "DU/MF/AC/PD detector emission" in skill
    pipeline = (rb.SKILL_DIR / "references/pipeline-code-errors.md").read_text(
        encoding="utf-8")
    assert "--no-documented-invocation" in pipeline
    assert "DU/MF/AC/PD source" in pipeline or \
        "per standard DU/MF/AC/PD source" in pipeline
    second_read = (rb.SKILL_DIR
                   / "references/prompts/second-read-worker.md").read_text(
        encoding="utf-8")
    assert ("Examine every path derivation and relative call in files listed as\n"
            "unparsed in audit/_run/path_derivation_bundles.md: does each resolve\n"
            "correctly under the package's documented invocation?") in second_read
    registers = (rb.SKILL_DIR / "references/registers.md").read_text(
        encoding="utf-8")
    assert "MF/PD or DU/CV" in registers
    recheck = (rb.SKILL_DIR
               / "references/prompts/recheck-cluster-worker.md").read_text(
        encoding="utf-8")
    assert "MF/PD or DU/CV" in recheck
