"""U11 AC macro-fronted extension: cross-file globals and unresolved_interpreter.

Tier 2 per the unit's roster: five pinned fixtures plus the namespace rules.
All plants are freshly invented synthetic material.
"""

import json

import pytest

import regbuild as rb

ac = rb.load_script("check_argument_contracts")

pytestmark = pytest.mark.u11

FIXTURES = {
    # (a) cross-file root global + an argument the callee never reads.
    "do/paths.do": (
        "global proj_root \"[BASE PATH]/study\"\n"
        "global out_dir \"data/derived\"\n"
        "global mix_exe \"tools/mix_a\"\n"
        "global shared_root \"[SHARED PATH]/base\"\n"
        "global code_dir \"jl\"\n"
    ),
    # (e) the conflicting value, and the equal-value duplicate controls.
    "do/alt_paths.do": (
        "global mix_exe \"tools/mix_b\"\n"
        "global shared_root \"[SHARED PATH]/base\"\n"
        "global code_dir \"jl\"\n"
    ),
    "do/master.do": (
        "global out_dir \"data/final\"\n"
        "local out_dir \"wrong/dir\"\n"
        "shell julia \"${proj_root}/jl/compute.jl\" \"${proj_root}\" \"out/tab1\"\n"
        "shell \"${runner_exe}\" jl/first.jl jl/second.jl\n"
        "shell python \"py/pack.py\" \"${out_dir}/a.csv\"\n"
        "shell \"${zip_exe}\" archive data/raw\n"
        "shell \"${mix_exe}\" jl/mix.jl\n"
        "shell python \"${shared_root}/py/ping.py\"\n"
        "shell julia \"${code_dir}/compute.jl\" \"out/tab9\"\n"
    ),
    "jl/compute.jl": "println(ARGS[1])\n",
    "jl/first.jl": "println(\"first\")\n",
    "jl/second.jl": "println(\"second\")\n",
    "jl/mix.jl": "println(\"mix\")\n",
    "py/pack.py": "import sys\nprint(sys.argv[1])\n",
    "py/ping.py": "print('ping')\n",
}

ANCHORS = {
    "a": "do/master.do:3@call=1",
    "b": "do/master.do:4@call=1",
    "c": "do/master.do:5@call=1",
    "d": "do/master.do:6@call=1",
    "e": "do/master.do:7@call=1",
    "e_control": "do/master.do:8@call=1",
    "segment": "do/master.do:9@call=1",
}


def _package(tmp_path, files):
    root = tmp_path / "package"
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    audit = root / "audit"
    (audit / "_run").mkdir(parents=True, exist_ok=True)
    (audit / "_run/manifest.json").write_text(json.dumps({
        "mode": "code_errors_only", "ladder_level": 1,
        "scope_exclusions": [], "off_limits": [],
    }), encoding="utf-8")
    return root, audit


@pytest.fixture(scope="module")
def artifact(tmp_path_factory):
    root, audit = _package(tmp_path_factory.mktemp("ac"), FIXTURES)
    scanned = ac.scan(root, audit)
    # The artifact must survive its own parser, including the new vocabulary.
    return ac.parse_artifact(ac.render(scanned))


def _call(artifact, key):
    return next((row for row in artifact.call_sites
                 if row.site_anchor == ANCHORS[key]), None)


def _findings(artifact, key):
    return [row for row in artifact.findings
            if row.site_anchor == ANCHORS[key]]


def _pair(artifact, key):
    """The call row and its linked finding rows, asserted as a pair."""
    return _call(artifact, key), _findings(artifact, key)


def test_fixture_a_cross_file_macro_reports_the_unread_argument(artifact):
    call, findings = _pair(artifact, "a")
    assert call is not None
    assert (call.resolution, call.resolved_callee, call.outcome) == (
        "audited_root_alias", "jl/compute.jl", "contract_mismatch")
    assert call.interpreter == "julia"
    assert (call.passed_positions, call.read_positions) == ((1, 2), (1,))
    assert [(row.witness_id, row.finding_kind, row.argument_position,
             row.callee_path) for row in findings] == [
        ("argpos:2", "passed_but_unread", "2", "jl/compute.jl")]


def test_fixture_b_unknown_macro_with_script_tokens_is_visible(artifact):
    call, findings = _pair(artifact, "b")
    assert call is not None
    assert (call.resolution, call.outcome) == (
        "unresolved_interpreter", "unresolved_callee")
    assert call.interpreter == "unknown"
    # The FIRST later script token is the callee candidate; jl/second.jl is
    # never reached.
    assert call.callee_token == "jl/first.jl"
    assert call.resolved_callee == "jl/first.jl"
    assert (call.passed_positions, call.read_positions) == ((), ())
    assert [(row.witness_id, row.finding_kind, row.argument_position,
             row.callee_path) for row in findings] == [
        ("callsite", "unresolved_callee", "—", "jl/first.jl")]


def test_fixture_c_same_file_global_wins_and_the_call_is_quiet(artifact):
    call, findings = _pair(artifact, "c")
    assert call is not None
    assert (call.resolution, call.resolved_callee, call.outcome) == (
        "macro_direct", "py/pack.py", "consumed")
    assert call.interpreter == "python"
    assert (call.passed_positions, call.read_positions) == ((1,), (1,))
    assert findings == []


def test_fixture_c_expansion_uses_the_same_file_global_not_the_local(tmp_path):
    root, _audit = _package(tmp_path, FIXTURES)
    files = [root / relative for relative in FIXTURES]
    table = ac.stata_global_table(files)
    calls = ac._invocations(root / "do/master.do", root, table)
    tokens = next(raw.tokens for raw in calls if raw.line == 5)
    assert tokens == ("python", "py/pack.py", "data/final/a.csv")


def test_fixture_d_macro_front_without_a_script_token_stays_dropped(artifact):
    assert _call(artifact, "d") is None
    assert _findings(artifact, "d") == []


def test_fixture_e_conflicting_cross_file_values_fall_to_the_fallback(artifact):
    call, findings = _pair(artifact, "e")
    assert call is not None
    assert (call.resolution, call.outcome) == (
        "unresolved_interpreter", "unresolved_callee")
    assert call.interpreter == "unknown"
    assert call.callee_token == "jl/mix.jl"
    assert call.resolved_callee == "jl/mix.jl"
    assert (call.passed_positions, call.read_positions) == ((), ())
    assert [(row.witness_id, row.finding_kind, row.argument_position,
             row.callee_path) for row in findings] == [
        ("callsite", "unresolved_callee", "—", "jl/mix.jl")]


def test_fixture_e_equal_values_in_two_files_never_conflict(artifact):
    call, findings = _pair(artifact, "e_control")
    assert call is not None
    assert (call.resolution, call.resolved_callee, call.outcome) == (
        "audited_root_alias", "py/ping.py", "consumed")
    assert call.interpreter == "python"
    assert (call.passed_positions, call.read_positions) == ((), ())
    assert findings == []


def test_cross_file_directory_segment_resolves_only_through_the_table(artifact):
    """The one row that discriminates a threaded table from no table at all.

    ``code_dir`` supplies a directory *segment*, not a placeholder root, and is
    assigned the same literal in two projected files.  Resolving it expands the
    callee to a projected path, so the row reads ``macro_direct``.  Drop the
    cross-file table — or let equal values conflict, or leave the name
    undefined — and the token stays unexpanded, the suffix rescue takes over,
    and the row degrades to ``audited_root_alias``.
    """
    call, findings = _pair(artifact, "segment")
    assert call is not None
    assert (call.resolution, call.resolved_callee, call.outcome) == (
        "macro_direct", "jl/compute.jl", "consumed")
    assert call.interpreter == "julia"
    assert call.callee_token == "jl/compute.jl"
    assert (call.passed_positions, call.read_positions) == ((1,), (1,))
    assert findings == []


def test_conflicting_names_leave_the_table_and_equal_ones_stay(tmp_path):
    root, _audit = _package(tmp_path, FIXTURES)
    table = ac.stata_global_table([root / relative for relative in FIXTURES])
    assert "mix_exe" not in table
    assert table["code_dir"] == "jl"
    assert table["shared_root"] == "[SHARED PATH]/base"
    assert table["proj_root"] == "[BASE PATH]/study"
    # Locals never enter the package-wide global table.
    assert "wrong/dir" not in table.values()


def test_every_call_site_carries_a_known_resolution(artifact):
    assert {row.resolution for row in artifact.call_sites} <= ac.RESOLUTIONS
    assert "unresolved_interpreter" in ac.RESOLUTIONS
    assert ac.FINDING_KINDS == {
        "passed_but_unread", "read_but_never_passed", "unresolved_callee"}
    assert ac.OUTCOMES == {"consumed", "contract_mismatch", "unresolved_callee"}


# --- namespace rules --------------------------------------------------------

def test_stata_namespaces_never_merge():
    scope = ac.MacroScope({"root": "from_global"}, {"root": "from_local"})
    assert ac._expand_text("${root}/x", scope)[0] == "from_global/x"
    assert ac._expand_text("$root/x", scope)[0] == "from_global/x"
    assert ac._expand_text("`root'/x", scope)[0] == "from_local/x"
    only_global = ac.MacroScope({"root": "from_global"}, {})
    # A local-syntax reference never reads a global assignment.
    assert ac._expand_text("`root'/x", only_global)[0] == "`root'/x"


def test_non_stata_adapters_keep_one_namespace():
    variables = ac._literal_assignments("ROOT='data'\n", "shell")
    assert ac._expand_text("${ROOT}/x", variables)[0] == "data/x"
    assert ac._expand_text("$ROOT/x", variables)[0] == "data/x"
    assert ac._expand_text("`ROOT'/x", variables)[0] == "data/x"


def test_unquoted_local_fronted_line_stays_a_visible_unresolved_syntax_row(tmp_path):
    """Accepted boundary: POSIX lexing precedes expansion; the row is visible."""
    root, audit = _package(tmp_path, {
        "do/master.do": "shell `exe' py/tool.py\n",
        "py/tool.py": "print('tool')\n",
    })
    artifact = ac.parse_artifact(ac.render(ac.scan(root, audit)))
    assert [row.resolution for row in artifact.call_sites] == ["unresolved_syntax"]
    assert [row.finding_kind for row in artifact.findings] == ["unresolved_callee"]
