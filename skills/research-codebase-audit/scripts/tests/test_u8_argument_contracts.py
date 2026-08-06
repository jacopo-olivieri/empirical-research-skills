"""U8a argument-contract channel, mapping closure, and adjudication flow."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import regbuild as rb


ac = rb.load_script("check_argument_contracts")
cs = rb.load_script("certify_stage")
dm = rb.load_script("build_detector_mapping")
second_read = rb.load_script("build_second_read_plan")
sf = rb.load_script("score_fixture")

pytestmark = pytest.mark.u8


def _manifest(root):
    a = rb.AuditDir(root)
    a.write_manifest(
        mode="code_errors_only", scope_exclusions=[], off_limits=[],
        review_depth="standard",
    )
    return a


def _write(root, relative, text):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _scan(tmp_path, files):
    root = tmp_path / "package"
    root.mkdir()
    for relative, text in files.items():
        _write(root, relative, text)
    a = _manifest(root)
    artifact = ac.scan(root, a.audit)
    parsed = ac.parse_artifact(ac.render(artifact))
    return root, a, parsed


def _callee(kind, read_count):
    if kind == "julia":
        refs = "\n".join(f"println(ARGS[{index}])" for index in range(1, read_count + 1))
        return "callee.jl", "julia", refs + "\n"
    if kind == "python_argv":
        refs = "\n".join(f"print(sys.argv[{index}])" for index in range(1, read_count + 1))
        return "callee.py", "python", "import sys\n" + refs + "\n"
    if kind == "python_argparse":
        refs = "\n".join(f"p.add_argument('arg{index}')" for index in range(1, read_count + 1))
        return "callee.py", "python", "import argparse\np = argparse.ArgumentParser()\n" + refs + "\np.parse_args()\n"
    if kind == "r":
        refs = "\n".join(f"print(args[[{index}]])" for index in range(1, read_count + 1))
        return "callee.R", "Rscript", "args <- commandArgs(trailingOnly = TRUE)\n" + refs + "\n"
    if kind == "stata":
        names = " ".join(f"arg{index}" for index in range(1, read_count + 1))
        return "callee.do", "stata", f"args {names}\ndisplay \"`arg1'\"\n"
    if kind == "shell":
        refs = " ".join(f"${index}" for index in range(1, read_count + 1))
        return "callee.sh", "bash", f"#!/bin/sh\nprintf '%s\\n' {refs}\n"
    raise AssertionError(kind)


def _caller(adapter, interpreter, callee, args):
    command = [interpreter]
    if interpreter == "stata":
        command += ["-b", "do"]
    command += [callee, *args]
    if adapter == "stata":
        return "caller.do", "shell " + " ".join(command) + "\n"
    if adapter == "python":
        return "caller.py", "import subprocess\nsubprocess.run(" + repr(command) + ")\n"
    if adapter == "r":
        quoted = ", ".join(json.dumps(part) for part in command[1:])
        return "caller.R", f"system2({json.dumps(command[0])}, args=c({quoted}))\n"
    if adapter == "julia":
        return "caller.jl", "run(`" + " ".join(command) + "`)\n"
    if adapter == "shell":
        return "caller.sh", "#!/bin/sh\n" + " ".join(command) + "\n"
    raise AssertionError(adapter)


@pytest.mark.parametrize("adapter,callee_kind", [
    ("stata", "julia"),
    ("python", "r"),
    ("r", "shell"),
    ("julia", "python_argv"),
    ("shell", "stata"),
])
@pytest.mark.parametrize("direction", ["passed_but_unread", "read_but_never_passed"])
def test_every_caller_adapter_emits_each_mismatch_direction(
        tmp_path, adapter, callee_kind, direction):
    read_count = 1 if direction == "passed_but_unread" else 2
    args = ["one", "two"] if direction == "passed_but_unread" else ["one"]
    callee, interpreter, body = _callee(callee_kind, read_count)
    caller, invocation = _caller(adapter, interpreter, callee, args)
    _root, _a, artifact = _scan(tmp_path, {caller: invocation, callee: body})
    assert [(row.finding_kind, row.argument_position)
            for row in artifact.findings] == [(direction, "2")]


@pytest.mark.parametrize("callee_kind,adapter", [
    ("julia", "shell"),
    ("python_argv", "stata"),
    ("python_argparse", "r"),
    ("r", "julia"),
    ("stata", "python"),
    ("shell", "r"),
])
@pytest.mark.parametrize("direction", ["passed_but_unread", "read_but_never_passed"])
def test_every_callee_idiom_emits_each_mismatch_direction_with_mixed_pairings(
        tmp_path, callee_kind, adapter, direction):
    read_count = 1 if direction == "passed_but_unread" else 2
    args = ["one", "two"] if direction == "passed_but_unread" else ["one"]
    callee, interpreter, body = _callee(callee_kind, read_count)
    caller, invocation = _caller(adapter, interpreter, callee, args)
    _root, _a, artifact = _scan(tmp_path, {caller: invocation, callee: body})
    assert {(row.witness_id, row.finding_kind)
            for row in artifact.findings} == {("argpos:2", direction)}


def test_stata_raw_args_and_fully_consuming_control_are_quiet(tmp_path):
    caller, invocation = _caller("shell", "stata", "callee.do", ["one", "two"])
    _root, _a, artifact = _scan(tmp_path, {
        caller: invocation,
        "callee.do": "display \"`0'\"\n",
    })
    assert len(artifact.call_sites) == 1
    assert artifact.call_sites[0].outcome == "consumed"
    assert artifact.findings == ()


@pytest.mark.parametrize("option", ["--threads 16", "--threads=16"])
def test_e1201_placeholder_suffix_and_option_arity_emit_only_argpos_2(
        tmp_path, option):
    _root, _a, artifact = _scan(tmp_path, {
        "master.sh": (
            "#!/bin/sh\nroot_dir=\"[YOUR PATH]\"\n"
            f"\"${{root_dir}}/bin/julia\" {option} "
            "\"${root_dir}/nested/main.jl\" alpha beta\n"
        ),
        "nested/main.jl": "println(ARGS[1])\n",
    })
    call = artifact.call_sites[0]
    assert call.resolution == "audited_root_alias"
    assert call.resolved_callee == "nested/main.jl"
    assert call.passed_positions == (1, 2)
    assert [(row.witness_id, row.finding_kind)
            for row in artifact.findings] == [("argpos:2", "passed_but_unread")]


def test_e1201_unknown_option_refuses_before_path_aliasing(tmp_path):
    _root, _a, artifact = _scan(tmp_path, {
        "master.sh": (
            "#!/bin/sh\nroot_dir=\"[YOUR PATH]\"\n"
            "\"${root_dir}/bin/julia\" --mystery 16 "
            "\"${root_dir}/nested/main.jl\" alpha\n"
        ),
        "nested/main.jl": "println(ARGS[1])\n",
    })
    assert artifact.call_sites[0].resolution == "unresolved_unknown_option"
    assert [(row.witness_id, row.finding_kind)
            for row in artifact.findings] == [("callsite", "unresolved_callee")]


def test_e1201_ambiguous_and_unknown_suffixes_fail_closed(tmp_path):
    files = {
        "master.sh": (
            "#!/bin/sh\n"
            "unknown_root=\"[YOUR PATH]\"\n"
            "julia \"${unknown_root}/nested/main.jl\" one\n"
            "julia \"${unknown_root}/missing/none.jl\" one\n"
        ),
        "a/nested/main.jl": "println(ARGS[1])\n",
        "b/nested/main.jl": "println(ARGS[1])\n",
    }
    _root, _a, artifact = _scan(tmp_path, files)
    assert [call.resolution for call in artifact.call_sites] == [
        "unresolved_ambiguous_path", "unresolved_unknown_path"]
    assert [row.witness_id for row in artifact.findings] == ["callsite", "callsite"]


@pytest.mark.parametrize("operator", ["&&", "||", "|", ";"])
def test_chained_shell_commands_enumerate_every_invocation(tmp_path, operator):
    _root, _a, artifact = _scan(tmp_path, {
        "master.sh": f"#!/bin/sh\npython a.py one {operator} python b.py two three\n",
        "a.py": "import sys\nprint(sys.argv[1])\n",
        "b.py": "import sys\nprint(sys.argv[1])\n",
    })
    assert [(row.resolved_callee, row.outcome) for row in artifact.call_sites] == [
        ("a.py", "consumed"), ("b.py", "contract_mismatch")]
    assert [(row.callee_path, row.witness_id, row.finding_kind)
            for row in artifact.findings] == [
                ("b.py", "argpos:2", "passed_but_unread")]


def test_redirection_tokens_never_count_as_passed_positionals(tmp_path):
    _root, _a, artifact = _scan(tmp_path, {
        "master.sh": (
            "#!/bin/sh\n"
            "python callee.py input.csv > run.log 2>&1\n"
            "python callee.py other.csv >> run.log\n"
            "python callee.py third.csv &> all.log < feed.txt\n"
        ),
        "callee.py": "import sys\nprint(sys.argv[1])\n",
    })
    assert [(row.passed_positions, row.outcome) for row in artifact.call_sites] == [
        ((1,), "consumed")] * 3
    assert artifact.findings == ()


def test_loop_wrapped_invocations_enumerate_and_flag_exactly(tmp_path):
    _root, _a, artifact = _scan(tmp_path, {
        "master.sh": (
            "#!/bin/sh\n"
            "for f in data/*.csv; do python clean.py \"$f\"; done\n"
            "for g in data/*.csv; do python audit.py \"$g\" extra; done\n"
        ),
        "clean.py": "import sys\nprint(sys.argv[1])\n",
        "audit.py": "import sys\nprint(sys.argv[1])\n",
    })
    assert [(row.resolved_callee, row.outcome) for row in artifact.call_sites] == [
        ("clean.py", "consumed"), ("audit.py", "contract_mismatch")]
    assert [(row.callee_path, row.witness_id, row.finding_kind)
            for row in artifact.findings] == [
                ("audit.py", "argpos:2", "passed_but_unread")]


def test_unbalanced_quotes_flag_invocations_only(tmp_path):
    _root, _a, artifact = _scan(tmp_path, {
        "master.sh": (
            "#!/bin/sh\n"
            "cat <<EOF\n"
            "it don't matter\n"
            "EOF\n"
            "python a.py \"unclosed\n"
        ),
        "a.py": "import sys\nprint(sys.argv[1])\n",
    })
    assert [(row.site_anchor, row.resolution, row.outcome)
            for row in artifact.call_sites] == [
                ("master.sh:5@call=1", "unresolved_syntax", "unresolved_callee")]
    assert [(row.witness_id, row.finding_kind) for row in artifact.findings] == [
        ("callsite", "unresolved_callee")]


def test_line_continuations_carry_the_full_argument_tail(tmp_path):
    _root, _a, artifact = _scan(tmp_path, {
        "master.sh": (
            "#!/bin/sh\n"
            "python a.py \\\n"
            "  one two\n"
            "python b.py \\\n"
            "  uno\n"
        ),
        "a.py": "import sys\nprint(sys.argv[1])\n",
        "b.py": "import sys\nprint(sys.argv[1])\n",
    })
    assert [(row.site_anchor, row.passed_positions, row.outcome)
            for row in artifact.call_sites] == [
                ("master.sh:2@call=1", (1, 2), "contract_mismatch"),
                ("master.sh:4@call=1", (1,), "consumed")]
    assert [(row.callee_path, row.witness_id, row.finding_kind)
            for row in artifact.findings] == [
                ("a.py", "argpos:2", "passed_but_unread")]


def test_two_python_invocations_on_one_line_have_distinct_source_ids(tmp_path):
    _root, _a, artifact = _scan(tmp_path, {
        "master.py": (
            "import os\n"
            "os.system('python first.py one'); os.system('python second.py one')\n"
        ),
        "first.py": "import sys\nprint(sys.argv[1])\n",
        "second.py": "import sys\nprint(sys.argv[1])\n",
    })
    assert len(artifact.call_sites) == 2
    assert len({row.source_id for row in artifact.call_sites}) == 2
    assert [row.site_anchor for row in artifact.call_sites] == [
        "master.py:2@call=1", "master.py:2@call=2"]


def test_artifact_zero_forms_counts_and_id_recomputation(tmp_path):
    _root, _a, artifact = _scan(tmp_path, {"plain.py": "VALUE = 1\n"})
    text = ac.render(artifact)
    assert "Recognized call sites: 0" in text
    assert "Findings: 0" in text
    assert "No call sites." in text and "No findings." in text
    with pytest.raises(ac.ArgumentContractError, match="invalid Source ID"):
        ac.parse_artifact(text.replace("No call sites.", (
            "| " + " | ".join(ac.CALL_COLS) + " |\n"
            "| " + " | ".join(["---"] * len(ac.CALL_COLS)) + " |\n"
            "| AC-000000000000 | x.py:1@call=1 | shell | python | y.py | y.py | direct | — | — | consumed |"
        )).replace("Recognized call sites: 0", "Recognized call sites: 1"))


def test_planted_ac_artifact_has_exact_flag_and_scorer_enforces_survival(tmp_path):
    audit = tmp_path / "audit"
    (audit / "_run").mkdir(parents=True)
    (audit / "_run/manifest.json").write_text(json.dumps({
        "mode": "replication", "scope_exclusions": [], "off_limits": [],
    }), encoding="utf-8")
    artifact = ac.scan(rb.FIXTURE_DIR / "planted", audit)
    calls = [row for row in artifact.call_sites
             if row.site_anchor.startswith("sh/ac_master.sh:")]
    findings = [row for row in artifact.findings
                if row.site_anchor.startswith("sh/ac_master.sh:")]
    assert len(calls) == 2
    assert [(row.finding_kind, row.witness_id, row.callee_path)
            for row in findings] == [
                ("passed_but_unread", "argpos:2", "jl/ac_e1201.jl")]
    assert next(row for row in calls
                if row.resolved_callee == "py/ac_control.py").outcome == "consumed"
    (audit / "_run/argument_contracts.md").write_text(
        ac.render(artifact), encoding="utf-8")
    finding = findings[0]
    mapping_row = {
        "Channel": "AC", "Source ID": finding.source_id,
        "Witness ID": finding.witness_id, "Error ID": "E-7000",
        "Mapping Kind": "new_candidate", "Site Anchor": finding.site_anchor,
    }
    (audit / "_run/detector_mapping.md").write_text(dm.render_mapping(
        "E-7000–E-7099", {"DU": [], "MF": [], "CV": [], "AC": [mapping_row]}),
        encoding="utf-8")
    row = rb.error_row(
        "E-7000", etype="missing_input_or_output",
        source="`sh/ac_master.sh`; `jl/ac_e1201.jl`",
        status="confirmation_needed", severity="1",
        desc="the caller argument contract has an unread callee argpos:2",
    )
    (audit / "code_error_register.md").write_text(
        rb.register_text("Code-error register", rb.ERROR_COLS, [row]),
        encoding="utf-8")
    expected = {"argument_contract_plants": [{
        "id": "P-26", "caller": "sh/ac_master.sh",
        "callee": "jl/ac_e1201.jl", "control": "py/ac_control.py",
        "finding_kind": "passed_but_unread", "witness_id": "argpos:2",
    }]}
    status, note = sf.check_argument_contract_channel(audit, expected)
    assert status == "PASS", note
    row[rb.ERROR_COLS.index("Status")] = "not_error"
    row[rb.ERROR_COLS.index("Severity")] = ""
    (audit / "code_error_register.md").write_text(
        rb.register_text("Code-error register", rb.ERROR_COLS, [row]),
        encoding="utf-8")
    status, note = sf.check_argument_contract_channel(audit, expected)
    assert status == "FAIL" and "without a verification receipt" in note


def test_ac_candidate_existing_detector_reason_schedules_caller_and_callee(tmp_path):
    a = rb.AuditDir(tmp_path)
    a.write("_run/detector_mapping.md", dm.render_mapping(
        "E-7000–E-7099", {
            "DU": [], "MF": [], "CV": [],
            "AC": [{
                "Channel": "AC", "Source ID": "AC-0123456789ab",
                "Witness ID": "argpos:2", "Error ID": "E-7000",
                "Mapping Kind": "new_candidate",
                "Site Anchor": "sh/master.sh:3@call=1",
            }],
        }))
    rows = [{
        column: value for column, value in zip(rb.ERROR_COLS, rb.error_row(
            "E-7000", etype="missing_input_or_output",
            source="`sh/master.sh`; `jl/callee.jl`", status="candidate"))
    }]
    inventory = ["sh/master.sh", "jl/callee.jl", "py/unrelated.py"]
    assert second_read._detector_paths(a.audit, rows, inventory) == {
        "sh/master.sh", "jl/callee.jl"}


def _mapping_tree(tmp_path, *, initialize=False):
    root = tmp_path / "mapped"
    root.mkdir()
    _write(root, "master.sh", "#!/bin/sh\njulia nested/main.jl one two\n")
    _write(root, "nested/main.jl", "println(ARGS[1])\n")
    a = _manifest(root)
    a.write_register("code_error_register.md", rb.ERROR_COLS, [])
    if initialize:
        result = subprocess.run(
            [sys.executable, str(rb.SCRIPTS_DIR / "certify_stage.py"), "init",
             "--package-root", str(root)], capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        result = subprocess.run(
            [sys.executable, str(rb.SCRIPTS_DIR / "certify_stage.py"), "start",
             "--package-root", str(root), "--stage", "code_b3d"],
            capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
    a.write_register("_run/snapshots/code_b3d/code_error_register.md", rb.ERROR_COLS, [])
    assert rb.run_script("emit_definition_use_bundles.py", root,
                         "--audit-dir", a.audit).returncode == 0
    assert rb.run_script("check_manifests.py", root,
                         "--audit-dir", a.audit).returncode == 0
    rb.emit_argument_contracts(a)
    rb.emit_path_derivations(a)
    sources = dm.parse_raw_sources(a.audit)
    source_id_value = next(iter(sources["AC"]))
    source = sources["AC"][source_id_value]
    candidate = rb.error_row(
        "E-7000", etype="missing_input_or_output",
        source="`master.sh`; `nested/main.jl`",
        location=f"`{source['witnesses'][0]['anchor']}`",
        status="candidate", severity="2",
        desc="the caller passes an argument the callee never reads",
        why="the cross-language handoff silently ignores an input",
    )
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [candidate])
    a.write(
        "_run/detector_mapping_decisions.md",
        "# Detector decisions\n\nDeclared detector Error-ID range: E-7000–E-7099\n\n"
        + rb.md_table(dm.DECISION_COLS, [
            ["AC", source_id_value, "E-7000", "new_candidate"],
        ]),
    )
    return root, a, source_id_value, source, candidate


def test_a1_unmapped_source_refuses_and_closure_check_has_teeth(tmp_path, monkeypatch):
    root, a, source_id_value, _source, _candidate = _mapping_tree(tmp_path)
    decisions = a.audit / "_run/detector_mapping_decisions.md"
    decisions.write_text(
        decisions.read_text().replace(
            f"| AC | {source_id_value} | E-7000 | new_candidate |\n", ""),
        encoding="utf-8",
    )
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [])
    refused = rb.run_script("build_detector_mapping.py", root, "--audit-dir", a.audit)
    assert refused.returncode == 1 and "unmapped detector source" in refused.stderr
    with pytest.raises(dm.MappingError, match="unmapped detector source"):
        dm.validate_inputs(root, a.audit)
    monkeypatch.setattr(dm, "_expected_rows", lambda *_args, **_kwargs: {
        "DU": [], "MF": [], "CV": [], "AC": []})
    _display, rows = dm.validate_inputs(root, a.audit)
    assert rows["AC"] == []


def test_a1_production_cli_refuses_deleted_mapping_row_and_false_zero(tmp_path):
    root, a, _source_id, _source, _candidate = _mapping_tree(
        tmp_path, initialize=True)
    emitted = rb.run_script("build_detector_mapping.py", root, "--audit-dir", a.audit)
    assert emitted.returncode == 0, emitted.stdout + emitted.stderr
    os.replace(a.audit / "_staging/code_error_register.md",
               a.audit / "code_error_register.md")
    finished = subprocess.run(
        [sys.executable, str(rb.SCRIPTS_DIR / "certify_stage.py"), "finish",
         "--package-root", str(root), "--stage", "code_b3d", "--outcome", "done"],
        capture_output=True, text=True)
    assert finished.returncode == 0, finished.stdout + finished.stderr

    mapping = a.audit / "_run/detector_mapping.md"
    original = mapping.read_text(encoding="utf-8")
    deleted = "\n".join(
        line for line in original.splitlines()
        if not line.startswith("| AC |")) + "\n"
    mapping.write_text(deleted, encoding="utf-8")
    checked = rb.run_script(
        "build_detector_mapping.py", root, "--audit-dir", a.audit, "--check")
    assert checked.returncode == 1 and "exactly close" in checked.stderr
    verified = subprocess.run(
        [sys.executable, str(rb.SCRIPTS_DIR / "certify_stage.py"), "verify-run",
         "--package-root", str(root)], capture_output=True, text=True)
    assert verified.returncode == 1 and "code_b3d" in verified.stderr

    prefix = original[:original.index(dm.MARKERS[3])]
    suffix = original[original.index(dm.MARKERS[4]):]
    mapping.write_text(
        prefix + dm.MARKERS[3] + "\n\n" + dm.AC_ZERO + "\n\n" + suffix,
        encoding="utf-8")
    false_zero = rb.run_script(
        "build_detector_mapping.py", root, "--audit-dir", a.audit, "--check")
    assert false_zero.returncode == 1 and "exactly close" in false_zero.stderr


@pytest.mark.parametrize("mutation,needle", [
    (lambda text: text.replace(dm.MARKERS[3], ""), "exactly once"),
    (lambda text: text.replace(dm.MARKERS[2], "TEMP").replace(
        dm.MARKERS[3], dm.MARKERS[2]).replace("TEMP", dm.MARKERS[3]),
     "out of order"),
])
def test_ac_marker_missing_or_reordered_refuses(tmp_path, mutation, needle):
    root, a, _source_id, _source, _candidate = _mapping_tree(tmp_path)
    emitted = rb.run_script("build_detector_mapping.py", root, "--audit-dir", a.audit)
    assert emitted.returncode == 0, emitted.stdout + emitted.stderr
    mapping = a.audit / "_run/detector_mapping.md"
    with pytest.raises(dm.MappingError, match=needle):
        dm.parse_mapping_text(mutation(mapping.read_text(encoding="utf-8")))


def test_ac_source_with_two_witnesses_fans_out_one_candidate(tmp_path):
    root = tmp_path / "fanned"
    root.mkdir()
    _write(root, "master.sh", "#!/bin/sh\npython callee.py one two three\n")
    _write(root, "callee.py", "import sys\nprint(sys.argv[1])\n")
    a = _manifest(root)
    a.write_register("code_error_register.md", rb.ERROR_COLS, [])
    a.write_register("_run/snapshots/code_b3d/code_error_register.md", rb.ERROR_COLS, [])
    assert rb.run_script("emit_definition_use_bundles.py", root,
                         "--audit-dir", a.audit).returncode == 0
    assert rb.run_script("check_manifests.py", root,
                         "--audit-dir", a.audit).returncode == 0
    rb.emit_argument_contracts(a)
    rb.emit_path_derivations(a)
    sources = dm.parse_raw_sources(a.audit)
    assert len(sources["AC"]) == 1
    source_id_value = next(iter(sources["AC"]))
    assert [w["witness_id"] for w in sources["AC"][source_id_value]["witnesses"]] == [
        "argpos:2", "argpos:3"]
    candidate = rb.error_row(
        "E-7000", etype="missing_input_or_output",
        source="`master.sh`; `callee.py`", status="candidate", severity="2",
        desc="two arguments the callee never reads",
        why="the handoff silently drops two inputs")
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [candidate])
    a.write(
        "_run/detector_mapping_decisions.md",
        "# D\n\nDeclared detector Error-ID range: E-7000–E-7099\n\n"
        + rb.md_table(dm.DECISION_COLS, [
            ["AC", source_id_value, "E-7000", "new_candidate"]]))
    emitted = rb.run_script("build_detector_mapping.py", root, "--audit-dir", a.audit)
    assert emitted.returncode == 0, emitted.stdout + emitted.stderr
    text = (a.audit / "_run/detector_mapping.md").read_text(encoding="utf-8")
    ac_rows = [line for line in text.splitlines() if line.startswith("| AC |")]
    assert [row.split(" | ")[1:4] for row in ac_rows] == [
        [source_id_value, "argpos:2", "E-7000"],
        [source_id_value, "argpos:3", "E-7000"]]


def test_ac_superstring_code_data_source_cell_is_refused(tmp_path):
    root, a, _source_id, _source, candidate = _mapping_tree(tmp_path)
    padded = list(candidate)
    padded[rb.ERROR_COLS.index("Code/Data Source")] = (
        "`master.sh`; `nested/main.jl.orig`")
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [padded])
    refused = rb.run_script("build_detector_mapping.py", root, "--audit-dir", a.audit)
    assert refused.returncode == 1
    assert "Code/Data Source omits nested/main.jl" in refused.stderr


def test_ac_raw_artifact_byte_drift_refuses_check(tmp_path):
    root, a, _source_id, _source, _candidate = _mapping_tree(tmp_path)
    emitted = rb.run_script("build_detector_mapping.py", root, "--audit-dir", a.audit)
    assert emitted.returncode == 0, emitted.stdout + emitted.stderr
    os.replace(a.audit / "_staging/code_error_register.md",
               a.audit / "code_error_register.md")
    raw = a.audit / "_run/argument_contracts.md"
    raw.write_text(raw.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    checked = rb.run_script(
        "build_detector_mapping.py", root, "--audit-dir", a.audit, "--check")
    assert checked.returncode == 1
    assert "detector artifact is stale or edited" in checked.stderr


def _ac_dismissal_case(tmp_path, *, with_record):
    root, a, source_id_value, source, candidate = _mapping_tree(tmp_path)
    emitted = rb.run_script("build_detector_mapping.py", root, "--audit-dir", a.audit)
    assert emitted.returncode == 0, emitted.stdout + emitted.stderr
    witness = source["witnesses"][0]["witness_id"]
    ledger = rb.code_ledger_row(
        "E-7000", evidence=source_id_value, verdict="not_error",
        proposed_status="not_error", proposed_severity="—",
        accepted_type="missing_input_or_output", witness_ids=witness,
        record_ids=("VR-AC-0001" if with_record else "—"),
    )
    outcome = rb.witness_outcome_row(
        "AC", source_id_value, witness, verdict="not_error", severity="—")
    records_text = "No verification records.\n"
    if with_record:
        records_text = rb.md_table(rb.PROBE_VERIFICATION_COLS, [[
            "AC", "VR-AC-0001", source_id_value, witness,
            "the argument is read through an indirection", "probe.py",
            "accepted", source["witnesses"][0]["anchor"],
        ]])
    shard = a.write(
        "_code_error_recheck/k1.md",
        rb.register_text("Recheck ledger", rb.CODE_LEDGER_COLS, [ledger])
        + "\n### Witness outcomes\n\n"
        + rb.md_table(rb.WITNESS_OUTCOME_COLS, [outcome])
        + "\n### Verification records\n\n"
        + records_text
        + "\n### Footer dispositions\n\n"
        + rb.md_table(rb._lint_mod.FOOTER_COLS, []),
    )
    if with_record:
        (shard.parent / "probe.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS, [candidate])
    a.write("code_error_recheck_summary.md", "# Recheck summary\n")
    return root, a


def test_ac_not_error_without_verification_record_dies_at_production_verifier(tmp_path):
    root, a = _ac_dismissal_case(tmp_path, with_record=False)
    result = rb.run_script("verify_dismissals.py", root, "--audit-dir", a.audit)
    assert result.returncode == 1
    assert "requires exactly one verification record" in result.stderr


def test_ac_legitimate_indirection_probe_receipt_flows_through_boundary(tmp_path):
    root, a = _ac_dismissal_case(tmp_path, with_record=True)
    verified = rb.run_script("verify_dismissals.py", root, "--audit-dir", a.audit)
    assert verified.returncode == 0, verified.stdout + verified.stderr
    assembled = rb.run_script("assemble_boundary.py", root, "--audit-dir", a.audit)
    assert assembled.returncode == 0, assembled.stdout + assembled.stderr
    staging = (a.audit / "_staging/code_error_register.md").read_text(encoding="utf-8")
    assert "| E-7000 | missing_input_or_output |" in staging
    assert "| not_error |  |" in staging
    receipts = (a.audit / "_run/code_b6a/dismissal_receipts.md").read_text(
        encoding="utf-8")
    assert "| AC | RCP-" in receipts and "| yes |" in receipts
