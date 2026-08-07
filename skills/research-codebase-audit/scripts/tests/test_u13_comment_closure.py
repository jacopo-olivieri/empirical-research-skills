"""U13 — the DU comment-closure adjudication contract (issue #18).

Tier-1 members: (a) supported-channel span-scan/coverage, (b) the
``contradicts_guard`` hard rule, (c) fail-closed span sources, (d) the
decoded-quote verbatim comparison, (e) verdict-vocabulary enforcement.
Everything else is Tier-2.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

import regbuild as rb

cc = rb.load_script("comment_closure")
dm = rb.load_script("build_detector_mapping")
du_emitter = rb.load_script("emit_definition_use_bundles")
lint = rb.load_script("lint_registers")
mechanism = rb.load_script("mechanism_schema")

pytestmark = pytest.mark.u13

VERIFIER = rb.SCRIPTS_DIR / "verify_dismissals.py"
COMMENT_CLOSURE_COLS = lint.COMMENT_CLOSURE_COLS

# --------------------------------------------------------------- the package
#
# Every name below is freshly invented for U13.  Stata files live under ``do/``
# rather than the checklist's ``code/`` because production's DU emitter scans
# only ``PACKAGE_ROOT/do/**/*.do``; review finding F9 requires the planted
# bundle to be one production can actually emit, so the directory is the one
# mechanical rename the checklist sanctions.

MIX_DO = """* ripe_batch_flag marks batches past the cure window
* a missing cure_days means the batch was never cured - treat it as ripe
gen ripe_batch_flag = 0
replace ripe_batch_flag = 1 if cure_days > 21
keep if ripe_batch_flag == 1 & cure_days < .
"""

PACK_DO = """* sealed_crate_flag marks crates ready to ship
* rows with missing seal_hours were never sealed and stay excluded
gen sealed_crate_flag = 0
replace sealed_crate_flag = 1 if seal_hours > 12
keep if sealed_crate_flag == 1 & seal_hours < .

summarize seal_hours

* rows with missing seal_hours were never sealed and stay excluded
summarize crate_id
"""

TALLY_DO = """* stock_ready_flag depends on the count below
* counts arriving as zero are placeholders, not real tallies
gen stock_ready_flag = 0
replace stock_ready_flag = 1 if batch_count > 0
replace stock_ready_flag = 0
keep if stock_ready_flag == 1 & batch_count < .
"""

BLEND_DO = """* blend_ratio holds a 30% | 70% split when either source is short
gen blend_ratio = 0.3
"""

LOAD_RUN_PY = '''def main(run_label, retries):
    """Drive one batch step."""
    # run_label must match the batch ledger spelling
    call_step(run_label, retries)  # retries capped upstream
'''

LEDGER_CSV = "crate_id,seal_hours\n1,4\n"

PACKAGE_FILES = {
    "do/mix_batches.do": MIX_DO,
    "do/pack_crates.do": PACK_DO,
    "do/tally_stock.do": TALLY_DO,
    "do/blend_rates.do": BLEND_DO,
    "tools/load_run.py": LOAD_RUN_PY,
    "data/crate_ledger.csv": LEDGER_CSV,
}

PROBE_PY = """rows = [
    {"crate_id": 1, "seal_hours": 20.0},
    {"crate_id": 2, "seal_hours": 4.0},
    {"crate_id": 3, "seal_hours": None},
]
kept = [r for r in rows
        if (r["seal_hours"] is not None and r["seal_hours"] > 12)
        and r["seal_hours"] is not None]
print("kept", [r["crate_id"] for r in kept])
"""

# ------------------------------------------------------------------ the keys

MIX = {
    "channel": "DU", "source": "DU-a11111111111", "witness": "DUW-a11111111111",
    "anchor": "do/mix_batches.do:5",
    "du": {"variable": "ripe_batch_flag", "shape": "producer_group",
           "definition": "do/mix_batches.do:3", "consumer": "do/mix_batches.do:5",
           "producer": "gen ripe_batch_flag = 0",
           "statement": "keep if ripe_batch_flag == 1 & cure_days < .",
           "guard": "ripe_batch_flag == 1 & cure_days < ."},
}
PACK = {
    "channel": "DU", "source": "DU-b22222222222", "witness": "DUW-b22222222222",
    "anchor": "do/pack_crates.do:5",
    "du": {"variable": "sealed_crate_flag", "shape": "producer_group",
           "definition": "do/pack_crates.do:3", "consumer": "do/pack_crates.do:5",
           "producer": "gen sealed_crate_flag = 0",
           "statement": "keep if sealed_crate_flag == 1 & seal_hours < .",
           "guard": "sealed_crate_flag == 1 & seal_hours < ."},
}
TALLY = {
    "channel": "DU", "source": "DU-c33333333333", "witness": "DUW-c33333333333",
    "anchor": "do/tally_stock.do:6",
    "du": {"variable": "stock_ready_flag", "shape": "producer_group",
           "definition": "do/tally_stock.do:3", "consumer": "do/tally_stock.do:6",
           "producer": "gen stock_ready_flag = 0",
           "statement": "keep if stock_ready_flag == 1 & batch_count < .",
           "guard": "stock_ready_flag == 1 & batch_count < ."},
}
# [post-U11] the overwrite bundle: the producer group's `gen` line is the
# artifact's Definition Site, so the producer-group span comes free.
TALLY_OVERWRITE = {
    "channel": "DU", "source": "DU-c44444444444", "witness": "DUW-c44444444444",
    "anchor": "do/tally_stock.do:5",
    "du": {"variable": "stock_ready_flag", "shape": "producer_group",
           "definition": "do/tally_stock.do:3", "consumer": "do/tally_stock.do:5",
           "producer": "gen stock_ready_flag = 0",
           "statement": "replace stock_ready_flag = 0",
           "guard": "stock_ready_flag == 1 & batch_count < ."},
}
AC_KEY = {
    "channel": "AC", "source": "AC-d55555555555", "witness": "ACW-d55555555555",
    "anchor": "tools/load_run.py:4@call=1",
}
CV_KEY = {
    "channel": "CV", "source": "CV-e66666666666", "witness": "CVW-e66666666666",
    "anchor": "do/blend_rates.do:2",
}
MF_KEY = {
    "channel": "MF", "source": "MF-f77777777777", "witness": "MFW-f77777777777",
    "anchor": "data/crate_ledger.csv:1",
}

DU_ARTIFACT_COLS = [
    "Bundle ID", "Witness ID", "Identity Tuple", "Variable", "Producer Shape",
    "Definition Site", "Producer Statement", "Consumer Site",
    "Consumer Statement", "Full Guard", "Code/Comment Context",
    "Obligation Question",
]

MANIFEST_CHECK = (
    "# Manifest check\n\n"
    "| Source ID | Manifest | Format | Consumer Role | Witness Count |\n"
    "| --- | --- | --- | --- | --- |\n"
    f"| `{MF_KEY['source']}` | `crate_ledger` | csv | unknown | 1 |\n\n"
    "| Source ID | Witness ID | Site Anchor | Rule Slug | Offending Text | Problem |\n"
    "| --- | --- | --- | --- | --- | --- |\n"
    f"| `{MF_KEY['source']}` | `{MF_KEY['witness']}` | "
    f"`{MF_KEY['anchor']}` | pip_extras | header | header shape |\n"
)


def _site(key, line):
    file = key["anchor"].split("@", 1)[0].rsplit(":", 1)[0]
    return f"{file}:{line}"


def _quote(package_root, site):
    relative, line = site.rsplit(":", 1)
    text = (package_root / relative).read_text(encoding="utf-8").splitlines()
    return mechanism.encode_cell(text[int(line) - 1].strip())


def closure_row(package_root, key, line, verdict="consistent",
                basis="the comment agrees with the guard", quoted=None,
                site=None):
    site = site or _site(key, line)
    return [key["channel"], key["source"], key["witness"], site,
            quoted if quoted is not None else _quote(package_root, site),
            verdict, basis]


def _du_artifact(keys):
    rows = []
    for index, key in enumerate(keys, start=1):
        spec = key["du"]
        rows.append([
            f"`{key['source']}`", f"`{key['witness']}`",
            f"`(identity {index})`", spec["variable"], spec["shape"],
            f"`{spec['definition']}`", f"`{spec['producer']}`",
            f"`{spec['consumer']}`", f"`{spec['statement']}`",
            f"`{spec['guard']}`", "context", "review narrowing",
        ])
    return (
        "# Stata definition/use bundles\n\n## Scan summary\n\n"
        "- Stata files scanned: 4\n"
        f"- Standard producer groups (file + gen line + variable): {len(rows)}\n"
        f"- Standard candidates: {len(rows)}\n"
        "- Advisory candidates: 0\n\n"
        "## Candidate findings\n\n" + rb.md_table(DU_ARTIFACT_COLS, rows) + "\n"
        "## Advisory candidates\n\n" + rb.md_table(DU_ARTIFACT_COLS, [])
    )


def _mapping_text(assignments):
    by_channel = {name: [] for name in dm.CHANNELS}
    for eid, key in assignments:
        by_channel[key["channel"]].append({
            "Channel": key["channel"], "Source ID": key["source"],
            "Witness ID": key["witness"], "Error ID": eid,
            "Mapping Kind": "new_candidate", "Site Anchor": key["anchor"],
        })
    return dm.render_mapping("E-7000–E-7099", by_channel)


def _records(key, record_id, excluded=None):
    """Return (mf_rows, probe_rows) for one dismissed key."""
    if key["channel"] in ("MF", "PD"):
        return [[key["channel"], record_id, key["source"], key["witness"],
                 "0" * 64, "pip", "pinned", "pip install --dry-run",
                 "accepted", "yes"]], []
    if excluded is None:
        excluded = "yes" if key["channel"] == "DU" else "na"
    return [], [[key["channel"], record_id, key["source"], key["witness"],
                 "the guard keeps the intended rows", "probe.py", "accepted",
                 key["anchor"], excluded]]


def _shard_text(ledger_rows, outcome_rows, mf_records, probe_records,
                closure_rows, *, closure_block=True):
    text = rb.register_text("Recheck ledger", rb.CODE_LEDGER_COLS, ledger_rows)
    text += "\n### Witness outcomes\n\n" + rb.md_table(
        rb.WITNESS_OUTCOME_COLS, list(outcome_rows))
    text += "\n### Verification records\n\n"
    if mf_records:
        text += rb.md_table(rb.MF_VERIFICATION_COLS, list(mf_records)) + "\n"
    if probe_records:
        text += rb.md_table(rb.PROBE_VERIFICATION_COLS, list(probe_records)) + "\n"
    if not mf_records and not probe_records:
        text += "No verification records.\n"
    if closure_block:
        text += "\n### Comment closure\n\n" + rb.md_table(
            COMMENT_CLOSURE_COLS, list(closure_rows))
    text += "\n### Footer dispositions\n\n" + rb.md_table(lint.FOOTER_COLS, [])
    return text


def build(tmp_path, cases, *, closure=None, closure_block=True,
          du_keys=None, write_du_artifact=True, write_manifest_check=True,
          package_files=None, probe=True):
    """Assemble a synthetic package + audit dir at the b5-code boundary.

    *cases* is a list of ``(error_id, verdict, [key, ...])``.  *closure* is the
    literal ``### Comment closure`` table; when None it is derived by quoting
    every expected site of every dismissed key.
    """
    root = tmp_path / "package"
    root.mkdir()
    for relative, body in (package_files or PACKAGE_FILES).items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    a = rb.AuditDir(root)
    a.write_manifest(stages={
        "code_b5": {"status": "done", "retries": 0,
                    "shards": {"audit/_code_error_recheck/k1.md":
                               {"status": "done", "retries": 0}}},
    })
    assignments = [(eid, key) for eid, _verdict, keys in cases for key in keys]
    a.write("_run/detector_mapping.md", _mapping_text(assignments))
    if write_du_artifact:
        artifact_keys = du_keys if du_keys is not None else [
            key for _eid, key in assignments if key["channel"] == "DU"]
        a.write("_run/definition_use_bundles.md", _du_artifact(artifact_keys))
    if write_manifest_check:
        a.write("_run/manifest_check.md", MANIFEST_CHECK)

    ledger_rows, outcomes, mf_records, probe_records = [], [], [], []
    register_rows, counter = [], 0
    for eid, verdict, keys in cases:
        record_ids = []
        for key in keys:
            outcomes.append(rb.witness_outcome_row(
                key["channel"], key["source"], key["witness"], verdict=verdict,
                severity=("—" if verdict == "not_error" else "2")))
            if verdict == "not_error":
                counter += 1
                record_id = f"VR-{counter:04d}"
                record_ids.append(record_id)
                mf_rows, probe_rows = _records(key, record_id)
                mf_records += mf_rows
                probe_records += probe_rows
        ledger_rows.append(rb.code_ledger_row(
            eid, evidence="; ".join(key["source"] for key in keys),
            verdict=verdict,
            witness_ids="; ".join(key["witness"] for key in keys),
            record_ids="; ".join(record_ids) if record_ids else "—",
        ))
        register_rows.append(rb.error_row(eid, status="candidate", severity="2"))

    if closure is None:
        closure = []
        for eid, verdict, keys in cases:
            if verdict != "not_error":
                continue
            for key in keys:
                relative, sites = cc.expectation_for_key(
                    root, a.audit, key["channel"], key["source"],
                    key["witness"], key["anchor"])
                for line in sites:
                    closure.append(closure_row(root, key, line,
                                               site=f"{relative}:{line}"))

    # Design call 1: the marker is conditional, so a shard with no mapped
    # `not_error` row carries no block at all.
    closure_block = closure_block and any(
        verdict == "not_error" for _eid, verdict, _keys in cases)
    ids = [eid for eid, _v, _k in cases]
    inventory = [(eid, "detector", "; ".join(k["source"] for k in keys))
                 for eid, _v, keys in cases]
    clusters = [("K1", "detector", "; ".join(ids),
                 "`audit/_code_error_recheck/k1.md`")]
    a.write("plans/code_error_recheck_plan.md",
            rb.recheck_plan_text("code", inventory, clusters))
    a.write("plans/code_error_second_read_plan.md", "# Code second-read plan\n")
    a.write("plans/code_error_review_plan.md", rb._code_b1_plan())
    a.write_register("code_error_register.md", rb.ERROR_COLS, register_rows,
                     title="Code-error register")
    a.write_recheck_summary("code")
    shard = a.write("_code_error_recheck/k1.md", _shard_text(
        ledger_rows, outcomes, mf_records, probe_records, closure,
        closure_block=closure_block))
    if probe:
        (shard.parent / "probe.py").write_text(PROBE_PY, encoding="utf-8")
    return root, a, shard, closure


def rewrite(shard, closure, cases, *, closure_block=True, **kw):
    """Re-render an existing shard with a different closure table."""
    text = shard.read_text(encoding="utf-8")
    head, _sep, _rest = text.partition("\n### Comment closure\n")
    ledger_and_records = head
    body = ledger_and_records
    if closure_block:
        body += "\n### Comment closure\n\n" + rb.md_table(
            COMMENT_CLOSURE_COLS, list(closure))
    body += "\n### Footer dispositions\n\n" + rb.md_table(lint.FOOTER_COLS, [])
    shard.write_text(body, encoding="utf-8")
    return shard


def good(tmp_path, **kw):
    """The good audit dir: every supported channel dismissed, gate quiet."""
    return build(tmp_path, [("E-7000", "not_error",
                             [PACK, TALLY, TALLY_OVERWRITE, AC_KEY, CV_KEY,
                              MF_KEY])], **kw)


def planted(tmp_path, **kw):
    """The planted DU dismissal: line 2 of the span contradicts the guard."""
    root, a, shard, closure = build(
        tmp_path, [("E-7000", "not_error", [MIX])], **kw)
    return root, a, shard, closure


def _run(a, shard, stage="b5-code"):
    return rb.lint(a, stage, shard)


# ------------------------------------------------- module unit-level checks


def test_grammar_table_is_closed_and_suffix_keyed():
    assert cc.grammar_for("do/x.do") == "stata"
    assert cc.grammar_for("do/x.ado") == "stata"
    assert cc.grammar_for("tools/x.py") == "hash"
    assert cc.grammar_for("tools/X.R") == "hash"
    assert cc.grammar_for("tools/x.r") == "hash"
    assert cc.grammar_for("data/x.csv") is None


def test_stata_label_commands_are_singleton_intent_units():
    lines = [
        "* seal_hours drives the flag",
        "label variable seal_hours \"hours under seal\"",
        "* trailing note about seal_hours",
    ]
    assert cc.comment_blocks(lines, "stata") == [[1], [2], [3]]


def test_string_literals_never_open_a_comment():
    stata = ['display "a // b"', 'display "/* not a comment */"', "* real"]
    assert cc.comment_blocks(stata, "stata") == [[3]]
    hashed = ['label = "# not a comment"', "# real"]
    assert cc.comment_blocks(hashed, "hash") == [[2]]


def test_block_comment_extent_is_one_block():
    lines = ["/* first", "second", "third */", "gen x = 1"]
    assert cc.comment_blocks(lines, "stata") == [[1, 2, 3]]


def test_trailing_comment_attaches_to_its_code_line():
    lines = ["* above", "gen x = 1 // trailing"]
    assert cc.comment_blocks(lines, "stata") == [[1], [2]]


def test_name_filter_is_full_token_and_case_sensitive():
    matcher = cc.name_matcher(["seal_hours"])
    assert matcher.search("* seal_hours matters")
    assert not matcher.search("* seal_hours_extra matters")
    assert not matcher.search("* SEAL_HOURS matters")


# ------------------------------- Tier 1 (a) — supported-channel span/coverage


def test_a_good_shard_is_quiet(tmp_path):
    """Test 2 (stays quiet): the complete block over every channel passes."""
    _root, a, shard, _closure = good(tmp_path)
    result = _run(a, shard)
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_du_border_resolution_requires_every_expected_row(tmp_path):
    root, a, shard, closure = good(tmp_path)
    dropped = _site(PACK, 2)
    rewrite(shard, [row for row in closure if row[3] != dropped], None)
    result = _run(a, shard)
    assert result.returncode == 1
    assert (f"E-7000 not_error is missing the '### Comment closure' row for "
            f"DU/{PACK['source']}/{PACK['witness']} at {dropped}"
            in result.stdout)
    assert root.is_dir()


def test_a_block_level_selection_catches_the_decisive_sibling_line(tmp_path):
    """Only line 1 names the flag; line 2 is decisive and still expected."""
    _root, a, shard, closure = good(tmp_path)
    dropped = _site(TALLY, 2)
    assert dropped in {row[3] for row in closure}
    rewrite(shard, [row for row in closure if not (
        row[3] == dropped and row[1] == TALLY["source"])], None)
    result = _run(a, shard)
    assert result.returncode == 1
    assert (f"row for DU/{TALLY['source']}/{TALLY['witness']} at {dropped}"
            in result.stdout)


def test_a_producer_group_span_reads_the_gen_line(tmp_path):
    """[post-U11] the overwrite bundle's Definition Site is the `gen` line."""
    _root, a, shard, closure = good(tmp_path)
    owned = [row[3] for row in closure if row[1] == TALLY_OVERWRITE["source"]]
    assert owned == [_site(TALLY_OVERWRITE, 1), _site(TALLY_OVERWRITE, 2)]
    rewrite(shard, [row for row in closure
                    if row[1] != TALLY_OVERWRITE["source"]], None)
    result = _run(a, shard)
    assert result.returncode == 1
    assert (f"row for DU/{TALLY_OVERWRITE['source']}/"
            f"{TALLY_OVERWRITE['witness']} at {owned[0]}" in result.stdout)


def test_a_ac_anchor_window_covers_the_trailing_comment(tmp_path):
    """The AC `@call=<n>` anchor grammar plus the call-line name list."""
    _root, a, shard, closure = good(tmp_path)
    owned = [row[3] for row in closure if row[1] == AC_KEY["source"]]
    assert owned == [_site(AC_KEY, 3), _site(AC_KEY, 4)]
    dropped = _site(AC_KEY, 4)
    rewrite(shard, [row for row in closure if row[3] != dropped], None)
    result = _run(a, shard)
    assert result.returncode == 1
    assert (f"row for AC/{AC_KEY['source']}/{AC_KEY['witness']} at {dropped}"
            in result.stdout)


def test_a_cv_anchor_window_uses_the_statement_line_tokens(tmp_path):
    _root, a, shard, closure = good(tmp_path)
    owned = [row[3] for row in closure if row[1] == CV_KEY["source"]]
    assert owned == [_site(CV_KEY, 1)]
    rewrite(shard, [row for row in closure if row[1] != CV_KEY["source"]], None)
    result = _run(a, shard)
    assert result.returncode == 1
    assert f"row for CV/{CV_KEY['source']}/{CV_KEY['witness']}" in result.stdout


def test_a_repeated_text_elsewhere_cannot_stand_in(tmp_path):
    """Review F4: coverage joins on the full row identity, never on the text."""
    root, a, shard, closure = good(tmp_path)
    expected = _site(PACK, 2)
    elsewhere = _site(PACK, 9)
    assert (root / "do/pack_crates.do").read_text().splitlines()[1].strip() == (
        (root / "do/pack_crates.do").read_text().splitlines()[8].strip())
    moved = []
    for row in closure:
        if row[3] == expected:
            row = list(row)
            row[3] = elsewhere
            row[4] = _quote(root, elsewhere)
        moved.append(row)
    rewrite(shard, moved, None)
    result = _run(a, shard)
    assert result.returncode == 1
    assert f"at {expected}" in result.stdout


# --------------------------------------- Tier 1 (b) — the hard rule


def test_b_contradicts_guard_forbids_not_error(tmp_path):
    """The planted DU dismissal: the honest verdict blocks the dismissal."""
    root, a, shard, closure = planted(tmp_path)
    assert [row[3] for row in closure] == [_site(MIX, 1), _site(MIX, 2)]
    marked = [list(row) for row in closure]
    marked[1][5] = "contradicts_guard"
    marked[1][6] = "missing cure_days is inside the error set"
    rewrite(shard, marked, None)
    result = _run(a, shard)
    assert result.returncode == 1
    assert ("E-7000 not_error is forbidden by the contradicts_guard comment "
            f"closure row DU/{MIX['source']}/{MIX['witness']} at "
            f"{_site(MIX, 2)}; the minimum verdict is confirmation_needed"
            in result.stdout)
    assert root.is_dir()


def test_b_hard_rule_is_key_joined_not_shard_wide(tmp_path):
    """Design call 6: two independent dismissals do not poison each other."""
    root, a, shard, closure = build(
        tmp_path,
        [("E-7000", "not_error", [MIX]), ("E-7001", "not_error", [PACK])])
    marked = []
    for row in closure:
        row = list(row)
        if row[1] == MIX["source"] and row[3] == _site(MIX, 2):
            row[5] = "contradicts_guard"
            row[6] = "missing cure_days is inside the error set"
        marked.append(row)
    rewrite(shard, marked, None)
    result = _run(a, shard)
    assert result.returncode == 1
    assert "E-7000 not_error is forbidden" in result.stdout
    assert "E-7001 not_error is forbidden" not in result.stdout
    assert root.is_dir()


def test_b_contradiction_beside_a_confirmed_error_row_is_silent(tmp_path):
    """The duty binds `not_error` only."""
    _root, a, shard, _closure = build(
        tmp_path, [("E-7000", "confirmed_error", [MIX])])
    result = _run(a, shard)
    assert result.returncode == 0, result.stdout + result.stderr


# --------------------------------------------- Tier 1 (c) — fail closed


def test_c_missing_du_artifact_refuses_the_gate(tmp_path):
    _root, a, shard, _closure = good(tmp_path)
    (a.audit / "_run/definition_use_bundles.md").unlink()
    result = _run(a, shard)
    assert result.returncode == 1
    assert "comment-closure span source refused for DU/" in result.stdout
    assert "definition_use_bundles.md" in result.stdout


def test_c_malformed_du_artifact_refuses_the_gate(tmp_path):
    _root, a, shard, _closure = good(tmp_path)
    a.write("_run/definition_use_bundles.md", "# not an artifact\n")
    result = _run(a, shard)
    assert result.returncode == 1
    assert "the definition/use artifact is malformed" in result.stdout


def test_c_unresolvable_du_row_refuses_the_gate(tmp_path):
    _root, a, shard, _closure = good(tmp_path)
    a.write("_run/definition_use_bundles.md", _du_artifact([PACK]))
    result = _run(a, shard)
    assert result.returncode == 1
    assert ("the definition/use artifact resolves 0 standard rows for "
            f"{TALLY['source']}/{TALLY['witness']}" in result.stdout)


def test_c_out_of_range_du_coordinate_refuses_the_gate(tmp_path):
    """Review F5: parseable-but-out-of-range is a refusal, not an empty set."""
    _root, a, shard, _closure = good(tmp_path)
    far = dict(PACK, du=dict(PACK["du"], consumer="do/pack_crates.do:9999"))
    a.write("_run/definition_use_bundles.md",
            _du_artifact([far, TALLY, TALLY_OVERWRITE]))
    result = _run(a, shard)
    assert result.returncode == 1
    assert ("the DU Consumer Site names do/pack_crates.do:9999, outside the "
            "file's 10 line(s)" in result.stdout)


def test_c_backwards_du_bounds_refuse_the_gate(tmp_path):
    _root, a, shard, _closure = good(tmp_path)
    flipped = dict(PACK, du=dict(PACK["du"], definition="do/pack_crates.do:5",
                                 consumer="do/pack_crates.do:3"))
    a.write("_run/definition_use_bundles.md",
            _du_artifact([flipped, TALLY, TALLY_OVERWRITE]))
    result = _run(a, shard)
    assert result.returncode == 1
    assert "DU span for" in result.stdout and "runs backwards" in result.stdout


def test_c_unparseable_anchor_refuses_the_gate(tmp_path):
    """A DU coordinate is never line-optional: an unparseable one fails closed."""
    _root, a, shard, _closure = good(tmp_path)
    vague = dict(PACK, du=dict(PACK["du"], consumer="somewhere-vague"))
    a.write("_run/definition_use_bundles.md",
            _du_artifact([vague, TALLY, TALLY_OVERWRITE]))
    result = _run(a, shard)
    assert result.returncode == 1
    assert ("DU Site Anchor 'somewhere-vague' does not parse as <file>:<line>"
            in result.stdout)


def test_c_ac_anchor_must_carry_the_call_ordinal(tmp_path):
    """Review F2: the AC anchor grammar is `<file>:<line>@call=<n>`."""
    plain = dict(AC_KEY, anchor="tools/load_run.py:4")
    _root, a, shard, _closure = build(
        tmp_path, [("E-7000", "not_error", [plain])], closure=[])
    result = _run(a, shard)
    assert result.returncode == 1
    assert ("AC Site Anchor 'tools/load_run.py:4' does not parse as "
            "<file>:<line>@call=<n>" in result.stdout)


def test_c_missing_audited_file_refuses_the_gate(tmp_path):
    _root, a, shard, _closure = good(tmp_path)
    (Path(a.audit).parent / "do/tally_stock.do").unlink()
    result = _run(a, shard)
    assert result.returncode == 1
    assert "source file is missing or unreadable: do/tally_stock.do" in result.stdout


@pytest.mark.parametrize("key, anchor, label", [
    # `check_manifests.py` falls back to the bare manifest name when a finding
    # carries no line (conda-oracle rejection, invalid UTF-8, invalid TOML, a
    # requirements entry without a line).
    (MF_KEY, "data/crate_ledger.csv", "line-less MF"),
    # `cv_scan.py` anchors every not_divergent witness by the verdict digest.
    (CV_KEY, "audit/_run/cv_scan.md:verdict:a1b2c3d4e5f6", "CV verdict digest"),
    # The same digest, drawn all-numeric: the residual colon still marks it as
    # a content token, so it must not be read as line 123456789012.
    (CV_KEY, "audit/_run/cv_scan.md:verdict:123456789012", "numeric CV digest"),
])
def test_line_optional_anchor_yields_an_empty_expected_set(
        tmp_path, key, anchor, label):
    """An anchor with no usable line coordinate names no span, and is not a refusal."""
    swapped = dict(key, anchor=anchor)
    keys = [k for k in (PACK, TALLY, TALLY_OVERWRITE, AC_KEY, CV_KEY, MF_KEY)
            if k["channel"] != key["channel"]] + [swapped]
    _root, a, shard, _closure = build(
        tmp_path, [("E-7000", "not_error", keys)])
    result = _run(a, shard)
    assert result.returncode == 0, f"{label} anchor was refused: {result.stdout}"


def test_line_optional_channels_still_fail_closed_on_a_real_coordinate(tmp_path):
    """Member (c) is not weakened: an in-range failure on MF/CV still refuses."""
    _root, a, shard, _closure = good(tmp_path)
    a.write("_run/detector_mapping.md", _mapping_text(
        [("E-7000", k) for k in (PACK, TALLY, TALLY_OVERWRITE, AC_KEY, MF_KEY)]
        + [("E-7000", dict(CV_KEY, anchor="do/blend_rates.do:9999"))]))
    result = _run(a, shard)
    assert result.returncode == 1
    assert "the CV Site Anchor names do/blend_rates.do:9999" in result.stdout


def test_c_missing_manifest_check_refuses_the_mf_name_source(tmp_path):
    _root, a, shard, _closure = good(tmp_path)
    (a.audit / "_run/manifest_check.md").unlink()
    result = _run(a, shard)
    assert result.returncode == 1
    assert "the manifest-check artifact is missing or unreadable" in result.stdout


# ---------------------------------- Tier 1 (d) — the decoded-quote comparison


def test_d_harmless_quote_at_the_decisive_site_fails(tmp_path):
    root, a, shard, closure = planted(tmp_path)
    swapped = [list(row) for row in closure]
    swapped[1][4] = mechanism.encode_cell(
        "* the cure window is documented in the protocol")
    swapped[1][5] = "consistent"
    rewrite(shard, swapped, None)
    result = _run(a, shard)
    assert result.returncode == 1
    assert (f"comment closure row DU/{MIX['source']}/{MIX['witness']} at "
            f"{_site(MIX, 2)} Quoted Text does not match the source line at "
            "that site" in result.stdout)
    assert root.is_dir()


def test_d_encoded_reserved_characters_round_trip(tmp_path):
    """The CV span line carries both `%` and `|`; encode/decode must survive."""
    root, a, shard, closure = good(tmp_path)
    cell = next(row[4] for row in closure if row[1] == CV_KEY["source"])
    assert "%25" in cell and "%7C" in cell
    assert mechanism.decode_cell(cell) == (
        "* blend_ratio holds a 30% | 70% split when either source is short")
    assert _run(a, shard).returncode == 0
    assert root.is_dir()


def test_d_undecodable_quote_fails(tmp_path):
    _root, a, shard, closure = good(tmp_path)
    broken = [list(row) for row in closure]
    broken[0][4] = "%zz broken"
    rewrite(shard, broken, None)
    result = _run(a, shard)
    assert result.returncode == 1
    assert "Quoted Text is not a valid encoded cell" in result.stdout


# ------------------------------------- Tier 1 (e) — verdict vocabulary


def test_e_free_text_verdict_fails(tmp_path):
    _root, a, shard, closure = good(tmp_path)
    bad = [list(row) for row in closure]
    bad[0][5] = "fine"
    rewrite(shard, bad, None)
    result = _run(a, shard)
    assert result.returncode == 1
    assert ("has invalid Verdict 'fine' (closed list: consistent | "
            "contradicts_guard | unrelated)" in result.stdout)


def test_e_unrelated_and_consistent_are_legal(tmp_path):
    _root, a, shard, closure = good(tmp_path)
    relabelled = [list(row) for row in closure]
    relabelled[0][5] = "unrelated"
    relabelled[0][6] = "the comment describes the report, not the guard"
    rewrite(shard, relabelled, None)
    result = _run(a, shard)
    assert result.returncode == 0, result.stdout + result.stderr


# ------------------------------------------------------------------- Tier 2


def test_basis_must_be_non_empty(tmp_path):
    _root, a, shard, closure = good(tmp_path)
    bad = [list(row) for row in closure]
    bad[0][6] = "—"
    rewrite(shard, bad, None)
    result = _run(a, shard)
    assert result.returncode == 1
    assert "has an empty Basis" in result.stdout


def test_extra_row_with_a_mapped_key_and_verifying_quote_passes(tmp_path):
    root, a, shard, closure = good(tmp_path)
    extra = closure_row(root, PACK, 9, verdict="unrelated",
                        basis="a repeat far outside the span")
    rewrite(shard, list(closure) + [extra], None)
    result = _run(a, shard)
    assert result.returncode == 0, result.stdout + result.stderr


def test_extra_row_with_an_unmapped_key_fails(tmp_path):
    root, a, shard, closure = good(tmp_path)
    extra = closure_row(root, MIX, 1, basis="a key that is not mapped here")
    rewrite(shard, list(closure) + [extra], None)
    result = _run(a, shard)
    assert result.returncode == 1
    assert (f"comment closure row names unmapped key DU/{MIX['source']}/"
            f"{MIX['witness']}" in result.stdout)


def test_duplicate_full_row_identity_fails(tmp_path):
    _root, a, shard, closure = good(tmp_path)
    rewrite(shard, list(closure) + [list(closure[0])], None)
    result = _run(a, shard)
    assert result.returncode == 1
    assert "duplicate comment closure row" in result.stdout


def test_no_grammar_suffix_yields_an_empty_expected_set(tmp_path):
    _root, a, shard, closure = build(
        tmp_path, [("E-7000", "not_error", [MF_KEY])])
    assert closure == []
    result = _run(a, shard)
    assert result.returncode == 0, result.stdout + result.stderr


def test_span_without_name_bearing_blocks_yields_an_empty_expected_set(tmp_path):
    files = dict(PACKAGE_FILES)
    files["do/blend_rates.do"] = "* nothing here names the statement\ndisplay 1\n"
    _root, a, shard, closure = build(
        tmp_path, [("E-7000", "not_error", [CV_KEY])], package_files=files)
    assert closure == []
    result = _run(a, shard)
    assert result.returncode == 0, result.stdout + result.stderr


def test_marker_is_required_when_a_mapped_not_error_exists(tmp_path):
    _root, a, shard, _closure = good(tmp_path, closure_block=False)
    result = _run(a, shard)
    assert result.returncode == 1
    assert "expected exactly one '### Comment closure' marker, found 0" in result.stdout


def test_marker_is_forbidden_without_a_mapped_not_error(tmp_path):
    """Design call 1: no verdict path, so no standing empty marker."""
    _root, a, shard, _closure = build(
        tmp_path, [("E-7000", "confirmed_error", [MIX])])
    text = shard.read_text(encoding="utf-8")
    assert "### Comment closure" not in text
    assert _run(a, shard).returncode == 0
    shard.write_text(text + "\n### Comment closure\n\n"
                     + rb.md_table(COMMENT_CLOSURE_COLS, []), encoding="utf-8")
    result = _run(a, shard)
    assert result.returncode == 1
    assert ("'### Comment closure' is forbidden in a shard with no "
            "mechanically-mapped not_error row, found 1" in result.stdout)


def test_duplicate_marker_fails(tmp_path):
    _root, a, shard, _closure = good(tmp_path)
    shard.write_text(shard.read_text(encoding="utf-8")
                     + "\n### Comment closure\n", encoding="utf-8")
    result = _run(a, shard)
    assert result.returncode == 1
    assert "expected exactly one '### Comment closure' marker, found 2" in result.stdout


@pytest.mark.parametrize(("channel_key", "value", "token"), [
    (PACK, "—", "has invalid Excluded-Class Input"),
    (PACK, "no", "has invalid Excluded-Class Input"),
    (PACK, "na", "on channel DU must declare Excluded-Class Input 'yes'"),
    (CV_KEY, "yes", "on channel CV must declare Excluded-Class Input 'na'"),
])
def test_excluded_class_input_value_rule(tmp_path, channel_key, value, token):
    _root, a, shard, _closure = good(tmp_path)
    text = shard.read_text(encoding="utf-8")
    lines = []
    for line in text.split("\n"):
        cells = lint.split_row(line)
        if (len(cells) == len(rb.PROBE_VERIFICATION_COLS)
                and cells[2] == channel_key["source"]):
            cells[-1] = value
            line = "| " + " | ".join(cells) + " |"
        lines.append(line)
    shard.write_text("\n".join(lines), encoding="utf-8")
    result = _run(a, shard)
    assert result.returncode == 1 and token in result.stdout


def test_probe_schema_carries_the_new_column_last_in_both_mirrors():
    verifier = rb.load_script("verify_dismissals")
    assert lint.PROBE_VERIFICATION_COLS[-1] == "Excluded-Class Input"
    assert verifier.PROBE_RECORD_COLS == lint.PROBE_VERIFICATION_COLS
    assert lint.MF_VERIFICATION_COLS == verifier.MF_RECORD_COLS
    assert len(lint.CODE_LEDGER_COLS) == 17


def test_verify_dismissals_runs_the_python_probe_on_the_good_dir(tmp_path):
    """Review F10: the probe is self-contained Python and the CLI executes it."""
    root, a, _shard, _closure = build(
        tmp_path, [("E-7000", "not_error", [PACK])])
    result = subprocess.run(
        [sys.executable, str(VERIFIER), str(root), "--audit-dir", str(a.audit)],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    receipts = (a.audit / "_run/code_b6a/dismissal_receipts.md").read_text()
    assert "RCP-" in receipts and "python" in receipts


def test_du_planted_bundle_is_production_valid(tmp_path):
    """Review F9: the gate is never tested against an unemittable upstream."""
    root = tmp_path / "package"
    (root / "do").mkdir(parents=True)
    (root / "do/mix_batches.do").write_text(MIX_DO, encoding="utf-8")
    (root / "audit/_run").mkdir(parents=True)
    (root / "audit/_run/manifest.json").write_text(json.dumps({}), encoding="utf-8")
    bundles = du_emitter.scan_package(root)["bundles"]
    standard = [b for b in bundles if b["category"] == "standard"]
    assert len(standard) == 1
    bundle = standard[0]
    assert bundle["variable"] == "ripe_batch_flag"
    assert bundle["definition_line"] == 3 and bundle["consumer_line"] == 5
    assert bundle["guard"] == "ripe_batch_flag == 1 & cure_days < ."


# =========================================== Tier-1: Test 3, the test of the test
#
# Each leg neuters exactly one guarded behaviour in a fresh in-process copy of
# the lint and asserts that the corresponding Test-1 finding stops firing.


def _b5_in_process(a, shard):
    """Run the b5-code shard validation in-process so it can be monkeypatched."""
    lintmod = rb.load_script("lint_registers")
    state = lintmod.Lint()
    manifest = json.loads(
        (a.audit / "_run/manifest.json").read_text(encoding="utf-8"))
    return lintmod, state, manifest


def _findings(lintmod, state, a, shard, supplementary=False):
    lintmod.stage_b5(state, a.audit, "code", shard, json.loads(
        (a.audit / "_run/manifest.json").read_text(encoding="utf-8")),
        supplementary=supplementary)
    return "\n".join(state.errors)


def test_test3_a_du_border_resolution(tmp_path, monkeypatch):
    _root, a, shard, closure = good(tmp_path)
    dropped = _site(PACK, 2)
    rewrite(shard, [row for row in closure if row[3] != dropped], None)
    assert dropped in _findings(*_b5_in_process(a, shard)[:2], a, shard)

    lintmod, state, _m = _b5_in_process(a, shard)
    real = lintmod.comment_closure.du_artifact_row

    def collapsed(audit, source_id, witness_id):
        row = dict(real(audit, source_id, witness_id))
        row["Definition Site"] = "do/pack_crates.do:7"
        row["Consumer Site"] = "do/pack_crates.do:7"
        return row

    monkeypatch.setattr(lintmod.comment_closure, "du_artifact_row", collapsed)
    assert dropped not in _findings(lintmod, state, a, shard)


def test_test3_a_du_name_list_derivation(tmp_path, monkeypatch):
    _root, a, shard, closure = good(tmp_path)
    dropped = _site(TALLY, 2)
    rewrite(shard, [row for row in closure if not (
        row[1] == TALLY["source"] and row[3] == dropped)], None)
    assert dropped in _findings(*_b5_in_process(a, shard)[:2], a, shard)

    lintmod, state, _m = _b5_in_process(a, shard)
    real = lintmod.comment_closure.du_artifact_row

    def nameless(audit, source_id, witness_id):
        row = dict(real(audit, source_id, witness_id))
        row["Variable"], row["Full Guard"] = "", ""
        return row

    monkeypatch.setattr(lintmod.comment_closure, "du_artifact_row", nameless)
    assert f"{TALLY['source']}/{TALLY['witness']} at {dropped}" not in _findings(
        lintmod, state, a, shard)


def test_test3_a_anchor_window_resolution(tmp_path, monkeypatch):
    _root, a, shard, closure = good(tmp_path)
    dropped = _site(AC_KEY, 4)
    rewrite(shard, [row for row in closure if row[3] != dropped], None)
    assert dropped in _findings(*_b5_in_process(a, shard)[:2], a, shard)

    lintmod, state, _m = _b5_in_process(a, shard)
    real = lintmod.comment_closure.parse_anchor
    monkeypatch.setattr(
        lintmod.comment_closure, "parse_anchor",
        lambda anchor, channel: (("tools/load_run.py", 1) if channel == "AC"
                                 else real(anchor, channel)))
    assert dropped not in _findings(lintmod, state, a, shard)


def test_test3_a_statement_line_name_list(tmp_path, monkeypatch):
    _root, a, shard, closure = good(tmp_path)
    dropped = _site(CV_KEY, 1)
    rewrite(shard, [row for row in closure if row[1] != CV_KEY["source"]], None)
    assert dropped in _findings(*_b5_in_process(a, shard)[:2], a, shard)

    lintmod, state, _m = _b5_in_process(a, shard)
    monkeypatch.setattr(lintmod.comment_closure, "code_portion",
                        lambda raw, grammar: "")
    assert dropped not in _findings(lintmod, state, a, shard)


def test_test3_b_hard_rule_join(tmp_path, monkeypatch):
    _root, a, shard, closure = planted(tmp_path)
    marked = [list(row) for row in closure]
    marked[1][5] = "contradicts_guard"
    marked[1][6] = "missing cure_days is inside the error set"
    rewrite(shard, marked, None)
    assert "forbidden by the contradicts_guard" in _findings(
        *_b5_in_process(a, shard)[:2], a, shard)

    lintmod, state, _m = _b5_in_process(a, shard)
    monkeypatch.setattr(lintmod.comment_closure, "CONTRADICTS_GUARD",
                        "never_emitted")
    assert "forbidden by the contradicts_guard" not in _findings(
        lintmod, state, a, shard)


def test_test3_c_coordinate_validation(tmp_path, monkeypatch):
    _root, a, shard, _closure = good(tmp_path)
    far = dict(PACK, du=dict(PACK["du"], consumer="do/pack_crates.do:9999"))
    a.write("_run/definition_use_bundles.md",
            _du_artifact([far, TALLY, TALLY_OVERWRITE]))
    assert "outside the file's 10 line(s)" in _findings(
        *_b5_in_process(a, shard)[:2], a, shard)

    lintmod, state, _m = _b5_in_process(a, shard)
    monkeypatch.setattr(lintmod.comment_closure, "require_in_range",
                        lambda *args, **kw: None)
    assert "outside the file's" not in _findings(lintmod, state, a, shard)


def test_test3_c_span_source_presence(tmp_path, monkeypatch):
    _root, a, shard, _closure = good(tmp_path)
    (a.audit / "_run/definition_use_bundles.md").unlink()
    assert "definition_use_bundles.md" in _findings(
        *_b5_in_process(a, shard)[:2], a, shard)

    lintmod, state, _m = _b5_in_process(a, shard)
    monkeypatch.setattr(
        lintmod.comment_closure, "du_artifact_row",
        lambda audit, source_id, witness_id: {
            "Definition Site": "do/pack_crates.do:7",
            "Consumer Site": "do/pack_crates.do:7",
            "Variable": "sealed_crate_flag", "Full Guard": "seal_hours < ."})
    assert "definition_use_bundles.md" not in _findings(lintmod, state, a, shard)


def test_test3_d_quote_comparison(tmp_path, monkeypatch):
    _root, a, shard, closure = planted(tmp_path)
    swapped = [list(row) for row in closure]
    swapped[1][4] = mechanism.encode_cell("* an entirely different sentence")
    rewrite(shard, swapped, None)
    assert "Quoted Text does not match the source line" in _findings(
        *_b5_in_process(a, shard)[:2], a, shard)

    lintmod, state, _m = _b5_in_process(a, shard)
    monkeypatch.setattr(lintmod, "_verify_comment_quote",
                        lambda *args, **kw: None)
    assert "Quoted Text does not match the source line" not in _findings(
        lintmod, state, a, shard)


def test_test3_e_verdict_vocabulary(tmp_path, monkeypatch):
    _root, a, shard, closure = good(tmp_path)
    bad = [list(row) for row in closure]
    bad[0][5] = "fine"
    rewrite(shard, bad, None)
    assert "has invalid Verdict 'fine'" in _findings(
        *_b5_in_process(a, shard)[:2], a, shard)

    lintmod, state, _m = _b5_in_process(a, shard)
    monkeypatch.setattr(lintmod.comment_closure, "VERDICTS",
                        lintmod.comment_closure.VERDICTS + ("fine",))
    assert "has invalid Verdict 'fine'" not in _findings(lintmod, state, a, shard)


# ------------------------------------------ b5s inheritance + CLI drills


def _supplementary(tmp_path):
    """The good case projected onto a b5s supplementary shard."""
    root, a, shard, closure = good(tmp_path)
    a.write("code_error_recheck_summary.md",
            "# code recheck summary\n\nSplits declared: 1\nMerges declared: 0\n\n"
            + rb.md_table(lint.LINEAGE_COLS,
                          [["E-7000", "E-7100", key["channel"], key["source"],
                            key["witness"]]
                           for key in (PACK, TALLY, TALLY_OVERWRITE, AC_KEY,
                                       CV_KEY, MF_KEY)]))
    body = shard.read_text(encoding="utf-8").replace("E-7000", "E-7100")
    supplementary = a.write("_code_error_recheck_supplementary/k1.md", body)
    (supplementary.parent / "probe.py").write_text(PROBE_PY, encoding="utf-8")
    inventory = [("E-7100", "detector", PACK["source"])]
    clusters = [("K1", "detector", "E-7100",
                 "`audit/_code_error_recheck_supplementary/k1.md`")]
    a.write("plans/code_error_supplementary_recheck_plan.md",
            rb.recheck_plan_text("code", inventory, clusters))
    return root, a, supplementary, closure


def test_b5s_inherits_the_gate(tmp_path):
    _root, a, supplementary, _closure = _supplementary(tmp_path)
    result = _run(a, supplementary, stage="b5s-code")
    assert result.returncode == 0, result.stdout + result.stderr


def test_b5s_drill_deleting_a_required_row_fails(tmp_path):
    _root, a, supplementary, closure = _supplementary(tmp_path)
    dropped = _site(PACK, 2)
    rewrite(supplementary, [row for row in closure if row[3] != dropped], None)
    result = _run(a, supplementary, stage="b5s-code")
    assert result.returncode == 1
    assert f"E-7100 not_error is missing the '### Comment closure' row" in result.stdout


def test_drill_hard_rule_flips_in_both_directions(tmp_path):
    """Production-CLI drill (ii): the failure appears and disappears on demand."""
    _root, a, shard, closure = planted(tmp_path)
    contradicting = [list(row) for row in closure]
    contradicting[1][5] = "contradicts_guard"
    contradicting[1][6] = "missing cure_days is inside the error set"
    rewrite(shard, contradicting, None)
    assert "forbidden by the contradicts_guard" in _run(a, shard).stdout
    softened = [list(row) for row in contradicting]
    softened[1][5] = "consistent"
    rewrite(shard, softened, None)
    quiet = _run(a, shard)
    assert quiet.returncode == 0, quiet.stdout + quiet.stderr
    rewrite(shard, contradicting, None)
    restored = _run(a, shard)
    assert restored.returncode == 1
    assert "forbidden by the contradicts_guard" in restored.stdout
