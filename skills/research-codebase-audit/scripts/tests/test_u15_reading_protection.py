"""U15 — the open-reading budget protection policy.

Five rules, of which two carry lints and both are Tier-1 members:

* **Rule 2 — the phase-note partition.** Every non-recheck shard footer gains a
  third part, a `| Phase | Register IDs |` table partitioning the shard's own
  rows into `found_by_reading` / `found_by_probe`; the b3/b3b merge reports
  carry the exact union as `phase_partition`.  Partition only — the lint never
  judges the two counts.
* **Rule 3 — the block-coverage duty.** A second-read shard divides each
  readable assigned scope into natural blocks and writes one
  `| Scope | Block Lines | Purpose | Outcome |` line per block; the lint proves
  a gap-free tiling that reaches the scope's extent (code: the file's real last
  line, claims: the conductor-declared span's endpoints).

Rules 1, 4 and 5 are prose: the two-phase prompt duty, the ungated drift line,
and the untouched probe budget.  Fixture content is an invented
orchard-irrigation study; nothing here is derived from any real package.
"""

import json

import pytest

import regbuild as rb


lint = rb.load_script("lint_registers")

pytestmark = pytest.mark.u15


# --------------------------------------------------------------------------
# The synthetic package tree (invented; no real study is referenced)
# --------------------------------------------------------------------------

PANEL = "code/build_orchard_panel.py"
PANEL_LINES = 48
PANEL_BLOCKS = [("1–6", "imports and path setup"), ("7–18", "data load"),
                ("19–37", "transform section"), ("38–48", "figure and export")]
WATER = "code/estimate_water_effect.do"
WATER_LINES = 30
ORCHARD_ENV = "requirements-orchard.txt"
PAPER = "paper/orchard_paper.md"
PAPER_LINES = 240
CLAIMS_SPAN = (210, 239)


def write_package(a):
    """Write the invented orchard package beside the synthetic audit dir."""
    rb.write_code_scope(a, PANEL, PANEL_LINES)
    rb.write_code_scope(a, WATER, WATER_LINES)
    rb.write_code_scope(a, PAPER, PAPER_LINES)
    rb.write_code_scope(a, ORCHARD_ENV, 4)


def blocks(rows):
    return "\n### Block coverage\n\n" + rb.block_table_text(rows)


def panel_blocks(findings_on="19–37", finding="E-0911"):
    """The canonical gap-free tiling of the 48-line panel builder."""
    return [(f"`{PANEL}`", lines, purpose,
             f"findings: {finding}" if lines == findings_on else "clean")
            for lines, purpose in PANEL_BLOCKS]


# --------------------------------------------------------------------------
# b2 first-pass fixtures (Rule 2 only — the block duty is second-read only)
# --------------------------------------------------------------------------

def b2_code(tmp_path, *, reading=("E-0901",), probe=("E-0902",),
            rows=("E-0901", "E-0902"), phase=True, phase_rows=None):
    a = rb.AuditDir(tmp_path)
    a.write_manifest()
    write_package(a)
    a.write(
        "plans/code_error_review_plan.md",
        "# Code-error review plan\n\n"
        "| Chunk ID | Script Scope | Error ID Range | Shard File |\n"
        "| --- | --- | --- | --- |\n"
        f"| C01 | `{PANEL}` | E-0900–E-0949 | `audit/_code_errors/c01.md` |\n\n"
        "Merge-coordinator range: E-0990–E-0999\n\n"
        "| Script | Chunk |\n| --- | --- |\n"
        f"| `{PANEL}` | C01 |\n\n"
        "| Hygiene File | Chunk |\n| --- | --- |\n"
        f"| `{ORCHARD_ENV}` | C01 |\n",
    )
    error_rows = [rb.error_row(rid, status="candidate", severity="2",
                               source=f"`{PANEL}`",
                               location=f"`{PANEL}:20`")
                  for rid in rows]
    text = rb.md_table(rb.ERROR_COLS, error_rows)
    text += "\n### Coverage\n\n" + rb.md_table(
        lint.COVERAGE_COLS,
        [[f"`{PANEL}`", f"findings: {'; '.join(rows)}" if rows else "clean"],
         [f"`{ORCHARD_ENV}`", "clean"],
         [f"`{lint.HYGIENE_SINGLETON}`", "clean"]])
    text += "\n### Footer dispositions\n\n" + rb.md_table(
        lint.FOOTER_COLS,
        [[f"OBS-{index:04d}", "candidate", rid, "row retained", ""]
         for index, rid in enumerate(rows, start=1)])
    if phase:
        text += "\n### Reading phase\n\n" + (
            rb.md_table(lint.PHASE_COLS, phase_rows) if phase_rows
            else rb.phase_table_text(reading, probe))
    return a, a.write("_code_errors/c01.md", text)


def b2_claims(tmp_path, *, reading=("C-0901", "C-0902", "O-0901"), probe=()):
    a = rb.AuditDir(tmp_path)
    a.write_manifest()
    a.write(
        "plans/claims_review_plan.md",
        "# Claims review plan\n\n"
        "| Worker ID | Worker Scope | Claim ID Range | Output ID Range | Shard File |\n"
        "| --- | --- | --- | --- | --- |\n"
        "| S01 | orchard paper | C-0900–C-0949 | O-0900–O-0949 | "
        "`audit/_work/s01.md` |\n\n"
        "Merge-coordinator range: C-0990–C-0999\n"
        "Merge-coordinator range: O-0990–O-0999\n",
    )
    claims = [rb.claims_row("C-0901", status="unclear"),
              rb.claims_row("C-0902", status="unclear")]
    outputs = [rb.output_row("O-0901")]
    text = rb.register_text("Claims", rb.CLAIMS_COLS, claims)
    text += "\n" + rb.register_text("Outputs", rb.OUTPUT_COLS, outputs)
    text += "\n### Coverage\n\nEvery assigned unit has a row or a skip note.\n"
    text += "\n### Footer dispositions\n\n" + rb.md_table(
        lint.FOOTER_COLS,
        [["OBS-0001", "candidate", "C-0901; C-0902; O-0901",
          "rows retained", ""]])
    text += "\n### Reading phase\n\n" + rb.phase_table_text(reading, probe)
    return a, a.write("_work/s01.md", text)


# --------------------------------------------------------------------------
# b3b second-read fixtures (Rules 2 and 3)
# --------------------------------------------------------------------------

def b3b_code(tmp_path, *, block_rows=None, coverage=None, rows=("E-0911",),
             blocked_second_scope=False, phase=True):
    a = rb.AuditDir(tmp_path)
    a.write_manifest()
    write_package(a)
    plan = (
        "# Code-error second-read plan\n\n"
        "| Worker ID | Script Scope | Shard File | Error ID Range | "
        "Reason | Known Findings | Assigned Handoff IDs |\n"
        "| --- | --- | --- | --- | --- | --- | --- |\n"
        f"| sr-c01 | `{PANEL}`"
        + (f"; `{WATER}`" if blocked_second_scope else "")
        + " | `audit/_code_errors_second_read/sr-c01.md` | "
        "E-0911–E-0920 | flagged | E-0142 | — |\n"
    )
    a.write("plans/code_error_second_read_plan.md", plan)
    a.write(
        "plans/code_error_review_plan.md",
        "# Code-error review plan\n\n"
        "| Chunk ID | Script Scope | Error ID Range | Shard File |\n"
        "| --- | --- | --- | --- |\n"
        f"| C01 | `{PANEL}` | E-0100–E-0199 | `audit/_code_errors/c01.md` |\n\n"
        "Merge-coordinator range: E-0800–E-0849\n\n"
        "| Script | Chunk |\n| --- | --- |\n"
        f"| `{PANEL}` | C01 |\n",
    )
    error_rows = [rb.error_row(rid, status="candidate", severity="2",
                               source=f"`{PANEL}`",
                               location=f"`{PANEL}:20`")
                  for rid in rows]
    coverage = coverage if coverage is not None else (
        [[f"`{PANEL}`", f"findings: {'; '.join(rows)}" if rows else "clean"]]
        + ([[f"`{WATER}`", "blocked: proprietary license"]]
           if blocked_second_scope else []))
    text = rb.md_table(rb.ERROR_COLS, error_rows)
    text += "\n### Coverage\n\n" + rb.md_table(lint.COVERAGE_COLS, coverage)
    text += "\n### Footer dispositions\n\n" + rb.md_table(
        lint.FOOTER_COLS,
        [[f"OBS-{index:04d}", "candidate", rid, "row retained", ""]
         for index, rid in enumerate(rows, start=1)])
    if phase:
        text += "\n### Reading phase\n\n" + rb.phase_table_text(rows)
    text += blocks(block_rows if block_rows is not None
                   else panel_blocks(finding=rows[0] if rows else "E-0911"))
    return a, a.write("_code_errors_second_read/sr-c01.md", text)


def b3b_claims(tmp_path, *, block_rows=None, scope_cell=None,
               claim_rows=("C-0911",), exempt=()):
    """A claims second-read shard; *exempt* rows are cited by resolved handoffs.

    The handoff-exemption leg is exercised without the U7 ledger machinery by
    keeping the exempt row out of ``claim_rows`` where it is not wanted; the
    U7 suite covers the ledger-backed path end to end.
    """
    a = rb.AuditDir(tmp_path)
    a.write_manifest()
    write_package(a)
    cell = scope_cell if scope_cell is not None else (
        f"Irrigation-response section — `{PAPER}:{CLAIMS_SPAN[0]}–{CLAIMS_SPAN[1]}`")
    a.write(
        "plans/claims_second_read_plan.md",
        "# Claims second-read plan\n\n"
        "| Worker ID | File/Section Scope | Shard File | Claim ID Range | "
        "Output ID Range | Reason | Known Findings | Assigned Handoff IDs |\n"
        "| --- | --- | --- | --- | --- | --- | --- | --- |\n"
        f"| sr-s01 | {cell} | `audit/_work_second_read/sr-s01.md` | "
        "C-0911–C-0920 | O-0911–O-0920 | flagged | C-0142 |  |\n",
    )
    a.write_claims_plan()
    claims = [rb.claims_row(cid, status="inconsistent") for cid in claim_rows]
    text = rb.register_text("Claims", rb.CLAIMS_COLS, claims)
    text += "\n" + rb.register_text("Outputs", rb.OUTPUT_COLS, [])
    text += "\n### Coverage\n\nThe assigned section was reread in full.\n"
    text += "\n### Footer dispositions\n\n" + rb.md_table(
        lint.FOOTER_COLS,
        [[f"OBS-{index:04d}", "candidate", cid, "row retained", ""]
         for index, cid in enumerate(claim_rows, start=1)])
    text += "\n### Reading phase\n\n" + rb.phase_table_text(claim_rows)
    default = [(f"`{PAPER}`", "210–224", "headline estimate paragraphs",
                f"findings: {'; '.join(claim_rows)}" if claim_rows else "clean"),
               (f"`{PAPER}`", "225–239", "robustness discussion", "clean")]
    text += blocks(block_rows if block_rows is not None else default)
    return a, a.write("_work_second_read/sr-s01.md", text)


def b3b_code_merge(tmp_path, *, report_overrides=None, **kwargs):
    """A complete b3b code merge boundary around one second-read shard."""
    a, shard = b3b_code(tmp_path, **kwargs)
    rows = kwargs.get("rows", ("E-0911",))
    error_rows = [rb.error_row(rid, status="candidate", severity="2",
                               source=f"`{PANEL}`", location=f"`{PANEL}:20`")
                  for rid in rows]
    a.write_register("_run/snapshots/code_b3b/code_error_register.md",
                     rb.ERROR_COLS, [])
    a.write_register("code_error_register.md", rb.ERROR_COLS, error_rows)
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS,
                     error_rows)
    report = {
        "code_error_register.md": {
            "shard_rows": len(rows), "dedup_removed": 0, "added": len(rows)},
        "footer_dispositions": [
            f"audit/_code_errors_second_read/sr-c01.md#OBS-{index:04d} | "
            f"candidate:{rid}" for index, rid in enumerate(rows, start=1)],
        **rb.report_phase_fields(reading=list(rows), blocks=(4, 3)),
    }
    report.update(report_overrides or {})
    a.write("_run/merge_report_code_b3b.json", json.dumps(report))
    a.write_manifest(stages={"code_b3b": {
        "status": "running", "retries": 0,
        "shards": {"audit/_code_errors_second_read/sr-c01.md": {
            "status": "done", "retries": 0}}}})
    return a, shard


def b3_code_merge(tmp_path, *, report_overrides=None, **kwargs):
    """A complete b3 code merge boundary around one first-pass shard."""
    a, _shard = b2_code(tmp_path, **kwargs)
    rows = kwargs.get("rows", ("E-0901", "E-0902"))
    error_rows = [rb.error_row(rid, status="candidate", severity="2",
                               source=f"`{PANEL}`", location=f"`{PANEL}:20`")
                  for rid in rows]
    a.write_register("code_error_register.md", rb.ERROR_COLS, error_rows)
    a.write_register("_staging/code_error_register.md", rb.ERROR_COLS,
                     error_rows)
    report = {
        "code_error_register.md": {
            "shard_rows": len(rows), "dedup_removed": 0, "added": len(rows),
            "conflicts": [], "coverage_gaps": [], "blocked_shards": []},
        "footer_dispositions": [
            f"audit/_code_errors/c01.md#OBS-{index:04d} | candidate:{rid}"
            for index, rid in enumerate(rows, start=1)],
        "unreviewed_files": [],
        "coverage_outcomes": {
            PANEL: f"findings: {'; '.join(rows)}" if rows else "clean",
            ORCHARD_ENV: "clean", lint.HYGIENE_SINGLETON: "clean"},
        **rb.report_phase_fields(reading=[rows[0]], probe=[rows[1]]),
    }
    report.update(report_overrides or {})
    a.write("_run/merge_report_code.json", json.dumps(report))
    a.write_manifest(stages={"code_b2": {
        "status": "done", "retries": 0,
        "shards": {"audit/_code_errors/c01.md": {
            "status": "done", "retries": 0}}}})
    return a


# ==========================================================================
# Tier-1 member (a) — the phase-note partition
# ==========================================================================

# --- Test 1: it fires ------------------------------------------------------


def test_row_absent_from_both_phase_lists_fails_naming_the_id(tmp_path):
    a, shard = b2_code(tmp_path, reading=["E-0901"], probe=[])
    res = rb.lint(a, "b2-code", shard)
    assert res.returncode == 1
    assert ("E-0902 is missing from both phase lists") in res.stdout


def test_row_in_both_phase_lists_fails(tmp_path):
    a, shard = b2_code(tmp_path, reading=["E-0901", "E-0902"],
                       probe=["E-0902"])
    res = rb.lint(a, "b2-code", shard)
    assert res.returncode == 1
    assert "E-0902 in both found_by_reading and found_by_probe" in res.stdout


def test_phantom_phase_id_that_is_not_a_shard_row_fails(tmp_path):
    a, shard = b2_code(tmp_path, reading=["E-0901", "E-0999"],
                       probe=["E-0902"])
    res = rb.lint(a, "b2-code", shard)
    assert res.returncode == 1
    assert "phase table lists E-0999, which is not a row in the shard" in res.stdout


def test_missing_phase_table_fails(tmp_path):
    a, shard = b2_code(tmp_path, phase=False)
    res = rb.lint(a, "b2-code", shard)
    assert res.returncode == 1
    assert "expected exactly one phase table" in res.stdout


def test_three_row_phase_table_fails(tmp_path):
    a, shard = b2_code(tmp_path, phase_rows=[
        ["found_by_reading", "E-0901"], ["found_by_probe", "E-0902"],
        ["found_by_hunch", " "]])
    res = rb.lint(a, "b2-code", shard)
    assert res.returncode == 1
    assert "phase table must have exactly 2 rows" in res.stdout


def test_wrong_phase_row_order_fails(tmp_path):
    a, shard = b2_code(tmp_path, phase_rows=[
        ["found_by_probe", "E-0902"], ["found_by_reading", "E-0901"]])
    res = rb.lint(a, "b2-code", shard)
    assert res.returncode == 1
    assert "phase table row 1 must be 'found_by_reading'" in res.stdout


def test_claims_b2_shard_partition_fires(tmp_path):
    a, shard = b2_claims(tmp_path, reading=["C-0901", "O-0901"])
    res = rb.lint(a, "b2-claims", shard)
    assert res.returncode == 1
    assert "C-0902 is missing from both phase lists" in res.stdout


def test_b3b_shard_partition_fires(tmp_path):
    a, shard = b3b_code(tmp_path, rows=["E-0911", "E-0912"])
    # The builder lists both rows under reading; drop one to open the hole.
    shard.write_text(
        shard.read_text(encoding="utf-8").replace(
            "E-0911; E-0912", "E-0911"), encoding="utf-8")
    res = rb.lint(a, "b3b-code", shard)
    assert res.returncode == 1
    assert "E-0912 is missing from both phase lists" in res.stdout


def test_b3_merge_report_omitting_a_phase_id_fails(tmp_path):
    a = b3_code_merge(tmp_path, report_overrides={
        "phase_partition": {"found_by_reading": ["E-0901"],
                            "found_by_probe": []}})
    res = rb.lint(a, "b3-code")
    assert res.returncode == 1
    assert "phase_partition disagrees with shard evidence" in res.stdout


def test_b3_merge_report_with_a_phantom_phase_id_fails(tmp_path):
    a = b3_code_merge(tmp_path, report_overrides={
        "phase_partition": {"found_by_reading": ["E-0901"],
                            "found_by_probe": ["E-0902", "E-0999"]}})
    res = rb.lint(a, "b3-code")
    assert res.returncode == 1
    assert "phase_partition disagrees with shard evidence" in res.stdout


def test_b3b_merge_report_omitting_a_phase_id_fails(tmp_path):
    a, _shard = b3b_code_merge(tmp_path, report_overrides={
        "phase_partition": {"found_by_reading": [], "found_by_probe": []}})
    res = rb.lint(a, "b3b-code")
    assert res.returncode == 1
    assert "phase_partition disagrees with shard evidence" in res.stdout


def test_b3b_merge_report_missing_block_coverage_fails(tmp_path):
    a, _shard = b3b_code_merge(tmp_path)
    path = a.audit / "_run/merge_report_code_b3b.json"
    report = json.loads(path.read_text())
    del report["block_coverage"]
    path.write_text(json.dumps(report), encoding="utf-8")
    res = rb.lint(a, "b3b-code")
    assert res.returncode == 1
    assert "must carry object-valued 'block_coverage'" in res.stdout


def test_b3b_merge_revalidates_block_ranges_not_just_counts(tmp_path):
    """Review F3: an invalid tiling cannot cross the merge behind good counts.

    The shard lint is never run here — only the b3b merge stage — so this is the
    half of Tier-1 member (b) that survives a skipped or resumed shard lint.
    """
    gapped = [row for row in panel_blocks() if row[1] != "7–18"]
    a, _shard = b3b_code_merge(tmp_path, block_rows=gapped,
                               report_overrides={"block_coverage": {
                                   "blocks_covered": 3, "blocks_clean": 2}})
    res = rb.lint(a, "b3b-code")
    assert res.returncode == 1, res.stdout + res.stderr
    assert "block gap between lines 6 and 19" in res.stdout
    # The counts themselves agree, so only the re-validation can be speaking.
    assert "block_coverage disagrees" not in res.stdout


def test_b3b_merge_revalidates_the_extent_anchor(tmp_path):
    truncated = [row if row[1] != "38–48" else (row[0], "38–45", row[2], row[3])
                 for row in panel_blocks()]
    a, _shard = b3b_code_merge(tmp_path, block_rows=truncated)
    res = rb.lint(a, "b3b-code")
    assert res.returncode == 1, res.stdout + res.stderr
    assert "blocks end at 45" in res.stdout
    assert "block_coverage disagrees" not in res.stdout


def test_b3b_merge_report_block_counts_off_by_one_fails(tmp_path):
    a, _shard = b3b_code_merge(tmp_path, report_overrides={
        "block_coverage": {"blocks_covered": 4, "blocks_clean": 4}})
    res = rb.lint(a, "b3b-code")
    assert res.returncode == 1
    assert "block_coverage disagrees with shard evidence" in res.stdout


# --- Test 2: it stays quiet ------------------------------------------------


def test_correct_partition_passes_on_a_b2_code_shard(tmp_path):
    a, shard = b2_code(tmp_path)
    res = rb.lint(a, "b2-code", shard)
    assert res.returncode == 0, res.stdout + res.stderr


def test_all_reading_partition_passes_on_a_b2_claims_shard(tmp_path):
    a, shard = b2_claims(tmp_path)
    res = rb.lint(a, "b2-claims", shard)
    assert res.returncode == 0, res.stdout + res.stderr


def test_correct_partition_passes_on_a_b3b_shard(tmp_path):
    a, shard = b3b_code(tmp_path)
    res = rb.lint(a, "b3b-code", shard)
    assert res.returncode == 0, res.stdout + res.stderr


def test_all_probe_partition_passes_no_count_judgment(tmp_path):
    a, shard = b2_code(tmp_path, reading=[], probe=["E-0901", "E-0902"])
    res = rb.lint(a, "b2-code", shard)
    assert res.returncode == 0, res.stdout + res.stderr


def test_rowless_shard_with_two_empty_lists_passes(tmp_path):
    a, shard = b2_code(tmp_path, rows=[], reading=[], probe=[])
    res = rb.lint(a, "b2-code", shard)
    assert res.returncode == 0, res.stdout + res.stderr


def test_matching_phase_partition_passes_at_b3(tmp_path):
    a = b3_code_merge(tmp_path)
    res = rb.lint(a, "b3-code")
    assert res.returncode == 0, res.stdout + res.stderr


def test_matching_phase_partition_and_blocks_pass_at_b3b(tmp_path):
    a, _shard = b3b_code_merge(tmp_path)
    res = rb.lint(a, "b3b-code")
    assert res.returncode == 0, res.stdout + res.stderr


# ==========================================================================
# Tier-1 member (b) — the block-coverage duty
# ==========================================================================

# --- Test 1: it fires ------------------------------------------------------


def test_interior_block_gap_fails_naming_the_gap(tmp_path):
    rows = [row for row in panel_blocks() if row[1] != "7–18"]
    a, shard = b3b_code(tmp_path, block_rows=rows)
    res = rb.lint(a, "b3b-code", shard)
    assert res.returncode == 1
    assert "block gap between lines 6 and 19" in res.stdout


def test_overlapping_blocks_fail(tmp_path):
    rows = [(f"`{PANEL}`", "1–6", "imports and path setup", "clean"),
            (f"`{PANEL}`", "5–18", "data load", "clean"),
            (f"`{PANEL}`", "19–37", "transform section", "findings: E-0911"),
            (f"`{PANEL}`", "38–48", "figure and export", "clean")]
    a, shard = b3b_code(tmp_path, block_rows=rows)
    res = rb.lint(a, "b3b-code", shard)
    assert res.returncode == 1
    assert "overlap" in res.stdout


def test_truncated_last_block_fails_naming_the_extent(tmp_path):
    rows = [row if row[1] != "38–48" else (row[0], "38–45", row[2], row[3])
            for row in panel_blocks()]
    a, shard = b3b_code(tmp_path, block_rows=rows)
    res = rb.lint(a, "b3b-code", shard)
    assert res.returncode == 1
    assert "blocks end at 45" in res.stdout
    assert "ends at line 48" in res.stdout


def test_claims_blocks_omitting_the_span_start_fail(tmp_path):
    a, shard = b3b_claims(tmp_path, block_rows=[
        (f"`{PAPER}`", "212–239", "headline estimate paragraphs",
         "findings: C-0911")])
    res = rb.lint(a, "b3b-claims", shard)
    assert res.returncode == 1
    assert "blocks start at 212" in res.stdout
    assert "starts at line 210" in res.stdout


def test_claims_blocks_omitting_the_span_end_fail(tmp_path):
    a, shard = b3b_claims(tmp_path, block_rows=[
        (f"`{PAPER}`", "210–230", "headline estimate paragraphs",
         "findings: C-0911")])
    res = rb.lint(a, "b3b-claims", shard)
    assert res.returncode == 1
    assert "blocks end at 230" in res.stdout


def test_claims_interior_gap_fails(tmp_path):
    a, shard = b3b_claims(tmp_path, block_rows=[
        (f"`{PAPER}`", "210–224", "headline estimate paragraphs",
         "findings: C-0911"),
        (f"`{PAPER}`", "226–239", "robustness discussion", "clean")])
    res = rb.lint(a, "b3b-claims", shard)
    assert res.returncode == 1
    assert "block gap between lines 224 and 226" in res.stdout


def test_claims_allocation_without_a_span_token_fails_closed(tmp_path):
    a, shard = b3b_claims(tmp_path, scope_cell="Irrigation-response section")
    res = rb.lint(a, "b3b-claims", shard)
    assert res.returncode == 1
    assert "declares no readable span token" in res.stdout


def test_readable_scope_with_zero_block_rows_fails(tmp_path):
    a, shard = b3b_code(tmp_path, block_rows=[])
    res = rb.lint(a, "b3b-code", shard)
    assert res.returncode == 1
    assert "carries zero block-coverage rows" in res.stdout


def test_block_citing_a_non_shard_row_fails(tmp_path):
    rows = [row if row[1] != "19–37" else (row[0], row[1], row[2],
                                           "findings: E-0999")
            for row in panel_blocks()]
    a, shard = b3b_code(tmp_path, block_rows=rows)
    res = rb.lint(a, "b3b-code", shard)
    assert res.returncode == 1
    assert "cites E-0999, which is not a row in the shard" in res.stdout


def test_code_block_findings_union_must_equal_the_script_outcome(tmp_path):
    rows = [(row[0], row[1], row[2], "clean") for row in panel_blocks()]
    a, shard = b3b_code(tmp_path, block_rows=rows)
    res = rb.lint(a, "b3b-code", shard)
    assert res.returncode == 1
    assert "block findings IDs do not equal its" in res.stdout


def test_claims_ordinary_row_omitted_from_every_block_fails(tmp_path):
    a, shard = b3b_claims(tmp_path, block_rows=[
        (f"`{PAPER}`", "210–224", "headline estimate paragraphs", "clean"),
        (f"`{PAPER}`", "225–239", "robustness discussion", "clean")])
    res = rb.lint(a, "b3b-claims", shard)
    assert res.returncode == 1
    assert "block findings IDs do not equal the shard's non-handoff claim rows" \
        in res.stdout


MULTI_SPAN_CELL = (
    f"Sections 3 and 5 — `{PAPER}:100–140`; `{PAPER}:{CLAIMS_SPAN[0]}–"
    f"{CLAIMS_SPAN[1]}`")


def test_multi_span_cell_covering_only_the_last_span_fails(tmp_path):
    """A second declared span of the same file cannot be silently dropped."""
    a, shard = b3b_claims(tmp_path, scope_cell=MULTI_SPAN_CELL, block_rows=[
        (f"`{PAPER}`", "210–224", "headline paragraphs", "findings: C-0911"),
        (f"`{PAPER}`", "225–239", "robustness discussion", "clean")])
    res = rb.lint(a, "b3b-claims", shard)
    assert res.returncode == 1
    assert "declared span 100–140 carries zero block-coverage rows" in res.stdout


def test_multi_span_cell_covering_both_spans_passes(tmp_path):
    """The honest multi-span shard must be passable, span by span."""
    a, shard = b3b_claims(tmp_path, scope_cell=MULTI_SPAN_CELL, block_rows=[
        (f"`{PAPER}`", "100–120", "setup discussion", "clean"),
        (f"`{PAPER}`", "121–140", "identification argument", "clean"),
        (f"`{PAPER}`", "210–224", "headline paragraphs", "findings: C-0911"),
        (f"`{PAPER}`", "225–239", "robustness discussion", "clean")])
    res = rb.lint(a, "b3b-claims", shard)
    assert res.returncode == 0, res.stdout + res.stderr


def test_gap_inside_one_span_of_a_multi_span_cell_fails(tmp_path):
    a, shard = b3b_claims(tmp_path, scope_cell=MULTI_SPAN_CELL, block_rows=[
        (f"`{PAPER}`", "100–120", "setup discussion", "clean"),
        (f"`{PAPER}`", "125–140", "identification argument", "clean"),
        (f"`{PAPER}`", "210–224", "headline paragraphs", "findings: C-0911"),
        (f"`{PAPER}`", "225–239", "robustness discussion", "clean")])
    res = rb.lint(a, "b3b-claims", shard)
    assert res.returncode == 1
    assert "block gap between lines 120 and 125" in res.stdout


def test_readable_and_blocked_spans_of_one_file_coexist(tmp_path):
    """The documented `blocked:` grammar must not deadlock the block checks."""
    a, shard = b3b_claims(
        tmp_path,
        scope_cell=(f"`{PAPER}:{CLAIMS_SPAN[0]}–{CLAIMS_SPAN[1]}`; "
                    f"blocked: {PAPER.replace('orchard_paper', 'appendix')}"
                    ":240–260 — appendix under embargo"))
    res = rb.lint(a, "b3b-claims", shard)
    assert res.returncode == 0, res.stdout + res.stderr


def test_one_path_declared_both_readable_and_blocked_fails(tmp_path):
    a, shard = b3b_claims(
        tmp_path,
        scope_cell=(f"`{PAPER}:{CLAIMS_SPAN[0]}–{CLAIMS_SPAN[1]}`; "
                    f"blocked: {PAPER}:240–260 — appendix under embargo"))
    res = rb.lint(a, "b3b-claims", shard)
    assert res.returncode == 1
    assert "declared both readable and blocked" in res.stdout


def test_block_starting_outside_every_declared_span_fails(tmp_path):
    a, shard = b3b_claims(tmp_path, block_rows=[
        (f"`{PAPER}`", "210–224", "headline paragraphs", "findings: C-0911"),
        (f"`{PAPER}`", "225–239", "robustness discussion", "clean"),
        (f"`{PAPER}`", "300–320", "unassigned appendix", "clean")])
    res = rb.lint(a, "b3b-claims", shard)
    assert res.returncode == 1
    assert "block 300–320 starts outside every declared span" in res.stdout


def test_missing_block_table_on_a_b3b_shard_fails(tmp_path):
    a, shard = b3b_code(tmp_path)
    text = shard.read_text(encoding="utf-8")
    shard.write_text(text[:text.index("### Block coverage")], encoding="utf-8")
    res = rb.lint(a, "b3b-code", shard)
    assert res.returncode == 1
    assert "expected exactly one block-coverage table" in res.stdout


def test_unreadable_code_scope_file_fails_closed(tmp_path):
    a, shard = b3b_code(tmp_path)
    (a.root / PANEL).unlink()
    res = rb.lint(a, "b3b-code", shard)
    assert res.returncode == 1
    assert "cannot read block-coverage scope" in res.stdout


def test_block_level_blocked_outcome_is_refused(tmp_path):
    rows = [row if row[1] != "38–48" else
            (row[0], row[1], row[2], "blocked: generated output")
            for row in panel_blocks()]
    a, shard = b3b_code(tmp_path, block_rows=rows)
    res = rb.lint(a, "b3b-code", shard)
    assert res.returncode == 1
    assert "blocking is scope-level" in res.stdout


# --- Test 2: it stays quiet ------------------------------------------------


def test_gap_free_tiling_to_the_files_last_line_passes(tmp_path):
    a, shard = b3b_code(tmp_path)
    res = rb.lint(a, "b3b-code", shard)
    assert res.returncode == 0, res.stdout + res.stderr


def test_blocked_scope_with_zero_block_rows_passes(tmp_path):
    a, shard = b3b_code(tmp_path, blocked_second_scope=True)
    res = rb.lint(a, "b3b-code", shard)
    assert res.returncode == 0, res.stdout + res.stderr


def test_claims_span_starting_mid_file_passes_contiguity(tmp_path):
    a, shard = b3b_claims(tmp_path)
    res = rb.lint(a, "b3b-claims", shard)
    assert res.returncode == 0, res.stdout + res.stderr


def test_dash_class_is_accepted_in_block_lines(tmp_path):
    rows = [(row[0], row[1].replace("–", "-"), row[2], row[3])
            for row in panel_blocks()]
    a, shard = b3b_code(tmp_path, block_rows=rows)
    res = rb.lint(a, "b3b-code", shard)
    assert res.returncode == 0, res.stdout + res.stderr


# ==========================================================================
# Test 3 — the test of the test (one leg per failure class, review F4)
# ==========================================================================


def _errors(a, stage, shard=None):
    res = rb.lint(a, stage, shard)
    return res.stdout


def test_test3_neutered_partition_membership_kills_the_shard_assertions(
        tmp_path, monkeypatch):
    """Leg 1 — neuter `validate_phase_partition` (accept any lists)."""
    monkeypatch.setattr(lint, "validate_phase_partition",
                        lambda *_args, **_kw: None)
    state = lint.Lint()
    a, shard = b2_code(tmp_path, reading=["E-0901"], probe=[])
    text = shard.read_text(encoding="utf-8")
    entries, coverage, phase = lint.typed_shard_footer(
        state, shard, text, "code")
    lint.validate_footer_candidates(state, shard, text, "code", entries,
                                    coverage, phase)
    assert not any("missing from both phase lists" in error
                   for error in state.errors)


def test_test3_neutered_phase_report_identity_kills_the_merge_assertions(
        tmp_path, monkeypatch):
    """Leg 2 — neuter `check_phase_partition_report`."""
    monkeypatch.setattr(lint, "check_phase_partition_report",
                        lambda *_args, **_kw: None)
    a = b3_code_merge(tmp_path, report_overrides={
        "phase_partition": {"found_by_reading": ["E-0901"],
                            "found_by_probe": []}})
    state = lint.Lint()
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    lint.stage_b3(state, a.audit, "code", manifest)
    assert not any("phase_partition disagrees" in error
                   for error in state.errors)


def test_test3_neutered_block_count_identity_kills_the_b3b_assertion(
        tmp_path, monkeypatch):
    """Leg 3 — neuter `check_block_coverage_report`."""
    monkeypatch.setattr(lint, "check_block_coverage_report",
                        lambda *_args, **_kw: None)
    a, _shard = b3b_code_merge(tmp_path, report_overrides={
        "block_coverage": {"blocks_covered": 4, "blocks_clean": 4}})
    state = lint.Lint()
    manifest = json.loads((a.audit / "_run/manifest.json").read_text())
    lint.stage_b3b(state, a.audit, "code", manifest)
    assert not any("block_coverage disagrees" in error
                   for error in state.errors)


def test_test3_neutered_contiguity_kills_the_gap_and_overlap_assertions(
        tmp_path, monkeypatch):
    """Leg 4 — neuter the production contiguity predicate itself."""
    monkeypatch.setattr(lint, "check_block_contiguity",
                        lambda *_args, **_kw: None)
    gapped = [row for row in panel_blocks() if row[1] != "7–18"]
    a, shard = b3b_code(tmp_path / "gap", block_rows=gapped)
    state = lint.Lint()
    lint.stage_b3b_shard(state, a.audit, "code", shard)
    assert not any("block gap between lines" in error for error in state.errors), \
        state.errors

    overlapping = [(f"`{PANEL}`", "1–6", "imports", "clean"),
                   (f"`{PANEL}`", "5–18", "data load", "clean"),
                   (f"`{PANEL}`", "19–37", "transforms", "findings: E-0911"),
                   (f"`{PANEL}`", "38–48", "outputs", "clean")]
    b, overlap_shard = b3b_code(tmp_path / "overlap", block_rows=overlapping)
    state = lint.Lint()
    lint.stage_b3b_shard(state, b.audit, "code", overlap_shard)
    assert not any("overlap" in error for error in state.errors), state.errors


def test_test3_contiguity_leg_fails_when_the_predicate_is_live(tmp_path):
    """The leg-4 neuter is real: unpatched, both Test-1 assertions do fire."""
    gapped = [row for row in panel_blocks() if row[1] != "7–18"]
    a, shard = b3b_code(tmp_path / "gap", block_rows=gapped)
    state = lint.Lint()
    lint.stage_b3b_shard(state, a.audit, "code", shard)
    assert any("block gap between lines" in error for error in state.errors)


def test_test3_neutered_extent_anchor_kills_the_endpoint_assertions(
        tmp_path, monkeypatch):
    """Leg 5 — neuter the production extent-anchor predicate itself."""
    monkeypatch.setattr(lint, "check_block_extent", lambda *_args, **_kw: None)
    truncated = [row if row[1] != "38–48" else (row[0], "38–45", row[2], row[3])
                 for row in panel_blocks()]
    a, shard = b3b_code(tmp_path / "code", block_rows=truncated)
    state = lint.Lint()
    lint.stage_b3b_shard(state, a.audit, "code", shard)
    assert not any("blocks end at 45" in error for error in state.errors), \
        state.errors

    b, claims_shard = b3b_claims(tmp_path / "claims", block_rows=[
        (f"`{PAPER}`", "212–239", "headline paragraphs", "findings: C-0911")])
    state = lint.Lint()
    lint.stage_b3b_shard(state, b.audit, "claims", claims_shard)
    assert not any("blocks start at 212" in error for error in state.errors), \
        state.errors


def test_test3_extent_leg_fails_when_the_predicate_is_live(tmp_path):
    """The leg-5 neuter is real: unpatched, both Test-1 assertions do fire."""
    truncated = [row if row[1] != "38–48" else (row[0], "38–45", row[2], row[3])
                 for row in panel_blocks()]
    a, shard = b3b_code(tmp_path / "code", block_rows=truncated)
    state = lint.Lint()
    lint.stage_b3b_shard(state, a.audit, "code", shard)
    assert any("blocks end at 45" in error for error in state.errors)

    b, claims_shard = b3b_claims(tmp_path / "claims", block_rows=[
        (f"`{PAPER}`", "212–239", "headline paragraphs", "findings: C-0911")])
    state = lint.Lint()
    lint.stage_b3b_shard(state, b.audit, "claims", claims_shard)
    assert any("blocks start at 212" in error for error in state.errors)


# ==========================================================================
# Production-CLI sabotage drills (through the real gate)
# ==========================================================================


def test_tier1_drill_b2_phase_table_omitting_a_row_stops_the_cli(tmp_path):
    """Drill (i): plant a b2 code shard whose phase table omits one row ID."""
    a, shard = b2_code(tmp_path / "planted", reading=["E-0901"], probe=[])
    planted = rb.lint(a, "b2-code", shard)
    assert planted.returncode == 1, planted.stdout + planted.stderr
    assert "E-0902 is missing from both phase lists" in planted.stdout

    shard.write_text(
        shard.read_text(encoding="utf-8").replace(
            "| found_by_reading | E-0901 |",
            "| found_by_reading | E-0901; E-0902 |"),
        encoding="utf-8")
    repaired = rb.lint(a, "b2-code", shard)
    assert repaired.returncode == 0, repaired.stdout + repaired.stderr


def test_tier1_drill_hand_removed_block_line_stops_the_cli(tmp_path):
    """Drill (ii), #23's operator-named drill: remove one block line by hand."""
    a, shard = b3b_code(tmp_path / "drill")
    passing = rb.lint(a, "b3b-code", shard)
    assert passing.returncode == 0, passing.stdout + passing.stderr

    original = shard.read_text(encoding="utf-8")
    removed_line = f"| `{PANEL}` | 7–18 | data load | clean |\n"
    assert removed_line in original
    shard.write_text(original.replace(removed_line, ""), encoding="utf-8")
    sabotaged = rb.lint(a, "b3b-code", shard)
    assert sabotaged.returncode == 1, sabotaged.stdout + sabotaged.stderr
    assert "block gap between lines 6 and 19" in sabotaged.stdout

    shard.write_text(original, encoding="utf-8")
    restored = rb.lint(a, "b3b-code", shard)
    assert restored.returncode == 0, restored.stdout + restored.stderr


def test_tier1_drill_corrupted_merge_phase_partition_stops_the_cli(tmp_path):
    """Drill (iii): drop one ID from the b3b report's `phase_partition`."""
    a, _shard = b3b_code_merge(tmp_path / "merge")
    passing = rb.lint(a, "b3b-code")
    assert passing.returncode == 0, passing.stdout + passing.stderr

    path = a.audit / "_run/merge_report_code_b3b.json"
    report = json.loads(path.read_text())
    report["phase_partition"]["found_by_reading"] = []
    path.write_text(json.dumps(report), encoding="utf-8")
    sabotaged = rb.lint(a, "b3b-code")
    assert sabotaged.returncode == 1, sabotaged.stdout + sabotaged.stderr
    assert "phase_partition disagrees with shard evidence" in sabotaged.stdout


# ==========================================================================
# Tier 2
# ==========================================================================


def test_recheck_shard_without_a_phase_table_still_passes():
    """The recheck exemption: no phase table is required and none is refused."""
    state = lint.Lint()
    text = rb.md_table(lint.FOOTER_COLS, [
        ["OBS-0001", "candidate", "", "a defect", ""]])
    entries, coverage, phase = lint.typed_shard_footer(
        state, "k1.md", text, "code", recheck=True)
    assert state.errors == []
    assert phase is None
    assert coverage == []
    assert len(entries) == 1


def test_zero_work_b3b_report_with_empty_lists_and_zeros_passes(tmp_path):
    a = rb.AuditDir(tmp_path)
    a.write_manifest(stages={"code_b3b": {"status": "running", "retries": 0,
                                          "shards": {}}})
    a.write("plans/code_error_second_read_plan.md",
            "# Code-error second-read plan\n\n"
            "| Worker ID | Script Scope | Shard File | Error ID Range | "
            "Reason | Known Findings | Assigned Handoff IDs |\n"
            "| --- | --- | --- | --- | --- | --- | --- |\n")
    a.write(
        "plans/code_error_review_plan.md",
        "# Code-error review plan\n\n"
        "| Chunk ID | Script Scope | Error ID Range | Shard File |\n"
        "| --- | --- | --- | --- |\n"
        f"| C01 | `{PANEL}` | E-0100–E-0199 | `audit/_code_errors/c01.md` |\n\n"
        "Merge-coordinator range: E-0800–E-0849\n",
    )
    a.write_register("code_error_register.md", rb.ERROR_COLS, [])
    a.write_register("_run/snapshots/code_b3b/code_error_register.md",
                     rb.ERROR_COLS, [])
    a.write("_run/merge_report_code_b3b.json", json.dumps({
        "code_error_register.md": {"shard_rows": 0, "dedup_removed": 0,
                                   "added": 0},
        "footer_dispositions": [],
        **rb.report_phase_fields(blocks=(0, 0)),
    }))
    res = rb.lint(a, "b3b-code")
    assert res.returncode == 0, res.stdout + res.stderr


def test_handoff_exempt_claim_absent_from_every_block_still_passes(tmp_path):
    """Review F2's exemption leg, exercised on the validator directly."""
    a, shard = b3b_claims(tmp_path, claim_rows=["C-0911", "C-0912"],
                          block_rows=[
                              (f"`{PAPER}`", "210–224", "headline paragraphs",
                               "findings: C-0911"),
                              (f"`{PAPER}`", "225–239", "robustness discussion",
                               "clean")])
    text = shard.read_text(encoding="utf-8")
    allocation = {"File/Section Scope":
                  f"Irrigation-response section — "
                  f"`{PAPER}:{CLAIMS_SPAN[0]}–{CLAIMS_SPAN[1]}`"}
    state = lint.Lint()
    rows = lint.block_coverage_table(
        state, a.audit, shard, text, "claims", allocation, [],
        lint.shard_register_ids(text, "claims"), {"C-0912"})
    assert state.errors == []
    assert len(rows) == 2

    strict = lint.Lint()
    lint.block_coverage_table(
        strict, a.audit, shard, text, "claims", allocation, [],
        lint.shard_register_ids(text, "claims"), frozenset())
    assert any("C-0912" in error for error in strict.errors)


def test_claims_coverage_note_prose_check_is_untouched():
    """`shard_footer` still requires the word, and U15 added nothing to it."""
    state = lint.Lint()
    lint.shard_footer(state, "s01.md", "no note here\n")
    assert any("missing coverage note in shard footer" in error
               for error in state.errors)
    quiet = lint.Lint()
    lint.shard_footer(quiet, "s01.md", "Coverage: every unit accounted for.\n")
    assert quiet.errors == []


def test_purpose_is_free_prose_but_must_be_present(tmp_path):
    rows = [(row[0], row[1], "—", row[3]) for row in panel_blocks()]
    a, shard = b3b_code(tmp_path, block_rows=rows)
    res = rb.lint(a, "b3b-code", shard)
    assert res.returncode == 1
    assert "requires a one-line Purpose" in res.stdout


def test_rule_5_moves_no_budget():
    """Rule 5: the probe budget and second-read caps stay byte-identical."""
    plan = rb.load_script("build_second_read_plan")
    assert plan.CAPS == {"shallow": 0, "standard": 10, "deep": 15}
    skill = (rb.SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
    assert '"compute_budget_minutes": 15' in skill


def test_typed_shard_footer_returns_the_three_tuple_contract():
    """Design call 1's return contract, relied on by all seven callers."""
    state = lint.Lint()
    text = rb.md_table(lint.FOOTER_COLS, []) + "\n" + rb.phase_table_text()
    result = lint.typed_shard_footer(state, "s.md", text, "claims")
    assert len(result) == 3
    assert result[2] == {"found_by_reading": [], "found_by_probe": [],
                         "parsed": True}
