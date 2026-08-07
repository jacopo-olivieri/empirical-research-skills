"""Smoke tests for export_xlsx.py (home for U6's hardening tests)."""

import pytest

import regbuild as rb

openpyxl = pytest.importorskip("openpyxl")

# U17: the exact author-facing Paper Claims shape — the 13 register columns
# minus `Used in Text`, `Output IDs`, `Blocked Check`, plus `Potential Issue`
# after `Status`, in register order.
VISIBLE_CLAIMS_COLS = [
    "Claim ID", "Paper Context", "Paper Quote", "Claim Type", "Claim Text",
    "Code/Data Source", "Status", "Potential Issue", "Severity",
    "Issue Description", "Related Error IDs",
]
HIDDEN_CLAIMS_COLS = ["Used in Text", "Output IDs", "Blocked Check"]


def make_canon_audit(tmp_path):
    a = rb.AuditDir(tmp_path)
    a.write_manifest(warnings=["one degraded-confidence warning"])
    a.write_register("claims_register.md", rb.CLAIMS_COLS, [
        rb.claims_row("C-0000"),  # schema example row — must be dropped
        rb.claims_row("C-0101", status="confirmed"),
        rb.claims_row("C-0102", status="inconsistent", severity="3",
                      issue="the paper and the artifact disagree"),
    ])
    a.write_register("code_error_register.md", rb.ERROR_COLS, [
        rb.error_row("E-0101", severity="2"),
    ])
    return a


def test_export_replication_workbook(tmp_path):
    a = make_canon_audit(tmp_path)
    out = tmp_path / "code_review.xlsx"
    res = rb.run_script("export_xlsx.py", "--audit-dir", a.audit,
                        "--mode", "replication", "-o", out)
    assert res.returncode == 0, res.stdout + res.stderr

    wb = openpyxl.load_workbook(out, read_only=True)
    assert set(wb.sheetnames) == {"Overview", "Paper Claims", "Code Errors"}

    ws = wb["Paper Claims"]
    data = list(ws.values)
    headers = [str(h) for h in data[0]]
    assert headers == VISIBLE_CLAIMS_COLS  # exact 11-column order
    assert not set(HIDDEN_CLAIMS_COLS) & set(headers)
    rows = {r[headers.index("Claim ID")]: r for r in data[1:]}
    assert "C-0000" not in rows  # example row dropped
    assert rows["C-0101"][headers.index("Potential Issue")] == "FALSE"
    assert rows["C-0102"][headers.index("Potential Issue")] == "TRUE"


# ---------------------------------------------------------------- U6 hardening


def _export(a, tmp_path, mode="replication"):
    out = tmp_path / "code_review.xlsx"
    res = rb.run_script("export_xlsx.py", "--audit-dir", a.audit,
                        "--mode", mode, "-o", out)
    return res, out


def _claims_cell(out, claim_id, column):
    """Read one cell of the Paper Claims sheet back with openpyxl."""
    wb = openpyxl.load_workbook(out)
    ws = wb["Paper Claims"]
    data = list(ws.values)
    headers = [str(h) for h in data[0]]
    row = next(r for r in data[1:] if r[headers.index("Claim ID")] == claim_id)
    cell_value = row[headers.index(column)]
    # locate the same physical cell so we can inspect its data_type
    col_i = headers.index(column) + 1
    for r_i, r in enumerate(data[1:], start=2):
        if r[headers.index("Claim ID")] == claim_id:
            return cell_value, ws.cell(row=r_i, column=col_i)
    return cell_value, None


def test_formula_cell_exported_inert(tmp_path):
    """A cell text beginning with '=' exports as inert text, not a live formula."""
    a = rb.AuditDir(tmp_path)
    a.write_manifest()
    a.write_register("claims_register.md", rb.CLAIMS_COLS, [
        rb.claims_row("C-0201", text="=HYPERLINK(\"http://evil\",\"click\")"),
    ])
    a.write_register("code_error_register.md", rb.ERROR_COLS, [
        rb.error_row("E-0201"),
    ])
    res, out = _export(a, tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr

    value, cell = _claims_cell(out, "C-0201", "Claim Text")
    assert cell.data_type == "s", "cell must be a string, not a formula"
    assert value.startswith("'="), value  # apostrophe-guarded, still readable
    assert value.lstrip("'").startswith("=HYPERLINK"), value


def test_plus_and_at_cells_exported_inert(tmp_path):
    """Cells beginning with '+' or '@' are likewise neutralised."""
    a = rb.AuditDir(tmp_path)
    a.write_manifest()
    a.write_register("claims_register.md", rb.CLAIMS_COLS, [
        rb.claims_row("C-0301", text="+1+1"),
        rb.claims_row("C-0302", text="@SUM(A1:A9)"),
    ])
    a.write_register("code_error_register.md", rb.ERROR_COLS, [
        rb.error_row("E-0301"),
    ])
    res, out = _export(a, tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr

    v1, c1 = _claims_cell(out, "C-0301", "Claim Text")
    assert c1.data_type == "s" and v1 == "'+1+1", v1
    v2, c2 = _claims_cell(out, "C-0302", "Claim Text")
    assert c2.data_type == "s" and v2 == "'@SUM(A1:A9)", v2


def test_negative_number_text_survives_readably(tmp_path):
    """A leading-'-' text cell (a negative number) stays readable text, not a formula."""
    a = rb.AuditDir(tmp_path)
    a.write_manifest()
    a.write_register("claims_register.md", rb.CLAIMS_COLS, [
        rb.claims_row("C-0401", text="-30% vs the stated 30%"),
    ])
    a.write_register("code_error_register.md", rb.ERROR_COLS, [
        rb.error_row("E-0401"),
    ])
    res, out = _export(a, tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr

    value, cell = _claims_cell(out, "C-0401", "Claim Text")
    assert cell.data_type == "s", "cell must be a string, not a formula/number"
    assert value.lstrip("'") == "-30% vs the stated 30%", value  # content intact


def test_invalid_manifest_json_exits_cleanly(tmp_path):
    """Malformed manifest JSON exits non-zero with a clear message, no traceback."""
    a = rb.AuditDir(tmp_path)
    a.write("_run/manifest.json", "{ this is : not valid json ,,, ")
    a.write_register("claims_register.md", rb.CLAIMS_COLS, [
        rb.claims_row("C-0501"),
    ])
    a.write_register("code_error_register.md", rb.ERROR_COLS, [
        rb.error_row("E-0501"),
    ])
    res, _ = _export(a, tmp_path)
    assert res.returncode != 0
    assert "invalid manifest json" in res.stderr.lower()
    assert "Traceback" not in res.stderr


def test_non_list_warnings_does_not_crash(tmp_path):
    """A non-list 'warnings' value is coerced, not crashed on."""
    a = rb.AuditDir(tmp_path)
    a.write_manifest(warnings="a single degraded-confidence warning as a bare string")
    a.write_register("claims_register.md", rb.CLAIMS_COLS, [
        rb.claims_row("C-0601"),
    ])
    a.write_register("code_error_register.md", rb.ERROR_COLS, [
        rb.error_row("E-0601"),
    ])
    res, out = _export(a, tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    # the bare string surfaces as a single warning on the Overview sheet
    wb = openpyxl.load_workbook(out)
    overview_text = "\n".join(
        str(c.value) for row in wb["Overview"].iter_rows() for c in row if c.value
    )
    assert "a single degraded-confidence warning as a bare string" in overview_text


# ------------------------------------------------------- U17 workbook cut


def make_bikeshare_code_audit(tmp_path):
    """Fresh U17 fixture domain: a synthetic municipal bike-share study."""
    a = rb.AuditDir(tmp_path)
    a.write_manifest(mode="code_errors_only")
    a.write_register("code_error_register.md", rb.ERROR_COLS, [
        rb.error_row(
            "E-0701", source="`code/station_counts.py`",
            location="`code/station_counts.py:41`", severity="2",
            desc="docking-station counts are summed before the weather merge",
            why="rain-day ridership is overstated in the pooled sample"),
    ])
    return a


def _overview_rows(out):
    wb = openpyxl.load_workbook(out)
    return [(row[0].value, row[1].value)
            for row in wb["Overview"].iter_rows(min_col=1, max_col=2)]


def _overview_section(rows, title, head):
    """Column-A values of the two-column table that follows *title* (whose
    header cell in column A is *head*), up to the trailing blank row."""
    title_i = next(i for i, (a, _b) in enumerate(rows) if a == title)
    head_i = next(i for i in range(title_i + 1, len(rows)) if rows[i][0] == head)
    values = []
    for a, _b in rows[head_i + 1:]:
        if a is None:
            break
        values.append(a)
    return values


@pytest.mark.u17
def test_code_errors_only_export_is_exactly_two_sheets_with_all_error_columns(tmp_path):
    a = make_bikeshare_code_audit(tmp_path)
    res, out = _export(a, tmp_path, mode="code_errors_only")
    assert res.returncode == 0, res.stdout + res.stderr
    wb = openpyxl.load_workbook(out, read_only=True)
    assert set(wb.sheetnames) == {"Overview", "Code Errors"}
    headers = [str(h) for h in next(wb["Code Errors"].values)]
    assert headers == list(rb.ERROR_COLS)  # all 9, one shape in both modes
    assert len(headers) == 9


@pytest.mark.u17
def test_export_still_writes_late_observation_coverage_md(tmp_path):
    """The coverage md outlives its sheet: still derived and written on export."""
    a = make_bikeshare_code_audit(tmp_path)
    res, _out = _export(a, tmp_path, mode="code_errors_only")
    assert res.returncode == 0, res.stdout + res.stderr
    coverage = (a.audit / "_run/late_observation_coverage.md").read_text()
    assert "| Stream | Required | b6b State | Collection State | Artifact Head | Blocker Evidence IDs |" in coverage
    assert "| claims | no | not applicable | not required | not recorded | none recorded |" in coverage
    assert "| code | yes | not present | incomplete | not recorded | none recorded |" in coverage


@pytest.mark.u17
def test_overview_lists_exactly_present_sheets_and_visible_columns(tmp_path):
    """Review F1: Overview content is asserted, not assumed. The sheet guide
    lists exactly the sheets present (no ghost entries for the removed three)
    and the claims variable legend lists exactly the 11 visible columns."""
    a = make_canon_audit(tmp_path)
    res, out = _export(a, tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    rows = _overview_rows(out)
    guide = _overview_section(rows, "Code review — overview", "Sheet")
    assert guide == ["Paper Claims", "Code Errors"]
    col_a = {a for a, _b in rows if a}
    assert not col_a & {"Handoff ledger", "Late observations (unverified)",
                        "Late observation coverage"}
    legend = _overview_section(rows, "Claims variable legend", "Column")
    assert legend == VISIBLE_CLAIMS_COLS


@pytest.mark.u17
def test_code_errors_only_overview_has_two_sheet_guide_and_no_claims_legend(tmp_path):
    a = make_bikeshare_code_audit(tmp_path)
    res, out = _export(a, tmp_path, mode="code_errors_only")
    assert res.returncode == 0, res.stdout + res.stderr
    rows = _overview_rows(out)
    guide = _overview_section(rows, "Code review — overview", "Sheet")
    assert guide == ["Code Errors"]
    assert all(a != "Claims variable legend" for a, _b in rows)
