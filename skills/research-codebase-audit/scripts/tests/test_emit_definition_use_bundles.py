"""Tests for the Stata definition/use bundle emitter."""

import pytest

import regbuild as rb


def make_pkg(tmp_path, text):
    root = tmp_path / "pkg"
    path = root / "do" / "analysis.do"
    path.parent.mkdir(parents=True)
    path.write_text(text, encoding="utf-8")
    return root


def run_emitter(tmp_path, text):
    root = make_pkg(tmp_path, text)
    audit = root / "review-output"
    res = rb.run_script("emit_definition_use_bundles.py", root, "--audit-dir", audit)
    artifact = audit / "_run" / "definition_use_bundles.md"
    return res, artifact.read_text(encoding="utf-8") if artifact.is_file() else None


def test_producer_group_flag_with_narrowed_consumer_is_standard(tmp_path):
    res, art = run_emitter(tmp_path, """
* Release eligibility covers two routes.
gen release_ok = 0
replace release_ok = 1 if consent == "individual"
replace release_ok = 1 if consent == "community"
keep if release_ok == 1 & wave == 1
""")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "Standard candidates: 1" in art
    assert "release_ok" in art
    assert "keep if release_ok == 1 & wave == 1" in art
    assert "DU-" in art


def test_boolean_gen_variant_is_standard(tmp_path):
    res, art = run_emitter(tmp_path, """
gen consent_ok = inlist(consent, "individual", "community")
keep if consent_ok == 1 & enrolled == 1
""")
    assert res.returncode == 0
    assert "Standard candidates: 1" in art
    assert "boolean_gen" in art


def test_intentional_subset_is_still_emitted_for_semantic_recheck(tmp_path):
    res, art = run_emitter(tmp_path, """
* Intentionally baseline-wave-only diagnostic; not the estimation sample.
gen baseline_diag_ok = (weight != .)
preserve
keep if baseline_diag_ok == 1 & wave == 1
summarize outcome
restore
""")
    assert res.returncode == 0
    assert "Standard candidates: 1" in art
    assert "Intentionally baseline-wave-only diagnostic" in art


def test_recode_consumer_is_advisory_only(tmp_path):
    res, art = run_emitter(tmp_path, """
gen sample_ok = (age >= 18)
recode employed (0=.) if sample_ok == 1 & wave == 2
""")
    assert res.returncode == 0
    assert "Standard candidates: 0" in art
    assert "Advisory candidates: 1" in art
    assert "## Advisory candidates" in art


def test_macro_rich_recode_consumer_remains_advisory(tmp_path):
    """Stata's macro-closing apostrophe is not a string delimiter."""
    res, art = run_emitter(tmp_path, """
gen master_only = 0
replace master_only = 1 if m_`buff'b_floods == 2
recode flood_`buff'b_`x' (.=0) if gc_lat_`x' != . & master_only == 0
""")
    assert res.returncode == 0
    assert "Advisory candidates: 1" in art
    assert "master_only" in art


def test_multiline_block_comment_hides_candidate_commands(tmp_path):
    res, art = run_emitter(tmp_path, """gen visible = (score >= 10)
/* Disabled alternative retained for reference.
gen hidden = (score >= 20)
keep if hidden == 1 & wave == 2
*/
keep if visible == 1 & wave == 1
""")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "Standard candidates: 1" in art
    assert "`do/analysis.do:1`" in art
    assert "`do/analysis.do:6`" in art


def test_code_after_multiline_block_comment_close_is_scanned(tmp_path):
    res, art = run_emitter(tmp_path, """gen visible = (score >= 10)
/* Disabled consumer retained for reference.
keep if visible == 1 & wave == 2
*/ keep if visible == 1 & ///
    wave == 1
""")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "Standard candidates: 1" in art
    assert "`do/analysis.do:1`" in art
    assert "`do/analysis.do:4`" in art
    assert "keep if visible == 1 & wave == 1" in art


def test_block_marker_inside_line_comment_does_not_hide_later_code(tmp_path):
    res, art = run_emitter(tmp_path, """gen visible = (score >= 10)
// Documentation mentions an unmatched /* marker.
keep if visible == 1 & wave == 1
""")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "Standard candidates: 1" in art
    assert "`do/analysis.do:1`" in art
    assert "`do/analysis.do:3`" in art


@pytest.mark.parametrize("body", [
    "gen sample_ok = (age >= 18)\nkeep if sample_ok == 1\n",
    "gen sample_ok = (age >= 18)\nsummarize wage\n",
])
def test_no_extra_conjunct_or_no_consumer_emits_nothing(tmp_path, body):
    res, art = run_emitter(tmp_path, body)
    assert res.returncode == 0
    assert "Standard candidates: 0" in art
    assert "Advisory candidates: 0" in art


def test_group_with_only_unguarded_replaces_still_feeds_a_narrowing_consumer(tmp_path):
    """The producer group no longer demands a guarded member replace."""
    res, art = run_emitter(tmp_path, (
        "gen city = \"\"\nreplace city = source_city\n"
        "replace matched = 1 if city != \"\" & wave == 1\n"
    ))
    assert res.returncode == 0
    assert "Standard candidates: 1" in art
    assert "producer_group" in art
    assert "Advisory candidates: 0" in art


def test_ids_are_deterministic_and_each_consumer_gets_a_distinct_id(tmp_path):
    body = """
gen eligible = (score >= 10)
keep if eligible == 1 & wave == 1
drop if eligible == 0 & missing(score)
"""
    first_res, first = run_emitter(tmp_path / "a", body)
    second_res, second = run_emitter(tmp_path / "b", body)
    assert first_res.returncode == second_res.returncode == 0
    first_ids = [part.split()[0] for part in first.split("`DU-")[1:]]
    second_ids = [part.split()[0] for part in second.split("`DU-")[1:]]
    assert first_ids == second_ids
    assert len(first_ids) == 2
    assert len(set(first_ids)) == 2
    assert "Standard producer groups (file + gen line + variable): 1" in first


def test_injected_hash_collision_fails_loudly(tmp_path, monkeypatch):
    emitter = rb.load_script("emit_definition_use_bundles")
    root = make_pkg(tmp_path, """
gen eligible = (score >= 10)
keep if eligible == 1 & wave == 1
drop if eligible == 0 & missing(score)
""")
    monkeypatch.setattr(emitter, "short_hash", lambda _identity: "deadbeef")
    with pytest.raises(RuntimeError, match="hash collision"):
        emitter.scan_package(root)


def test_zero_bundle_artifact_is_populated_and_excludes_audit_workspace(tmp_path):
    root = make_pkg(tmp_path, "summarize wage\n")
    audit = root / "review-output"
    audit.mkdir()
    (audit / "audit_readme.md").write_text("generated audit", encoding="utf-8")
    hidden = audit / "do" / "generated.do"
    hidden.parent.mkdir()
    hidden.write_text(
        "gen bad = (x == 1)\nkeep if bad == 1 & wave == 1\n",
        encoding="utf-8",
    )
    res = rb.run_script("emit_definition_use_bundles.py", root, "--audit-dir", audit)
    art = (audit / "_run" / "definition_use_bundles.md").read_text(encoding="utf-8")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "Stata files scanned: 1" in art
    assert "Standard candidates: 0" in art
    assert "No standard definition/use bundles found." in art
    assert "No advisory definition/use bundles found." in art
