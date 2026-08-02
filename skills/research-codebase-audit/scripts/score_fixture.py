#!/usr/bin/env python3
"""Automated scorer for the planted-error fixture.

Reads ``fixture/expected_findings.json`` and a completed run's final
registers, matches each planted finding by mechanism (keyword signatures,
never by ID or wording), and prints a per-plant HIT/MISS table plus a
GATE GREEN / GATE RED verdict. Replaces the hand-adjudicated scorecard
matching for the recall/precision core; severity, status, and the P-14
branch logic are encoded exactly as the answer key's ``scoring`` field
states.

Rules encoded here:

- Recall: every ``must_find`` item needs a row in some register whose text
  matches the plant's mechanism signature, with a qualifying status
  (claims: ``inconsistent``/``confirmation_needed`` or severity-flagged;
  code errors: ``confirmed``/``confirmation_needed``) at
  Severity >= ``min_severity``.
- P-14 dual-accept (branch logic): mechanism found AND (an ``inconsistent``
  claim at qualifying severity OR a ``blocked`` claim whose NON-EMPTY
  Blocked Check itself records the one-in-ten vs 1-in-20 contradiction —
  severity floor waived in that branch). A silent block (empty Blocked
  Check, or one that does not record the contradiction) scores MISS.
- Precision: the D-01 decoy (``placebo`` / ``fig_placebo``) must be absent
  from every register and from the cross-link summary; presence turns the
  gate RED.
- SC-01 (approximation of the key's conditional rule): a claims row that
  still CONFIRMS the long-run-mean shock definition while a confirmed
  code-error row records the P-11 mechanism is an unresolved status
  conflict and turns the gate RED.
- P-20 reuses the P-14 dual-accept branch logic (blocked-visible plant
  family): inconsistent at qualifying severity, OR blocked with a Blocked
  Check that itself records the 15-km vs 25 km contradiction.
- Per-class breakdown (U9 tags, U10 reporting): a ``failure_class`` field on
  a must_find item is echoed on its line, and the ``Per-class:`` block under
  the aggregate recall lists EVERY planted class with hit/miss counts. The
  pre-2026-07-07 plants P-01..P-14 carry no ``failure_class`` tag in the
  answer key (they predate the class taxonomy and each tests a mechanism,
  not one of the U1-U5 failure classes); rather than back-tag them, the
  breakdown rolls them up in an explicit ``unclassified_legacy`` bucket so
  the aggregate is always the sum of the per-class lines.
- Artifact-layer checks (U9; Build Process gate, single-re-score layer per
  KTD-8 — these outcomes are produced by committed scripts/lints, so one
  re-score settles them; the gate scorecard records them separately from
  the register-based two-run results):
  * U2: ``AUDIT_DIR/_run/manifest_check.md`` must name ``pyproject.toml``
    in its Candidate findings section (gate-settling; the parser emission
    is deterministic given the plant).
  * U4: if the P-19 claim closed ``confirmed``, the anchoring advisory
    (``lint_registers.check_anchoring_advisory``) must have warned on its
    recheck-ledger row (gate-settling when a ledger row exists; a confirmed
    close outside the recheck sample is reported NOT COVERED, not FAIL —
    the advisory is a tripwire over the recheck sample by design/KTD-3).
  * U5: if the P-20 row rests ``blocked``, the filename-parameter advisory
    (``lint_registers.check_filename_parameter_advisory``) must warn on it
    (gate-settling).
  * U1: a conventions-artifact/b4-candidate presence check, INFORMATIVE
    only, never gate-settling — the b3c consolidation and grep-term choice
    are worker-dependent (KTD-8), so this line feeds diagnosis, not the
    verdict.
  * Definition/use channel: P-21 and D-03 are located by their fixture source
    sites in ``definition_use_bundles.md`` and traced through b4 mapping/inventory,
    code recheck ledger, and final code-error register. P-21 must finish as a
    confirmed severity>=2 issue (or explicit duplicate to an equivalent one);
    D-03 must finish ``not_error`` with no surviving issue row.

Not enforced here (still scorecard/reviewer territory): expected_type
adjudication and the ``expected_confirmed_examples`` cleanliness checks.

Usage:
    score_fixture.py --audit-dir PATH [--expected fixture/expected_findings.json]

Exit codes: 0 = GATE GREEN, 1 = GATE RED, 2 = usage/IO error.
"""

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import definition_use as du
import build_detector_mapping as detector_mapping
import check_argument_contracts as argument_contracts
import mechanism_schema as mechanism_schema
import severity_tokens
import verify_dismissals as dismissal_verifier

SKILL_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = Path(__file__).resolve().parent
DEFAULT_EXPECTED = SKILL_DIR / "fixture" / "expected_findings.json"


def load_lint_module():
    """Import scripts/lint_registers.py by path (scripts/ is not a package).

    The artifact-layer checks reuse the committed advisory-check functions so
    the scorer can never drift from the lint's actual behavior."""
    spec = importlib.util.spec_from_file_location(
        "lint_registers", SCRIPTS_DIR / "lint_registers.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

# Mechanism signatures: plant ID -> list of groups; a row matches when, for
# EVERY group, at least one alternative substring appears in the row's text
# (case-insensitive). Mirrors how prior scorecards hand-matched mechanisms.
SIGNATURES = {
    "P-01": [["0.083"], ["0.038"]],
    "P-02": [["cluster"], ["village"], ["household"]],
    "P-03": [["weight"],
             ["unweighted", "svy_weight", "no weight", "without weight",
              "not weighted", "omits the weight"]],
    "P-04": [["bootstrap"], ["seed"]],
    "P-05": [["waves"],
             ["keep if", "revers", "invert", "exclu", "fewer than two",
              "< 2", "<2"]],
    "P-06": [["panel_v2"]],
    "P-07": [["controls"], ["global", "comment"]],
    "P-08": [["income"], ["100"], ["thousand", "1000", "1,000", "factor"]],
    "P-09": [["rainfall_stations"]],
    "P-10": [["gps", "head_name", "coordinates", "pii"]],
    "P-11": [["rain_mean", "long-run", "long run", "climate normal", "1991",
              "in-sample", "in sample"],
             ["mean", "normal", "baseline"]],
    "P-12": [["legend"],
             ["revers", "swap", "mislabel", "backward", "wrong order",
              "shocked"]],
    "P-13": [["725"], ["30"]],
    "P-14": [["one-in-ten", "one in ten", "1-in-10", "1 in 10"],
             ["1-in-20", "one-in-twenty", "1 in 20", "one in twenty"]],
    "P-15": [["remittance"],
             ["component", "crop", "income"],
             ["omit", "miss", "excl", "without", "only", "left out",
              "not includ", "drop", "three", "absent"]],
    "P-16": [["pyproject"],
             ["toml", "parse", "invalid", "version", "malformed", "reject"]],
    "P-17": [["hhsize"], ["missing"],
             ["never", "only", "already", "non-missing", "nonmissing",
              "excl", "does not fill", "doesn't fill", "not fill", "< .",
              "present"]],
    "P-18": [["has_wages", "wage indicator", "wage-indicator", "wage flag",
              "wage_flag", "wages indicator", "wages flag"],
             ["overwrit", "overwrite", "erase", "clobber", "last", "reset",
              "final", "each iteration", "replaces"],
             ["loop", "iteration", "wave"]],
    "P-19": [["winsor"],
             ["wage_earnings", "wage earnings"],
             ["crop_sales", "crop sales"]],
    "P-20": [["15-km", "15 km", "15km", "fifteen"],
             ["25km", "25-km", "25 km", "twenty-five"]],
    "P-21": [["consent"],
             ["community"],
             ["keep if", "drop", "exclu", "omit", "narrow",
              "conjunct", "silently", "left out", "not kept",
              "removed", "restrict"]],
    "P-23": [["requirements-recall"], ["numpy"],
             ["whitespace", "operator", "invalid", "reject", "parse"]],
    "P-24": [["requirements-recall"], ["pandas"], ["2.2.2"], ["1.5.3"],
             ["conflict", "incompat", "duplicate", "two", "mutually"]],
    "P-25": [["calculated"], ["reference"], ["speed"],
             ["overlap", "disjoint", "8", "11", "28", "34"]],
    "P-26": [["argument"], ["callee", "contract"],
             ["unread", "never reads", "ignored", "argpos:2"]],
    "P-27": [["income_pc", "income per member", "income per household member",
              "per-capita income", "per capita income"],
             ["age_head", "age of head", "head age", "head's age"]],
    "P-28": [["wage_pc"],
             ["age_head", "age of head", "head age", "head's age"]],
    "P-29": [["crop_pc"],
             ["age_head", "age of head", "head age", "head's age"]],
}
# Plants scored with the P-14 dual-accept branch logic (blocked-visible
# family): inconsistent at qualifying severity OR blocked with a Blocked
# Check that itself records the contradiction (severity floor waived).
BLOCKED_VISIBLE_PLANTS = {"P-14", "P-20"}
# Each decoy is (site_terms, qualifier_terms). A row trips the decoy when it
# matches a site term AND, if qualifier_terms is set, also a qualifier term.
# D-02's qualifier restricts it to subset-omission complaints — the planted
# bait — so an unrelated true observation inside the signposted block (e.g.
# a zero-division guard) is scored on its own merits, not condemned by site.
# Qualified decoys match at SENTENCE granularity, and a sentence carrying
# exculpatory language (DECOY_EXCULPATIONS) never trips: a legitimate P-15
# recovery row may QUOTE the farm_components signpost comment as evidence
# ("deliberately a subset ...", "recorded reviewed-not-divergent") while
# flagging the total-income omission — that is not the planted bait. A row
# that flags the intentional subset AS the error carries no such exculpation
# in its tripping sentence and still turns the gate red (narrowed 2026-07-08
# after a gate run condemned legitimate P-15 rows for quoting the comment).
# The qualifier set names the OMISSION GRIEVANCE only (omits/diverges/incomplete
# /excludes/missing, or the full four-component set / an omitted member). Bare
# "subset" was dropped 2026-07-09: it is the signpost's own descriptive noun
# ("the farm subset's share"), so it fired on rows that merely NAME the subset
# while flagging an unrelated ratio-basis defect (defuse gate run 2, E-0283) —
# not the planted list-is-incomplete bait. Every genuine bait phrasing carries a
# grievance term above (verified against the four D-02 tests).
DECOYS = {
    "D-01": (["placebo", "fig_placebo"], None),
    "D-02": (["farm_income", "farm-income", "farm income", "farm_components",
              "farm components", "farm_share", "farm share"],
             ["omit", "diverg", "four-component", "four component",
              "four income", "remittance", "incomplete", "excludes",
              "missing component"]),
}
# Sentence-level exculpations: language recording the subset as intentional
# or already reviewed. Mechanism-general (the signpost's own vocabulary plus
# the reviewed-not-divergent bookkeeping term), not any one run's phrasing.
DECOY_EXCULPATIONS = [
    "deliberate", "intentional", "signpost", "reviewed-not-divergent",
    "reviewed not divergent", "not divergent", "explicitly local",
    "is fine", "by design", "on purpose",
]
# --- artifact-layer constants (U9) ----------------------------------------
# the U2 plant: the malformed manifest the parser artifact must name
MANIFEST_PLANT = "pyproject.toml"
# locators for the plant CLAIM rows the conditional advisory checks key on
# (looser than the full mechanism signatures: they must find the claim row
# even when the run failed to record the contradiction)
U4_CLAIM_LOCATOR = [["winsor"], ["wage_earnings", "wage earnings"]]
U5_CLAIM_LOCATOR = [["15-km", "15 km", "15km", "fifteen"], ["radius", "km"]]
# terms identifying the U1 member-list convention in the b3c artifact
U1_CONVENTION_CATEGORY = "enumerated_member_list"
U1_MEMBER_TERMS = ["remittance", "crop", "livestock", "wage"]
# terms indicating a claims row asserts the long-run shock definition (SC-01)
P11_DEFINITION_TERMS = ["long-run", "long run", "climate normal", "1991"]

REGISTERS = [
    ("claims_register.md", "Claim ID"),
    ("code_error_register.md", "Error ID"),
    ("output_register.md", "Output ID"),
]
LEDGER_COLS = [
    "ID", "Current Status", "Current Severity", "Evidence Checked",
    "Evidence Level", "Verdict", "Proposed Register Change",
    "Pipeline/Output Impact", "Proposed Note",
]
CODE_LEDGER_COLS = LEDGER_COLS + [
    "Proposed Status", "Proposed Severity", "Accepted Error Type",
    "Accepted Mechanism", "Outcome Witness IDs", "Duplicate Target",
    "Proposed Field Patches", "Verification Record IDs",
]
DEFINITION_USE_LOCATORS = {
    "P-21": {
        "variable": "consent_ok",
        "definition": "do/build_panel.do:15",
        "consumer": "do/build_panel.do:18",
    },
    "D-03": {
        "variable": "baseline_diag_ok",
        "definition": "do/analysis.do:13",
        "consumer": "do/analysis.do:14",
    },
}


# --------------------------------------------------------------- md parsing


def split_row(line):
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    cells, cur, esc = [], [], False
    for ch in line:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            cur.append(ch)
            esc = True
        elif ch == "|":
            cells.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    cells.append("".join(cur).strip())
    return cells


def parse_tables(text):
    lines = text.split("\n")
    tables, i = [], 0
    while i < len(lines) - 1:
        if lines[i].lstrip().startswith("|") and re.match(r"^\s*\|[\s:|-]+\|\s*$", lines[i + 1]):
            headers = split_row(lines[i])
            rows, j = [], i + 2
            while j < len(lines) and lines[j].lstrip().startswith("|"):
                rows.append(split_row(lines[j]))
                j += 1
            tables.append((headers, rows))
            i = j
        else:
            i += 1
    return tables


def load_rows(path, id_col):
    """Row dicts from the first table carrying *id_col* and Status.

    Tolerates extra columns (post-b8 registers carry ``*_Original``);
    drops schema example rows ([CEO]-0000).
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    for headers, rows in parse_tables(text):
        if id_col in headers and "Status" in headers:
            out = []
            for r in rows:
                if len(r) != len(headers):
                    continue
                d = dict(zip(headers, r))
                if re.fullmatch(r"[CEO]-0000", d[id_col]):
                    continue
                out.append(d)
            return out
    return []


# --------------------------------------------------------------- matching


def row_text(d):
    return " | ".join(str(v) for v in d.values()).lower()


def is_d03(row):
    """Match only the D-03 plant, without borrowing Error Type vocabulary."""
    text = row_text(row).replace("`", "")
    semantic_text = row_text({
        key: value for key, value in row.items() if key != "Error Type"
    }).replace("`", "")
    at_fixture_site = (
        row.get("Error Type") == "sample_filter_or_flag_error"
        and any(
            re.search(
                re.escape(DEFINITION_USE_LOCATORS["D-03"][site]) + r"(?!\d)",
                text,
            )
            for site in ("definition", "consumer")
        )
    )
    semantic_anchor = (
        "baseline_diag_ok" in semantic_text
        or "do/analysis.do" in semantic_text
    )
    semantic_match = (
        semantic_anchor
        and any(term in semantic_text for term in ("diagnostic", "diagnostics"))
        and any(term in semantic_text for term in (
            "baseline", "wave 1", "wave-1", "wave one", "first wave",
        ))
        and any(term in semantic_text for term in (
            "narrow", "filter", "restrict", "exclude", "drop", "remove",
        ))
        and any(term in semantic_text for term in (
            "sample", "observation", "case", "analytic population",
            "estimation population",
        ))
    )
    return "baseline_diag_ok" in text or at_fixture_site or semantic_match


def sig_match(text, groups):
    return all(any(alt in text for alt in group) for group in groups)


def severity(d):
    try:
        return int((d.get("Severity") or "").strip())
    except ValueError:
        return 0


def qualifies(kind, d):
    st = (d.get("Status") or "").strip()
    if kind == "claims":
        return st in {"inconsistent", "confirmation_needed"} or bool(
            (d.get("Severity") or "").strip()
        )
    if kind == "errors":
        return st in {"confirmed", "confirmation_needed"}
    return st == "inconsistent"  # outputs


def describe(kind, id_col, d):
    return f"{d.get(id_col, '?')} ({kind}, status={d.get('Status', '')}, sev={d.get('Severity', '') or '-'})"


def score_generic(item, tagged_rows):
    """(verdict, note) for a standard must_find item."""
    sig = SIGNATURES[item["id"]]
    min_sev = int(item.get("min_severity", 1))
    matched, hits = [], []
    for kind, id_col, d in tagged_rows:
        if not sig_match(row_text(d), sig):
            continue
        matched.append((kind, id_col, d))
        if qualifies(kind, d) and severity(d) >= min_sev:
            hits.append(describe(kind, id_col, d))
    if hits:
        return "HIT", "; ".join(hits)
    if matched:
        return "MISS", ("mechanism matched but no qualifying row at "
                        f"severity >= {min_sev}: "
                        + "; ".join(describe(k, c, d) for k, c, d in matched))
    return "MISS", "no row matches the mechanism signature"


def score_blocked_visible(item, tagged_rows):
    """Dual-accept branch logic for the blocked-visible plant family
    (P-14, P-20): mechanism found AND (a qualifying flagged row OR a blocked
    claim whose non-empty Blocked Check itself records the contradiction)."""
    sig = SIGNATURES[item["id"]]
    min_sev = int(item.get("min_severity", 2))
    silent, hits = [], []
    for kind, id_col, d in tagged_rows:
        text = row_text(d)
        if not sig_match(text, sig):
            continue
        st = (d.get("Status") or "").strip()
        if kind == "claims" and st == "blocked":
            # accepted branch: a non-empty Blocked Check that itself records
            # the contradiction (severity floor waived)
            bc = (d.get("Blocked Check") or "").strip()
            if bc and sig_match(bc.lower(), sig):
                hits.append(describe(kind, id_col, d)
                            + " [blocked branch: Blocked Check records the contradiction]")
            else:
                silent.append(describe(kind, id_col, d))
        elif qualifies(kind, d) and severity(d) >= min_sev:
            hits.append(describe(kind, id_col, d))
    if hits:
        return "HIT", "; ".join(hits)
    if silent:
        return "MISS", ("mechanism matched only silently-blocked row(s) — "
                        "empty Blocked Check or one that does not record the "
                        "contradiction: " + "; ".join(silent))
    return "MISS", "no row matches the mechanism signature"


def _decoy_sentences(text):
    """Sentence-ish units: split on sentence enders followed by whitespace and
    on the cell separators row_text inserts. Dotted filenames/line refs
    (build_income.py:14) carry no space after the dot, so they stay intact."""
    return re.split(r"(?<=[.;!?])\s+|\s\|\s", text)


def check_decoy(terms, quals, tagged_rows, summary_text):
    def trips(text):
        if quals is None:
            return any(t in text for t in terms)
        # Qualified decoy: site and qualifier must co-occur in one sentence,
        # and a sentence with exculpatory language never trips — it records
        # the subset as intentional/reviewed instead of flagging it as the
        # error (quoting the signpost comment as evidence for ANOTHER finding
        # is not the planted bait).
        for sent in _decoy_sentences(text):
            if (any(t in sent for t in terms)
                    and any(q in sent for q in quals)
                    and not any(e in sent for e in DECOY_EXCULPATIONS)):
                return True
        return False
    found = []
    for kind, id_col, d in tagged_rows:
        # Precision decoys are forbidden as surviving issues, not as an audit
        # trail showing that a tempting candidate was reviewed and cleared.
        status = (d.get("Status") or "").strip()
        if status == "not_error" or status.startswith("duplicate_of:"):
            continue
        if qualifies(kind, d) and trips(row_text(d)):
            found.append(describe(kind, id_col, d))
    if summary_text and trips(summary_text.lower()):
        found.append("register_cross_link_summary.md")
    return found


def check_sc01(tagged_rows):
    """Unresolved P-11 status conflict surviving to the final registers."""
    confirmed_claim = [
        describe(k, c, d) for k, c, d in tagged_rows
        if k == "claims" and (d.get("Status") or "").strip() == "confirmed"
        and "shock" in row_text(d)
        and any(t in row_text(d) for t in P11_DEFINITION_TERMS)
    ]
    confirmed_error = [
        describe(k, c, d) for k, c, d in tagged_rows
        if k == "errors" and (d.get("Status") or "").strip() == "confirmed"
        and sig_match(row_text(d), SIGNATURES["P-11"])
    ]
    if confirmed_claim and confirmed_error:
        return ("confirmed shock-definition claim coexists with the "
                "confirmed P-11 error: "
                + "; ".join(confirmed_claim + confirmed_error))
    return None


# ------------------------------------------------- artifact-layer checks (U9)
#
# The register score reads the FINAL registers, downstream of worker
# disposition, so a candidate emitted and dispositioned away is
# indistinguishable from no emission. These checks read the deterministic
# layer directly (the U2 parser artifact; the U4/U5 advisory lints re-run on
# the run's own tables), so the Build Process gate can record the
# single-re-score outcomes separately from the register-based two-run
# outcomes (KTD-8). Each returns (status, note): status "FAIL" adds a red
# reason; "PASS"/"NOT COVERED" does not; the U1 check returns "INFO" always.


def check_artifact_manifest(audit):
    """U2 (gate-settling): the parser artifact names the malformed manifest."""
    path = audit / "_run" / "manifest_check.md"
    if not path.is_file():
        return "FAIL", f"artifact not found: {path} (run check_manifests.py at b4)"
    text = path.read_text(encoding="utf-8", errors="replace")
    _, _, findings = text.partition("## Candidate findings")
    # Bound the search to the Candidate-findings section body only: render_artifact
    # writes a `## Warnings` section AFTER the candidate findings, and a run that
    # could not parse the plant emits a warning line naming pyproject.toml with
    # ZERO candidate findings — so the plant must appear in the findings proper.
    findings = findings.split("\n## ")[0]
    if MANIFEST_PLANT.lower() in findings.lower():
        return "PASS", f"_run/manifest_check.md names {MANIFEST_PLANT}"
    return "FAIL", (f"_run/manifest_check.md does not name {MANIFEST_PLANT} "
                    "in its Candidate findings")


def check_clean_recall_chain(audit):
    """U6a: mechanical P-23 chain plus conditional P-24 b3b provenance."""
    plant = "requirements-recall.txt"
    manifest_path = audit / "_run/manifest_check.md"
    mapping_path = audit / "_run/detector_mapping.md"
    plan_path = audit / "plans/code_error_second_read_plan.md"
    required = (manifest_path, mapping_path, plan_path)
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        return "FAIL", "missing U6a artifact(s): " + ", ".join(missing)
    manifest_text = manifest_path.read_text(encoding="utf-8", errors="replace")
    mapping_text = mapping_path.read_text(encoding="utf-8", errors="replace")
    plan_text = plan_path.read_text(encoding="utf-8", errors="replace")
    if plant not in manifest_text:
        return "FAIL", f"P-23 absent from {manifest_path.name}"
    if plant not in mapping_text:
        return "FAIL", f"P-23 absent from {mapping_path.name}"
    plan_rows = []
    for headers, rows in parse_tables(plan_text):
        if {"Script Scope", "Shard File", "Reason"} <= set(headers):
            plan_rows.extend(dict(zip(headers, row)) for row in rows
                             if len(row) == len(headers))
    owners = [row for row in plan_rows
              if plant in row["Script Scope"] and row["Reason"].strip("`") == "detector"]
    if not owners:
        return "FAIL", "P-23 file is not allocated with reason detector"

    # code_b3 is the pre-merge snapshot; code_b3d is taken immediately after
    # b3 promotion and is therefore the recorded post-b3 state.
    post_b3 = audit / "_run/snapshots/code_b3d/code_error_register.md"
    if post_b3.is_file() and sig_match(
            post_b3.read_text(encoding="utf-8", errors="replace"), SIGNATURES["P-24"]):
        return "PASS", "P-23 detector chain present; P-24 provenance vacuous (found at first pass)"
    final_rows = load_rows(audit / "code_error_register.md", "Error ID")
    p24 = [row for row in final_rows
           if plant in row_text(row) and sig_match(row_text(row), SIGNATURES["P-24"])]
    if not p24:
        return "FAIL", "P-24 absent after first pass and absent from final code register"
    expected_ids = {row["Error ID"] for row in p24}
    for owner in owners:
        shard = audit.parent / owner["Shard File"].strip().strip("`")
        if shard.is_file():
            shard_text = shard.read_text(encoding="utf-8", errors="replace")
            if expected_ids & set(re.findall(r"E-\d{4}", shard_text)):
                return "PASS", "P-23 detector chain present; P-24 originates in its b3b shard"
    return "FAIL", "P-24 lacks the file's b3b-shard provenance"


def check_u7_allocation_split(audit):
    """P-25 cannot score green when one worker owns assertion and figure."""
    from claim_handoffs import (
        allocation_source_entry, load_claims_allocations, parse_line_intervals,
    )
    try:
        manifest = json.loads(
            (audit / "_run/manifest.json").read_text(encoding="utf-8")
        )
        source_set = manifest["paper_source_set"]
        allocations, _ = load_claims_allocations(
            audit / "plans/claims_review_plan.md"
        )
    except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        return "FAIL", f"cannot inspect executed U7 claims allocation: {exc}"
    if len({row["Worker ID"] for row in allocations}) < 2:
        return "FAIL", "executed claims plan has fewer than two workers"
    paper_entry = next((entry for entry in source_set if str(
        entry.get("source_path", "")).replace("\\", "/").endswith("paper/paper.tex")), None)
    if paper_entry is None:
        return "FAIL", "paper_source_set does not contain paper/paper.tex"
    lines = Path(paper_entry["source_path"]).read_text(encoding="utf-8").splitlines()
    assertion = [number for number, line in enumerate(lines, start=1)
                 if "calculated and reference speeds show substantial overlap" in line]
    figure = [number for number, line in enumerate(lines, start=1)
              if "\\label{fig:speed-overlap}" in line]
    if len(assertion) != 1 or len(figure) != 1:
        return "FAIL", "P-25 assertion or appendix figure anchor is not unique"

    def owner(line_number):
        found = []
        for row in allocations:
            try:
                entry = allocation_source_entry(row, source_set, audit.parent)
                intervals = parse_line_intervals(row["Line Intervals"])
            except ValueError:
                continue
            if (Path(entry["source_path"]).resolve() ==
                    Path(paper_entry["source_path"]).resolve()
                    and any(start <= line_number <= end for start, end in intervals)):
                found.append(row["Worker ID"])
        return found[0] if len(found) == 1 else None

    assertion_owner, figure_owner = owner(assertion[0]), owner(figure[0])
    if assertion_owner is None or figure_owner is None:
        return "FAIL", "P-25 assertion or figure lacks exactly one interval owner"
    if assertion_owner == figure_owner:
        return "FAIL", (f"P-25 masking: {assertion_owner} owns both body assertion "
                        "and appendix figure")
    return "PASS", (f"body assertion owned by {assertion_owner}; appendix figure "
                    f"owned by {figure_owner}")


def _table_with_headers(text, required, exact=False):
    for headers, rows in parse_tables(text):
        if (headers == required if exact else set(required) <= set(headers)):
            return headers, [r for r in rows if len(r) == len(headers)]
    return None, None


def _clean(value):
    return du.normalize_cell(value or "")


def _list_cell(value):
    value = _clean(value)
    if value in {"", "-", "—"}:
        return []
    return [_clean(part) for part in value.split(";") if _clean(part)]


def check_channel_adjudication(audit, expected):
    """Trace the three U3b manifest plants through every adjudication layer."""
    plants = expected.get("adjudication_contract_plants", [])
    if not plants:
        return "NOT COVERED", "answer key has no U3b adjudication plants"
    manifest_path = audit / "_run/manifest_check.md"
    if not manifest_path.is_file():
        return "FAIL", f"manifest artifact missing: {manifest_path}"
    manifest_text = manifest_path.read_text(encoding="utf-8", errors="replace")
    plant_paths = {item["manifest"] for item in plants}
    # Legacy synthetic scorer fixtures predate U3b. Do not pretend they test
    # this channel; report it explicitly instead of turning unrelated unit
    # tests red. A real fixture run emits at least one of the two conda paths.
    if not any(path in manifest_text for path in plant_paths - {"pyproject.toml"}):
        return "NOT COVERED", "U3b conda plants are absent from this synthetic artifact"
    source_rows = []
    for headers, rows in parse_tables(manifest_text):
        if {"Source ID", "Manifest", "Witness Count"} <= set(headers):
            source_rows.extend(dict(zip(headers, row)) for row in rows
                               if len(row) == len(headers))
    source_by_manifest = {}
    for row in source_rows:
        source_by_manifest[_clean(row["Manifest"])] = _clean(row["Source ID"])
    missing = sorted(plant_paths - set(source_by_manifest))
    if missing:
        return "FAIL", "manifest candidates missing for " + ", ".join(missing)

    try:
        _declared, _display, mappings = detector_mapping.load_mapping(
            audit / "_run/detector_mapping.md")
    except detector_mapping.MappingError as exc:
        return "FAIL", f"detector mapping is missing or malformed: {exc}"
    mappings_by_source = {}
    for row in mappings:
        mappings_by_source.setdefault(row["Source ID"], []).append(row)

    plan_path = audit / "plans/code_error_recheck_plan.md"
    if not plan_path.is_file():
        return "FAIL", f"code recheck plan missing: {plan_path}"
    plan_text = plan_path.read_text(encoding="utf-8", errors="replace")
    headers, rows = _table_with_headers(plan_text, ["ID", "Reason", "Likely Evidence"])
    inventory = [dict(zip(headers, row)) for row in rows] if rows is not None else []

    ledgers, records = [], {}
    ledger_root = audit / "_code_error_recheck"
    if ledger_root.is_dir():
        for path in sorted(ledger_root.rglob("*.md")):
            text = path.read_text(encoding="utf-8", errors="replace")
            for table_headers, table_rows in parse_tables(text):
                if table_headers == CODE_LEDGER_COLS:
                    ledgers.extend(dict(zip(table_headers, row)) for row in table_rows
                                   if len(row) == len(table_headers))
                if table_headers in (dismissal_verifier.MF_RECORD_COLS,
                                     dismissal_verifier.PROBE_RECORD_COLS):
                    for row in table_rows:
                        if len(row) == len(table_headers):
                            record = dict(zip(table_headers, row))
                            records[_clean(record["Record ID"])] = record
    ledger_by_id = {}
    for row in ledgers:
        ledger_by_id.setdefault(_clean(row["ID"]), []).append(row)

    receipt_path = audit / "_run/code_b6a/dismissal_receipts.md"
    receipt_rows = []
    if receipt_path.is_file():
        text = receipt_path.read_text(encoding="utf-8", errors="replace")
        headers, rows = _table_with_headers(
            text, dismissal_verifier.RECEIPT_COLS, exact=True)
        if rows is not None:
            receipt_rows = [dict(zip(headers, row)) for row in rows]
    boundary_path = audit / "_run/code_b6a/witness_outcomes.md"
    if not boundary_path.is_file():
        return "FAIL", f"assembled witness boundary missing: {boundary_path}"
    boundary_text = boundary_path.read_text(encoding="utf-8", errors="replace")
    headers, rows = _table_with_headers(
        boundary_text, list(mechanism_schema.POST_BOUNDARY_WITNESS_COLUMNS),
        exact=True)
    post_rows = [dict(zip(headers, row)) for row in rows] if rows is not None else []
    post_keys = {tuple(_clean(row[field]) for field in
                       ("Channel", "Source ID", "Witness ID")) for row in post_rows}
    assembled = set()
    headers, rows = _table_with_headers(boundary_text, ["Error ID"], exact=True)
    if rows is not None:
        assembled = {_clean(row[0]) for row in rows}

    final_path = audit / "code_error_register.md"
    if not final_path.is_file():
        return "FAIL", f"final code-error register missing: {final_path}"
    final_by_id = {row["Error ID"]: row for row in load_rows(final_path, "Error ID")}

    notes = []
    for item in plants:
        label, manifest = item["id"], item["manifest"]
        source = source_by_manifest[manifest]
        source_mappings = mappings_by_source.get(source, [])
        if not source_mappings:
            return "FAIL", f"{label} source {source} is absent from detector mapping"
        error_ids = {_clean(row["Error ID"]) for row in source_mappings}
        if len(error_ids) != 1:
            return "FAIL", f"{label} source {source} maps to {len(error_ids)} Error IDs"
        error_id = next(iter(error_ids))
        inv = [row for row in inventory if _clean(row.get("ID")) == error_id]
        if len(inv) != 1 or source not in inv[0].get("Likely Evidence", ""):
            return "FAIL", f"{label} {error_id} is absent from b4 inventory evidence"
        dispositions = ledger_by_id.get(error_id, [])
        if len(dispositions) != 1:
            return "FAIL", f"{label} {error_id} has {len(dispositions)} structured ledger rows"
        ledger = dispositions[0]
        if _clean(ledger["Verdict"]) != item["verdict"]:
            return "FAIL", f"{label} ledger verdict is {_clean(ledger['Verdict'])}, expected {item['verdict']}"
        expected_keys = {tuple(_clean(row[field]) for field in
                               ("Channel", "Source ID", "Witness ID"))
                         for row in source_mappings}
        if set(_list_cell(ledger["Outcome Witness IDs"])) != {key[2] for key in expected_keys}:
            return "FAIL", f"{label} ledger does not declare every mapped witness"
        # The adjudication contract requires accepted type/mechanism only for
        # error-accepting verdicts (confirmed_error, duplicate); a compliant
        # not_error row may leave them blank — the closed error taxonomy has
        # no "not an error" entry. Key on the answer key's expected verdict:
        # ledger-verdict equality was already enforced above, and the answer
        # key is the stable side.
        if item["verdict"] in {"confirmed_error", "duplicate"} and (
                not _clean(ledger["Accepted Error Type"])
                or not _clean(ledger["Accepted Mechanism"])):
            return "FAIL", f"{label} structured accepted type/mechanism is empty"
        if not expected_keys <= post_keys:
            return "FAIL", f"{label} witnesses are absent from assembled boundary"
        final = final_by_id.get(error_id)
        if final is None or _clean(final.get("Status")) != item["final_status"]:
            found = _clean(final.get("Status")) if final else "missing"
            return "FAIL", f"{label} final status is {found}, expected {item['final_status']}"
        if "min_severity" in item and severity(final) < item["min_severity"]:
            return "FAIL", f"{label} final severity is below {item['min_severity']}"
        if "exact_severity" in item and severity(final) != item["exact_severity"]:
            return "FAIL", f"{label} final severity must equal {item['exact_severity']}"
        if item.get("receipt_required"):
            record_ids = set(_list_cell(ledger["Verification Record IDs"]))
            covered = set()
            for receipt in receipt_rows:
                key = tuple(_clean(receipt[field]) for field in
                            ("Channel", "Source ID", "Witness ID"))
                if (key in expected_keys and _clean(receipt["Record ID"]) in record_ids
                        and _clean(receipt["Accepted (yes/no)"]) == "yes"):
                    covered.add(key)
                    plant_file = (audit.parent / manifest).resolve()
                    if _clean(receipt["Input Digest (sha256)"]) != hashlib.sha256(
                            plant_file.read_bytes()).hexdigest():
                        return "FAIL", f"{label} receipt input digest does not bind the plant"
            if covered != expected_keys or error_id not in assembled:
                return "FAIL", f"{label} lacks qualifying receipt/assembled coverage"
            plant_file = (audit.parent / manifest).resolve()
            _tool, _version, _invocation, result = dismissal_verifier._manifest_run(
                plant_file, "micromamba")
            if not dismissal_verifier.accepted_result(result.returncode, result.stderr):
                return "FAIL", f"{label} independent pinned-oracle recheck did not accept"
        notes.append(f"{label} {source} -> {error_id} {item['final_status']}")
    return "PASS", "; ".join(notes)


def check_argument_contract_channel(audit, expected):
    """Trace the U8a plant from raw AC output through mapping and final canon."""
    plants = expected.get("argument_contract_plants", [])
    if not plants:
        return "NOT COVERED", "answer key has no U8a argument-contract plant"
    path = audit / "_run/argument_contracts.md"
    if not path.is_file():
        return "FAIL", f"argument-contract artifact missing: {path}"
    try:
        artifact = argument_contracts.parse_artifact(
            path.read_text(encoding="utf-8"))
        _declared, _display, mappings = detector_mapping.load_mapping(
            audit / "_run/detector_mapping.md")
    except (argument_contracts.ArgumentContractError,
            detector_mapping.MappingError) as exc:
        return "FAIL", f"U8a artifact is malformed: {exc}"
    final_path = audit / "code_error_register.md"
    if not final_path.is_file():
        return "FAIL", f"final code-error register missing: {final_path}"
    final = {row["Error ID"]: row for row in load_rows(final_path, "Error ID")}
    receipts = []
    receipt_path = audit / "_run/code_b6a/dismissal_receipts.md"
    if receipt_path.is_file():
        headers, rows = _table_with_headers(
            receipt_path.read_text(encoding="utf-8", errors="replace"),
            dismissal_verifier.RECEIPT_COLS, exact=True)
        if rows is not None:
            receipts = [dict(zip(headers, row)) for row in rows]
    notes = []
    for plant in plants:
        caller = plant["caller"]
        calls = [row for row in artifact.call_sites
                 if row.site_anchor.startswith(caller + ":")]
        findings = [row for row in artifact.findings
                    if row.site_anchor.startswith(caller + ":")]
        if len(calls) != 2:
            return "FAIL", f"{plant['id']} expected two master call sites; found {len(calls)}"
        if [(row.finding_kind, row.witness_id, row.callee_path)
                for row in findings] != [(plant["finding_kind"],
                                           plant["witness_id"],
                                           plant["callee"])]:
            return "FAIL", f"{plant['id']} raw artifact does not contain its exact one-flag set"
        flagged_source = findings[0].source_id
        control = [row for row in calls if row.resolved_callee == plant["control"]]
        if len(control) != 1 or control[0].outcome != "consumed":
            return "FAIL", f"{plant['id']} fully-consuming control is not quiet"
        mapped = [row for row in mappings
                  if row["Channel"] == "AC" and row["Source ID"] == flagged_source]
        if len(mapped) != 1 or mapped[0]["Witness ID"] != plant["witness_id"]:
            return "FAIL", f"{plant['id']} flagged source lacks exact AC mapping coverage"
        error_id = mapped[0]["Error ID"]
        row = final.get(error_id)
        if row is None:
            return "FAIL", f"{plant['id']} mapped candidate {error_id} is absent from final canon"
        if row.get("Status") == "not_error":
            covered = [receipt for receipt in receipts
                       if _clean(receipt.get("Channel")) == "AC"
                       and _clean(receipt.get("Source ID")) == flagged_source
                       and _clean(receipt.get("Witness ID")) == plant["witness_id"]
                       and _clean(receipt.get("Accepted (yes/no)")) == "yes"]
            if not covered:
                return "FAIL", f"{plant['id']} was dismissed without a verification receipt"
            return "FAIL", f"{plant['id']} was dismissed instead of surviving as a downgraded issue"
        if row.get("Status") not in {"confirmed", "confirmation_needed", "blocked"}:
            return "FAIL", f"{plant['id']} final status {row.get('Status')!r} is not an issue status"
        if row.get("Error Type") != "missing_input_or_output":
            return "FAIL", f"{plant['id']} final row has wrong Error Type"
        notes.append(f"{plant['id']} {flagged_source} -> {error_id} {row.get('Status')}")
    return "PASS", "; ".join(notes)


def check_severity_token_plants(audit, expected):
    """U8b severity plants: receipted token on arm (a), band caps on (b)/(c).

    Artifact-layer assertions in the ``adjudication_contract_plants`` style:
    arm (a) must close confirmed within its severity band, carrying exactly
    one mode-qualifying token whose target resolves to a reported output row
    and whose verifier receipt exists only when it closes severe (severity
    >= 3) — below the severe threshold the receipt machinery is disengaged,
    mirroring the production contract where tokens bind severe proposals;
    arms (b)/(c) assert the severity band REGARDLESS of status — a
    ``confirmation_needed`` row above the band still fails the plant."""
    plants = expected.get("severity_token_plants", [])
    if not plants:
        return "NOT COVERED", "answer key has no U8b severity-token plants"
    final_path = audit / "code_error_register.md"
    if not final_path.is_file():
        return "FAIL", f"final code-error register missing: {final_path}"
    rows = load_rows(final_path, "Error ID")
    receipts = {}
    for stage in ("code_b6b", "code_b6a"):
        if (audit / f"_run/{stage}/token_receipts.md").is_file():
            parsed, failures = severity_tokens.load_receipts(audit, stage)
            if failures:
                return "FAIL", f"{stage} token receipts are malformed: {failures[0]}"
            for key, receipt in parsed.items():
                receipts.setdefault(key, receipt)
    output_rows = []
    output_path = audit / "output_register.md"
    if output_path.is_file():
        output_rows = load_rows(output_path, "Output ID")
    notes = []
    for item in plants:
        pid = item["id"]
        matched = [d for d in rows if sig_match(row_text(d), SIGNATURES[pid])]
        if len(matched) != 1:
            return "FAIL", f"{pid} matches {len(matched)} register rows (need exactly one)"
        d = matched[0]
        sev, status = severity(d), (d.get("Status") or "").strip()
        if "max_severity" in item and sev > int(item["max_severity"]):
            return "FAIL", (f"{pid} arm ({item.get('arm', '?')}) severity {sev} exceeds "
                            f"its band <= {item['max_severity']} (status={status!r} — "
                            "the band binds regardless of status)")
        if "min_severity" in item and sev < int(item["min_severity"]):
            return "FAIL", (f"{pid} arm ({item.get('arm', '?')}) severity {sev} falls below "
                            f"its band >= {item['min_severity']} (status={status!r} — "
                            "the band binds regardless of status)")
        if "exact_severity" in item and sev != int(item["exact_severity"]):
            return "FAIL", f"{pid} final severity is {sev}, expected {item['exact_severity']}"
        if "final_status" in item and status != item["final_status"]:
            return "FAIL", f"{pid} final status is {status!r}, expected {item['final_status']}"
        if item.get("receipt_required") and sev >= 3:
            carrier = severity_tokens.why_text(d)
            found = severity_tokens.literal_tokens(carrier)
            kind = item.get("token_kind", "output")
            if len(found) != 1 or not found[0].startswith(kind + ":"):
                return "FAIL", (f"{pid} carrier must hold exactly one {kind}: token "
                                f"(found {found})")
            token = found[0]
            target = token.split(":", 1)[1]
            target_row = next((r for r in output_rows
                               if (r.get("Output ID") or "").strip() == target), None)
            if kind == "output" and (target_row is None or not (
                    target_row.get("Paper Location") or "").strip(" -—")):
                return "FAIL", f"{pid} token target {target} does not resolve to a reported output row"
            covered = [key for key in receipts
                       if key[0] == d.get("Error ID") and key[1] == token]
            if len(covered) != 1:
                return "FAIL", f"{pid} lacks exactly one verifier token receipt for {token}"
        notes.append(f"{pid} {d.get('Error ID')} {status} sev={sev}")
    return "PASS", "; ".join(notes)


def check_channel_definition_use(audit):
    """Trace P-21 and D-03 through artifact, b4, ledger, and final register."""
    artifact = audit / "_run" / "definition_use_bundles.md"
    if not artifact.is_file():
        return "FAIL", f"definition/use artifact not found: {artifact}"
    text = artifact.read_text(encoding="utf-8", errors="replace")
    try:
        parsed_artifact = du.parse_artifact(text)
    except du.DefinitionUseFormatError as exc:
        return "FAIL", f"definition/use artifact is malformed: {exc}"
    artifact_rows = parsed_artifact.standard_rows
    located = {}
    for label, locator in DEFINITION_USE_LOCATORS.items():
        matches = []
        for row in artifact_rows:
            if (du.normalize_cell(row.get("Variable", "")) == locator["variable"]
                    and du.normalize_cell(row.get("Definition Site", "")) == locator["definition"]
                    and du.normalize_cell(row.get("Consumer Site", "")) == locator["consumer"]):
                matches.append(du.normalize_cell(row.get("Bundle ID", "")))
        if len(matches) != 1 or not re.fullmatch(r"DU-[0-9A-Za-z]+", matches[0] if matches else ""):
            return ("FAIL", f"{label} bundle not uniquely located at "
                    f"{locator['definition']} -> {locator['consumer']}")
        located[label] = matches[0]

    plan = audit / "plans" / "code_error_recheck_plan.md"
    if not plan.is_file():
        return "FAIL", f"code recheck plan missing: {plan}"
    plan_text = plan.read_text(encoding="utf-8", errors="replace")
    detector_mappings = None
    detector_path = audit / "_run/detector_mapping.md"
    if detector_path.is_file():
        try:
            _declared, _display, detector_mappings = detector_mapping.load_mapping(
                detector_path)
        except detector_mapping.MappingError as exc:
            return "FAIL", f"detector mapping is malformed: {exc}"
        mappings = None
    else:
        try:
            mappings = du.parse_mappings(plan_text)
        except du.DefinitionUseFormatError as exc:
            return "FAIL", f"Definition/use bundle mapping table is malformed: {exc}"
    _, inventory_rows = _table_with_headers(
        plan_text, ["ID", "Reason", "Likely Evidence"])
    if inventory_rows is None:
        return "FAIL", "b4 inventory missing"
    inventory = [dict(zip(["ID", "Reason", "Likely Evidence"], row))
                 for row in inventory_rows]
    mapped_ids, mapped_witnesses = {}, {}
    for label, bid in located.items():
        if detector_mappings is not None:
            matches = [row for row in detector_mappings
                       if row["Channel"] == "DU" and row["Source ID"] == bid]
            ids = {row["Error ID"] for row in matches}
            if len(ids) != 1:
                return "FAIL", f"{label} {bid} maps to {len(ids)} Error IDs"
            eid = next(iter(ids))
            mapped_witnesses[label] = {
                (row["Channel"], row["Source ID"], row["Witness ID"])
                for row in matches}
        else:
            matches = [row for row in mappings
                       if du.normalize_cell(row.get("Bundle ID", "")) == bid]
            if len(matches) == 1:
                eid = du.normalize_cell(matches[0].get("Error ID", ""))
        if len(matches) != 1:
            if detector_mappings is None:
                return "FAIL", f"{label} {bid} has {len(matches)} mapping rows (expected 1)"
            if not matches:
                return "FAIL", f"{label} {bid} has no detector mapping rows"
        inv = [row for row in inventory
               if du.normalize_cell(row.get("ID", "")) == eid]
        if len(inv) != 1:
            return "FAIL", f"{label} mapped Error ID {eid} absent from b4 inventory"
        if bid not in du.extract_bundle_tokens(inv[0].get("Likely Evidence", "")):
            return "FAIL", f"{label} {bid} absent from inventory Likely Evidence"
        mapped_ids[label] = eid

    ledger_rows, verification_records = [], {}
    ledger_root = audit / "_code_error_recheck"
    if ledger_root.is_dir():
        for path in sorted(ledger_root.rglob("*.md")):
            ledger_text = path.read_text(encoding="utf-8", errors="replace")
            headers, rows = _table_with_headers(
                ledger_text, CODE_LEDGER_COLS, exact=True)
            if rows is not None:
                ledger_rows.extend(dict(zip(headers, row)) for row in rows)
            else:
                headers, rows = _table_with_headers(
                    ledger_text, LEDGER_COLS, exact=True)
                if rows is not None:
                    ledger_rows.extend(dict(zip(headers, row)) for row in rows)
            for headers, rows in parse_tables(ledger_text):
                if headers in (dismissal_verifier.MF_RECORD_COLS,
                               dismissal_verifier.PROBE_RECORD_COLS):
                    for row in rows:
                        if len(row) == len(headers):
                            record = dict(zip(headers, row))
                            verification_records[_clean(record["Record ID"])] = record
    ledgers = {}
    for label, eid in mapped_ids.items():
        matches = [row for row in ledger_rows
                   if du.normalize_cell(row.get("ID", "")) == eid]
        if len(matches) != 1:
            return "FAIL", f"{label} mapped Error ID {eid} has {len(matches)} ledger dispositions"
        if located[label] not in du.extract_bundle_tokens(
                matches[0].get("Evidence Checked", "")):
            return "FAIL", f"{label} {located[label]} absent from ledger Evidence Checked"
        ledgers[label] = matches[0]

    final_path = audit / "code_error_register.md"
    if not final_path.is_file():
        return "FAIL", "final code-error register missing"
    final_rows = load_rows(final_path, "Error ID")
    final_by_id = {row.get("Error ID", ""): row for row in final_rows}

    p_eid = mapped_ids["P-21"]
    p_ledger = ledgers["P-21"]
    p_row = final_by_id.get(p_eid)
    if p_ledger.get("Verdict") != "confirmed_error":
        return "FAIL", (f"P-21 {p_eid} ledger verdict must be confirmed_error; "
                        f"found {p_ledger.get('Verdict', '')}")
    if p_row is None:
        return "FAIL", f"P-21 mapped Error ID {p_eid} missing from final register"
    p_status = p_row.get("Status", "")
    duplicate = re.fullmatch(r"duplicate_of:(E-\d{4})", p_status)
    if duplicate:
        target_id = duplicate.group(1)
        proposal = (p_ledger.get("Proposed Register Change", "") + " "
                    + p_ledger.get("Proposed Note", ""))
        target = final_by_id.get(target_id)
        if p_status not in proposal or target is None:
            return "FAIL", f"P-21 duplicate mapping does not explicitly name {target_id}"
        p_issue = target
    else:
        p_issue = p_row
    if (p_issue.get("Status") != "confirmed" or severity(p_issue) < 2
            or not sig_match(row_text(p_issue), SIGNATURES["P-21"])):
        return "FAIL", "P-21 did not land in an equivalent confirmed severity>=2 issue row"

    d_eid = mapped_ids["D-03"]
    d_ledger = ledgers["D-03"]
    d_row = final_by_id.get(d_eid)
    if d_ledger.get("Verdict") != "not_error":
        return "FAIL", (f"D-03 {d_eid} ledger verdict must be not_error; "
                        f"found {d_ledger.get('Verdict', '')}")
    if d_row is None or d_row.get("Status") != "not_error":
        found = d_row.get("Status", "missing") if d_row else "missing"
        return "FAIL", f"D-03 mapped Error ID {d_eid} must finish not_error; found {found}"
    if detector_mappings is not None:
        record_ids = set(_list_cell(d_ledger.get("Verification Record IDs", "")))
        record_coverage = {
            tuple(_clean(record[field]) for field in
                  ("Channel", "Source ID", "Witness ID"))
            for record_id, record in verification_records.items()
            if record_id in record_ids
        }
        if record_coverage != mapped_witnesses["D-03"]:
            return "FAIL", "D-03 lacks a qualifying synthetic verification record per witness"
        receipt_path = audit / "_run/code_b6a/dismissal_receipts.md"
        receipt_coverage = set()
        if receipt_path.is_file():
            receipt_text = receipt_path.read_text(encoding="utf-8", errors="replace")
            headers, rows = _table_with_headers(
                receipt_text, dismissal_verifier.RECEIPT_COLS, exact=True)
            if rows is not None:
                for raw in rows:
                    receipt = dict(zip(headers, raw))
                    if (_clean(receipt["Record ID"]) in record_ids
                            and _clean(receipt["Accepted (yes/no)"]) == "yes"):
                        receipt_coverage.add(tuple(_clean(receipt[field]) for field in
                                                   ("Channel", "Source ID", "Witness ID")))
        if receipt_coverage != mapped_witnesses["D-03"]:
            return "FAIL", "D-03 synthetic verification records lack qualifying receipts"
    issue_rows = [row for row in final_rows
                  if row.get("Status") in {"candidate", "confirmed", "confirmation_needed", "blocked"}
                  and is_d03(row)]
    claims_path = audit / "claims_register.md"
    if claims_path.is_file():
        issue_rows.extend(
            row for row in load_rows(claims_path, "Claim ID")
            if is_d03(row) and (
                row.get("Status") in {"inconsistent", "confirmation_needed"}
                or bool(row.get("Severity", "").strip())))
    outputs_path = audit / "output_register.md"
    if outputs_path.is_file():
        issue_rows.extend(
            row for row in load_rows(outputs_path, "Output ID")
            if is_d03(row) and row.get("Status") in {"inconsistent", "unclear"})
    if issue_rows:
        return "FAIL", "D-03 baseline diagnostic survives as an issue row"
    return ("PASS", f"P-21 {located['P-21']} -> {p_eid} confirmed; "
            f"D-03 {located['D-03']} -> {d_eid} not_error")


def _find_claims_table(lint_mod, audit):
    """(headers, rows) of the final claims register's table, tolerating the
    post-b8 ``*_Original`` extra columns; (None, None) if unparsable.

    The b8 rewrite pass inserts each ``*_Original`` column immediately after
    its source column (e.g. ``Issue Description | Issue Description Original``),
    so the canonical columns are a subset of the header, NOT a prefix of it.
    Match on set-containment and zip rows against the actual header, mirroring
    ``lint_registers.load_register(allow_extra=True)`` and the containment fix
    in ``check_anchoring_advisory``."""
    path = audit / "claims_register.md"
    if not path.is_file():
        return None, None
    text = path.read_text(encoding="utf-8", errors="replace")
    for headers, rows, _ in lint_mod.parse_tables(text):
        if set(lint_mod.CLAIMS_COLS) <= set(headers):
            return headers, [r for r in rows if len(r) == len(headers)]
    return None, None


def _locate_claim_rows(headers, rows, locator):
    """Claim-row dicts whose full text matches *locator* (signature groups)."""
    out = []
    for r in rows:
        d = dict(zip(headers, r))
        if sig_match(row_text(d), locator):
            out.append(d)
    return out


def check_artifact_anchoring(lint_mod, audit):
    """U4 (conditional, gate-settling): if the P-19 claim closed confirmed,
    the anchoring advisory must have warned on its recheck-ledger row."""
    headers, rows = _find_claims_table(lint_mod, audit)
    if headers is None:
        return "FAIL", "claims register missing or unparsable"
    matches = _locate_claim_rows(headers, rows, U4_CLAIM_LOCATOR)
    if not matches:
        return ("NOT COVERED",
                "no claim row locates the P-19 plant (register layer scores it)")
    confirmed = [d for d in matches
                 if (d.get("Status") or "").strip() == "confirmed"]
    if not confirmed:
        return "PASS", ("vacuous — P-19 claim not confirmed "
                        "(closed " + "/".join(sorted(
                            (d.get("Status") or "?").strip() for d in matches))
                        + ")")
    ledger_rows = []
    recheck_dir = audit / "_recheck"
    if recheck_dir.is_dir():
        for p in sorted(recheck_dir.rglob("*.md")):
            text = p.read_text(encoding="utf-8", errors="replace")
            for h, rws, _ in lint_mod.parse_tables(text):
                if h == lint_mod.LEDGER_COLS:
                    ledger_rows.extend(r for r in rws if len(r) == len(h))
    ids = {d.get("Claim ID", "") for d in confirmed}
    covered = [r for r in ledger_rows
               if dict(zip(lint_mod.LEDGER_COLS, r)).get("ID") in ids]
    if not covered:
        return ("NOT COVERED",
                "P-19 claim closed confirmed with no recheck-ledger row — the "
                "advisory is a tripwire over the recheck sample (KTD-3) and "
                "never saw it; the register layer scores the miss")
    lint = lint_mod.Lint()
    lint_mod.check_anchoring_advisory(lint, audit, covered)
    fired = [w for w in lint.warnings
             if "anchoring:" in w and any(i in w for i in ids)]
    if fired:
        return "PASS", "tripwire fired — " + "; ".join(fired)
    return "FAIL", ("P-19 claim closed confirmed but the anchoring advisory "
                    "stayed silent on its ledger row(s): " + ", ".join(sorted(ids)))


def check_artifact_filename_parameter(lint_mod, audit):
    """U5 (conditional, gate-settling): if the P-20 row rests blocked, the
    filename-parameter advisory must warn on it."""
    headers, rows = _find_claims_table(lint_mod, audit)
    if headers is None:
        return "FAIL", "claims register missing or unparsable"
    matches = _locate_claim_rows(headers, rows, U5_CLAIM_LOCATOR)
    if not matches:
        return ("NOT COVERED",
                "no claim row locates the P-20 plant (register layer scores it)")
    blocked = [d for d in matches
               if (d.get("Status") or "").strip() == "blocked"]
    if not blocked:
        return "PASS", ("vacuous — P-20 row not blocked "
                        "(closed " + "/".join(sorted(
                            (d.get("Status") or "?").strip() for d in matches))
                        + ")")
    ids = {d.get("Claim ID", "") for d in blocked}
    lint = lint_mod.Lint()
    raw = [[d.get(c, "") for c in headers] for d in blocked]
    lint_mod.check_filename_parameter_advisory(
        lint, audit / "claims_register.md", raw, cols=headers)
    fired = [w for w in lint.warnings
             if "filename-parameter" in w and any(i in w for i in ids)]
    if fired:
        return "PASS", "tripwire fired — " + "; ".join(fired)
    return "FAIL", ("P-20 row rests blocked but the filename-parameter "
                    "advisory stayed silent on: " + ", ".join(sorted(ids)))


def check_artifact_conventions(lint_mod, audit, tagged_rows):
    """U1 (INFORMATIVE only, never gate-settling per KTD-8): is the
    enumerated-member-list convention in the b3c artifact, and does any final
    register row carry the P-15 mechanism?"""
    path = audit / "_run" / "conventions.md"
    conv = "artifact absent"
    if path.is_file():
        conv = f"{U1_CONVENTION_CATEGORY} convention ABSENT from the artifact"
        text = path.read_text(encoding="utf-8", errors="replace")
        for headers, rows, _ in lint_mod.parse_tables(text):
            for r in rows:
                joined = " | ".join(r).lower()
                if (U1_CONVENTION_CATEGORY in joined
                        and any(t in joined for t in U1_MEMBER_TERMS)):
                    conv = f"{U1_CONVENTION_CATEGORY} convention PRESENT"
                    break
    reg = "no register row matches the P-15 mechanism"
    for kind, id_col, d in tagged_rows:
        if sig_match(row_text(d), SIGNATURES["P-15"]):
            reg = f"P-15 mechanism row present ({describe(kind, id_col, d)})"
            break
    return "INFO", f"{conv}; {reg} (worker-dependent — informative, not gate-settling)"


# --------------------------------------------------------------- main


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--audit-dir", type=Path, required=True,
                    help="directory holding the run's FINAL registers")
    ap.add_argument("--expected", type=Path, default=DEFAULT_EXPECTED)
    args = ap.parse_args()

    if not args.expected.is_file():
        print(f"ERROR: expected-findings file not found: {args.expected}",
              file=sys.stderr)
        return 2
    expected = json.loads(args.expected.read_text(encoding="utf-8"))

    audit = args.audit_dir
    run_manifest = {}
    run_manifest_path = audit / "_run" / "manifest.json"
    if run_manifest_path.is_file():
        try:
            run_manifest = json.loads(run_manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    u7_fixture_active = isinstance(run_manifest.get("allocation_override"), dict)
    tagged_rows = []
    for fname, id_col in REGISTERS:
        path = audit / fname
        if not path.is_file():
            if fname == "output_register.md":
                continue  # optional (code_errors_only runs)
            print(f"ERROR: register not found: {path}", file=sys.stderr)
            return 2
        kind = {"Claim ID": "claims", "Error ID": "errors",
                "Output ID": "outputs"}[id_col]
        for d in load_rows(path, id_col):
            tagged_rows.append((kind, id_col, d))

    summary_path = audit / "register_cross_link_summary.md"
    summary_text = (summary_path.read_text(encoding="utf-8", errors="replace")
                    if summary_path.is_file() else None)

    missing_sigs = [i["id"] for i in expected.get("must_find", [])
                    if i["id"] not in SIGNATURES]
    if missing_sigs:
        print("ERROR: no mechanism signature for plant(s) "
              f"{', '.join(missing_sigs)} — extend SIGNATURES in "
              "score_fixture.py", file=sys.stderr)
        return 2

    print(f"Fixture score — audit dir: {audit}")
    print(f"Answer key: {args.expected}")
    print()

    red_reasons = []
    n_hit = 0
    class_totals, class_hits = {}, {}
    must_find = expected.get("must_find", [])
    for item in must_find:
        scorer = (score_blocked_visible if item["id"] in BLOCKED_VISIBLE_PLANTS
                  else score_generic)
        verdict, note = scorer(item, tagged_rows)
        cls = item.get("failure_class")
        # untagged plants (the pre-2026-07-07 P-01..P-14) roll up in an
        # explicit legacy bucket so every planted item appears in the
        # per-class breakdown and the aggregate equals the per-class sum
        bucket = cls or "unclassified_legacy"
        class_totals[bucket] = class_totals.get(bucket, 0) + 1
        if verdict == "HIT":
            n_hit += 1
            class_hits[bucket] = class_hits.get(bucket, 0) + 1
        else:
            red_reasons.append(f"{item['id']} MISS")
        tag = f" [class={cls}]" if cls else ""
        print(f"{item['id']}: {verdict}{tag} — {note}")

    print()
    for did, (terms, quals) in DECOYS.items():
        found = check_decoy(terms, quals, tagged_rows, summary_text)
        if found:
            print(f"{did} decoy: PRESENT — {'; '.join(found)}")
            red_reasons.append(f"{did} decoy present")
        else:
            note = "" if summary_text is not None else \
                " (cross-link summary not found; registers only)"
            print(f"{did} decoy: ABSENT{note}")

    sc01 = check_sc01(tagged_rows)
    if sc01:
        print(f"SC-01: FAIL — {sc01}")
        red_reasons.append("SC-01 unresolved status conflict")
    else:
        print("SC-01: PASS")

    # artifact-layer checks (U9; single-re-score layer per KTD-8)
    print()
    print("Artifact-layer checks (single-re-score layer; record separately "
          "from the register-based two-run results):")
    lint_mod = None
    try:
        lint_mod = load_lint_module()
    except Exception as exc:  # never crash the register score
        print(f"WARNING: could not load lint_registers.py "
              f"({exc.__class__.__name__}: {exc}); the gate-settling U4/U5 "
              "artifact checks did not run (red), and the U1 INFO check is "
              "skipped")
        red_reasons.append("U4/U5 artifact checks unrun: lint_registers.py "
                           "failed to load")
    status, note = check_artifact_manifest(audit)
    print(f"U2 manifest artifact: {status} — {note}")
    if status == "FAIL":
        red_reasons.append("U2 manifest artifact check failed")
    expected_ids = {item.get("id") for section in ("must_find", "must_not_find")
                    for item in expected.get(section, [])}
    if {"P-21", "D-03"} & expected_ids:
        status, note = check_channel_definition_use(audit)
    else:
        status, note = ("NOT COVERED",
                        "answer key does not request definition/use channel plants")
    print(f"Definition/use channel: {status} — {note}")
    if status == "FAIL":
        red_reasons.append("definition/use channel check failed")
    if {"P-23", "P-24"} <= expected_ids:
        status, note = check_clean_recall_chain(audit)
    else:
        status, note = ("NOT COVERED", "answer key does not request the U6a plant pair")
    print(f"U6a clean-recall chain: {status} — {note}")
    if status == "FAIL":
        red_reasons.append("U6a clean-recall chain check failed")
    if "P-25" in expected_ids:
        if u7_fixture_active:
            status, note = check_u7_allocation_split(audit)
        else:
            status, note = ("FAIL", (
                "run manifest lacks allocation_override: the P-25 fixture run "
                "must pin its two-worker allocation (fixture/README.md)"
            ))
    else:
        status, note = ("NOT COVERED", "answer key does not request the U7a P-25 plant")
    print(f"U7a allocation split: {status} — {note}")
    if status == "FAIL":
        red_reasons.append("U7a allocation split check failed")
    status, note = check_channel_adjudication(audit, expected)
    print(f"U3b adjudication channel: {status} — {note}")
    if status == "FAIL":
        red_reasons.append("U3b adjudication channel check failed")
    if "P-26" in expected_ids:
        status, note = check_argument_contract_channel(audit, expected)
    else:
        status, note = ("NOT COVERED", "answer key does not request the U8a P-26 plant")
    print(f"U8a argument-contract channel: {status} — {note}")
    if status == "FAIL":
        red_reasons.append("U8a argument-contract channel check failed")
    if {"P-27", "P-28", "P-29"} <= expected_ids:
        status, note = check_severity_token_plants(audit, expected)
    else:
        status, note = ("NOT COVERED",
                        "answer key does not request the U8b severity plants")
    print(f"U8b severity-token plants: {status} — {note}")
    if status == "FAIL":
        red_reasons.append("U8b severity-token plant check failed")
    if lint_mod is not None:
        for label, fn, red in (
            ("U4 anchoring advisory", check_artifact_anchoring,
             "U4 anchoring advisory check failed"),
            ("U5 filename-parameter advisory",
             check_artifact_filename_parameter,
             "U5 filename-parameter advisory check failed"),
        ):
            status, note = fn(lint_mod, audit)
            print(f"{label}: {status} — {note}")
            if status == "FAIL":
                red_reasons.append(red)
        status, note = check_artifact_conventions(lint_mod, audit, tagged_rows)
        print(f"U1 conventions artifact: {status} — {note}")

    print()
    print(f"Recall: {n_hit}/{len(must_find)}")
    if class_totals:
        print("Per-class:")
        for bucket, tot in sorted(class_totals.items()):
            hits = class_hits.get(bucket, 0)
            print(f"  {bucket}: {hits}/{tot} hit, {tot - hits} miss")
    if red_reasons:
        print(f"GATE RED — {'; '.join(red_reasons)}")
        return 1
    print("GATE GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
