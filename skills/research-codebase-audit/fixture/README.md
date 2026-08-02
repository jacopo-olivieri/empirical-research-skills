# Fixture — planted-error validation package

`planted/` is a tiny synthetic replication package (mini paper, two Stata scripts, two
Python scripts, data, manifests, artifacts, README) with **28 planted findings**
(`must_find` items P-01 through P-21 plus P-23 through P-29) spanning the error taxonomy — including the three
classes added by the design (seed, SE specification, weights), a transcription mismatch
against a shipped artifact, hygiene/PII findings, and **three decoys** that must NOT be
flagged (a commented-out figure, an intentional subset of a stated member list, and an
intentional baseline-only diagnostic that exercises the detector/recheck channel).

**Behavior-test plants (added 2026-07-06)** — P-12/P-13/P-14 exist to predict the Floods
failure mode, keyed to the behavior each tests:
- **P-12** — a second, independent error (a reversed figure legend) in `py/make_figures.py`,
  whose prominent first finding is the P-06 stale path. Recovering it requires the
  **second-read recall sweep** re-reading an already-flagged file.
- **P-13** — an arithmetic slip in the paper prose (725 of 2,416 households is 30%, not the
  stated 25%). Caught by the **cheap-check arithmetic recompute**, not left located-unverified.
- **P-14** — a claim (`one-in-ten subsample`) resting on restricted data but contradicted by
  visible package metadata (the README calls `households.csv` a `1-in-20 subsample`). Tests the
  **blocked-visible-metadata discipline**: flagged inconsistent (or blocked with a Blocked Check
  note), never silently blocked.

**Failure-class plants (added 2026-07-07)** — P-15 through P-20 plant one instance of each
mechanism from the recall-determinism refactor (U1–U5), each in a domain fresh relative to
the Floods package, each tagged with a `failure_class` the scorer reports per class:
- **P-15** (`enumerated_member_list`, U1) — the paper states a four-component income list;
  `py/build_income.py` hand-retypes it as three, omitting remittances. Recovery is attributed
  to the b3c consolidation single-row carve-out plus the b4 set-difference grep.
- **P-16** (`manifest_parseability`, U2) — `pyproject.toml` is invalid TOML (unquoted
  `version = 0.4.1`), a different format/ecosystem from the Floods requirements defect;
  `check_manifests.py` must name it in `audit/_run/manifest_check.md`.
- **P-17 / P-18** (`empirical_verification`, U3) — a Stata backfill guard whose comment says
  it fills missing `hhsize` but whose `if hhsize < .` condition excludes the missing case
  (in `do/build_panel.do`, already carrying P-05/P-08/P-11), and a Python loop that
  overwrites `has_wages` each iteration so the last wave erases earlier matches (in
  `py/build_income.py`, alongside P-15/P-19) — each in a file with unrelated plants, the
  shape of the real misses.
- **P-19** (`identifier_anchoring`, U4) — the paper says `wage_earnings` is winsorised at
  the 99th percentile; the code winsorises `crop_sales`. The claim must not close confirmed.
- **P-20** (`step_parameter_filename`, U5) — Appendix A step 2 states a 15-km gauge radius;
  the shipped file is `data/village_rain_radius_25km.csv`. Dual-accept like P-14.
- **D-02 decoy** — `farm_components` in `py/build_income.py` keeps a deliberate,
  comment-signposted subset of the stated income list; flagging it is a false positive
  (exercises the U1 intentional-subset guard).

**Definition/use contract plant (added 2026-07-08)** — P-21 exercises the reworded
standing check 2 (a derived control variable used only for the cases its own definition
covers):
- **P-21** (`definition_use_contract`) — in `do/build_panel.do` (already carrying
  P-05/P-08/P-11/P-17), the `consent_ok` release flag's comment states it covers both
  consent families (individual data-sharing consent AND village-level community consent),
  but the estimation-sample filter `keep if consent_ok == 1 & consent == "individual"`
  adds a conjunct that silently drops the community-consent households. The narrowed
  sample flows to `output/panel.dta` -> `do/analysis.do` -> `artifacts/tab1.tex`, so the
  severity floor of 2 is honest under the materiality rubric. Fresh domain (survey consent
  gating a published table); the excluded case family is named in the comment, not a
  missing-value idiom.
- **D-03 detector-channel precision decoy** — in `do/analysis.do`, after the panel is
  loaded, `baseline_diag_ok` gates a `preserve`/`restore`-contained baseline-wave-only
  diagnostic. Its `keep if baseline_diag_ok == 1 & wave == 1` deliberately matches the
  detector surface shape and therefore must be emitted and mapped through recheck, then
  cleared `not_error`: the additional wave restriction is explicitly the diagnostic's
  domain and `restore` prevents it from narrowing the estimation sample.

**Clean-file recall pair (added 2026-07-18)** — P-23/P-24 share the otherwise-clean
`requirements-recall.txt`. P-23 is the mechanically flaggable whitespace-operator error that
must enter the b3d manifest artifact/mapping and force a `detector` second read. P-24 is a
human-only pair of individually legal but mutually incompatible exact pandas pins; if first pass
does not recover it, its candidate must originate in that file's b3b shard.

**Claim-handoff plant (added 2026-07-20)** — P-25 says the calculated and reference speeds
substantially overlap in body prose while appendix Figure A2's planted code uses disjoint ranges.
The run manifest must carry `allocation_override` with purpose `fixture`; its exact b1 allocation
must use at least two claims workers and place the P-25 body sentence and `fig:speed-overlap`
appendix figure in different line intervals. It must also allocate every line of the mechanically
included `artifacts/tab1.tex` source. `score_fixture.py` refuses a one-worker collapse regardless
of whether a final row happens to recover P-25.

**Severity-token plants (added 2026-07-21)** — P-27/P-28/P-29 are three arms of one
wrong-denominator mechanism family in `py/build_capita.py` (every per-member measure
divides by `age_head` instead of `hhsize`, against the paper's stated definition), built
to exercise the U8b severity-token contract end to end:
- **P-27 (arm a)** — `income_pc` is consumed downstream by `py/make_tab2.py`, which writes
  the reported Table 2 means, so the reported quantity is wrong. Must end `confirmed`
  within the 2–3 severity band, carrying exactly one receipted `output:` token resolving
  to the Table 2 output row whenever it closes severe (severity 3)
  (`severity_token_plants` in the answer key; scored by
  `check_severity_token_plants`).
- **P-28 (arm b)** — `wage_pc` shares the mechanism but is never read again (not saved,
  not aggregated). The final severity must stay at or below 2 **regardless of status**.
- **P-29 (arm c)** — `crop_pc` is consumed two lines later by a village `groupby` mean
  that is only printed; its descendants never reach any output (the E-0304
  local-consumption shape). Severity band <= 2, again regardless of status.

`expected_findings.json` is the answer key. It lives here, **outside the audited scope**:
when running the audit, hand the skill `fixture/planted/` as the repo root so no worker can
see this folder's other files.
The outer harness records that the fixture is synthetic; the package shown to blind reviewers
does not make that claim, so the privacy check is judged from the public package as presented.

## Running the validation

1. Copy `planted/` to a scratch location (the audit writes an `audit/` folder into it).
2. Invoke `research-codebase-audit` on that copy: mode = full replication audit,
   **review-ladder level 2** (static inspection plus parser/runtime checks, unit tests
   with simulated data, and small targeted reruns where a check needs them, each bounded
   by a 15-minute per-check compute budget), review depth `standard`, nothing off-limits.
   Every scored run of record has used this configuration; hold it fixed across runs so the
   run-to-run comparison in the Evaluation protocol below stays valid — a run at a different
   ladder level is not comparable to the recorded ones.
3. When the run finishes, score `audit/code_review.xlsx` (or the registers) against
   `expected_findings.json`:
   - **Recall**: all 28 `must_find` mechanisms present as issue-flagged or confirmed rows
     (any register; matching is by mechanism, not wording), severities at or above
     `min_severity` (see `expected_findings.json` `scoring` for the P-14/P-20 dual-accept
     rule).
   - **Precision**: nothing about the placebo figure / `fig_placebo.pdf`, nothing about the
     farm-components subset, and no issue row for the intentional baseline diagnostic
     (`must_not_find`); the `expected_confirmed_examples` come out clean rather than flagged.

### Automated scoring

`scripts/score_fixture.py` automates the recall/precision core of the scorecard
(mechanism-signature matching, the P-14/P-20 dual-accept branch logic, the decoy
greps, an SC-01 unresolved-conflict check, a per-failure-class breakdown
alongside the aggregate recall — P-15..P-20 report under their `failure_class`
tags, and the pre-taxonomy plants P-01..P-14 roll up in an explicit
`unclassified_legacy` bucket so the aggregate always equals the per-class
sum — and the
artifact-layer checks: the U2 parser artifact must name `pyproject.toml`; the U4
and U5 advisory lints must have fired if the corresponding plant closed in the
failure state; the U1 conventions-artifact check is informative only, never
gate-settling; and the definition/use channel check traces P-21 and D-03 from
the detector artifact through b4 mapping/inventory, recheck ledger, and final
register outcome). Point it at the finished run's
final registers:

```
python scripts/score_fixture.py --audit-dir /path/to/pkg/audit
```

Exit 0 = GATE GREEN, 1 = GATE RED. Type adjudication and the
`expected_confirmed_examples` cleanliness checks remain hand-scored; record the
scorer output in the dated scorecard either way. Dated scorecards
(`score-<date>-*.md`, `measurement-*.md`, `last_run_score.md`) are development
records kept locally under `docs/rca-scorecards/`; they are not committed to
this fixture directory.

## Test harness

The scripts' committed pytest suite (linter contract tests, scorer self-tests,
export and comment-blanking smoke tests, and a plant-drift hash check that
catches an accidental "fix" to a planted bug) runs green with one command from
the skill folder:

```
uv run --no-project --with pytest --with openpyxl -- pytest scripts/tests/
```

(or `python -m pytest scripts/tests/` if pytest and openpyxl are installed).
Builders for synthetic registers, plans, and audit directories live in
`scripts/tests/regbuild.py` — new lint checks should land with failing-first
negative tests there. If you edit anything under `planted/`, regenerate
`scripts/tests/data/planted_sha256.json` (see `scripts/tests/test_plant_drift.py`).

## When to re-score

Re-run this fixture after **any** edit to a prompt skeleton, pipeline file, `registers.md`,
or lint script. The fixture is the cheap regression; the full quality gate remains the
Floods re-run (baseline to match: 20/22 code errors, 6/18 claims confirmed — see the design
doc).

The data are fabricated; the PII-looking columns (names, GPS) are invented and planted
deliberately as finding P-10.

## Evaluation protocol — how a scored run is interpreted

This section is human interpretation guidance. It is a measurement and interpretation
protocol, not a code check: nothing below is enforced by the scorer or the linter, and it
exists so that the run-to-run randomness of an LLM pipeline is not mistaken for progress
or regression. Three scored runs of the Floods gate have shown four item-level flips, so a
single run is one draw from a noisy process and must be read as one.

**Interpretation rules for the next scored Floods run:**

1. **The four permanent misses are the primary endpoint.** Four defects have been missed
   in all three scored runs (they are described in the run-3 scorecard and the 2026-07-07
   plan; they are not restated here). Whether the next run recovers any of them is the
   primary measure of the cycle. Movement on other items is secondary and is read under
   rules 2 and 3.
2. **A previously-flipping item counts as fixed only when it hits in two consecutive
   runs.** An item that was found in one run and missed in another has already
   demonstrated that a single hit can be luck. One hit after a change is evidence, not a
   fix; the "fixed" label waits for the second consecutive hit.
3. **Deterministic-mechanism recoveries carry the most weight only after the mechanism has
   reproduced its hit across two consecutive scored runs.** The design leans on mechanisms
   that search mechanically rather than depend on a worker noticing, and their recoveries
   are the strongest evidence the approach works — but the determinism claim is itself a
   hypothesis resting on a single observed run. The chain from consolidation through
   grep-term choice to recheck disposition has model-dependent links, so the heavier
   weighting is earned by observed reproduction, not granted by construction.

**Pre-merge fixture-re-score gate rules** (recorded from the build process, so the gate is
pre-registered rather than improvised at merge time):

- An outcome produced by a committed script or lint — the U2 parser artifact naming the
  malformed manifest, the U4/U5 advisory warnings in the lint output — is settled by a
  **single re-score**, because that layer is deterministic given the plant.
- An outcome that depends on worker behavior — a candidate surviving recheck disposition,
  a claim closing flagged rather than confirmed, a procedure extracted as multiple rows,
  any conventions-grep emission, any recovery from a reading-based change — needs **two
  consecutive re-scores**.
- **Exactly two re-scores** are run for the worker-dependent gate. Both must pass for
  merge. Any failure requires a diagnosed change before further re-scoring. A pass-then-fail
  split fails the gate — with one recorded exit: if the split's
  recorded diagnosis attributes the flip to run variance (the mechanism artifact is intact
  and no code or prompt defect is found), the rest of the batch may merge, the split unit
  merges without a "fixed" claim, and its stability is adjudicated at the next scored run
  under rule 2 above. Single-run-settled outcomes are never blocked by a reading-unit split.
- **No harvesting:** running additional re-scores to collect two consecutive passes is
  prohibited.
- **Every re-score outcome is recorded in the gate scorecard**, with the artifact-layer
  (single-re-score) results recorded separately from the register-based two-run results.
