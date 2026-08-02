# Pipeline — finalize (cross-link, rewrite, export)

Runs after both streams (or the only stream) reach `done`/`blocked` at b6b.

## Mode skip rules

| Mode | b7 cross-link | severity-token rulings | b8 rewrite | b9 export |
| --- | --- | --- | --- | --- |
| Full replication | yes | yes | both registers | Overview + Paper Claims + Code Errors + both late-observation sheets |
| Code-errors-only | **skip** (no claims register) | **skip by stage-tuple omission** | code register only | Overview + Code Errors + both late-observation sheets |

A stream that ended with blocked stages still finalizes: blocked rows carry their status into
the export; blocked *stages* are listed in the final report, and cross-link runs on whatever
canon exists.

## claims_adjudication_lineage — final carrier equivalence

Run once after bC (if no correction was approved, after both b6b streams) and
before b7. Start the stage, then freeze canonical `claims_register.md` and
`audit/_run/handoff_ledger.json` under
`audit/_run/snapshots/claims_adjudication_lineage/`. Run
`claims_adjudication.py <package-root>
--audit-dir audit --stage claims_adjudication_lineage --build-worklist`. The
builder follows only terminal `duplicate_of:` redirects and tombstone statuses.
Byte-identical unbranched carriers need no worker verdict; every changed,
absent, split-shaped, or dead carrier becomes an item.

For non-empty work dispatch one fresh-context worker with
`prompts/claims-adjudicator.md` (role: `claims_adjudication_lineage`) to write
`audit/_run/claims_adjudication_lineage_verdicts.md`, run the script with
`--apply`, and finish `done`. Empty work certifies from the exact zero artifact.
Retry once; on a second failure finish `blocked`, degrading every pending item
to `blocked_fallback`. `equivalence_refused` remains recorded and forces
close-run refusal.

## b7 — Cross-link (full replication only)

1. Snapshot both link-bearing registers to `audit/_run/snapshots/b7/`.
2. Dispatch one subagent with `prompts/cross-linker.md` (role: `b7_cross_linker`), with
   `{CONTRACT_PATH}` set to
   `audit/_run/contracts/cross_link.md`. It edits **only** `Related Error IDs` (claims) and
   `Related Claim IDs` (code errors) in staging copies, and writes
   `audit/register_cross_link_summary.md` — including a `## Status conflicts` section for
   every link pairing a `confirmed` claim with a `confirmed` code error, a
   `## Escalated mapped claims` section for every link pairing a `confirmed` code error with a
   `mapped` claim it contradicts, and a `## Severity divergences` section for every link whose
   two rows carry filled, differing severities. It also writes `## Severity-token adjudications`
   with one exact `upheld`/`rejected` row per token-bearing severe Error ID, or exact `none`.
   Claim tokens use the ordinary reciprocal claim↔error columns. Before dispatch, compute the
   confirmed-claim↔confirmed-error code-location overlaps and pass the pair list in the
   dispatch as the floor of the worker's step-2 overlap enumeration; the worker adjudicates
   every overlap candidate individually, and no sibling's judgment call clears another row
   citing the same lines. Obtain the list by running `lint_registers.py --stage b7` right
   after the step-1 snapshot and reading its `overlap-conflict` WARNING lines — at that
   point the cross-link summary does not exist yet, so the stage prints the warnings and
   then FAILS on the missing summary; that pre-dispatch failure is expected, and only the
   WARNING lines are consumed. The floor is ranged-only (a bare-file citation never appears
   in it); whole-file overlap coverage is the worker's own addition per its step-2 rule.
3. `lint_registers.py --stage b7`: non-link columns byte-identical to snapshot; every link
   resolves both ways (C-x lists E-y ⟺ E-y lists C-x); summary exists; every
   confirmed-claim↔confirmed-error link is listed under `## Status conflicts`; every
   mapped-claim↔confirmed-error contradiction is listed under `## Escalated mapped claims`;
   every divergent-severity link is listed under `## Severity divergences`; and the severity
   token table exactly covers the severe token set. A recomputed-non-live citation must be
   rejected. Atomic rename.
4. **Conditional claims recheck.** Inspect the union of `## Status conflicts`,
   `## Severity divergences`, and `## Escalated mapped claims`. If it is non-empty, dispatch the
   existing `recheck-cluster-worker.md` exactly once (role: `b7_claim_recheck`) over exactly the
   claims rows named anywhere in that union, with `{CONTRACT_PATH}` set to
   `audit/_run/contracts/recheck_claims.md` and the linked error rows named as evidence. The one
   shard covers the resolution duties in steps 4–6; do not dispatch separate workers per section.
   For status conflicts, apply the standard verdict→register mapping (registers.md) to the
   claims register mechanically. Whenever the recheck chooses between `inconsistent` and
   `confirmation_needed`, apply the visibility test in `references/registers.md`. If a verdict
   leaves the claim `confirmed` (the error does
   not actually contradict it), the link itself was wrong: remove it from both rows and note
   the removal in the summary. No confirmed-claim↔confirmed-error link may survive into b8
   (lint b8 enforces).
5. **Escalated-mapped-claim second look** (only when the summary lists escalated mapped
   claims): the step-4 recheck revisits each `mapped` claim with the
   linked error named as evidence and returns a verdict; the conductor applies the
   verdict→register mapping mechanically. The outcome is open — the claim may become
   `inconsistent` (the error settles it) or legitimately stay `mapped` (the error does not
   settle it); an escalation to `inconsistent` must pass the visibility test (step 4).
   Unlike a status conflict, a `mapped`-and-linked pair may survive to b8: b8
   requires only that the second look happened (a recheck ledger entry for the claim), not a
   particular status. Record the second look in the summary line.
6. **Severity-divergence resolution** (only when the summary lists divergences): the step-4
   recheck revisits each listed pair and returns a verdict; the
   conductor then either aligns the two severities (verdict→register mapping, mechanically
   applied) or appends a one-line justification for the gap — taken from the ledger's
   `Proposed Note` — to the pair's line in the summary. The recheck worker writes only its
   shard, never the summary. Where the verdict also moves a status, the
   `inconsistent`/`confirmation_needed` choice follows the visibility test (step 4).
   Legitimate gaps exist (a claim row may assert something
   narrower than the error breaks) but are never left silent. Pairs still divergent at b8
   must remain listed in the section (lint b8 enforces listing; the justification is a
   prose obligation on the conductor).
7. Whenever step 4, 5, or 6 changed any register row, refresh the b7 snapshot and re-run
   the b7 lint before moving on (otherwise post-run `--stage b7` replay fails on the
   changed rows).
8. After promotion, certify with `certify_stage.py finish --stage b7 --outcome done`.

## severity_token_rulings — rejected-token decisions (full replication only)

Start this stage immediately after certified b7. The certifier freezes the certified b7
rejected-token worklist and code register and derives `b7_certification_sha256`. The trusted
operator reads
`audit/_run/snapshots/severity_token_rulings/b7_rejected_worklist.json` and must copy its `b7_certification_sha256`
exactly into `audit/_run/severity_token_rulings.json`, then writes the
remaining authority fields in the exact schema and closed uphold/cap/hold matrix from
`registers.md`; do not recompute the digest by hand, and no worker or conductor invents a
default decision. With no rejected tokens, write the exact `zero_rejected_severity_tokens`
skip form.

Finish the stage. The certifier snapshots the authority artifact, atomically applies only
Status/Severity, and reruns `lint_registers.py --stage severity_token_rulings`. Missing coverage
or a doctored/non-live uphold produces zero promotion. Do not start b8 until this stage is
`done`; close-run independently enforces the same fail-closed tail.

## b8 — Author-facing rewrite

1. Snapshot to `audit/_run/snapshots/b8/`.
2. Dispatch one subagent with `prompts/rewriter.md` (role: `b8_rewriter`; register paths per mode), with
   `{CONTRACT_PATH}` set to `audit/_run/contracts/rewrite.md`. This is the dedicated clarity
   pass: it renames technical fields to `*_Original` and writes author-facing
   versions, armed with the five contrastive gold examples and the jargon ban carried verbatim
   in the skeleton.
3. `lint_registers.py --stage b8`: first refuses unless the activated full-mode rulings stage
   is `done`; then counts/IDs/statuses/paths byte-identical; `*_Original`
   columns preserve prior text; blankness pairing both directions; no `Notes` columns; any
   linked pair with differing severities listed under `## Severity divergences`.
4. **Promote by copy, not move**: copy the staging registers over canon — each register
   written via temp file + atomic rename on the canon side, so a crash mid-promotion cannot
   leave canon half-updated — and leave the copies in `_staging/` untouched as
   the frozen b8 boundary state, so `lint_registers.py --stage b8` stays replayable after
   the run. Add one line to `audit_readme.md`: `_staging/` holds the frozen b8 registers,
   superseded by the root registers.
5. Certify with `certify_stage.py finish --stage b8 --outcome done`; its b8 validator reads the
   deliberately frozen `_staging/` boundary.

## b9 — Export (script only — never an LLM)

1. Run `scripts/certify_stage.py verify-run --package-root <package-root>`. A failure blocks
   export; demote and rerun stale stages before trying b9 again.
2. Run `scripts/export_xlsx.py --audit-dir audit/ --manifest audit/_run/manifest.json
   --mode <mode>` → `audit/code_review.xlsx`.
   - Sheets per the mode table above; `Overview` carries the sheet guide, status legends,
     variable legends, and a **Degraded-confidence warnings** section from the manifest
     `warnings` (CODEMAP preconditions score).
   - Author-facing columns in; every `*_Original` column out; `Potential Issue` computed on
     the Paper Claims sheet only.
   - Full-replication paper runs include `Handoff ledger`, an exact publication
     of every H/X entry's terminal state, carrier, and disposition.
   - `audit/_run/late_observation_coverage.md` and the two workbook sheets derive from the b6b
     artifacts and manifest. `Artifact Head` / `Blocker Evidence IDs` are the explicit-absence
     values `not recorded` / `none recorded`; a blocked b6b reports degraded coverage.
3. `lint_registers.py --stage b9`: workbook opens; per-sheet row counts and ID sets match the
   registers; excluded/required columns verified.
4. Certify with `certify_stage.py finish --stage b9 --outcome done`.

## After b9

Return to SKILL.md for the single `close-run` instruction, then Phase 4 (report + targeted manual
QA follow-up). `close-run` is the completion-report gate: with late observations recorded, it
refuses until the first Phase-4 disposition batch replaces every `pending` state (b9 itself
exports pending rows on the unverified sheet without refusing). In a full-replication U7 run it
re-derives both worklists and verdict joins and refuses if either adjudication
stage is pending or absent, an H/X state is not final-passable, a disposition
is raw, lineage equivalence was refused, or a `blocked_fallback` lacks an exact
operator decision in `audit/_run/handoff_blocked_decisions.json`. On a blocked
stage every worklist item lacking a valid verdict must itself be
`blocked_fallback`. It also refuses an activated full-mode run unless
`severity_token_rulings` is `done` with exact frozen-worklist coverage.

## Operator-approved bC correction cycle

Enter `bC` only after explicit operator approval of one or more Phase-4 late observations.
Write `audit/plans/late_observation_corrections.md` using the exact plan serialization in
`registers.md`, snapshot the applicable canonical registers **and each present
`late_observations_<stream>.md` artifact** under `audit/_run/snapshots/bC/`, and apply the
declared rows/patches and disposition transitions to staging. Run the production token verifier
before promotion as
`scripts/verify_dismissals.py <package-root> --audit-dir audit --tokens --token-stage bC`; the
typed token record for every severe code mint is appended to this plan and receipts live at
`audit/_run/bC/token_receipts.md`. Then atomically promote, run
`lint_registers.py --stage bC`, and certify `bC`.
The lint compares canonical registers against
the snapshot and plan, requires late-observation evidence bytes to remain unchanged, and checks
each old → new disposition against the monotone matrix; it accepts no row-carried LO provenance
and no undeclared cell edit.

Every bC severity-3/4 code mint must already carry exactly one receipted, live token; cap it to
Severity 1–2 otherwise, and refuse a non-live citation. In full-replication mode, no claims
lineage-rulings rerun is required: bC patches only reciprocal link cells on existing rows and
mints new rows no claims ledger entry cites. Rerun b7 in replay-plus-extension mode for new-row
links and require every bC token to be upheld. Cap/hold keys from the frozen main-cycle worklist
may disappear; any new rejected key is a hard failure. Never rerun `severity_token_rulings`.
Then rerun
b8 **scoped to the new rows only** and rerun b9. In code-errors-only mode b7 remains skipped;
rerun b8 scoped to the new rows only, then b9. A correction that adds an output includes its
companion claims edit in the same BC-ID group. Never create another supplementary wave.
