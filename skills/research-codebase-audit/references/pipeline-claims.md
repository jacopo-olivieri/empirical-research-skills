# Pipeline — claims stream (paper vs. code)

Conductor instructions for stages b1–b6 of the claims stream. Skeletons live in
`references/prompts/`; schemas and vocabulary in `references/registers.md` (workers see their
generated role contract). Lint stages here are `--stage b<N>-claims`.

## b1 — Plan

1. Dispatch one planner subagent with `prompts/planner-claims.md` filled (role:
   `claims_b1_planner`); set
   `{CONTRACT_PATH}` to `audit/_run/contracts/planning.md`.
2. Planner writes `audit/plans/claims_review_plan.md` with the exact allocation columns from
   `registers.md`, including `Paper File`, `Line Intervals`, and `H ID Range`. Intervals exactly
   partition every line in `paper_source_set`; reserve one globally disjoint 50-ID
   `Adjudication range: C-…–C-…` below the table. If `allocation_override` is present, copy its
   ordered allocation verbatim instead of free-planning; the ordinary b1 lint still applies.
3. Run `lint_registers.py --stage b1-claims`. After it passes and before any b2 dispatch, run
   `build_crossref_inventory.py <package-root> --audit-dir audit`. This writes the digest-bound
   inventory and assignment artifacts. Certifying claims_b1 re-derives and byte-compares both.

**Sizing rules (the planner skeleton carries these verbatim; you verify the plan obeys them):**

- Paper scope per worker: one coherent section or ≤ ~10 paper pages; split longer sections.
- Expected claims per worker: 15–35. If a scope would exceed that, split it.
- ID ranges are generous: per worker, `max(50, 3 × expected claims)` claim IDs and
  `max(30, 3 × expected outputs)` output IDs, globally disjoint. Reserve a 50-ID
  merge-coordinator range per register on top.
- Support passes are **dropped in v1**: worker contradictions are preserved as
  `unclear`/`inconsistent` at merge and flow mechanically into the recheck inventory.

## b2 — Section workers (parallel, fire-and-forget)

1. For each row, fill `prompts/section-worker.md` with its assigned X IDs from
   `crossref_assignments.json` and the inventory path (role:
   `claims_b2_section`; one subagent per
   worker, single message, `worker_model` from the manifest); set `{CONTRACT_PATH}` to
   `audit/_run/contracts/claims_first_pass.md`.
2. A worker is complete when its shard exists at the planned path **and** passes
   `lint_registers.py --stage b2-claims --shard <path>`; then record it with
   `certify_stage.py set-shard --stage claims_b2 --shard <path> --status done`.
3. On lint failure: re-dispatch that worker once with the lint report appended. Second failure:
   run `certify_stage.py set-shard --stage claims_b2 --shard <path> --status blocked --reason
   "<lint failure>"`, then continue.

Every claims shard carries the dedicated `### Handoffs` and `### Cross-reference coverage`
tables (or their exact zero forms) in addition to the frozen typed footer.

## b3 — First merge (adds rows)

1. Snapshot `claims_register.md` + `output_register.md` to `audit/_run/snapshots/claims_b3/`.
2. Dispatch one coordinator with `prompts/merge-first-pass.md` filled for the claims stream
   (role: `claims_b3_merge`); set
   `{CONTRACT_PATH}` to `audit/_run/contracts/merge_first_pass.md`.
   It writes **staging** registers (`audit/_staging/claims_register.md`,
   `audit/_staging/output_register.md`) and `audit/_run/merge_report_claims.json`
   (per register: `shard_rows`, `dedup_removed`, `added`, `conflicts`, `coverage_gaps`,
   `blocked_shards`).
3. Atomically rename staging over canon, then run `build_handoff_ledger.py <package-root>
   --audit-dir audit --stage claims_b3`. It freezes the b3 ledger snapshot and adds the
   `handoff_ledger` reconciliation block to the merge report. Then run
   `lint_registers.py --stage b3-claims`
   (checks the promoted registers + report: no dup IDs, IDs ⊆ union of planned ranges, links
   C↔O bidirectional, cross-link columns blank, row-count reconciliation, typed-footer
   dispositions reconciled — the same lint the `claims_b3` certification obligation re-runs).
   On failure, restore canon from `audit/_run/snapshots/claims_b3/` and re-merge.

## b3c — Shared-conventions consolidation (adds no rows; emits a cross-stream artifact)

Operationalizes standing self-consistency check 2 ("Shared and definition/use conventions agree", `registers.md`):
the merged claims register now records, across many rows, the conventions the package uses in
more than one place; this step collects them into one small list for the b3d conventions-scan
worker in `pipeline-code-errors.md`. Runs after the
first merge (b3), before the recheck plan (b4). Non-blocking: a package with no qualifying
convention produces a header-only artifact and nothing downstream fails.

1. Dispatch one worker with `prompts/consolidate-conventions.md` filled (claims stream; role:
   `claims_b3c_conventions`); set
   `{CONTRACT_PATH}` to `audit/_run/contracts/conventions.md`. It reads the canonical
   `claims_register.md` and writes `audit/_run/conventions.md` — a small Markdown
   table, one row per stated convention the paper uses in more than one place, drawn **only** from
   the categories standing check 2 enumerates (fiscal-year or sample-window boundary, date-parse
   mask, missing-value sentinel, unit/scale factor, path separator, ID/merge key, enumerated
   member list), with columns
   `| Convention | Category | Stated Definition | Sites Already Seen |`. `Stated Definition` is
   what the paper states (with the C-ID it came from; for an `enumerated_member_list` it quotes
   the full member set verbatim); `Sites Already Seen` lists the files/rows
   already logged for it. A convention stated in only one place is **not** listed — except an
   `enumerated_member_list`, where a single register row naming the member set qualifies: the
   second side of the comparison is supplied by the code-side re-materialization sites the b3d
   conventions-scan worker locates, not by a second register row.
2. If no convention qualifies — none is used in more than one place and no single register row
   names an enumerated member list — the worker writes the table header with no rows. The file is
   always present and non-empty; the step never blocks and adds no register rows.
3. This step mutates no canonical register, so there is no snapshot/staging/rename. It is a
   read-only emit; the artifact is required input to the code-stream b3d conventions scan. Certify with
   `certify_stage.py finish --stage claims_b3c --outcome done`.

## b3b — Second-read recall sweep (conductor-planned, adds candidates)

A recall pass, not a recheck: re-read every file/section the first pass already flagged, to
surface the inconsistencies it missed. See `references/review-principles.md` for why. Runs after
b3, before the recheck plan (b4), so the new rows flow into the recheck automatically.

1. **Trigger set (per `review_depth`, from the SKILL.md depth-knob table).** Start
   `claims_b3b` as required by SKILL.md, then mechanically compute the set of files/sections that
   produced at least one issue-flagged (`inconsistent`) claim — at
   `shallow` only those with a Severity ≥ 3 issue, at `standard`/`deep` any issue-flagged claim.
   Add every destination scope named by a `forwarded` H ledger entry; a handoff-only scope uses
   Reason `handoff`. Key ordinary triggers to the claim row's `Code/Data Source` file(s) and
   `Paper Context` section. If the combined set is empty, do not dispatch workers; instead
   freeze the zero-work evidence the b3b
   certification obligation verifies — write the plan with a header-only allocation table,
   snapshot both registers to `audit/_run/snapshots/claims_b3b/`, and write a zero-work
   `audit/_run/merge_report_claims_b3b.json` (both register entries
   `{"shard_rows": 0, "dedup_removed": 0, "added": 0}` plus `"footer_dispositions": []`,
   `"phase_partition": {"found_by_reading": [], "found_by_probe": []}` and
   `"block_coverage": {"blocks_covered": 0, "blocks_clean": 0}`), run
   `build_handoff_ledger.py <package-root> --audit-dir audit --stage claims_b3b`, then
   certify `claims_b3b` done via
   `certify_stage.py finish --stage claims_b3b --outcome done` against the canonical registers
   already promoted by b3.
2. **Allocation.** Write `audit/plans/claims_second_read_plan.md` yourself: one second-read worker
   per flagged file/section, columns `| Worker ID | File/Section Scope | Shard File | Claim ID
   Range | Output ID Range | Reason | Known Findings | Assigned Handoff IDs |` (use the header
   `Shard File` exactly — the b3b lint requires it — and put each shard path, under
   `audit/_work_second_read/`, in the cell). Reason is `flagged` for ordinary recall;
   `handoff` is used for a scope selected only by forwarded work. Every `File/Section Scope`
   cell also carries a machine-readable **span declaration** beside its prose: one or more
   `;`-separated tokens `` `<paper source path>:<start>–<end>` `` (repo-relative, 1-based
   inclusive lines) naming exactly the lines the worker must cover, with any off-limits span
   written `blocked: <path>:<start>–<end> — <reason>`. One cell may declare several spans of
   the same file; each is anchored independently, so none can hide behind a covered sibling.
   A path may not be declared both readable and blocked. The b3b lint anchors the worker's
   block-coverage table to these spans endpoint to endpoint, and a cell with no parseable
   span token fails the lint, so declare the span even when the prose already names the
   section. `Assigned Handoff IDs` is
   `—` or a comma-separated allocation and exactly covers every `forwarded` H-ID once across
   the plan. Ranges
   are fresh and globally disjoint from every b1 range and both merge-coordinator ranges. `Known
   Findings` lists the C-IDs and one-line mechanism already logged there.
3. **Dispatch** `prompts/second-read-worker.md` (stream = claims; role:
   `claims_b3b_second_read`), one subagent per row,
   with `{CONTRACT_PATH}` set to `audit/_run/contracts/second_read_claims.md`,
   fire-and-forget. At `deep` depth dispatch a second pass with a different `{MANDATE_LENS}` and
   its own disjoint ranges. A worker is complete when its shard exists at the planned path **and**
   passes `lint_registers.py --stage b3b-claims --shard <path>`; retry-once → blocked-continue.
4. **Merge.** Snapshot `claims_register.md` + `output_register.md` to
   `audit/_run/snapshots/claims_b3b/`; dispatch `prompts/merge-first-pass.md` filled for the
   claims b3b merge (role: `claims_b3b_merge`) and for the
   claims stream with `{CONTRACT_PATH}` set to `audit/_run/contracts/merge_first_pass.md`,
   `{SHARD_DIR}` = `audit/_work_second_read/`, `{PLAN_PATH}` = the b3b allocation plan, and
   `{MERGE_REPORT}` = `audit/_run/merge_report_claims_b3b.json`. The merge
   **adds** the new rows to the existing canon, preserving every b3 row unchanged. Each
   resolver shard writes the exact handoff-resolution table from `registers.md`; a cited
   resolution row may use the full first-pass claims status vocabulary.
5. Atomic rename over canon, then run `build_handoff_ledger.py <package-root> --audit-dir audit
   --stage claims_b3b`, which freezes the b3b-era ledger and updates the merge report. Run
   `lint_registers.py --stage b3b-claims` (new claim rows in
   b3b ranges and `inconsistent` or `unclear`; new output rows not `listed`/`confirmed`; no b3
   row deleted or mutated; C↔O links bidirectional; report identity holds — the same lint the
   certification obligation re-runs). On failure, restore canon from
   `audit/_run/snapshots/claims_b3b/` and re-merge; on pass certify with
   `certify_stage.py finish --stage claims_b3b --outcome done`.

The recheck inventory (b4) then picks up every new issue-flagged and `unclear` row.

## claims_adjudication — H/X capture verdicts

Run after `claims_b3b` and before `claims_b4`.

1. Start the stage. Copy canonical claims and outputs to
   `audit/_run/snapshots/claims_adjudication/`, and copy the b3b-era ledger to
   that directory before any mint.
2. Run `claims_adjudication.py <package-root> --audit-dir audit --stage
   claims_adjudication --build-worklist`. For an empty list, dispatch no worker;
   the builder writes the exact zero-verdict artifact.
3. Otherwise dispatch one fresh-context worker with
   `prompts/claims-adjudicator.md` (role: `claims_adjudication`). It writes only
   `audit/_run/claims_adjudication_verdicts.md`. Retry one failed application
   once.
4. Run the script with `--apply`. It validates exact verdict completeness,
   vocabulary, mint range, claim schema, and containment; then atomically
   projects the claims and ledger. Finish `done`.
5. After a second failure finish `blocked` with the reason. The blocker path
   re-derives the worklist and degrades every item lacking a valid verdict to
   `blocked_fallback`.

## b4 — Recheck plan (conductor-computed, no LLM)

Build the recheck inventory **mechanically** from the canonical claims register (claims rows
only — output rows are never rechecked directly; they change only through the claims recheck
merge):

- every issue-flagged claim row (Severity non-empty — this subsumes all `inconsistent` rows
  and all severities), plus
- every `unclear` row, plus
- a deterministic sample of `confirmed` rows, stratified by Claim Type, using the claims stream
  parameters in the deterministic recheck sampling rule (`references/registers.md`).

Also include every C-ID minted by `claims_adjudication`, unconditionally, with
the exact Reason `adjudicated_handoff`.

Cluster per `review_depth` (manifest). At `shallow`/`standard`: group the inventory by Claim
Type into clusters of ≤ 8 IDs. At `deep`: every **substantive ID** gets its own single-ID
cluster — a substantive ID is any inventory claim row that is issue-flagged (Severity
non-empty) or `unclear`; the sampled clean `confirmed` rows are not substantive and may still
be grouped by Claim Type into clusters of ≤ 8 IDs. Assign each cluster a shard file
under `audit/_recheck/`. Write `audit/plans/claims_recheck_plan.md` yourself with:
an inventory table `| ID | Reason | Likely Evidence |`; a cluster table
`| Cluster ID | Cluster Name | Assigned IDs | Shard File |`; and a pointer to the
verdict/evidence vocabulary in the recheck claims contract. There is exactly **one** recheck pass — no
looping. Run `lint_registers.py --stage b4-claims`.

## b5 — Recheck cluster workers (parallel)

Fill `prompts/recheck-cluster-worker.md` per cluster (stream = claims; role:
`claims_b5_recheck_cluster`), with
`{CONTRACT_PATH}` set to `audit/_run/contracts/recheck_claims.md`. Completion, lint (`--stage
b5-claims --shard <path>`), and retry follow b2. Record a passing shard with
`certify_stage.py set-shard --stage claims_b5 --shard <path> --status done`, or a twice-failing
shard with `--status blocked --reason "<lint failure>"`. Workers judge assigned IDs only and
mint no IDs.

## b6a — Phase-one merge and supplementary plan

1. Snapshot both registers to `audit/_run/snapshots/claims_b6a/`.
2. Dispatch one coordinator with `prompts/merge-recheck.md` (stream = claims; role:
   `claims_b6_merge`). It writes staging registers and `audit/claims_recheck_summary.md`.
   The summary carries exact `Splits declared: <n>`, `Merges declared: <n>`, and
   `Discoveries declared: C=<n>; O=<n>; E=0` lines, the main b5 footer dispositions, and the
   output-discovery disposition table specified in `registers.md`.
3. The coordinator also writes `audit/plans/claims_supplementary_recheck_plan.md` using the
   supplementary naming/range contract in `registers.md`. Its inventory is exactly every new
   C-ID and split descendant minted at b6a; output rows never enter the inventory. An empty
   inventory uses the exact zero-work form there.
4. Atomically promote, then run `lint_registers.py --stage b6a-claims` and certify
   `claims_b6a`. The certification lint reads canon plus the frozen snapshot, never staging.

## b5s — One supplementary recheck wave

Start `claims_b5s`. For a non-empty plan, dispatch `prompts/recheck-cluster-worker.md` once per
cluster (role: `claims_b5_recheck_cluster`), filling the supplementary plan and shard paths.
Use the same validator and ledger contract as b5: `lint_registers.py --stage b5s-claims
--shard <path>`, then `set-shard --stage claims_b5s`. A worker never mints register rows;
fresh defect observations use the typed footer's recheck-context `candidate` form. For an empty
inventory, dispatch no worker and run the unsharded `b5s-claims` lint. In both cases `finish
--stage claims_b5s --outcome done` certifies from the plan artifact; there is no dummy shard.

## b6b — Final supplementary merge and late observations

1. Snapshot both registers to `audit/_run/snapshots/claims_b6b/`.
2. Dispatch the existing merge coordinator (role: `claims_b6_merge`) over the supplementary
   plan/shards. It may mutate assigned rows but mint no rows. It writes
   `audit/claims_supplementary_recheck_summary.md` and
   `audit/late_observations_claims.md` using the exact contracts in `registers.md`.
3. Atomically promote, then run `lint_registers.py --stage b6b-claims` and certify
   `claims_b6b`. The lint proves every supplementary inventory row has one ledger disposition,
   every footer entry becomes a late observation or explicit dismissal, and no row vanishes.

The stream is complete after exactly this one b6a→b5s→b6b cycle.
