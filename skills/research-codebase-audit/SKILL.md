---
name: research-codebase-audit
description: Audit a research replication package — paper-code consistency, source-code errors, and package hygiene — producing an author-facing Excel workbook of findings.
disable-model-invocation: true
---

# research-codebase-audit

Static-first audit of a research codebase/replication package. You are the **thin conductor**:
run an interactive intake, then drive a fully autonomous pipeline of clean-context subagents.
Registers are the interface between stages; bundled Python scripts gate every stage boundary;
the run ends at `audit/code_review.xlsx`.

Reference files (all paths relative to this skill's folder):

- `references/registers.md` — schemas, vocabulary, IDs, severity. Single source of truth.
- `references/pipeline-claims.md`, `references/pipeline-code-errors.md`,
  `references/pipeline-finalize.md` — stage-by-stage pipeline instructions and sizing rules.
- `references/prompts/` — fixed prompt skeletons with slot tables.
- `scripts/lint_registers.py`, `scripts/blank_tex_comments.py`, `scripts/export_xlsx.py`,
  `scripts/check_manifests.py`, `scripts/emit_definition_use_bundles.py`,
  `scripts/check_argument_contracts.py`,
  `scripts/emit_path_derivation_bundles.py` (all conductor-invoked at
  certified `b3d`; see `references/pipeline-code-errors.md`), `scripts/verify_dismissals.py`,
  `scripts/severity_tokens.py`, `scripts/severity_token_rulings.py`,
  `scripts/assemble_boundary.py`, and `scripts/certify_stage.py` (the only writer of stage status;
  its typed evidence table is `scripts/stage_obligations.json`).

Invariants you never break:

- **Workers get filled prompts, never skill files.** Inside the audited repo a worker reads only
  its plan, its role contract under `audit/_run/contracts/`, `audit/CODEMAP.md`, the paper, and
  the code, shipped artifacts, and data in scope. The conductor and deliberate full-readme
  pointers may still read `audit/audit_readme.md`.
- **Skeleton text is invariant** — you and the planner subagents fill the designated slots only.
- **Every canonical register mutation** goes write-to-staging (`audit/_staging/`) → lint →
  atomic rename (`mv`), with a pre-stage snapshot of the register under
  `audit/_run/snapshots/<stage-key>/`. Exception: the final b8 promotion copies instead of
  renaming and leaves `_staging/` in place as the frozen b8 state (see pipeline-finalize.md).
- **Lint gate**: after every stage, run `lint_registers.py --stage <lint-stage>` (lint stages
  are stream-qualified: `b0`, `b1-claims`…`b5-claims`, `b1-code`…`b5-code`, the second-read
  sweep `b3b-claims`/`b3b-code`, `b7`, `severity_token_rulings`, `b8`, `b9`;
  worker-shard checks add `--shard <path>` —
  `b2`, `b5`, `b5s`, and `b3b` are the shard-lintable stages; the supplementary boundaries are
  `b6a-<stream>`, `b5s-<stream>`, and `b6b-<stream>`, and the approved correction stage is `bC`;
  `b3b` lints a second-read shard with
  `--shard` and the second-read merge without it). On failure, re-dispatch the producing agent once
  with the lint report appended to its prompt. On second failure, record that shard/stage
  `blocked` with `certify_stage.py set-shard` or `finish --outcome blocked`, and continue
  everything that does not depend on it. **Merges
  proceed over the non-blocked shards** and document blocked ones in the merge report.
- **After intake the run is unsupervised** — no user questions until the export exists.

## Phase 1 — Intake (interactive)

Converge with the user on the points below, then write the manifest. Ask concisely; propose
defaults and let the user correct.

1. **Materials inventory.** Locate: repo root, paper source, README, master scripts, shipped
   artifacts (e.g. `artifacts/**/*.tex`), existing `audit/` folder (offer resume — see Resume).
   The paper must be machine-readable: LaTeX or Markdown. PDF-only: if `marker` is available,
   convert to Markdown and use the conversion as the paper source; **no `marker` → warn and
   stop** (offer to proceed once the user converts it).
2. **Mode** — branch table:

   | Mode | Pipeline |
   | --- | --- |
   | Full replication audit | claims stream ∥ code-error stream → cross-link → rewrite → export |
   | Code-errors-only | code-error stream → rewrite → export (skip claims, cross-link; see pipeline-finalize skip rules) |
   | WIP review | **Not supported in v1.** Say so, offer code-errors-only or stop. |

3. **Review ladder + off-limits list.** Level 1 = static inspection only (code, docs, existing
   artifacts, read-only data inspection). Level 2 = adds parser/runtime checks, unit tests with
   simulated data, targeted reruns, each under a per-check compute budget (default per
   `references/registers.md`: 15 min). Level 3 = unrestricted. Record the level, the budget,
   and an explicit off-limits list (scripts/data/commands the run must not touch).
4. **Review depth.** How much redundancy the run spends on thoroughness — propose `standard`
   (the default) and let the user pick `shallow` or `deep`, same style as the ladder/budget.
   The chosen depth sets two conductor knobs — the second-read trigger threshold and whether
   the recheck runs per-finding — per the depth-knob table below.
5. **Scope exclusions.** Propose exclusions from a quick look at the repo (archives, obviously
   exploratory folders); the user corrects. Propose by default: `audit/` itself, `.git/`, caches
   (`__pycache__`, `.ipynb_checkpoints`, `.Rproj.user`, and similar), package-manager directories
   (`node_modules`, `renv/library`, `.venv`, `packrat`), and archived or import-only mirror
   folders. Record the final exclusion list.
6. **Known context.** Anything the user already knows: fragile areas, known issues, restricted
   data, quirks (e.g. mirror folders that are import-only).
7. **Output preferences and worker model tier** (default: inherit the session model).
8. **Effort exceptions.** Offer the fixed default map: every dispatch role runs at `high`
   except `b8_rewriter`, which runs at `medium`. Ask only for exceptions: “name any role you
   want moved.” Legal tiers are `low`, `medium`, `high`, `xhigh`, and `max`. The resulting map is
   written once at intake and never edited; changing effort later requires a fresh run.

Write `audit/_run/manifest.json`:

```json
{
  "mode": "replication | code_errors_only",
  "ladder_level": 1,
  "compute_budget_minutes": 15,
  "review_depth": "shallow | standard | deep",
  "off_limits": [],
  "scope_exclusions": [],
  "known_context": "…",
  "output_prefs": "…",
  "worker_model": "inherit",
  "effort_map": {
    "codemap": "high",
    "claims_b1_planner": "high", "claims_b2_section": "high",
    "claims_b3_merge": "high", "claims_b3c_conventions": "high",
    "claims_b3b_second_read": "high", "claims_b3b_merge": "high",
    "claims_adjudication": "high", "claims_adjudication_lineage": "high",
    "claims_b5_recheck_cluster": "high", "claims_b6_merge": "high",
    "code_b1_planner": "high", "code_b2_chunk": "high", "code_b3_merge": "high",
    "b3d_conventions_scan": "high", "code_b3b_second_read": "high",
    "code_b3b_merge": "high", "code_b5_recheck_cluster": "high",
    "code_b6_merge": "high", "b7_cross_linker": "high",
    "b7_claim_recheck": "high", "b8_rewriter": "medium"
  },
  "review_mode_sentence": "…",
  "paper_source_path": "<root .tex or single paper source>",
  "allocation_override": {
    "purpose": "fixture | development — OPTIONAL block, fixture/development runs only: omit on production runs; presence makes the run not gate-eligible",
    "allocation": ["<exact b1 claims allocation objects>"]
  },
  "git_head": "… | null",
  "warnings": []
}
```

Write this intake manifest to a temp file in the same directory, then atomically rename it over
`manifest.json`; never edit it in place. Do not create `stages` or `run_identity` at intake:
`certify_stage.py init` owns and creates both while preserving every intake field above. After
initialization, every stage-status or shard-status change goes through `certify_stage.py`; never
edit those blocks by hand.

`init` derives the ordered stage keys from `mode`. They are stream-qualified: `b0`,
`claims_b1`…`claims_b5`, then `claims_b6a` → `claims_b5s` → `claims_b6b`; claims consolidation
`claims_b3c`; `code_b1`…`code_b5`, then `code_b6a` → `code_b5s` → `code_b6b`; detector
emission `code_b3d`, the
second-read sweep `claims_b3b`/`code_b3b` (between b3 and b4),
`claims_adjudication` after claims b3b, `claims_adjudication_lineage` after bC,
then `b7`, `severity_token_rulings`, `b8`, `b9` (the rulings key exists only in full mode;
finalize keys
exist only where the mode runs them), plus optional operator-approved `bC`. Worker shard outcomes are recorded only with
`certify_stage.py set-shard`; the stage itself is certified separately.

`review_mode_sentence` is the single source for the review-mode text every skeleton slot
receives — compose it once from mode + ladder + budget + off-limits.

**Depth-knob table.** `review_depth` (default `standard`) resolves to two conductor knobs the
downstream stages read. This table is authoritative for those knobs; it lives here — beside the
manifest schema — and NOT in `references/registers.md`, because these are conductor behaviours,
not register semantics pasted into worker contexts.

| Knob | `shallow` | `standard` (default) | `deep` |
| --- | --- | --- | --- |
| **Second-read trigger** (recall sweep after code b3d) | every detector-flagged file, plus serious first-pass findings (Severity ≥ 3); no clean sample | every detector-flagged or first-pass-flagged file, plus a deterministic stratified clean-file sample capped at 10 | every detector-flagged or first-pass-flagged file with a second independent pass/different lens, plus a deterministic stratified clean-file sample capped at 15 |
| **Recheck granularity** (b4–b6) | per-cluster | per-cluster | per-finding: one single-ID cluster per substantive ID (issue-flagged/`unclear` claim; `candidate` or Severity ≥ 3 code row); only sampled clean `confirmed` rows may still be grouped |

Depth never changes *which* techniques are permitted (that is the ladder) — only how much
redundancy is spent. The trigger is per-file, not per-finding, so a file with five findings is
re-read once (or twice at `deep`), not five times. Detector reason takes precedence over flagged,
which takes precedence over clean sample. A *first-pass finding* is a `candidate` row in
the code stream or an issue-flagged (`inconsistent`) claim in the claims stream — b3b runs before
the recheck, so no row is `confirmed` at that point.

Completion: manifest written and every field above resolved with the user.

## Phase 2 — Init (boundary B0)

0. Run `scripts/certify_stage.py init --package-root <package-root>`, then
   `scripts/certify_stage.py start --package-root <package-root> --stage b0`. This records the
   run identity, creates the mode's pending stage entries, and creates `audit/_run/RUNNING`.
1. Create `audit/` with empty registers per `references/registers.md`, plus
   `audit/_work/`, `audit/_code_errors/`, `audit/_recheck/`, `audit/_code_error_recheck/`,
   `audit/_recheck_supplementary/`, `audit/_code_error_recheck_supplementary/`,
   `audit/_staging/`, `audit/_run/snapshots/`, and `audit/plans/`.
2. Run `scripts/build_worker_contracts.py --audit-dir audit` to generate
   `audit/audit_readme.md` and the per-role contracts in `audit/_run/contracts/`. Workers read
   their role contract, never the skill's own references.
3. `init` resolves the root paper's complete `\input`/`\include` closure and writes one
   line-preserving, comment-blanked twin per source under `audit/_run/paper_twins/`. It records
   `paper_source_set` entries with `source_path`, `source_sha256`, `audit_path`, and
   `audit_sha256`; the three singular paper fields remain pinned to the root entry only for
   compatibility. Unsupported inclusion syntax fails intake with its source line.
4. Dispatch the **CODEMAP subagent** (`references/prompts/codemap.md`; role: `codemap`): produces
   `audit/CODEMAP.md` with `S-/D-/B-` ID tables, materials inventory, the mode-governed
   **Reported Artifact Token Inventory**, and a **preconditions
   score** (README present? unique output↔script mapping? documented data sources?). Low
   scores are recorded as degraded-confidence `warnings` in the manifest — they surface in the
   export; they never stop the run.
5. Run `lint_registers.py --stage b0`.

Completion: lint passes; certify with `scripts/certify_stage.py finish --stage b0 --outcome done`.

## Phase 3 — Conductor loop (autonomous)

Drive the stage DAG for the chosen mode. Stage-by-stage instructions, sizing rules, and which
skeleton each stage uses live in the pipeline files — read the relevant one before dispatching
each stream:

| Stage keys | Lint stages | Instructions |
| --- | --- | --- |
| `claims_b1`–`claims_b3` (plan → section workers → merge) | `b1-claims`–`b3-claims` | `references/pipeline-claims.md` |
| `claims_b3c` shared-conventions consolidation | — | `references/pipeline-claims.md` |
| `claims_b3b` (second-read recall sweep → merge) | `b3b-claims` | `references/pipeline-claims.md` |
| `claims_adjudication` H/X capture verdicts | `claims_adjudication.py --check` | `references/pipeline-claims.md` |
| `claims_b4`–`claims_b6b` (recheck → b6a merge → one b5s wave → b6b) | `b4-claims`, `b5-claims`, `b6a-claims`, `b5s-claims`, `b6b-claims` | `references/pipeline-claims.md` |
| `code_b1`–`code_b3` (plan → chunk workers incl. hygiene → merge) | `b1-code`–`b3-code` | `references/pipeline-code-errors.md` |
| `code_b3d` DU/MF/AC/PD detector emission, conventions scan, and mapping (replication waits for certified `claims_b3c`) | `build_detector_mapping.py --check` via certification | `references/pipeline-code-errors.md` |
| `code_b3b` (second-read recall sweep → merge) | `b3b-code` | `references/pipeline-code-errors.md` |
| `code_b4`–`code_b6b` (recheck → b6a merge → one b5s wave → b6b) | `b4-code`, `b5-code`, `b6a-code`, `b5s-code`, `b6b-code` | `references/pipeline-code-errors.md` |
| optional `bC` late-observation correction | `bC` | `references/pipeline-finalize.md` |
| `claims_adjudication_lineage` final carrier verdicts | `claims_adjudication.py --check` | `references/pipeline-finalize.md` |
| `b7` cross-link | `b7` | `references/pipeline-finalize.md` |
| `severity_token_rulings` rejected-token operator decisions | `severity_token_rulings` | `references/pipeline-finalize.md` |
| `b8` author-facing rewrite | `b8` | `references/pipeline-finalize.md` |
| `b9` Excel export (`scripts/export_xlsx.py`, never an LLM) | `b9` | `references/pipeline-finalize.md` |

Mechanics:

- The two streams are independent — run them in parallel. Within a stream, workers of the same
  stage run in parallel (one subagent per worker/cluster, single fire-and-forget message each).
- Before a stage does work, run `certify_stage.py start --stage <key>`. After its boundary work,
  run `certify_stage.py finish --stage <key> --outcome done`; that command re-resolves the
  stage's evidence and is the only route to `done`. On a terminal retry failure, use
  `finish --stage <key> --outcome blocked --reason "<text>"`. For worker shards, use
  `set-shard --stage <key> --shard <path> --status done` only after the shard exists and lints,
  or `--status blocked --reason "<text>"` after the retry fails. A worker stage may certify
  `done` once every recorded shard is `done` or `blocked` and at least one is `done`; certification
  re-lints the `done` shards while preserving blocked shards for degraded-coverage reporting.
  Never edit `stages` by hand.
- **Progress ledger.** At each transition, regenerate `audit/_run/progress.md` from the manifest:
  one line per boundary giving its status, shards done/blocked, and last lint result. It is a
  human-readable mirror of the manifest, not a second source of truth — rewrite it whole from the
  manifest each time so an unsupervised run stays legible without reading the pipeline files.
- **Effort-keyed dispatch.** Resolve the dispatch role in the table below, read its tier from the
  manifest `effort_map`, and dispatch through `rca-carrier-<tier>` while continuing to use the
  user's `worker_model`; model and effort are orthogonal. Begin every worker prompt with
  `RCA-DISPATCH role=<role-key> stage=<stage-key>` so the observation hook can recover aggregate
  stage/role counts. Append the dispatch immediately with `scripts/dispatch_tracking.py record`
  (role, carrier, stage, shard-or-artifact, and monotone sequence number) to
  `audit/_run/dispatch_ledger.md`; never rewrite the ledger. Skeleton thinking cues stay as
  written but are not the effort mechanism, and the conductor adds no ad-hoc thinking cues.
- Blocked work never stalls the run: merges run over the non-blocked shards (documenting the
  blocked ones), a blocked claims stage does not stop the code stream, and vice versa. Blocked
  stages/shards are reported at the end, not retried in a loop.

Completion: b9 is certified `done`, and `audit/code_review.xlsx` exists and passes the b9 lint.
Run `certify_stage.py close-run` once. `close-run` is the completion-report gate: it refuses
while any late-observation disposition is still `pending`, so a run that collected late
observations closes only after the first Phase-4 disposition batch (registers.md § late
observations) has replaced every pending state.
In full-replication runs whose severity-token lifecycle is active, it also refuses until
`severity_token_rulings` is certified `done` and its frozen rejected worklist has exact ruling
coverage.
In full-replication runs with a paper source set, it also refuses while either reserved U7
adjudication stage is absent/nonterminal or any H/X ledger entry is non-final. U7a
intentionally leaves that tail pending; U7b supplies its only legal terminalizer. A
`blocked_fallback` entry is released only by the exact, ID-joined
`audit/_run/handoff_blocked_decisions.json` operator artifact; the ledger state is never
rewritten.

**Resolved role-key table.** Every production dispatch site in this file and the three pipeline
files carries exactly one of these keys; b4 is conductor-computed and has no planner role.

| Role key | Stage / assignment | Default effort |
| --- | --- | --- |
| `codemap` | b0 CODEMAP | high |
| `claims_b1_planner` | claims b1 planner | high |
| `claims_b2_section` | claims b2 section worker | high |
| `claims_b3_merge` | claims b3 first merge | high |
| `claims_b3c_conventions` | claims b3c consolidation | high |
| `claims_b3b_second_read` | claims b3b second read | high |
| `claims_b3b_merge` | claims b3b merge | high |
| `claims_adjudication` | claims H/X capture adjudicator | high |
| `claims_adjudication_lineage` | claims final-carrier lineage adjudicator | high |
| `claims_b5_recheck_cluster` | claims b5 recheck cluster | high |
| `claims_b6_merge` | claims b6a/b6b merge | high |
| `code_b1_planner` | code b1 planner | high |
| `code_b2_chunk` | code b2 chunk worker | high |
| `code_b3_merge` | code b3 first merge | high |
| `b3d_conventions_scan` | code b3d conventions scan | high |
| `code_b3b_second_read` | code b3b second read | high |
| `code_b3b_merge` | code b3b merge | high |
| `code_b5_recheck_cluster` | code b5 recheck cluster | high |
| `code_b6_merge` | code b6a/b6b merge | high |
| `b7_cross_linker` | b7 cross-link | high |
| `b7_claim_recheck` | b7 conditional claims recheck | high |
| `b8_rewriter` | b8 rewrite | medium |

## Phase 4 — Report and follow-up (interactive again)

Report to the user: row counts per register and status, issue-flagged rows by severity,
blocked/`confirmation_needed` rows, degraded-confidence warnings, and the workbook path. Run
`scripts/dispatch_tracking.py report --audit-dir audit` and include its per-stage-and-role ledger
dispatch counts versus observed hook-event counts. Name every mismatch at that granularity as an
**instrumentation gap for operator judgment**; the ledger and event files are reported only and
never gate a stage, `verify-run`, or export.

Offer the documented follow-up: **targeted manual QA** — the user picks specific IDs, you run an
interactive recheck of just those rows (same evidence standards as the recheck stage) and
propose replacement author-facing notes. Do not edit registers in this phase without explicit
user approval.

## Resume

If `audit/_run/manifest.json` exists at intake, offer to resume:

0. Run `scripts/certify_stage.py resume-check --package-root <package-root> --clear-stale-marker`.
   It replaces the crash-surviving marker, verifies the canonical root,
   tree fingerprint, and mechanism-schema version, and re-derives every recorded `done`. A tree
   or schema mismatch requires a fresh audit. For each stale evidence pass it reports, run
   `certify_stage.py demote --stage <key> --reason "<failed obligation>"`; never hand-demote it.
   Discard only that boundary's stale staging files, then rerun the same
   `resume-check --clear-stale-marker` command until all remaining recorded passes verify.
1. Resume at the first stage key whose status ≠ `done` (stream order: each stream
   independently, then finalize). Within a worker stage, re-dispatch only workers whose shards
   are missing or failing lint — completed shards are never re-run.
2. Registers are only ever mutated via staging + atomic rename, so a crashed run leaves canon
   consistent; stale staging files can be deleted.
