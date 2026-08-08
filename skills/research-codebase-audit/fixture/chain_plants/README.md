# Chain plants — campaign-close verification

Three tiny synthetic replication packages, one per run-8 gate-failing code
miss class, each carrying exactly one planted defect that materially flows
into the paper's reported quantity. They are campaign-close verification
for the run-8 fix campaign, separate from the 28-plant regression fixture
in `../planted/` (that README's re-scoring rules do not apply here). Each
plant proves, end to end through the unmodified production pipeline, that a
fresh instance of its class travels emitter → mapping → recheck →
adjudication → final register and lands at a gate-counting status with an
honest severity.

| Plant | Class proved | Package | Planted defect |
| --- | --- | --- | --- |
| `comment_closure/` | comment-contradicts-guard (definition/use narrowing) | school-meals nutrition program evaluation (Stata) | `do/build_sample.do` defines `eligible_flag` under a comment covering both meal plans, then the `keep` guard's extra `meal_plan == "standard"` conjunct silently drops every reduced-price student; the narrowed sample flows into the Table 1 mean |
| `producer_group/` | producer-group overwrite | municipal air-quality exceedance monitoring (Stata) | `do/build_flags.do` builds `exceed_any` with an overwriting `replace` inside a `foreach` loop (assignment, not accumulation), so the final pollutant erases every earlier exceedance; the understated share is the reported Table 1 number |
| `path_derivation/` | path-chain misresolution | interlibrary loan volumes (Python) | `py/tools/make_totals.py` derives its primary input with one `..` too many, the derivation fails to resolve, and a caught fallback silently reads the stale root-level `loans.csv`; the stale total is what the paper reports |

Each plant directory holds `package/` (the audited root) and
`expected.json` (the answer key, beside — not inside — the package). The
key's `run8_id` is historical scorecard correspondence only and is never
matched against. `scripts/tests/data/chain_plants_sha256.json` hashes every
package file and key; an "accidental fix" of a planted defect fails the
pytest harness (see `scripts/tests/test_plant_drift.py`).

## Run protocol

1. Copy the plant's `package/` to a scratch location (the audit writes an
   `audit/` folder into it). The scratch location must be an **empty**
   directory whose parent contains no sibling `data/` folder — a stray
   `data/loans.csv` one level above the copied package root would let
   `path_derivation`'s failed primary chain resolve and silently erase
   that plant's defect. The audit is handed the copied `package/` as
   the repo root and never sees `expected.json` or its siblings.
2. Invoke `research-codebase-audit` on the copy: full replication audit,
   review-ladder level 2, review depth `standard`, nothing off-limits,
   **accepting every intake default** — so the manifest's `effort_map` is
   the default map the scorer asserts.
3. When the run finishes, score it:

   ```
   python scripts/score_chain_plants.py \
       --plant fixture/chain_plants/<name> --audit-dir /path/to/pkg/audit
   ```

   Exit 0 = PLANT GREEN, 1 = PLANT RED, 2 = usage/IO error. On a RED, the
   operator diagnoses the broken chain link by hand from the named
   production artifacts (emitter output, detector mapping, recheck ledger,
   final register) — there is no automated trace.

## The no-stub rule

The plants run at campaign close, before run 9, and on demand — always
against the unmodified production pipeline. No stage may be stubbed or
replaced for a plant run. All three plants must be GREEN before run 9
launches. The plant runs are operator-launched sessions recorded on the
campaign execution issue; they are not part of the pytest harness or any
commit gate.

## The pass condition

A plant passes only when the final code-error register contains the
expected row — matched by mechanism signature, never by ID or wording — at
status `confirmed` with severity ≥ 2. **Presence at any other status is a
fail**: `not_error`, `confirmation_needed`, `blocked`, and unresolved
tombstones all score RED (run 8's missed rows were *present* — staged,
then closed `not_error` — so mere presence proves nothing). A
`duplicate_of:` tombstone passes only through a target row that also
matches the plant signature and meets the same bar.

Two ride-along assertions run on every plant: the exported
`audit/code_review.xlsx` must contain exactly the three post-U17 sheets
(Overview, Paper Claims, Code Errors) with the pinned visible and hidden
columns, and the run manifest's `effort_map` must equal the pinned default
map.

## Run-9 success definition (pre-registered)

The campaign counts as successful when run 9 achieves all four clauses:

1. **Gated code errors 10/10** (the post-E-0305-ruling gate).
2. **Gated claims 6/6, strict:** a gated claim hits only at
   `inconsistent`; `confirmation_needed` on a gated claim is a class-(b)
   partial miss — standing for all future gate runs.
3. **Gated outputs 5/5.**
4. **The baseline severity-4 mechanisms score severity ≥ 3** (the
   restoration target).

Non-gated items are reported but cannot fail the campaign; the scorecard
reports the E-1201 outcome in one line (non-gating). A run-9 failure goes
to the normal scorecard → diagnosis → operator adjudication process and
does not automatically re-open the campaign map.
