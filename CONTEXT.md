# Research-codebase-audit temporal model

The audit pipeline mutates its registers stage by stage. Correctness questions are
temporal: each question is answerable only against the register state at one named
moment. This glossary names those moments and the row origins, so validators and
documents share one language. Adopted by operator decision 2026-07-31.

## Language

### Evidence views

An **evidence view** is the register state at one named pipeline moment, backed by
exactly one owning artifact. A validator names the view it needs; it never selects
among snapshots by precedence or recency.

**b6b_proposal**:
The frozen register state at the end of b6b — every proposed final disposition
(Status, Severity) and every minted machine stamp, as b6b left them.
_Avoid_: final register, post-b6b canon, latest snapshot

**b7_classification**:
The immutable register state b7 classified against — accepted claim↔error pairings
and token verdicts, as of b7.
_Avoid_: b7 canon, classification snapshot

**pre_ruling**:
The exact register bytes handed to the severity-token rulings stage — the only
stage allowed to mutate Status and Severity cells.
_Avoid_: pre-ruling canon, rulings input

**rulings_applied**:
The register state after all rulings caps are applied and before any b8 rewrite —
the baseline b8 must start from.
_Avoid_: post-ruling state, b8 input, canon at rulings finish

**export_bound**:
The live canonical register after b8 — the author-facing text the final export
reads. Survival obligations (e.g. machine stamps) bind here, never to archive
columns.
_Avoid_: current canon, post-b8 register, staging

**bC_correction**:
The operator-approved late-correction packet — the authorized new rows and link
edits, exactly as declared. Any register change outside this packet after bC is
tampering.
_Avoid_: bC snapshot alone, correction overlay

### Row provenance

A row's **provenance** is where it was born. It never changes, and it determines
which evidence views can contain the row at all.

**main-cycle**:
A row minted in the normal audit cycle. Present in all views from its mint onward.

**supplementary**:
A row minted in the supplementary wave. Subject to the same temporal questions as
main-cycle rows; never a special case at proposal equality.

**bC-added**:
A row minted by an operator correction. Absent from every view before
bC_correction; judged only against its correction-plan payload and later lawful
deltas.

### Policy

**authorization projection**:
The single shared rulebook of permitted deltas between two named evidence views —
which rows, which cells, which values. Every checker reads it; no stage keeps a
private copy of the permission rules.
_Avoid_: authorized changes tuple, per-stage exceptions, overlay

**reciprocal link derivation**:
A bC-added row carries its own link in its approved payload; the existing row's
reciprocal cell is computed from the plan's declarations. Never read from a
separate record and never guessed.
_Avoid_: extension record, link receipt

### Rules of use

**fail closed**:
When a named view's owning artifact is absent or malformed, the consumer refuses.
The live register never substitutes for a missing view.
_Avoid_: fallback, mutable-canonical fallback, legacy mode
