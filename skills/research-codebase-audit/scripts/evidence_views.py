#!/usr/bin/env python3
"""Resolve named evidence views (root ``CONTEXT.md``, temporal model).

An **evidence view** is the register state at one named pipeline moment,
backed by exactly one owning artifact.  A consumer names the view it needs;
the resolver owns the phase conditional and the fail-closed rule.  It never
returns a "best available" substitute and it exposes no precedence
parameter.

``resolve`` returns exactly one of three typed results:

- ``ResolvedView`` — the view's owning artifact, read and (for register
  files) table-parsed, with raw bytes where the view is bytes-bound.
- ``ViewRefusal`` — the view should exist but its owning artifact is
  ``absent``, ``malformed``, or ``tampered``.  The live register never
  substitutes for a missing view.
- ``PrematureAsk`` — a typed caller error (never a refusal): the view's
  owning boundary has not been reached, so the caller should not have
  asked.

Naming convention, verified at HEAD: a snapshot directory named after
stage X holds the register state at X's **start**; a boundary's post-state
lives in the *following* stage's start image.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

import severity_tokens as tokens


VIEWS = (
    "b6b_proposal", "b7_classification", "pre_ruling", "rulings_applied",
    "export_bound", "bC_correction",
)
REFUSAL_REASONS = ("absent", "malformed", "tampered")

WORKLIST_SCHEMA = "severity-token-worklist/v2"
WORKLIST_PATH = "_run/snapshots/severity_token_rulings/b7_rejected_worklist.json"
PRE_RULING_REGISTER = "_run/snapshots/severity_token_rulings/code_error_register.md"
B7_SNAPSHOT_DIR = "_run/snapshots/b7"
B8_SNAPSHOT_DIR = "_run/snapshots/b8"
BC_SNAPSHOT_DIR = "_run/snapshots/bC"

ID_COLUMNS = {
    "claims_register.md": "Claim ID",
    "output_register.md": "Output ID",
    "code_error_register.md": "Error ID",
}


@dataclass(frozen=True)
class ResolvedView:
    view: str
    register: str
    source_path: Path
    text: str
    raw: bytes
    headers: tuple = ()
    rows: tuple = ()
    payload: dict | None = None


@dataclass(frozen=True)
class ViewRefusal:
    view: str
    register: str
    reason: str
    detail: str
    source_path: Path | None = None

    def __str__(self):
        return (
            f"{self.view} evidence refused ({self.reason}): {self.detail}")


@dataclass(frozen=True)
class PrematureAsk:
    view: str
    register: str
    detail: str

    def __str__(self):
        return f"premature ask for {self.view}: {self.detail}"


def stage_status(manifest, stage):
    stages = (manifest or {}).get("stages")
    if not isinstance(stages, dict):
        return None
    entry = stages.get(stage)
    return entry.get("status") if isinstance(entry, dict) else None


def stage_begun(manifest, stage):
    """The stage's start boundary was crossed, so its start image is minted."""
    return stage_status(manifest, stage) in {"running", "done", "blocked"}


def stage_done(manifest, stage):
    return stage_status(manifest, stage) == "done"


def _read(view, register, path, require_table=True):
    path = Path(path)
    if not path.exists():
        return ViewRefusal(
            view, register, "absent",
            f"{path} does not exist", path)
    if path.is_symlink() or not path.is_file():
        return ViewRefusal(
            view, register, "malformed",
            f"{path} is not a regular file", path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return ViewRefusal(
            view, register, "malformed", f"{path}: {exc}", path)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return ViewRefusal(
            view, register, "malformed", f"{path}: {exc}", path)
    headers, rows = (), ()
    id_column = ID_COLUMNS.get(register)
    if require_table and id_column is not None:
        for table_headers, table_rows, _line in tokens.parse_tables(text):
            if id_column in table_headers:
                headers = tuple(table_headers)
                rows = tuple(tuple(row) for row in table_rows)
                break
        else:
            return ViewRefusal(
                view, register, "malformed",
                f"{path} has no {id_column} register table", path)
    return ResolvedView(view, register, path, text, raw, headers, rows)


def _live_register(view, register, audit, prefer_staging=False):
    audit = Path(audit)
    if prefer_staging and (audit / "_staging" / register).is_file():
        return _read(view, register, audit / "_staging" / register)
    return _read(view, register, audit / register)


def _boundary_minted(manifest, stage, path):
    """A view exists once its owning artifact is minted at its boundary.

    The artifact's presence is the mint; the manifest adds the fail-closed
    direction — when it records the boundary as crossed, the artifact must
    exist, so the caller reads (and refuses on absence) instead of falling
    back to a pre-boundary source."""
    return Path(path).exists() or stage_begun(manifest, stage)


def _resolve_b6b_proposal(register, audit, manifest):
    """The frozen post-b6b state.

    The owning artifact is the start image of the first boundary crossed
    after b6b that freezes this register — in the wall-clock order the
    pipeline runs those boundaries (b7, then b8, then the post-export bC
    correction), never latest-first.  In a full-replication run that is the
    b7-start image for both link-bearing registers; the later boundaries
    matter only for registers or modes the earlier stages never snapshot
    (the output register, code-errors-only runs, degraded tails).  Before
    any such boundary, the live canonical register is the owning location.
    Once a boundary is recorded as crossed, its image is the sole anchor:
    a deleted image refuses instead of sliding to a later boundary."""
    audit = Path(audit)
    mode = (manifest or {}).get("mode", "replication")
    if mode == "code_errors_only":
        candidates = (("b8", B8_SNAPSHOT_DIR), ("bC", BC_SNAPSHOT_DIR))
    elif register == "output_register.md":
        # b7 and b8 never snapshot the output register; only bC may
        # lawfully touch it after b6b, so its start image owns the view.
        candidates = (("bC", BC_SNAPSHOT_DIR),)
    else:
        candidates = (
            ("b7", B7_SNAPSHOT_DIR), ("b8", B8_SNAPSHOT_DIR),
            ("bC", BC_SNAPSHOT_DIR))
    for owner_stage, owner_dir in candidates:
        owner = audit / owner_dir / register
        if _boundary_minted(manifest, owner_stage, owner):
            return _read("b6b_proposal", register, owner)
    return _live_register("b6b_proposal", register, audit)


def _resolve_b7_classification(register, audit, manifest):
    if register != "code_error_register.md":
        raise ValueError(
            f"b7_classification owns only the code-error register, not {register!r}")
    owner = Path(audit) / PRE_RULING_REGISTER
    if _boundary_minted(manifest, "severity_token_rulings", owner):
        return _read("b7_classification", register, owner)
    return _live_register(
        "b7_classification", register, audit, prefer_staging=True)


def _resolve_pre_ruling(register, audit, manifest):
    """The exact register bytes handed to the rulings stage, bytes/digest
    bound to the frozen rejected worklist."""
    if register != "code_error_register.md":
        raise ValueError(
            f"pre_ruling owns only the code-error register, not {register!r}")
    audit = Path(audit)
    worklist_path = audit / WORKLIST_PATH
    if not _boundary_minted(manifest, "severity_token_rulings", worklist_path):
        return PrematureAsk(
            "pre_ruling", register,
            "the pre-ruling artifacts are born when the rulings stage starts")
    worklist = _read("pre_ruling", register, worklist_path,
                     require_table=False)
    if isinstance(worklist, ViewRefusal):
        return worklist
    try:
        payload = json.loads(worklist.text)
    except json.JSONDecodeError as exc:
        return ViewRefusal(
            "pre_ruling", register, "malformed",
            f"{worklist_path}: cannot read frozen rejected worklist ({exc})",
            worklist_path)
    if not isinstance(payload, dict) or set(payload) != {
            "schema", "lines", "b7_register_sha256",
            "b7_certification_sha256"}:
        return ViewRefusal(
            "pre_ruling", register, "malformed",
            f"{worklist_path}: frozen worklist has unexpected fields",
            worklist_path)
    lines = payload.get("lines")
    register_sha256 = payload.get("b7_register_sha256")
    if payload.get("schema") != WORKLIST_SCHEMA or not isinstance(lines, list) \
            or not all(isinstance(line, str) for line in lines) \
            or lines != sorted(set(lines)) \
            or not isinstance(register_sha256, str) \
            or not re.fullmatch(r"[0-9a-f]{64}", register_sha256):
        return ViewRefusal(
            "pre_ruling", register, "malformed",
            f"{worklist_path}: malformed frozen worklist", worklist_path)
    snapshot = _read("pre_ruling", register, audit / PRE_RULING_REGISTER)
    if isinstance(snapshot, ViewRefusal):
        return snapshot
    if hashlib.sha256(snapshot.raw).hexdigest() != register_sha256:
        return ViewRefusal(
            "pre_ruling", register, "tampered",
            f"{snapshot.source_path}: snapshot digest mismatch",
            snapshot.source_path)
    if payload["b7_certification_sha256"] != worklist_digest(
            lines, register_sha256):
        return ViewRefusal(
            "pre_ruling", register, "tampered",
            f"{worklist_path}: frozen worklist digest mismatch",
            worklist_path)
    return ResolvedView(
        "pre_ruling", register, snapshot.source_path, snapshot.text,
        snapshot.raw, snapshot.headers, snapshot.rows, payload)


def _resolve_rulings_applied(register, audit, manifest):
    """The register state at rulings finish: the b8 start image byte-for-byte
    once that boundary is minted, the live canonical register before it."""
    audit = Path(audit)
    owner = audit / B8_SNAPSHOT_DIR / register
    if _boundary_minted(manifest, "b8", owner):
        return _read("rulings_applied", register, owner)
    return _live_register("rulings_applied", register, audit)


def _resolve_export_bound(register, audit, _manifest):
    return _live_register("export_bound", register, audit)


def _resolve_bc_correction(register, audit, manifest):
    owner = Path(audit) / BC_SNAPSHOT_DIR / register
    if not _boundary_minted(manifest, "bC", owner):
        return PrematureAsk(
            "bC_correction", register,
            "the bC packet is minted when the correction stage starts")
    return _read(
        "bC_correction", register, owner,
        require_table=register in ID_COLUMNS)


_RESOLVERS = {
    "b6b_proposal": _resolve_b6b_proposal,
    "b7_classification": _resolve_b7_classification,
    "pre_ruling": _resolve_pre_ruling,
    "rulings_applied": _resolve_rulings_applied,
    "export_bound": _resolve_export_bound,
    "bC_correction": _resolve_bc_correction,
}


def resolve(view, register, audit, manifest):
    """Resolve one named evidence view for one register file."""
    resolver = _RESOLVERS.get(view)
    if resolver is None:
        raise ValueError(f"unknown evidence view {view!r}")
    return resolver(register, audit, manifest)


def worklist_digest(lines, register_sha256):
    payload = json.dumps({
        "lines": sorted(lines),
        "b7_register_sha256": register_sha256,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
