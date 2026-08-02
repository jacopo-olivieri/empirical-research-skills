#!/usr/bin/env python3
"""The authorization projection (root ``CONTEXT.md``, "Policy").

The single shared rulebook of permitted deltas between two named evidence
views — which rows, which cells, which values.  Every checker reads it; no
stage keeps a private copy of the permission rules.  Everything not
returned is tampering.

Supported transitions:

- ``pre_ruling -> rulings_applied``: Status/Severity cells only, only for
  keys on the frozen rejected worklist, per the frozen rulings records,
  cap <= 2.
- ``rulings_applied -> export_bound``: rewrite-pair columns only, plus the
  added ``*Original`` archive columns; frozen columns byte-equal.
- ``bC_correction -> export_bound`` (once ``bC`` is ``done``): new rows
  exactly per plan payload; C<->O link patches exactly as declared; the
  derived C<->E reciprocal-link additions on the existing rows the
  new-row payloads name (**reciprocal link derivation** — a bC-added row
  carries its own link in its approved payload; the existing row's
  reciprocal cell is computed from the plan's declarations).

Validators several transitions past their anchor view ``compose`` the
permitted deltas along the chain; no local carve-outs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import evidence_views
import severity_tokens as tokens


BC_PLAN_COLS = [
    "BC ID", "LO ID", "Register", "Operation", "Row ID", "Payload JSON",
    "Old Value SHA256",
]
BC_RANGE_RE = re.compile(
    r"^Declared bC range:\s*([CEO]-\d{4})[–—-]([CEO]-\d{4})\s*$", re.M)
REWRITE_PAIRS = {
    "claims_register.md": [("Issue Description", "Issue Description Original")],
    "code_error_register.md": [
        ("Error Description", "Error Description Original"),
        ("Why It Matters", "Why It Matters Original"),
    ],
}
FROZEN_RULINGS = "_run/snapshots/severity_token_rulings/severity_token_rulings.json"

_REGISTER_FILES = {
    "claims": "claims_register.md",
    "output": "output_register.md",
    "code_error": "code_error_register.md",
}
_LINK_COLUMNS = {
    "claims_register.md": ("Related Error IDs", "E"),
    "code_error_register.md": ("Related Claim IDs", "C"),
}
# The only patchable cells: the reciprocal C<->O pair (lint_registers bC
# contract; C<->E link columns are never patched, only derived).
_PATCHABLE = {("claims", "Output IDs"), ("output", "Claim IDs")}


def _ids_in(text, letter):
    return re.findall(rf"{letter}-\d{{4}}", text or "")


def _blank(value):
    return value in ("", "-", "—")


@dataclass(frozen=True)
class PermittedDelta:
    """Exact allowed differences on top of an anchor view.

    ``exact_cells``: ``(row_id, column) -> exact allowed new value``.
    ``link_additions``: ``(row_id, column) -> frozenset(ids)`` that the
    derived reciprocal state adds to the anchor cell's id set.
    ``added_rows``: ``row_id -> payload`` for authorized new rows.
    ``rewrite_pairs``: ``(base, original)`` columns the b8 rewrite may
    rewrite while archiving the prior text.
    """

    exact_cells: dict = field(default_factory=dict)
    link_additions: dict = field(default_factory=dict)
    added_rows: dict = field(default_factory=dict)
    rewrite_pairs: tuple = ()

    def compose(self, other):
        link_additions = dict(self.link_additions)
        for key, ids in other.link_additions.items():
            link_additions[key] = link_additions.get(key, frozenset()) | ids
        return PermittedDelta(
            {**self.exact_cells, **other.exact_cells},
            link_additions,
            {**self.added_rows, **other.added_rows},
            tuple(self.rewrite_pairs) + tuple(
                pair for pair in other.rewrite_pairs
                if pair not in self.rewrite_pairs),
        )


EMPTY_DELTA = PermittedDelta()


def payload_matches_row(payload, final_row, headers, rewrite_pairs):
    """Compare an authorized new-row payload before or after the authorized
    b8 rewrite pass (a new-row payload equals its register row exactly)."""
    if set(payload) != set(headers):
        return False
    by_base = dict(rewrite_pairs)
    by_original = {original: base for base, original in rewrite_pairs}
    for column in headers:
        if column in by_base:
            original = by_base[column]
            observed = final_row.get(original, "")
            if _blank(observed):
                observed = final_row.get(column, "")
            if payload.get(column) != observed:
                return False
        elif column in by_original and _blank(payload.get(column, "")):
            if final_row.get(column, "") not in {
                    payload.get(column, ""),
                    payload.get(by_original[column], "")}:
                return False
        elif payload.get(column) != final_row.get(column):
            return False
    return True


def load_bc_plan(audit):
    """Parse the operator-approved correction plan.

    Returns ``(path, rows, ranges, failures)``; rows carry ``_payload``.
    """
    audit = Path(audit)
    path = audit / "plans/late_observation_corrections.md"
    failures = []
    if not path.is_file():
        return path, [], [], []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return path, [], [], [f"{path}: {exc}"]
    matches = [
        (rows, line)
        for headers, rows, line in tokens.parse_tables(text)
        if headers == BC_PLAN_COLS
    ]
    rows = []
    if len(matches) != 1:
        failures.append(
            f"{path}: expected exactly one bC plan table with columns "
            + " | ".join(BC_PLAN_COLS))
    else:
        for index, raw in enumerate(matches[0][0], start=1):
            if len(raw) != len(BC_PLAN_COLS):
                failures.append(f"{path}: malformed plan row {index}")
                continue
            row = dict(zip(BC_PLAN_COLS, raw))
            if not re.fullmatch(r"BC-\d{4}", row["BC ID"]):
                failures.append(f"{path}: invalid BC ID {row['BC ID']!r}")
            if not re.fullmatch(r"LO-[CE]-\d{4}", row["LO ID"]):
                failures.append(f"{path}: invalid LO ID {row['LO ID']!r}")
            if row["Register"] not in _REGISTER_FILES:
                failures.append(
                    f"{path}: invalid Register {row['Register']!r}")
            if row["Operation"] not in {"new_row", "patch"}:
                failures.append(
                    f"{path}: invalid Operation {row['Operation']!r}")
            try:
                payload = json.loads(row["Payload JSON"])
            except json.JSONDecodeError as exc:
                failures.append(
                    f"{path}: {row['BC ID']} Payload JSON is invalid: {exc}")
                payload = None
            if not isinstance(payload, dict):
                failures.append(
                    f"{path}: {row['BC ID']} Payload JSON must be an object")
            row["_payload"] = payload if isinstance(payload, dict) else {}
            rows.append(row)
    ranges = BC_RANGE_RE.findall(text)
    return path, rows, ranges, failures


def _rulings_delta(register, audit, manifest):
    if register != "code_error_register.md":
        return EMPTY_DELTA, []
    audit = Path(audit)
    resolved = evidence_views.resolve(
        "pre_ruling", "code_error_register.md", audit, manifest)
    if isinstance(resolved, evidence_views.PrematureAsk):
        return EMPTY_DELTA, [str(resolved)]
    if isinstance(resolved, evidence_views.ViewRefusal):
        return EMPTY_DELTA, [str(resolved)]
    worklist_keys = set(resolved.payload["lines"])
    frozen = audit / FROZEN_RULINGS
    if frozen.is_symlink() or not frozen.is_file():
        return EMPTY_DELTA, [
            f"{frozen}: frozen ruling artifact is missing"]
    try:
        payload = json.loads(frozen.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return EMPTY_DELTA, [f"{frozen}: invalid frozen rulings ({exc})"]
    rulings = payload.get("rulings") if isinstance(payload, dict) else None
    if not isinstance(rulings, list):
        return EMPTY_DELTA, [f"{frozen}: rulings must be an array"]
    exact_cells = {}
    failures = []
    for ruling in rulings:
        if not isinstance(ruling, dict):
            failures.append(f"{frozen}: malformed ruling entry")
            continue
        error_id = ruling.get("error_id")
        key = f"{error_id} {ruling.get('token')}"
        if key not in worklist_keys:
            failures.append(
                f"{frozen}: ruling names non-worklist token {key}")
            continue
        severity = str(ruling.get("resulting_severity"))
        if ruling.get("ruling") in {"cap", "hold"} \
                and severity not in {"1", "2"}:
            failures.append(
                f"{frozen}: {error_id} {ruling.get('ruling')} exceeds the "
                "severity cap")
            continue
        exact_cells[(error_id, "Status")] = ruling.get("resulting_status")
        exact_cells[(error_id, "Severity")] = severity
    return PermittedDelta(exact_cells=exact_cells), failures


def _bc_delta(register, audit, manifest):
    if not evidence_views.stage_done(manifest, "bC"):
        # bC not produced => no bC deltas.
        return EMPTY_DELTA, []
    plan_path, plan_rows, _ranges, failures = load_bc_plan(audit)
    if not plan_path.is_file():
        return EMPTY_DELTA, [
            f"{plan_path}: bC is done but the correction plan is absent"]
    exact_cells = {}
    link_additions = {}
    added_rows = {}
    for row in plan_rows:
        target = _REGISTER_FILES.get(row["Register"])
        payload = row["_payload"]
        if row["Operation"] == "new_row":
            if target == register:
                added_rows[row["Row ID"]] = payload
            # Reciprocal link derivation: the existing row's cell gains
            # exactly the plan-declared new-row referrers.
            link_column, _letter = _LINK_COLUMNS.get(target, (None, None))
            if link_column is not None:
                other = ("code_error_register.md"
                         if target == "claims_register.md"
                         else "claims_register.md")
                if other == register:
                    reciprocal, letter = _LINK_COLUMNS[register]
                    for named in _ids_in(
                            payload.get(link_column, ""),
                            "C" if letter == "E" else "E"):
                        key = (named, reciprocal)
                        link_additions[key] = (
                            link_additions.get(key, frozenset())
                            | {row["Row ID"]})
        elif row["Operation"] == "patch":
            payload_field = payload.get("field")
            if (row["Register"], payload_field) not in _PATCHABLE:
                failures.append(
                    f"{plan_path}: patch {row['BC ID']} may change only "
                    "reciprocal C↔O link columns")
                continue
            if target == register:
                exact_cells[(row["Row ID"], payload_field)] = payload.get(
                    "new_value", "")
    return PermittedDelta(
        exact_cells=exact_cells, link_additions=link_additions,
        added_rows=added_rows), failures


def _rewrite_delta(register, _audit, _manifest):
    return PermittedDelta(
        rewrite_pairs=tuple(REWRITE_PAIRS.get(register, ()))), []


_TRANSITIONS = {
    ("pre_ruling", "rulings_applied"): _rulings_delta,
    ("rulings_applied", "export_bound"): _rewrite_delta,
    ("bC_correction", "export_bound"): _bc_delta,
}


def permitted_delta(from_view, to_view, register, audit, manifest):
    """Return ``(PermittedDelta, failures)`` for one supported transition."""
    transition = _TRANSITIONS.get((from_view, to_view))
    if transition is None:
        raise ValueError(
            f"no authorized transition {from_view!r} -> {to_view!r}")
    return transition(register, audit, manifest)


def compose(*deltas):
    combined = EMPTY_DELTA
    for delta in deltas:
        combined = combined.compose(delta)
    return combined
