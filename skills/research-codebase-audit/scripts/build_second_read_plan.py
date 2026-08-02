#!/usr/bin/env python3
"""Build or verify the deterministic code-stream b3b second-read allocation.

The conductor owns prose outside the generated block.  This script owns every
allocation row and sampler-log line inside it.  It is intentionally code-stream
only; the claims allocation remains conductor-authored.
"""

import argparse
import hashlib
import json
import re
import sys
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

import build_detector_mapping as detector_mapping
import lint_registers as lr


BEGIN = "<!-- GENERATED:SECOND-READ-PLAN BEGIN -->"
END = "<!-- GENERATED:SECOND-READ-PLAN END -->"
EXTENSIONS = {
    ".py": "python", ".do": "stata", ".ado": "stata", ".r": "r",
    ".jl": "julia", ".m": "matlab", ".sas": "sas", ".sql": "sql",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
}
CAPS = {"shallow": 0, "standard": 10, "deep": 15}


class PlanError(RuntimeError):
    """The allocation cannot be derived from certified on-disk evidence."""


def _read(path):
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PlanError(f"cannot read {path}: {exc}") from exc


def _json(path):
    try:
        value = json.loads(_read(path))
    except json.JSONDecodeError as exc:
        raise PlanError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PlanError(f"{path} must contain an object")
    return value


def _table(text, predicate, label):
    matches = []
    for headers, rows, _line in lr.parse_tables(text):
        if predicate(headers):
            matches.append((headers, rows))
    if len(matches) != 1:
        raise PlanError(f"expected exactly one {label} table")
    headers, rows = matches[0]
    parsed = []
    for index, row in enumerate(rows, start=1):
        if len(row) != len(headers):
            raise PlanError(f"malformed {label} row {index}")
        parsed.append(dict(zip(headers, row)))
    return parsed


def _inventory(audit):
    plan = audit / "plans/code_error_review_plan.md"
    text = _read(plan)
    scripts = _table(
        text, lambda h: "Script" in h and "Chunk" in h, "script inventory")
    hygiene = _table(
        text, lambda h: h == ["Hygiene File", "Chunk"], "hygiene inventory")
    paths = []
    for row, column in [(r, "Script") for r in scripts] + [
            (r, "Hygiene File") for r in hygiene]:
        path = row[column].strip().strip("`")
        if path and path not in paths:
            paths.append(path)
    return paths, text


def _manifest_stage(manifest, name):
    stages = manifest.get("stages", {})
    return stages.get(name, {}) if isinstance(stages, dict) else {}


def _coverage(audit, manifest, plan_text):
    allocations, _ = lr.parse_plan(lr.Lint(), audit / "plans/code_error_review_plan.md", "Chunk ID")
    outcomes = {}
    missing = []
    for allocation in allocations or []:
        wire = lr.normalized_audit_path(allocation["Shard File"])
        state = lr.manifest_shard_state(manifest, "code_b2", wire)
        if state == "blocked":
            continue
        shard = lr.audit_path(audit, wire)
        if not shard.is_file():
            continue
        lint = lr.Lint()
        text = _read(shard)
        _entries, rows = lr.typed_shard_footer(lint, shard, text, "code")
        if lint.errors:
            raise PlanError("; ".join(lint.errors))
        for row in rows:
            outcomes.setdefault(row["script"], []).append(row["kind"])
    inventory, _ = _inventory(audit)
    result = {}
    for path in inventory:
        values = outcomes.get(path, [])
        if not values:
            missing.append(path)
            result[path] = "unreviewed"
        elif len(values) != 1:
            result[path] = "conflicting"
        else:
            result[path] = values[0]
    return result, missing


def _register_rows(audit, register_path=None):
    path = register_path or audit / "code_error_register.md"
    text = _read(path)
    rows = _table(text, lambda h: h == lr.ERROR_COLS, "code-error register")
    return [row for row in rows if row["Error ID"] != "E-0000"]


def _source_paths(cell, inventory):
    tokens = lr.scope_tokens(cell)
    by_base = {}
    for path in inventory:
        by_base.setdefault(Path(path).name, []).append(path)
    resolved = set()
    for token in tokens:
        token = token.split(":", 1)[0].strip().strip("`")
        if token in inventory:
            resolved.add(token)
        elif len(by_base.get(Path(token).name, [])) == 1:
            resolved.add(by_base[Path(token).name][0])
    return resolved


def _detector_paths(audit, rows, inventory):
    mapping = audit / "_run/detector_mapping.md"
    if not mapping.is_file():
        return set()
    try:
        _declared, _display, mapped = detector_mapping.load_mapping(mapping)
    except detector_mapping.MappingError as exc:
        raise PlanError(str(exc)) from exc
    ids = {
        row["Error ID"]
        for row in detector_mapping.actionable_rows(mapped)
    }
    return {path for row in rows if row["Error ID"] in ids
            for path in _source_paths(row["Code/Data Source"], inventory)}


def _flagged_paths(rows, inventory, depth):
    found = set()
    for row in rows:
        if row["Status"] != "candidate":
            continue
        if depth == "shallow" and int(row["Severity"] or 0) < 3:
            continue
        found |= _source_paths(row["Code/Data Source"], inventory)
    return found


def _codemap_strata(audit, inventory):
    strata = {path: set() for path in inventory}
    for path in inventory:
        language = EXTENSIONS.get(Path(path).suffix.lower())
        if language:
            strata[path].add(f"language:{language}")
    codemap = audit / "CODEMAP.md"
    if not codemap.is_file():
        return strata
    tables = lr.parse_tables(_read(codemap))
    by_base = {}
    for path in inventory:
        by_base.setdefault(Path(path).name, []).append(path)

    aliases = {}

    def resolve_path_token(token):
        token = token.strip().strip("`")
        if token in strata:
            return {token}
        matches = by_base.get(Path(token).name, [])
        return {matches[0]} if len(matches) == 1 else set()

    # CODEMAP's called/ancillary tables give lineage cells stable S-####
    # aliases. Resolve those aliases before expanding grouped lineage cells.
    for headers, rows, _line in tables:
        if {"ID", "Script"} <= set(headers):
            for row in rows:
                if len(row) != len(headers):
                    continue
                data = dict(zip(headers, row))
                paths = resolve_path_token(data["Script"])
                if re.fullmatch(r"S-\d{4}", data["ID"].strip()) and paths:
                    aliases[data["ID"].strip()] = paths

    def resolve(cell):
        answer = set()
        grouped = re.split(r"[;,]|<br\s*/?>", cell or "", flags=re.IGNORECASE)
        for token in grouped:
            for script_id in re.findall(r"S-\d{4}", token):
                answer |= aliases.get(script_id, set())
            candidates = re.findall(r"`([^`]+)`", token) or [token]
            for candidate in candidates:
                answer |= resolve_path_token(candidate)
                for base, paths in by_base.items():
                    if len(paths) == 1 and re.search(
                            rf"(?<![\w./-]){re.escape(base)}(?![\w.-])", candidate):
                        answer.add(paths[0])
        return answer

    for headers, rows, _line in tables:
        if {"Script", "Classification"} <= set(headers):
            for row in rows:
                if len(row) != len(headers):
                    continue
                data = dict(zip(headers, row))
                if data["Classification"].strip().lower() in {"ancillary", "helper", "unclear"}:
                    for path in resolve(data["Script"]):
                        strata[path].add("ancillary")
        producer = next((h for h in headers
                         if "producer" in h.lower() or h.lower() == "created by"), None)
        consumer = next((h for h in headers
                         if "consumer" in h.lower() or h.lower() == "consumed by"), None)
        if producer and consumer:
            for row in rows:
                if len(row) != len(headers):
                    continue
                data = dict(zip(headers, row))
                producers, consumers = resolve(data[producer]), resolve(data[consumer])
                for left in producers:
                    for right in consumers:
                        ll = EXTENSIONS.get(Path(left).suffix.lower())
                        rl = EXTENSIONS.get(Path(right).suffix.lower())
                        if ll and rl and ll != rl:
                            strata[left].add("handoff")
                            strata[right].add("handoff")
    manifest_materials = {"pyproject.toml", "environment.yml", "environment.yaml",
                          "pipfile", "renv.lock", "description", "package.json",
                          "package-lock.json", "poetry.lock", "cargo.toml", "cargo.lock"}
    for path in inventory:
        name = Path(path).name.lower()
        dependency_list = re.match(
            r"^(requirements|constraints)[\w.-]*\.(txt|in)$", name)
        if (name in manifest_materials or dependency_list
                or Path(path).suffix.lower() in {".toml", ".yml", ".yaml", ".json",
                                                 ".ini", ".cfg", ".lock"}):
            strata[path].add("ancillary")
    return strata


def _quota(count):
    return max(1, int((Decimal(count) * Decimal("0.10")).quantize(
        Decimal("1"), rounding=ROUND_HALF_UP)))


def select_clean(clean, memberships, cap):
    """Two-pass deterministic stratified sample plus explicit unserved strata."""
    strata = {}
    for path in clean:
        for stratum in memberships[path]:
            strata.setdefault(stratum, set()).add(path)
    languages = sorted(
        (name for name in strata if name.startswith("language:")),
        key=lambda name: (-len(strata[name]), name),
    )
    order = [name for name in ("handoff", "ancillary") if name in strata] + languages
    ordered_files = {
        name: sorted(paths, key=lambda path: hashlib.sha256(
            ("b3b-clean:" + path).encode("utf-8")).hexdigest())
        for name, paths in strata.items()
    }
    quotas = {name: _quota(len(paths)) for name, paths in strata.items()}
    selected = []

    def credit(name):
        return sum(path in strata[name] for path in selected)

    def add_for(name, target):
        while credit(name) < target and len(selected) < cap:
            choice = next((path for path in ordered_files[name]
                           if path not in selected), None)
            if choice is None:
                break
            selected.append(choice)

    for name in order:
        add_for(name, 1)
    for name in order:
        add_for(name, quotas[name])
    unserved = [name for name in order if credit(name) < quotas[name]]
    return selected, unserved, quotas


def _declared_ranges(audit):
    ranges = []
    for name, key, columns in (
            ("code_error_review_plan.md", "Chunk ID", ["Error ID Range"]),
            ("code_error_second_read_plan.md", "Worker ID", ["Error ID Range"])):
        path = audit / "plans" / name
        if not path.is_file() or name.endswith("second_read_plan.md"):
            continue
        lint = lr.Lint()
        alloc, coord = lr.parse_plan(lint, path, key)
        ranges += lr.alloc_ranges(lint, path, alloc or [], columns) + coord
        if lint.errors:
            raise PlanError("; ".join(lint.errors))
    mapping = audit / "_run/detector_mapping.md"
    if mapping.is_file():
        match = re.search(r"Declared detector Error-ID range:\s*(E-\d{4})[–-](E-\d{4})", _read(mapping))
        if match:
            ranges.append(("E", int(match.group(1)[2:]), int(match.group(2)[2:])))
    return ranges


def _render(audit, manifest, register_path=None):
    depth = manifest.get("review_depth", "standard")
    if depth not in CAPS:
        raise PlanError(f"invalid review_depth {depth!r}")
    if _manifest_stage(manifest, "code_b3d").get("status") != "done":
        raise PlanError("code_b3d must be certified done before the second-read plan is built")
    baseline = audit / "_run/snapshots/code_b3d/code_error_register.md"
    if not baseline.is_file():
        raise PlanError(f"missing pre-b3d snapshot proving second-read ordering: {baseline}")
    inventory, plan_text = _inventory(audit)
    coverage, missing = _coverage(audit, manifest, plan_text)
    rows = _register_rows(audit, register_path)
    detector = _detector_paths(audit, rows, inventory)
    flagged = _flagged_paths(rows, inventory, depth) - detector
    eligible = sorted(path for path in inventory if coverage.get(path) == "clean"
                      and path not in detector and path not in flagged)
    memberships = _codemap_strata(audit, inventory)
    sampled, unserved, quotas = select_clean(eligible, memberships, CAPS[depth])
    reasons = [(path, "detector") for path in sorted(detector)]
    reasons += [(path, "flagged") for path in sorted(flagged)]
    reasons += [(path, "clean_sample") for path in sampled]
    if depth == "deep":
        reasons = [item for path_reason in reasons
                   for item in ([path_reason, path_reason]
                                if path_reason[1] in {"detector", "flagged"} else [path_reason])]

    used = _declared_ranges(audit)
    next_id = max([end for letter, _start, end in used if letter == "E"] or [0]) + 1
    allocation_rows = []
    known = {path: [] for path in inventory}
    for row in rows:
        for path in _source_paths(row["Code/Data Source"], inventory):
            known[path].append(row["Error ID"])
    for index, (path, reason) in enumerate(reasons, start=1):
        end = next_id + 49
        if end > 9998:
            raise PlanError("code-error register identifier space exhausted while allocating b3b")
        allocation_rows.append([
            f"SR-{index:03d}", f"`{path}`",
            f"`audit/_code_errors_second_read/sr-{index:03d}.md`",
            f"E-{next_id:04d}–E-{end:04d}", reason,
            "; ".join(sorted(known.get(path, []))) or "—", "—",
        ])
        next_id = end + 1
    coord_end = next_id + 49
    if coord_end > 9998:
        raise PlanError("code-error register identifier space exhausted at b3b merge range")

    columns = lr.SECOND_READ_PLAN_COLS["code"]
    lines = [BEGIN, "", "| " + " | ".join(columns) + " |",
             "| " + " | ".join(["---"] * len(columns)) + " |"]
    lines += ["| " + " | ".join(row) + " |" for row in allocation_rows]
    lines += ["", f"Merge-coordinator range: E-{next_id:04d}–E-{coord_end:04d}", "",
              "## Sampler log (generated)", "",
              f"- Review depth: `{depth}`; clean-sample cap: {CAPS[depth]}.",
              "- Unreviewed files excluded: " + (", ".join(f"`{p}`" for p in missing) or "none."),
              "- Unserved strata: " + (", ".join(f"`{s}`" for s in unserved) or "none."),
              "- Stratum quotas: " + (", ".join(f"`{s}`={quotas[s]}" for s in sorted(quotas)) or "none."),
              "", END]
    return "\n".join(lines), bool(detector or flagged or sampled)


def _replace(text, block):
    pattern = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.S)
    if pattern.search(text):
        return pattern.sub(block, text)
    return text.rstrip() + "\n\n" + block + "\n"


def run(package_root, audit, output, check):
    manifest = _json(audit / "_run/manifest.json")
    register_path = None
    if check:
        # Phase-C erratum: --check is certification evidence and must read the
        # frozen post-b3d baseline (the pre-b3b-merge snapshot), never the
        # live register — canon legitimately evolves at b3b promotion and b6.
        register_path = audit / "_run/snapshots/code_b3b/code_error_register.md"
        if not register_path.is_file():
            raise PlanError(
                f"missing frozen b3b baseline register snapshot: {register_path}"
            )
    block, has_work = _render(audit, manifest, register_path)
    current = _read(output) if output.is_file() else "# Code-error second-read plan\n"
    expected = _replace(current, block)
    if check:
        if not output.is_file() or current != expected:
            raise PlanError(f"{output}: generated second-read allocation is stale or bypassed")
        if not has_work and any(row["Reason"] == "clean_sample" for row in
                                (lr.second_read_allocations(lr.Lint(), output, "code")[0] or [])):
            raise PlanError(f"{output}: skip predicate disagrees with generated work set")
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(expected, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_root", type=Path)
    parser.add_argument("--audit-dir", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.package_root.expanduser().resolve()
    audit = (args.audit_dir or root / "audit").expanduser().resolve()
    output = (args.output or audit / "plans/code_error_second_read_plan.md").expanduser().resolve()
    try:
        run(root, audit, output, args.check)
    except PlanError as exc:
        print(f"SECOND-READ PLAN FAIL: {exc}", file=sys.stderr)
        return 1
    print("SECOND-READ PLAN CHECK PASS" if args.check else f"wrote {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
