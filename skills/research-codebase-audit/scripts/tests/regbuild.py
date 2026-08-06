"""Builders for synthetic registers, plans, and audit directories.

Shared by every test module in this harness. The goal is that a later unit
(U1, U6, U8) can write a failing-first negative test in a few lines:

    a = regbuild.make_b6_claims(tmp_path, [regbuild.claims_row("C-0101", ...)])
    res = regbuild.lint(a, "b6-claims")
    assert res.returncode == 1

Column vocabularies are imported from ``lint_registers.py`` itself so the
builders can never drift from the linter's schema.
"""

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = TESTS_DIR.parent
SKILL_DIR = SCRIPTS_DIR.parent
FIXTURE_DIR = SKILL_DIR / "fixture"

# Path-loaded standalone scripts import sibling modules exactly as they do
# under direct CLI execution.
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


def load_script(name):
    """Import a scripts/ module by path (the scripts dir is not a package)."""
    spec = importlib.util.spec_from_file_location(name, SCRIPTS_DIR / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_lint_mod = load_script("lint_registers")
CLAIMS_COLS = _lint_mod.CLAIMS_COLS
OUTPUT_COLS = _lint_mod.OUTPUT_COLS
ERROR_COLS = _lint_mod.ERROR_COLS
LEDGER_COLS = _lint_mod.LEDGER_COLS
CODE_LEDGER_COLS = _lint_mod.CODE_LEDGER_COLS
WITNESS_OUTCOME_COLS = _lint_mod.WITNESS_OUTCOME_COLS
MF_VERIFICATION_COLS = _lint_mod.MF_VERIFICATION_COLS
PROBE_VERIFICATION_COLS = _lint_mod.PROBE_VERIFICATION_COLS
POST_WITNESS_COLS = _lint_mod.POST_WITNESS_COLS
_mechanism_mod = load_script("mechanism_schema")
_dispatch_mod = load_script("dispatch_tracking")


def run_script(name, *args, cwd=None):
    """Run a scripts/ CLI as a subprocess; returns CompletedProcess (text mode)."""
    cmd = [sys.executable, str(SCRIPTS_DIR / name)] + [str(a) for a in args]
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)


def emit_argument_contracts(auditdir):
    """Write the current deterministic AC raw artifact for a synthetic tree."""
    result = run_script(
        "check_argument_contracts.py", auditdir.root,
        "--audit-dir", auditdir.audit,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return auditdir.audit / "_run/argument_contracts.md"


_pd_mod = load_script("emit_path_derivation_bundles")


def path_derivation_artifact(file, witnesses, *, parsed_files=("source.py",)):
    """Render a PD raw artifact holding one unchecked group, source ``PD-001``.

    ``witnesses`` is a sequence of ``(line, idiom, statement, reason)``.  The
    renderer is the emitter's own, so this builder cannot drift from the
    artifact the production CLI writes.
    """
    report = _pd_mod.Report(_pd_mod.SeedRecord((), True))
    report.parsed_files = list(parsed_files)
    report.groups = [{"file": file, "witnesses": [
        {"line": line, "idiom": idiom, "statement": statement, "reason": reason}
        for line, idiom, statement, reason in witnesses]}]
    return _pd_mod.render_artifact(report)


def emit_path_derivations(auditdir, *entries):
    """Write the deterministic PD raw artifact for a synthetic tree.

    With no ``--entry`` pairs the package documents no invocation, which is
    the ordinary case for the synthetic trees the other units build.
    """
    seed = [flag for entry in entries for flag in ("--entry", entry)] \
        or ["--no-documented-invocation"]
    result = run_script(
        "emit_path_derivation_bundles.py", auditdir.root,
        "--audit-dir", auditdir.audit, *seed,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return auditdir.audit / "_run/path_derivation_bundles.md"


# --------------------------------------------------------------- md builders


def md_table(cols, rows):
    lines = ["| " + " | ".join(cols) + " |",
             "| " + " | ".join(["---"] * len(cols)) + " |"]
    for r in rows:
        lines.append("| " + " | ".join(r) + " |")
    return "\n".join(lines) + "\n"


def register_text(title, cols, rows):
    return f"# {title}\n\n" + md_table(cols, rows)


def claims_row(cid, *, context="Sec. 1 > para 2", quote="a claimed fact",
               used="TRUE", ctype="quantitative_result",
               text="the paper asserts a value", source="`do/analysis.do`",
               outputs="", status="confirmed", severity="", issue="",
               blocked_check="", related=""):
    return [cid, context, quote, used, ctype, text, source, outputs,
            status, severity, issue, blocked_check, related]


def output_row(oid, *, obj="Table 1", context="Sec. 3 > Table 1",
               location="`paper/paper.tex:10`", pattern="`artifacts/tab1.tex`",
               script="`do/analysis.do`", inputs="`output/panel.csv`",
               spec="baseline", claims="", status="mapped"):
    return [oid, obj, context, location, pattern, script, inputs, spec,
            claims, status]


def error_row(eid, *, etype="stale_or_wrong_path",
              source="`py/make_figures.py`",
              location="`py/make_figures.py:5`", status="confirmed",
              severity="2", desc="a description of what appears wrong",
              why="a consequence for the outputs", related=""):
    return [eid, etype, source, location, status, severity, desc, why, related]


# --------------------------------------------------------------- audit dirs


class AuditDir:
    """A synthetic ``audit/`` directory under a tmp root."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.audit = self.root / "audit"
        for sub in ("_run/snapshots", "_staging", "plans"):
            (self.audit / sub).mkdir(parents=True, exist_ok=True)
        # Historical tests address the pre-U6b singleton evidence paths. Keep
        # those names as fixture-only symlinks to the production b6a homes.
        evidence = self.audit / "_run/code_b6a"
        evidence.mkdir(parents=True, exist_ok=True)
        for name in ("dismissal_receipts.md", "witness_outcomes.md"):
            legacy = self.audit / "_run" / name
            if not legacy.exists() and not legacy.is_symlink():
                legacy.symlink_to(Path("code_b6a") / name)

    def write(self, rel, text):
        p = self.audit / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        # Pre-U6b tests intentionally speak the reviewed U6a snapshot name.
        # Mirror only in synthetic fixtures; production accepts b6a names only.
        for old, new in (("_run/snapshots/claims_b6/", "_run/snapshots/claims_b6a/"),
                         ("_run/snapshots/code_b6/", "_run/snapshots/code_b6a/")):
            if str(rel).startswith(old):
                mirror = self.audit / str(rel).replace(old, new, 1)
                mirror.parent.mkdir(parents=True, exist_ok=True)
                mirror.write_text(text, encoding="utf-8")
        return p

    def write_manifest(self, **kv):
        manifest = {
            "mode": "replication", "ladder_level": 1, "warnings": [],
            "effort_map": dict(_dispatch_mod.DEFAULT_EFFORT_MAP),
        }
        manifest.update(kv)
        return self.write("_run/manifest.json", json.dumps(manifest, indent=2))

    def write_register(self, rel, cols, rows, title=None):
        title = title or Path(rel).stem.replace("_", " ").title()
        return self.write(rel, register_text(title, cols, rows))

    def write_claims_plan(self):
        """Minimal b1 claims plan: one worker allocation + coordinator ranges."""
        text = (
            "# Claims review plan\n\n"
            "| Worker ID | Worker Scope | Claim ID Range | Output ID Range | Shard File |\n"
            "| --- | --- | --- | --- | --- |\n"
            "| W1 | full paper | C-0100–C-0999 | O-1000–O-1999 | `audit/_work/w1.md` |\n\n"
            "Merge-coordinator range: C-9000–C-9099\n"
            "Merge-coordinator range: O-9000–O-9099\n"
        )
        return self.write("plans/claims_review_plan.md", text)

    def write_recheck_summary(self, stream, splits=0, merges=0):
        name = ("claims_recheck_summary.md" if stream == "claims"
                else "code_error_recheck_summary.md")
        return self.write(
            name,
            f"# {stream} recheck summary\n\n"
            f"Splits declared: {splits}\nMerges declared: {merges}\n",
        )

    def snapshot(self, key, files):
        """Copy the named staging files into ``_run/snapshots/<key>/``."""
        snap = self.audit / "_run" / "snapshots" / key
        snap.mkdir(parents=True, exist_ok=True)
        for f in files:
            shutil.copy2(self.audit / "_staging" / f, snap / f)
        if key in {"claims_b6", "code_b6"}:
            mirror = self.audit / "_run" / "snapshots" / f"{key}a"
            mirror.mkdir(parents=True, exist_ok=True)
            for f in files:
                shutil.copy2(self.audit / "_staging" / f, mirror / f)
        return snap


def lint(auditdir: AuditDir, stage, shard=None):
    if stage in {"b6-claims", "b6-code"}:
        # Historical U1-U5 fixtures exercise the pre-U6 recheck-merge
        # boundary.  The production CLI refuses manifests without the b6a
        # stage key (design call 8), so these fixtures reach the legacy
        # contract only through the in-process fixture helper.
        return _lint_pre_u6_b6(auditdir, stage)
    args = ["--stage", stage, "--audit-dir", auditdir.audit]
    if shard is not None:
        args += ["--shard", shard]
    return run_script("lint_registers.py", *args)


def _lint_pre_u6_b6(auditdir: AuditDir, stage):
    """Run the pre-U6 b6 fixture validation in-process, CLI-shaped output."""
    manifest = {}
    manifest_path = auditdir.audit / "_run/manifest.json"
    lint_state = _lint_mod.Lint()
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            lint_state.fail(f"{manifest_path}: invalid JSON")
    stream = stage.split("-")[1]
    _lint_mod._stage_b6_pre_u6_fixture(lint_state, auditdir.audit, stream, manifest)
    lines = [f"WARNING [{stage}]: {warning}" for warning in lint_state.warnings]
    if lint_state.errors:
        lines.append(f"LINT FAIL [{stage}] — {len(lint_state.errors)} finding(s):")
        lines.extend(f"  - {error}" for error in lint_state.errors)
        returncode = 1
    else:
        lines.append(f"LINT PASS [{stage}]")
        returncode = 0
    return subprocess.CompletedProcess(
        args=["<in-process>", stage], returncode=returncode,
        stdout="\n".join(lines) + "\n", stderr="")


def make_b0(tmp_path) -> AuditDir:
    """A minimal audit dir that lints green at b0 (all registers empty)."""
    a = AuditDir(tmp_path)
    a.write_manifest()
    a.write_register("claims_register.md", CLAIMS_COLS, [])
    a.write_register("output_register.md", OUTPUT_COLS, [])
    a.write_register("code_error_register.md", ERROR_COLS, [])
    a.write("audit_readme.md", "# Audit readme\n\nVocabulary and rules.\n")
    a.write("CODEMAP.md",
            "# CODEMAP\n\nS-0001 do/analysis.do\nD-0001 data/households.csv\n"
            "B-0001 build step\n\nPRECONDITIONS: 5/5\n")
    return a


CONVENTIONS_COLS = ["Convention", "Category", "Stated Definition",
                    "Sites Already Seen"]


def conventions_row(name, *, category="fiscal_year_or_sample_window_boundary",
                    definition="fiscal year begins in July (C-0142)",
                    sites="`do/build_panel.do`; C-0142; C-0181"):
    return [name, category, definition, sites]


def make_conventions_b4_code(tmp_path, convention_rows=None,
                             include_artifact=True) -> AuditDir:
    """A minimal audit dir carrying the optional b3c conventions artifact.

    Exercises ``check_conventions_artifact`` (advisory) via ``--stage b4-code``.
    The recheck plan is intentionally absent, so the *overall* stage fails; the
    conventions check runs first and independently, and its WARNING/ silence is
    what these tests assert on. Pass ``include_artifact=False`` to omit the file.
    """
    a = AuditDir(tmp_path)
    a.write_manifest()
    if include_artifact:
        rows = [] if convention_rows is None else list(convention_rows)
        a.write("_run/conventions.md",
                register_text("Shared conventions", CONVENTIONS_COLS, rows))
    return a


def make_b6_claims(tmp_path, claims_rows, output_rows=()) -> AuditDir:
    """A minimal audit dir that reaches the b6-claims boundary cleanly.

    The staging registers equal the b6 snapshot (no splits/merges), so the
    boundary lints green as long as *claims_rows* themselves are valid.
    """
    a = AuditDir(tmp_path)
    a.write_manifest()
    a.write_claims_plan()
    a.write(
        "plans/claims_recheck_plan.md",
        recheck_plan_text("claims", [], []),
    )
    a.write_register("_staging/claims_register.md", CLAIMS_COLS,
                     list(claims_rows), title="Claims register")
    a.write_register("_staging/output_register.md", OUTPUT_COLS,
                     list(output_rows), title="Output register")
    a.snapshot("claims_b6", ["claims_register.md", "output_register.md"])
    a.write_recheck_summary("claims")
    return a


# --------------------------------------------------------------- U8 builders
#
# b4 recheck plans, b3b second-read shards, b5 recheck ledgers, and b9
# workbooks — the negative/positive homes for the four U8 lint checks.

LEDGER_COLS_ = LEDGER_COLS  # re-export for callers importing from regbuild


def ledger_row(rid, *, status="candidate", severity="3",
               evidence="`py/make_figures.py:5` reads a stale path",
               level="static_source_verified", verdict="confirmed_error",
               change="set status=confirmed", impact="figure 2 mislabelled",
               note="author-facing note"):
    return [rid, status, severity, evidence, level, verdict, change,
            impact, note]


def code_ledger_row(rid, *, status="candidate", severity="2", evidence="source",
                    level="static_source_verified", verdict="confirmed_error",
                    change="set status=confirmed", impact="output impact",
                    note="documented disposition", proposed_status=None,
                    proposed_severity=None,
                    accepted_type="sample_filter_or_flag_error",
                    accepted_mechanism="guard changes the selected sample",
                    witness_ids="—", duplicate_target="—", patches="—",
                    record_ids="—"):
    if proposed_status is None:
        proposed_status = {
            "confirmed_error": "confirmed", "not_error": "not_error",
            "confirmation_needed": "confirmation_needed", "blocked": "blocked",
            "deferred": "blocked", "duplicate": f"duplicate_of:{duplicate_target}",
        }[verdict]
    if proposed_severity is None:
        proposed_severity = ("—" if verdict in {"not_error", "duplicate"}
                             else severity)
    return ledger_row(
        rid, status=status, severity=severity, evidence=evidence, level=level,
        verdict=verdict, change=change, impact=impact, note=note,
    ) + [
        proposed_status, proposed_severity, accepted_type, accepted_mechanism,
        witness_ids, duplicate_target, patches, record_ids,
    ]


def witness_outcome_row(channel, source_id, witness_id, *,
                        verdict="confirmed_error", severity="2",
                        duplicate_target="—", mech_class="sample_filter_or_flag_error",
                        mech_object="sample_ok", relation="wrong_value",
                        expected="1", actual="0"):
    return [channel, source_id, witness_id, verdict, mech_class, mech_object,
            relation, expected, actual, severity, duplicate_target]


def recheck_plan_text(stream, inventory, clusters, mappings=()):
    """A recheck plan (b4 output): inventory table + cluster table + vocab pointer.

    *inventory* is a list of (ID, Reason, Likely Evidence) tuples; *clusters* is a
    list of (Cluster ID, Cluster Name, Assigned IDs, Shard File) tuples.
    """
    inv = md_table(["ID", "Reason", "Likely Evidence"],
                   [list(r) for r in inventory])
    clu = md_table(["Cluster ID", "Cluster Name", "Assigned IDs", "Shard File"],
                   [list(r) for r in clusters])
    mapping = md_table(
        ["Bundle ID", "Error ID", "Mapping Kind"],
        [list(r) for r in mappings],
    )
    return (f"# {stream} recheck plan\n\n"
            "## Inventory\n\n" + inv + "\n"
            + ("## Legacy fixture-only definition/use mapping\n\n" + mapping + "\n"
               if stream == "code" else "")
            + "## Clusters\n\n" + clu + "\n"
            + "Verdict/evidence vocabulary: `audit/audit_readme.md`.\n")


def detector_mapping_artifact(mappings=()):
    rows = []
    for i, item in enumerate(mappings, start=1):
        source_id, error_id, kind = item
        channel = source_id.split("-", 1)[0]
        rows.append([channel, source_id, f"{channel}W-{i:012x}", error_id,
                     kind, f"do/build_panel.do:{20+i}"])
    du_rows = [row for row in rows if row[0] == "DU"]
    mf_rows = [row for row in rows if row[0] == "MF"]
    cv_rows = [row for row in rows if row[0] == "CV"]
    ac_rows = [row for row in rows if row[0] == "AC"]
    pd_rows = [row for row in rows if row[0] == "PD"]
    cols = ["Channel", "Source ID", "Witness ID", "Error ID", "Mapping Kind", "Site Anchor"]
    def section(marker, section_rows, zero):
        return marker + "\n\n" + (md_table(cols, section_rows) if section_rows else zero) + "\n"
    return (
        "# Detector mapping\n\nDeclared detector Error-ID range: E-7000–E-7999\n\n"
        + section("<!-- GENERATED:DU -->", du_rows,
                  "No standard DU rows: the definition/use detector emitted zero standard candidates.")
        + section("<!-- GENERATED:MF -->", mf_rows,
                  "No standard MF rows: the manifest detector emitted zero standard candidates.")
        + section("<!-- CONDUCTOR:CV -->", cv_rows,
                  "No channel-mapped CV rows: no conventions were consolidated for this run.")
        + section("<!-- GENERATED:AC -->", ac_rows,
                  "No channel-mapped AC rows: the argument-contract checker emitted zero findings.")
        + section("<!-- GENERATED:PD -->", pd_rows,
                  "No channel-mapped PD rows: the path-derivation sweep emitted zero candidates.")
    )


def definition_use_artifact(bundle_ids=(), *, standard_bundle_ids=None,
                            advisory_bundle_ids=(), files_scanned=1,
                            producer_groups=None):
    standard_bundle_ids = (bundle_ids if standard_bundle_ids is None
                           else standard_bundle_ids)
    producer_groups = (len(standard_bundle_ids) if producer_groups is None
                       else producer_groups)

    def rows_for(bundle_ids, variable):
        rows = []
        for i, bid in enumerate(bundle_ids, start=1):
            rows.append([
                f"`{bid}`", f"`DUW-{i:012x}`",
                f"`(do/build_panel.do, {10+i}, {20+i}, {variable})`",
                variable, "boolean_gen", f"`do/build_panel.do:{10+i}`",
                f"`gen {variable} = consent != \"\"`",
                f"`do/build_panel.do:{20+i}`",
                f"`keep if {variable} == 1 & wave == 1`",
                f"`{variable} == 1 & wave == 1`", "context", "review narrowing",
            ])
        return rows

    standard_rows = rows_for(standard_bundle_ids, "consent_ok")
    advisory_rows = rows_for(advisory_bundle_ids, "advisory_ok")
    cols = [
        "Bundle ID", "Witness ID", "Identity Tuple", "Variable", "Producer Shape",
        "Definition Site", "Producer Statement", "Consumer Site",
        "Consumer Statement", "Full Guard", "Code/Comment Context",
        "Obligation Question",
    ]
    standard_table = md_table(cols, standard_rows)
    advisory_table = md_table(cols, advisory_rows)
    return (
        "# Stata definition/use bundles\n\n## Scan summary\n\n"
        f"- Stata files scanned: {files_scanned}\n"
        f"- Standard producer groups (file + gen line + variable): {producer_groups}\n"
        f"- Standard candidates: {len(standard_rows)}\n"
        f"- Advisory candidates: {len(advisory_rows)}\n\n"
        "## Candidate findings\n\n" + standard_table + "\n"
        "## Advisory candidates\n\n" + advisory_table
    )
def make_b4(tmp_path, stream, *, canon_claims=(), canon_outputs=(),
            canon_errors=(), inventory=None, clusters=None,
            review_depth="standard", bundle_ids=(), mappings=(),
            include_definition_use_artifact=True) -> AuditDir:
    """A minimal audit dir that reaches the b4-<stream> boundary.

    Canonical registers sit at ``audit/`` (b4 reads them via canon_ids). The
    recheck plan is written from *inventory* / *clusters*; if either is None it
    is derived automatically to cover every substantive canon ID in one cluster.
    """
    a = AuditDir(tmp_path)
    a.write_manifest(review_depth=review_depth)
    if stream == "claims":
        a.write_register("claims_register.md", CLAIMS_COLS,
                         list(canon_claims), title="Claims register")
        a.write_register("output_register.md", OUTPUT_COLS,
                         list(canon_outputs), title="Output register")
        plan_name = "plans/claims_recheck_plan.md"
    else:
        a.write_register("code_error_register.md", ERROR_COLS,
                         list(canon_errors), title="Code-error register")
        plan_name = "plans/code_error_recheck_plan.md"
        if include_definition_use_artifact:
            a.write("_run/definition_use_bundles.md", definition_use_artifact(bundle_ids))
        a.write("_run/detector_mapping.md", detector_mapping_artifact(mappings))
    if inventory is None or clusters is None:
        auto_inv, auto_clu = _auto_recheck(stream, canon_claims, canon_errors)
        inventory = auto_inv if inventory is None else inventory
        clusters = auto_clu if clusters is None else clusters
    a.write(plan_name, recheck_plan_text(stream, inventory, clusters, mappings))
    return a


def make_b6_code(tmp_path, *, before_rows, final_rows, inventory, clusters,
                 mappings, ledger_rows) -> AuditDir:
    """A b6-code boundary with real plan, ledger, snapshot, and staging."""
    a = AuditDir(tmp_path)
    shards = {
        cluster[3].strip("`"): {"status": "done", "retries": 0}
        for cluster in clusters
    }
    a.write_manifest(stages={
        "code_b5": {"status": "done", "retries": 0, "shards": shards},
    })
    a.write("plans/code_error_review_plan.md", _code_b1_plan())
    a.write("plans/code_error_recheck_plan.md",
            recheck_plan_text("code", inventory, clusters, mappings))
    a.write("_run/detector_mapping.md", detector_mapping_artifact(mappings))
    a.write_register("_staging/code_error_register.md", ERROR_COLS,
                     list(final_rows), title="Code-error register")
    a.write_register("_run/snapshots/code_b6/code_error_register.md", ERROR_COLS,
                     list(before_rows), title="Code-error register")
    a.write_recheck_summary("code")
    final_by_id = {
        dict(zip(ERROR_COLS, row))["Error ID"]: dict(zip(ERROR_COLS, row))
        for row in final_rows
    }
    upgraded = []
    for row in ledger_rows:
        if len(row) == len(CODE_LEDGER_COLS):
            upgraded.append(row)
            continue
        data = dict(zip(LEDGER_COLS, row))
        witness_ids = "; ".join(
            f"{source.split('-', 1)[0]}W-{index:012x}"
            for index, (source, mapped_id, _kind) in enumerate(mappings, start=1)
            if mapped_id == data["ID"])
        upgraded.append(code_ledger_row(
            data["ID"], status=data["Current Status"],
            severity=data["Current Severity"], evidence=data["Evidence Checked"],
            level=data["Evidence Level"], verdict=data["Verdict"],
            change=data["Proposed Register Change"],
            impact=data["Pipeline/Output Impact"], note=data["Proposed Note"],
            proposed_severity=(
                final_by_id.get(data["ID"], {}).get("Severity")
                or data["Current Severity"]
                if data["Verdict"] == "confirmed_error" else None
            ),
            witness_ids=witness_ids or "—",
        ))
    ledger_by_id = {row[0]: dict(zip(CODE_LEDGER_COLS, row)) for row in upgraded}
    pre_rows, post_rows = [], []
    for index, (source, mapped_id, _kind) in enumerate(mappings, start=1):
        channel = source.split("-", 1)[0]
        witness = f"{channel}W-{index:012x}"
        anchor = f"do/build_panel.do:{20 + index}"
        ledger = ledger_by_id.get(mapped_id)
        if ledger is None:
            continue
        verdict = ledger["Verdict"]
        proposed_severity = ledger["Proposed Severity"] or "—"
        if verdict in {"blocked", "deferred", "confirmation_needed"}:
            mechanism = "—"
        else:
            pre = witness_outcome_row(
                channel, source, witness, verdict=verdict,
                severity=proposed_severity,
            )
            pre_rows.append(pre)
            mechanism = _mechanism_mod.canonicalize_mechanism(
                *pre[4:9], register="code_errors", anchor=anchor,
                projection=_mechanism_mod.EMPTY_PROJECTION,
            ).sidecar
        post_rows.append([
            channel, source, witness, verdict, mechanism, proposed_severity,
            "—", ledger["Duplicate Target"] or "—",
        ])
    shard_text = register_text("Recheck ledger", CODE_LEDGER_COLS, upgraded)
    shard_text += "\n### Witness outcomes\n\n" + md_table(
        WITNESS_OUTCOME_COLS, pre_rows)
    shard_text += "\n### Verification records\n\nNo verification records.\n"
    a.write("_code_error_recheck/k1.md", shard_text)
    a.write("_run/dismissal_receipts.md",
            "# Dismissal receipts\n\n"
            "No mapped not_error dismissal receipts were required.\n")
    a.write("_run/witness_outcomes.md",
            "# Witness outcomes\n\n" + md_table(POST_WITNESS_COLS, post_rows)
            + "\n### Assembled dismissals\n\n"
            "No mapped Error IDs were assembled as not_error.\n")
    return a


def _substantive_claim(row):
    d = dict(zip(CLAIMS_COLS, row))
    return bool(d["Severity"]) or d["Status"] == "unclear"


def _substantive_error(row):
    d = dict(zip(ERROR_COLS, row))
    return d["Status"] == "candidate" or (
        d["Status"] == "confirmed" and d["Severity"] in {"3", "4"})


def _auto_recheck(stream, canon_claims, canon_errors):
    """Derive a well-formed inventory + single cluster covering every required ID."""
    if stream == "claims":
        req = [dict(zip(CLAIMS_COLS, r))["Claim ID"]
               for r in canon_claims if _substantive_claim(r)]
    else:
        req = [dict(zip(ERROR_COLS, r))["Error ID"]
               for r in canon_errors if _substantive_error(r)]
    inv = [(i, "issue-flagged", "static") for i in req]
    clu = [("K1", "cluster one", "; ".join(req), "`audit/_recheck/k1.md`")] if req else []
    return inv, clu


def _shard_footer_text(register_ids, *, code=False):
    ids = list(register_ids)
    coverage = (
        f"findings: {'; '.join(ids)}" if code and ids else
        "clean" if code else
        "Every item in scope has a row or a skip note."
    )
    footer_rows = [
        [f"OBS-{index:04d}", "candidate", register_id, "row retained", ""]
        for index, register_id in enumerate(ids, start=1)
    ]
    return (
        "\n### Coverage\n\n"
        + (md_table(["Script", "Outcome"], [["`py/x.py`", coverage]])
           if code else f"{coverage}\n")
        + "\n"
        "### Footer dispositions\n\n"
        + md_table(_lint_mod.FOOTER_COLS, footer_rows)
    )


def make_b3b_shard(tmp_path, stream, *, claims_rows=(), output_rows=(),
                   error_rows=(), claim_range="C-2000–C-2099",
                   output_range="O-2000–O-2099", error_range="E-2000–E-2099",
                   shard_rel=None, omit_output_table=False) -> tuple:
    """Build a b3b second-read shard plus the second-read plan referencing it.

    Returns (AuditDir, shard_path). The shard uses canonical columns, carries a
    footer, and its worker allocation range is disjoint from the default b1 plan.
    """
    a = AuditDir(tmp_path)
    a.write_manifest()
    if stream == "claims":
        shard_rel = shard_rel or "_work_second_read/w1.md"
        plan = (
            "# Claims second-read plan\n\n"
            "| Worker ID | File/Section Scope | Shard File | Claim ID Range | "
            "Output ID Range | Reason | Known Findings | Assigned Handoff IDs |\n"
            "| --- | --- | --- | --- | --- | --- | --- | --- |\n"
            f"| W1 | sec 4 | `audit/{shard_rel}` | {claim_range} | "
            f"{output_range} | detector | C-0142 |  |\n"
        )
        a.write("plans/claims_second_read_plan.md", plan)
        # a b1 plan is also read for range-disjointness
        a.write_claims_plan()
        body = register_text("Claims", CLAIMS_COLS, list(claims_rows))
        if not omit_output_table:
            body += "\n" + register_text("Outputs", OUTPUT_COLS, list(output_rows))
    else:
        shard_rel = shard_rel or "_code_errors_second_read/w1.md"
        plan = (
            "# Code-error second-read plan\n\n"
            "| Worker ID | Script Scope | Shard File | Error ID Range | "
            "Reason | Known Findings | Assigned Handoff IDs |\n"
            "| --- | --- | --- | --- | --- | --- | --- |\n"
            f"| W1 | `py/x.py` | `audit/{shard_rel}` | {error_range} | "
            "detector | E-0001 |  |\n"
        )
        a.write("plans/code_error_second_read_plan.md", plan)
        a.write("plans/code_error_review_plan.md", _code_b1_plan())
        body = register_text("Code errors", ERROR_COLS, list(error_rows))
    register_ids = [row[0] for row in (
        list(claims_rows) + list(output_rows) if stream == "claims"
        else list(error_rows)
    )]
    shard = a.write(
        shard_rel,
        body + _shard_footer_text(register_ids, code=(stream == "code")),
    )
    return a, shard


def _code_b1_plan():
    return (
        "# Code-error review plan\n\n"
        "| Chunk ID | Script Scope | Error ID Range | Shard File |\n"
        "| --- | --- | --- | --- |\n"
        "| K1 | `py/x.py` | E-0100–E-0999 | `audit/_code_errors/k1.md` |\n\n"
        "Merge-coordinator range: E-9000–E-9099\n\n"
        "| Script | Chunk |\n"
        "| --- | --- |\n"
        "| `py/x.py` | K1 |\n"
    )


def make_b5(tmp_path, stream, *, ledger_rows, assigned_ids=None,
            ladder_level=1, shard_rel=None) -> tuple:
    """Build a b5 recheck ledger shard plus the recheck plan that assigns it.

    Returns (AuditDir, shard_path). *ledger_rows* are LEDGER_COLS rows; the
    recheck plan's single cluster is assigned every ledger ID (or *assigned_ids*).
    """
    a = AuditDir(tmp_path)
    a.write_manifest(ladder_level=ladder_level)
    ids = assigned_ids if assigned_ids is not None else [r[0] for r in ledger_rows]
    shard_rel = shard_rel or (
        "_recheck/k1.md" if stream == "claims" else "_code_error_recheck/k1.md")
    inv = [(i, "issue-flagged", "static") for i in ids]
    clu = [("K1", "cluster one", "; ".join(ids), f"`audit/{shard_rel}`")]
    plan_name = ("plans/claims_recheck_plan.md" if stream == "claims"
                 else "plans/code_error_recheck_plan.md")
    a.write(plan_name, recheck_plan_text(stream, inv, clu))
    columns = LEDGER_COLS
    output_rows = list(ledger_rows)
    body = ""
    if stream == "code":
        columns = CODE_LEDGER_COLS
        output_rows = [
            row if len(row) == len(columns) else code_ledger_row(
                row[0], status=row[1], severity=row[2], evidence=row[3],
                level=row[4], verdict=row[5], change=row[6], impact=row[7],
                note=row[8])
            for row in output_rows
        ]
        a.write("_run/detector_mapping.md", detector_mapping_artifact([]))
        body = ("\n### Witness outcomes\n\n" + md_table(WITNESS_OUTCOME_COLS, [])
                + "\n### Verification records\n\nNo verification records.\n")
    shard = a.write(shard_rel, register_text("Recheck ledger", columns,
                                             output_rows) + body)
    return a, shard


def rewrite_pass_cols(base_cols, rows, names):
    """Return (cols, rows) in the faithful post-b8 rewrite shape.

    The b8 rewrite pass (registers.md 'Rewrite-pass columns') keeps the
    author-facing text under each source column's original name and INSERTS an
    ``<name> Original`` column immediately after it — e.g.
    ``Issue Description | Issue Description Original | Blocked Check``. It does
    NOT append the ``*Original`` columns at the end; a builder that appends
    produces a header that is still a superset of the canonical columns but in
    the wrong order, which a prefix-match parser tolerates and an
    order-independent (set-containment) parser handles identically — so append
    hides ordering bugs the real interleaved header exposes.
    """
    cols = list(base_cols)
    out = [list(r) for r in rows]
    for name in names:
        i = cols.index(name)
        cols.insert(i + 1, f"{name} Original")
        for r in out:
            r.insert(i + 1, r[i])
    return cols, out


CROSS_LINK_SUMMARY_STUB = (
    "# Cross-link summary\n\n## Status conflicts\n\nnone\n\n"
    "## Escalated mapped claims\n\nnone\n\n"
    "## Severity divergences\n\nnone\n"
)


def make_b7(tmp_path, *, claims_rows=(), error_rows=(), summary=None) -> AuditDir:
    """A minimal audit dir that reaches the b7 (cross-link) boundary cleanly.

    Staging and the b7 snapshot carry identical base-column registers (the
    cross-link pass changed nothing), and the cross-link summary is a clean
    stub unless *summary* overrides it. ``make_b8`` cannot serve here:
    ``stage_b7`` loads ``_run/snapshots/b7/``, which ``make_b8`` does not
    create. This is the home for the b7 overlap-conflict advisory tests.
    """
    a = AuditDir(tmp_path)
    a.write_manifest()
    a.write_register("_staging/claims_register.md", CLAIMS_COLS,
                     list(claims_rows), title="Claims register")
    a.write_register("_staging/code_error_register.md", ERROR_COLS,
                     list(error_rows), title="Code-error register")
    a.snapshot("b7", ["claims_register.md", "code_error_register.md"])
    a.write("register_cross_link_summary.md",
            summary if summary is not None else CROSS_LINK_SUMMARY_STUB)
    return a


def make_b8(tmp_path, *, claims_rows=(), error_rows=()) -> AuditDir:
    """A minimal audit dir that reaches the b8 (finalize/rewrite) boundary cleanly.

    Staging carries the post-rewrite registers with each ``*Original`` column
    inserted after its source column (the faithful rewrite shape) and the
    rewrite a no-op (rewritten text equals the frozen original); the b8
    snapshot carries the pre-rewrite base-column registers;
    the output register and cross-link summary are clean stubs. As long as
    *claims_rows* carry no confirmed-claim↔confirmed-error links, the boundary
    lints green — the home for the finalize-stage advisory checks (U1
    adjudication, U5 filename-parameter).
    """
    a = AuditDir(tmp_path)
    a.write_manifest()
    a.write_register("output_register.md", OUTPUT_COLS, [],
                     title="Output register")
    a.write("register_cross_link_summary.md",
            "# Cross-link summary\n\n## Status conflicts\n\nnone\n\n"
            "## Escalated mapped claims\n\nnone\n\n"
            "## Severity divergences\n\nnone\n")
    c_cols, c_stage = rewrite_pass_cols(
        CLAIMS_COLS, claims_rows, ["Issue Description"])
    a.write_register("_staging/claims_register.md", c_cols, c_stage,
                     title="Claims register")
    e_cols, e_stage = rewrite_pass_cols(
        ERROR_COLS, error_rows, ["Error Description", "Why It Matters"])
    a.write_register("_staging/code_error_register.md", e_cols, e_stage,
                     title="Code-error register")
    a.write_register("_run/snapshots/b8/claims_register.md", CLAIMS_COLS,
                     [list(r) for r in claims_rows], title="Claims register")
    a.write_register("_run/snapshots/b8/code_error_register.md", ERROR_COLS,
                     [list(r) for r in error_rows], title="Code-error register")
    return a


def make_b9(tmp_path, *, claims_rows=(), error_rows=(), mode="replication",
            populate_staging=True) -> AuditDir:
    """A minimal audit dir that reaches the b9 boundary.

    Writes the canonical registers, populates ``_staging/`` with the same
    (frozen b8) registers, and runs the *real* ``export_xlsx.py`` to build
    ``code_review.xlsx`` — so a b9 test starts from a workbook the exporter
    actually produced, then a test corrupts one cell to prove the check fires.
    """
    a = AuditDir(tmp_path)
    a.write_manifest(mode=mode)
    a.write_register("code_error_register.md", ERROR_COLS,
                     list(error_rows), title="Code-error register")
    if mode == "replication":
        a.write_register("claims_register.md", CLAIMS_COLS,
                         list(claims_rows), title="Claims register")
        a.write_register("output_register.md", OUTPUT_COLS, [],
                         title="Output register")
    if populate_staging:
        # b8 leaves _staging/ populated as the frozen b8 state; the b9 check
        # requires the non-empty frozen registers to still be there.
        a.write_register("_staging/code_error_register.md", ERROR_COLS,
                         list(error_rows), title="Code-error register")
        if mode == "replication":
            a.write_register("_staging/claims_register.md", CLAIMS_COLS,
                             list(claims_rows), title="Claims register")
    if mode == "replication":
        a.write("late_observations_claims.md",
                "# Late observations — claims\n\nNo late observations.\n\n"
                "## Dispositions\n\nNo dispositions.\n")
    a.write("late_observations_code.md",
            "# Late observations — code\n\nNo late observations.\n\n"
            "## Dispositions\n\nNo dispositions.\n")
    out = a.audit / "code_review.xlsx"
    res = run_script("export_xlsx.py", "--audit-dir", a.audit,
                     "--mode", mode, "-o", out)
    if res.returncode != 0:  # pragma: no cover - surfaces a builder misuse
        raise AssertionError(f"export_xlsx failed in make_b9:\n{res.stdout}\n{res.stderr}")
    return a
