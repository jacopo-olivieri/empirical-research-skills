#!/usr/bin/env python3
"""Certify research-codebase-audit stage state from on-disk evidence.

This script is the sole writer of the manifest's ``stages`` and
``run_identity`` blocks.  Run it from the audited package root, or pass that
root explicitly with ``--package-root``.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from mechanism_schema import MECHANISM_SCHEMA_VERSION
from source_projection import iter_in_scope_entries
import build_detector_mapping as detector_mapping
import dispatch_tracking
import evidence_views
import lint_registers as registers
import paper_sources
import severity_token_rulings
import severity_tokens


SCRIPT_DIR = Path(__file__).resolve().parent
OBLIGATIONS_PATH = SCRIPT_DIR / "stage_obligations.json"
CERTIFIED_REGISTER_EVIDENCE = {
    "b0": (
        "claims_register.md", "output_register.md", "code_error_register.md"),
    "claims_b4": ("claims_register.md", "output_register.md"),
    "claims_b5": ("claims_register.md", "output_register.md"),
    "code_b4": ("code_error_register.md",),
    "code_b5": ("code_error_register.md",),
}
CERTIFIED_EVIDENCE_VERSION = 1

FULL_STAGES = (
    "b0",
    "claims_b1", "claims_b2", "claims_b3", "claims_b3c", "claims_b3b",
    "claims_adjudication",
    "claims_b4", "claims_b5", "claims_b6a", "claims_b5s", "claims_b6b",
    "code_b1", "code_b2", "code_b3", "code_b3d", "code_b3b", "code_b4", "code_b5",
    "code_b6a", "code_b5s", "code_b6b",
    "bC", "claims_adjudication_lineage", "b7", "severity_token_rulings",
    "b8", "b9",
)
CODE_ONLY_STAGES = (
    "b0",
    "code_b1", "code_b2", "code_b3", "code_b3d", "code_b3b", "code_b4", "code_b5",
    "code_b6a", "code_b5s", "code_b6b",
    "bC", "b8", "b9",
)

LEGAL_START_STATES = {"pending", "blocked"}
VALID_STAGE_STATES = {"pending", "running", "done", "blocked"}

VALIDATORS = {
    "lint:b0": "b0",
    "lint:b1-claims": "b1-claims",
    "lint:b2-claims": "b2-claims",
    "lint:b3-claims": "b3-claims",
    "lint:b3b-claims": "b3b-claims",
    "lint:b4-claims": "b4-claims",
    "lint:b5-claims": "b5-claims",
    "lint:b6a-claims": "b6a-claims",
    "lint:b5s-claims": "b5s-claims",
    "lint:b6b-claims": "b6b-claims",
    "lint:b1-code": "b1-code",
    "lint:b2-code": "b2-code",
    "lint:b3-code": "b3-code",
    "lint:b3b-code": "b3b-code",
    "lint:b4-code": "b4-code",
    "lint:b5-code": "b5-code",
    "lint:b6a-code": "b6a-code",
    "lint:b5s-code": "b5s-code",
    "lint:b6b-code": "b6b-code",
    "lint:bC": "bC",
    "lint:b7": "b7",
    "lint:severity-token-rulings": "severity_token_rulings",
    "lint:b8": "b8",
    "lint:b9": "b9",
}
SHARD_VALIDATORS = {
    "lint:b2-claims", "lint:b5-claims", "lint:b5s-claims",
    "lint:b2-code", "lint:b5-code", "lint:b5s-code",
}
ZERO_WORK_SHARD_VALIDATORS = {"lint:b5s-claims", "lint:b5s-code"}


class CertificationError(RuntimeError):
    """A command cannot safely perform its requested state transition."""


def _is_certified_evidence_version(value):
    """Accept only the exact JSON integer version, never bools or floats."""
    return type(value) is int and value == CERTIFIED_EVIDENCE_VERSION


def canonical_package_root(path):
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise CertificationError(f"package root is not a directory: {root}")
    return root


def audit_paths(package_root):
    audit = package_root / "audit"
    run_dir = audit / "_run"
    return audit, run_dir, run_dir / "manifest.json", run_dir / "RUNNING"


def read_manifest(package_root):
    _, _, manifest_path, _ = audit_paths(package_root)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CertificationError(f"manifest does not exist: {manifest_path}") from exc
    except json.JSONDecodeError as exc:
        raise CertificationError(f"manifest is not valid JSON: {manifest_path}: {exc}") from exc
    if not isinstance(manifest, dict):
        raise CertificationError(f"manifest must contain a JSON object: {manifest_path}")
    return manifest


def write_manifest_atomic(package_root, manifest):
    """Serialize the complete manifest and atomically replace the old file."""
    _, run_dir, manifest_path, _ = audit_paths(package_root)
    run_dir.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(manifest, indent=2) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=".manifest.", suffix=".tmp", dir=run_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, manifest_path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def _sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _certified_evidence_dir(audit, stage):
    return audit / "_run" / "certified_stage_evidence" / stage


def _write_bytes_atomic(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def _capture_certified_stage_evidence(package_root, stage, entry):
    """Freeze and hash the mutable register inputs accepted for one stage."""
    filenames = CERTIFIED_REGISTER_EVIDENCE.get(stage)
    if filenames is None:
        return
    audit, _, _, _ = audit_paths(package_root)
    evidence_dir = _certified_evidence_dir(audit, stage)
    digests = {}
    for filename in filenames:
        source = audit / filename
        if source.is_symlink() or not source.is_file():
            raise CertificationError(
                f"cannot freeze certified evidence for {stage}: "
                f"{source} is not a regular file"
            )
        try:
            payload = source.read_bytes()
        except OSError as exc:
            raise CertificationError(
                f"cannot freeze certified evidence for {stage}: {source}: {exc}"
            ) from exc
        if not payload:
            raise CertificationError(
                f"cannot freeze certified evidence for {stage}: {source} is empty"
            )
        destination = evidence_dir / filename
        _write_bytes_atomic(destination, payload)
        digests[filename] = hashlib.sha256(payload).hexdigest()
    entry["certified_evidence"] = {
        "version": CERTIFIED_EVIDENCE_VERSION,
        "registers": digests,
    }


def _certified_stage_evidence_failures(package_root, manifest, stage, entry):
    filenames = CERTIFIED_REGISTER_EVIDENCE.get(stage)
    if filenames is None:
        return []
    failures = []
    if not _is_certified_evidence_version(
            manifest.get("certified_stage_evidence_version")):
        failures.append(
            f"run is missing certified stage-era evidence version "
            f"{CERTIFIED_EVIDENCE_VERSION}"
        )
    metadata = entry.get("certified_evidence")
    if not isinstance(metadata, dict):
        failures.append(
            f"stage {stage!r} is missing certified stage-era evidence")
        return failures
    if not _is_certified_evidence_version(metadata.get("version")):
        failures.append(
            f"stage {stage!r} has unsupported certified evidence version "
            f"{metadata.get('version')!r}"
        )
        return failures
    registers = metadata.get("registers")
    expected_names = set(filenames)
    if not isinstance(registers, dict) or set(registers) != expected_names:
        failures.append(
            f"stage {stage!r} certified register evidence is malformed; "
            f"expected exactly {sorted(expected_names)}"
        )
        return failures
    audit, _, _, _ = audit_paths(package_root)
    evidence_dir = _certified_evidence_dir(audit, stage)
    for filename in filenames:
        path = evidence_dir / filename
        expected_digest = registers.get(filename)
        if (not isinstance(expected_digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected_digest)
                or path.is_symlink()
                or not path.is_file()):
            failures.append(
                f"stage {stage!r} certified evidence is missing or malformed: {path}"
            )
            continue
        try:
            actual_digest = _sha256_file(path)
        except OSError as exc:
            failures.append(
                f"stage {stage!r} certified evidence cannot be read: {path}: {exc}"
            )
            continue
        if actual_digest != expected_digest:
            failures.append(
                f"stage {stage!r} certified evidence was edited after certification: "
                f"{path}"
            )
    return failures


def _certified_evidence_root_failures(manifest):
    """Require the run-level evidence contract for every initialized run."""
    stages = manifest.get("stages")
    if not isinstance(stages, dict):
        return []
    if not _is_certified_evidence_version(
            manifest.get("certified_stage_evidence_version")):
        return [
            f"run is missing certified stage-era evidence version "
            f"{CERTIFIED_EVIDENCE_VERSION}"
        ]
    return []


def compute_tree_fingerprint(package_root, manifest):
    """Hash regular files and link target strings in the audited tree."""
    package_root = canonical_package_root(package_root)
    entries = []
    for path, relative, kind in iter_in_scope_entries(package_root, manifest):
        digest = (hashlib.sha256(os.readlink(path).encode("utf-8")).hexdigest()
                  if kind == "symlink" else _sha256_file(path))
        entries.append((relative.as_posix(), digest))
    serialized = "\n".join(f"{relative},{digest}" for relative, digest in sorted(entries))
    return {
        "aggregate_sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
        "file_count": len(entries),
    }


def git_commit(package_root):
    result = subprocess.run(
        ["git", "-C", str(package_root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def read_usage_snapshot(package_root):
    """Return ``audit/_run/usage.json`` as a dict, or ``{}`` when unusable.

    The statusline feed script (``usage_statusline.py``) is the writer.  Every
    consumer treats the file as advisory: a missing, unreadable, or malformed
    snapshot is never an error, only an absence of data.
    """
    _, run_dir, _, _ = audit_paths(package_root)
    try:
        snapshot = json.loads((run_dir / "usage.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return snapshot if isinstance(snapshot, dict) else {}


def recorded_session_id(package_root):
    """The conversation ID the statusline feed last observed, or ``None``."""
    value = read_usage_snapshot(package_root).get("session_id")
    return value if isinstance(value, str) and value.strip() else None


def make_run_identity(package_root, manifest):
    return {
        "git_commit": git_commit(package_root),
        "canonical_package_root": str(package_root),
        "tree_fingerprint": compute_tree_fingerprint(package_root, manifest),
        "mechanism_schema_version": MECHANISM_SCHEMA_VERSION,
        # Informational only: a resumed conversation may be renumbered by the
        # platform, so ``_identity_failures`` never reads this key.
        "session_id": recorded_session_id(package_root),
    }


def _identity_failures(package_root, manifest, check_fingerprint):
    identity = manifest.get("run_identity")
    if not isinstance(identity, dict):
        return ["run identity is missing"]
    failures = []
    recorded_root = identity.get("canonical_package_root")
    if recorded_root != str(package_root):
        failures.append(
            "canonical package root mismatch: "
            f"recorded {recorded_root!r}, current {str(package_root)!r}"
        )
    recorded_version = identity.get("mechanism_schema_version")
    if recorded_version != MECHANISM_SCHEMA_VERSION:
        failures.append(
            "mechanism schema changed under the run "
            f"(recorded {recorded_version!r}, current {MECHANISM_SCHEMA_VERSION!r}); "
            "restart is required"
        )
    if check_fingerprint:
        recorded_fingerprint = identity.get("tree_fingerprint")
        current_fingerprint = compute_tree_fingerprint(package_root, manifest)
        if recorded_fingerprint != current_fingerprint:
            failures.append(
                "audited tree changed across the pause "
                f"(recorded {recorded_fingerprint!r}, current {current_fingerprint!r}); "
                "restarting the audit is the only path forward"
            )
    return failures


def require_canonical_identity(package_root, manifest):
    identity = manifest.get("run_identity")
    recorded = identity.get("canonical_package_root") if isinstance(identity, dict) else None
    if recorded != str(package_root):
        raise CertificationError(
            "canonical package root mismatch: "
            f"recorded {recorded!r}, current {str(package_root)!r}"
        )


def _utc_now_iso():
    """The one time convention this codebase writes: UTC, ISO 8601."""
    return datetime.now(timezone.utc).isoformat()


def _marker_text(conductor_pid=None):
    """Render the RUNNING marker.

    ``conductor_pid`` is the *long-lived conductor process's* PID, passed in
    explicitly.  This script's own ``os.getpid()`` is never recorded: it dies
    the moment the command returns, so it could only ever look stale.  When no
    conductor PID is resolvable the ``pid=`` line is omitted and the marker
    degrades to the flag-guarded behavior it had before conductor PIDs existed.
    """
    text = f"started_at={_utc_now_iso()}\n"
    if conductor_pid is not None:
        text += f"pid={int(conductor_pid)}\n"
    return text


def marker_pid(text):
    """Parse a marker's recorded PID; ``None`` when absent or unparseable."""
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() == "pid":
            try:
                return int(value.strip())
            except ValueError:
                return None
    return None


def pid_is_alive(pid):
    """True when the recorded process still exists.

    ``PermissionError`` means the process exists but is owned by another user —
    alive for our purposes.  Anything else (including a nonsensical PID) is
    treated as dead, because refusing on an unusable value would strand a run.
    """
    if pid is None or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (OSError, OverflowError, ValueError):
        return False
    return True


def live_conductor_refusal(marker_text, recorded_pid):
    """The amendment-3 refusal text for a marker naming a live foreign PID."""
    details = marker_text.strip()
    return (
        f"another audit run is live: audit/_run/RUNNING records conductor pid "
        f"{recorded_pid}, and that process is still running"
        + (f" ({details})" if details else "")
        + "; --clear-stale-marker cannot override a live conductor. Either "
        "continue that session in its own window, or terminate that process "
        "first and rerun."
    )


def replace_running_marker(package_root, clear_stale=False, conductor_pid=None):
    _, run_dir, _, marker = audit_paths(package_root)
    run_dir.mkdir(parents=True, exist_ok=True)
    if marker.exists():
        details = marker.read_text(encoding="utf-8", errors="replace")
        recorded_pid = marker_pid(details)
        # Self-ownership first: a marker naming *this* process cannot be a
        # second process, so it is replaceable under the ordinary flag rule.
        # Without this the guarded resume loop would deadlock on the marker its
        # own first pass wrote.  ``os.getpid()`` alone is not enough: run as a
        # CLI subprocess this is the short-lived certify process, never the
        # conductor, so a conductor re-registering its *own* marker would be
        # classified foreign-and-alive and hard-refused.  The caller-supplied
        # conductor PID is self-owned for the same reason.
        owned_pids = {os.getpid()}
        if conductor_pid is not None:
            owned_pids.add(int(conductor_pid))
        if (recorded_pid is not None and recorded_pid not in owned_pids
                and pid_is_alive(recorded_pid)):
            raise CertificationError(
                live_conductor_refusal(details, recorded_pid))
        if not clear_stale:
            stripped = details.strip()
            raise CertificationError(
                "another audit run appears to be live because audit/_run/RUNNING exists"
                + (f" ({stripped})" if stripped else "")
                + "; if the previous run is certainly dead, retry with --clear-stale-marker"
            )
        marker.unlink()
    marker.write_text(_marker_text(conductor_pid), encoding="utf-8")


def remove_running_marker(package_root):
    _, _, _, marker = audit_paths(package_root)
    try:
        marker.unlink()
    except FileNotFoundError as exc:
        raise CertificationError("audit/_run/RUNNING does not exist") from exc


def stages_for_mode(mode):
    if mode == "replication":
        return FULL_STAGES
    if mode == "code_errors_only":
        return CODE_ONLY_STAGES
    raise CertificationError(
        f"manifest mode must be 'replication' or 'code_errors_only', got {mode!r}"
    )


def init_run(package_root, clear_stale_marker=False, conductor_pid=None):
    manifest = read_manifest(package_root)
    stages = stages_for_mode(manifest.get("mode"))
    try:
        dispatch_tracking.validate_effort_map(manifest.get("effort_map"))
    except dispatch_tracking.DispatchError as exc:
        raise CertificationError(str(exc)) from exc
    _validate_allocation_override(manifest)
    if (manifest.get("mode") == "replication"
            and not manifest.get("paper_source_path")
            and not isinstance(manifest.get("allocation_override"), dict)):
        raise CertificationError(
            "replication mode requires paper_source_path; only a fixture/development "
            "manifest carrying allocation_override may omit it"
        )
    try:
        paper_sources.build_source_set(package_root, manifest)
    except paper_sources.PaperSourceError as exc:
        raise CertificationError(str(exc)) from exc
    replace_running_marker(package_root, clear_stale_marker, conductor_pid)
    manifest["run_identity"] = make_run_identity(package_root, manifest)
    manifest["certified_stage_evidence_version"] = CERTIFIED_EVIDENCE_VERSION
    # Fresh entries carry no times: a pending stage has neither started nor
    # ended, and an absent field is honest where a null would be noise.
    manifest["stages"] = {
        stage: {"status": "pending", "retries": 0, "shards": {}}
        for stage in stages
    }
    write_manifest_atomic(package_root, manifest)


def _validate_allocation_override(manifest):
    if "allocation_override" not in manifest:
        return
    from claim_handoffs import CLAIMS_PLAN_COLS
    value = manifest["allocation_override"]
    if not isinstance(value, dict) or set(value) != {"purpose", "allocation"}:
        raise CertificationError(
            "allocation_override must contain exactly purpose and allocation"
        )
    if value["purpose"] not in {"fixture", "development"}:
        raise CertificationError(
            "allocation_override purpose must be 'fixture' or 'development'"
        )
    if not isinstance(value["allocation"], list):
        raise CertificationError("allocation_override allocation must be an ordered array")
    for index, row in enumerate(value["allocation"], start=1):
        if not isinstance(row, dict) or list(row) != CLAIMS_PLAN_COLS:
            raise CertificationError(
                f"allocation_override row {index} must use the exact ordered b1 headers: "
                + " | ".join(CLAIMS_PLAN_COLS)
            )


def stage_entry(manifest, stage):
    stages = manifest.get("stages")
    if not isinstance(stages, dict) or stage not in stages:
        raise CertificationError(f"stage {stage!r} is not present in this run's manifest")
    entry = stages[stage]
    if not isinstance(entry, dict):
        raise CertificationError(f"manifest entry for stage {stage!r} is not an object")
    status = entry.get("status")
    if status not in VALID_STAGE_STATES:
        raise CertificationError(f"stage {stage!r} has invalid current state {status!r}")
    return entry


def start_stage(package_root, stage):
    manifest = read_manifest(package_root)
    require_canonical_identity(package_root, manifest)
    entry = stage_entry(manifest, stage)
    status = entry["status"]
    if status not in LEGAL_START_STATES:
        raise CertificationError(
            f"stage {stage!r} is {status!r}; start permits only pending -> running "
            "or blocked -> running"
        )
    if stage == "severity_token_rulings":
        b7 = manifest.get("stages", {}).get("b7", {})
        if not isinstance(b7, dict) or b7.get("status") != "done":
            raise CertificationError(
                "severity_token_rulings requires a certified done b7 stage")
        try:
            severity_token_rulings.snapshot_stage(
                package_root, package_root / "audit", manifest)
        except severity_token_rulings.RulingsError as exc:
            raise CertificationError(f"cannot freeze b7 rejected worklist: {exc}") from exc
    if status == "blocked":
        entry["retries"] = int(entry.get("retries", 0)) + 1
    entry["status"] = "running"
    entry["started_at"] = _utc_now_iso()
    # A retry starts a fresh attempt: the previous attempt's end time would
    # otherwise sit beside a running stage and read as a finished one.
    entry.pop("ended_at", None)
    entry.pop("reason", None)
    entry.pop("note", None)
    write_manifest_atomic(package_root, manifest)


def load_obligations(path=OBLIGATIONS_PATH):
    try:
        table = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CertificationError(f"cannot load obligations table {path}: {exc}") from exc
    if not isinstance(table, dict):
        raise CertificationError("obligations table must be a JSON object")
    return table


def _artifact_failure(audit, pattern):
    matches = [path for path in audit.glob(pattern)
               if path.is_file() and path.stat().st_size > 0]
    if matches:
        return None
    return f"artifact:{pattern} matched no existing non-empty file under {audit}"


def _resolve_shard_path(package_root, audit, raw):
    shard = Path(raw)
    if shard.is_absolute():
        return shard
    if shard.parts and shard.parts[0] == "audit":
        return package_root / shard
    return audit / shard


def _validator_commands(identifier, package_root, audit, stage_entry_value, stage=None):
    if identifier == "detector:mapping":
        return [[
            sys.executable, str(SCRIPT_DIR / "build_detector_mapping.py"),
            str(package_root), "--audit-dir", str(audit), "--check",
        ]]
    if identifier == "boundary:assemble":
        return [[
            sys.executable, str(SCRIPT_DIR / "assemble_boundary.py"),
            str(package_root), "--audit-dir", str(audit), "--check",
        ]]
    if identifier == "boundary:assemble-supplementary":
        return [[
            sys.executable, str(SCRIPT_DIR / "assemble_boundary.py"),
            str(package_root), "--audit-dir", str(audit), "--check",
            "--supplementary",
        ]]
    if identifier == "crossref:inventory":
        return [[
            sys.executable, str(SCRIPT_DIR / "build_crossref_inventory.py"),
            str(package_root), "--audit-dir", str(audit), "--check",
        ]]
    if identifier == "handoff:ledger":
        if stage not in {"claims_b3", "claims_b3b"}:
            raise CertificationError(
                f"handoff:ledger has no U7a implementation for stage {stage!r}"
            )
        return [[
            sys.executable, str(SCRIPT_DIR / "build_handoff_ledger.py"),
            str(package_root), "--audit-dir", str(audit),
            "--stage", stage, "--check",
        ]]
    if identifier in {"handoff:adjudication", "handoff:adjudication-lineage"}:
        wanted = ("claims_adjudication" if identifier == "handoff:adjudication"
                  else "claims_adjudication_lineage")
        if stage != wanted:
            raise CertificationError(f"{identifier} cannot validate stage {stage!r}")
        return [[
            sys.executable, str(SCRIPT_DIR / "claims_adjudication.py"),
            str(package_root), "--audit-dir", str(audit),
            "--stage", stage, "--check",
        ]]
    lint_stage = VALIDATORS.get(identifier)
    if lint_stage is None:
        raise CertificationError(f"unknown validator identifier {identifier!r}")
    base = [
        sys.executable,
        str(SCRIPT_DIR / "lint_registers.py"),
        "--stage", lint_stage,
        "--audit-dir", str(audit),
    ]
    if stage_entry_value.get("_use_certified_evidence"):
        evidence_dir = _certified_evidence_dir(audit, stage)
        base.extend(["--stage-evidence-dir", str(evidence_dir)])
    if identifier not in SHARD_VALIDATORS:
        return [base]
    shards = stage_entry_value.get("shards")
    if (not isinstance(shards, dict) or not shards) \
            and identifier in ZERO_WORK_SHARD_VALIDATORS:
        return [base]
    if not isinstance(shards, dict) or not shards:
        raise CertificationError(f"validator {identifier!r} requires recorded shard paths")
    nonterminal = []
    done_shards = []
    for raw, value in sorted(shards.items()):
        status = value.get("status") if isinstance(value, dict) else None
        if status not in {"done", "blocked"}:
            nonterminal.append(f"{raw} ({status!r})")
        elif status == "done":
            done_shards.append(raw)
    if nonterminal:
        raise CertificationError(
            f"validator {identifier!r} requires every shard to be done or blocked; "
            "nonterminal shard(s): " + ", ".join(nonterminal)
        )
    if not done_shards:
        raise CertificationError(
            f"validator {identifier!r} requires at least one done shard"
        )
    commands = []
    for raw in done_shards:
        command = list(base)
        command.extend(["--shard", str(_resolve_shard_path(package_root, audit, raw))])
        commands.append(command)
    return commands


def _run_validator(identifier, package_root, audit, stage_entry_value):
    failures = []
    try:
        commands = _validator_commands(
            identifier, package_root, audit, stage_entry_value,
            stage_entry_value.get("_validator_stage")
        )
    except CertificationError as exc:
        return [str(exc)]
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True, cwd=package_root)
        if result.returncode != 0:
            detail = (result.stdout + result.stderr).strip()
            failures.append(
                f"validate:{identifier} exited {result.returncode}"
                + (f": {detail}" if detail else "")
            )
    return failures


def resolve_stage_obligations(
        package_root, manifest, stage, table=None,
        use_certified_evidence=False):
    table = load_obligations() if table is None else table
    if stage not in table:
        return [f"obligations table has no entry for stage {stage!r}"]
    obligations = table[stage]
    if not isinstance(obligations, list) or not obligations:
        return [f"obligations table entry for stage {stage!r} is empty"]
    audit, _, _, _ = audit_paths(package_root)
    entry = stage_entry(manifest, stage)
    failures = []
    targeted_evidence_stage = stage in CERTIFIED_REGISTER_EVIDENCE
    if use_certified_evidence and targeted_evidence_stage:
        failures.extend(
            _certified_stage_evidence_failures(
                package_root, manifest, stage, entry))
    for obligation in obligations:
        if not isinstance(obligation, dict):
            failures.append(f"stage {stage!r} has a malformed obligation {obligation!r}")
            continue
        condition = obligation.get("when")
        if condition is not None:
            if condition == "paper_source_set":
                if not manifest.get("paper_source_set"):
                    continue
            elif condition == "replication":
                if manifest.get("mode") != "replication":
                    continue
            elif condition == "code_errors_only":
                if manifest.get("mode") != "code_errors_only":
                    continue
            else:
                failures.append(f"stage {stage!r} has unknown obligation condition {condition!r}")
                continue
        obligation_type = obligation.get("type")
        if obligation_type == "artifact":
            pattern = obligation.get("pattern")
            if not isinstance(pattern, str) or not pattern:
                failures.append(f"stage {stage!r} has an artifact obligation without a pattern")
                continue
            failure = _artifact_failure(audit, pattern)
            if failure:
                failures.append(failure)
        elif obligation_type == "validate":
            identifier = obligation.get("validator")
            if not isinstance(identifier, str) or not identifier:
                failures.append(f"stage {stage!r} has a validate obligation without an identifier")
                continue
            failures.extend(
                _run_validator(
                    identifier, package_root, audit,
                    {
                        **entry,
                        "_validator_stage": stage,
                        "_use_certified_evidence": (
                            use_certified_evidence
                            and targeted_evidence_stage
                        ),
                    },
                )
            )
        else:
            failures.append(
                f"stage {stage!r} has unknown obligation type {obligation_type!r}"
            )
    return failures


def finish_stage(package_root, stage, outcome, reason=None):
    manifest = read_manifest(package_root)
    require_canonical_identity(package_root, manifest)
    entry = stage_entry(manifest, stage)
    if entry["status"] != "running":
        raise CertificationError(
            f"stage {stage!r} is {entry['status']!r}; finish permits only "
            "running -> done or running -> blocked"
        )
    if outcome == "blocked":
        if reason is None or not reason.strip():
            raise CertificationError("a blocked outcome requires a non-empty --reason")
        if stage in {"claims_adjudication", "claims_adjudication_lineage"}:
            result = subprocess.run([
                sys.executable, str(SCRIPT_DIR / "claims_adjudication.py"),
                str(package_root), "--audit-dir", str(package_root / "audit"),
                "--stage", stage, "--block",
            ], capture_output=True, text=True, cwd=package_root)
            if result.returncode:
                raise CertificationError(
                    f"cannot record blocked {stage} honestly: "
                    + (result.stdout + result.stderr).strip()
                )
        entry["status"] = "blocked"
        entry["ended_at"] = _utc_now_iso()
        entry["reason"] = " ".join(reason.split())
        write_manifest_atomic(package_root, manifest)
        return
    if stage == "severity_token_rulings":
        try:
            severity_token_rulings.apply_rulings(
                package_root, package_root / "audit", manifest)
        except severity_token_rulings.RulingsError as exc:
            raise CertificationError(
                f"severity_token_rulings refused with zero promotion: {exc}") from exc
    failures = resolve_stage_obligations(package_root, manifest, stage)
    if failures:
        raise CertificationError(
            f"stage {stage!r} failed obligation(s): " + " | ".join(failures)
        )
    _capture_certified_stage_evidence(package_root, stage, entry)
    entry["status"] = "done"
    entry["ended_at"] = _utc_now_iso()
    entry.pop("reason", None)
    entry.pop("note", None)
    write_manifest_atomic(package_root, manifest)


def set_shard(package_root, stage, shard, status, reason=None):
    manifest = read_manifest(package_root)
    require_canonical_identity(package_root, manifest)
    entry = stage_entry(manifest, stage)
    if entry["status"] != "running":
        raise CertificationError(
            f"stage {stage!r} is {entry['status']!r}; shards may change only while it is running"
        )
    shards = entry.setdefault("shards", {})
    if not isinstance(shards, dict):
        raise CertificationError(f"stage {stage!r} has a non-object shards entry")
    shard_path = _resolve_shard_path(package_root, package_root / "audit", shard)
    if status == "done" and (not shard_path.is_file() or shard_path.stat().st_size == 0):
        raise CertificationError(
            f"shard {shard!r} cannot be done: file is missing or empty ({shard_path})"
        )
    if status == "blocked" and (reason is None or not reason.strip()):
        raise CertificationError("a blocked shard requires a non-empty --reason")
    if stage in {"code_b5", "code_b5s"} and status == "blocked":
        _write_code_b5_blocked_fallback(
            package_root, shard_path, reason, supplementary=stage == "code_b5s")
    previous = shards.get(shard, {})
    retries = int(previous.get("retries", 0))
    if previous.get("status") == "blocked" and status == "done":
        retries += 1
    value = {"status": status, "retries": retries}
    if status == "blocked":
        value["reason"] = " ".join(reason.split())
    shards[shard] = value
    write_manifest_atomic(package_root, manifest)


def _md_table(columns, rows):
    lines = ["| " + " | ".join(columns) + " |",
             "| " + " | ".join(["---"] * len(columns)) + " |"]
    lines.extend(
        "| " + " | ".join(str(cell).replace("|", "\\|") for cell in row) + " |"
        for row in rows
    )
    return "\n".join(lines) + "\n"


def _write_text_atomic(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def _write_code_b5_blocked_fallback(package_root, shard_path, reason,
                                    supplementary=False):
    audit = package_root / "audit"
    plan_path = audit / "plans" / (
        "code_error_supplementary_recheck_plan.md" if supplementary
        else "code_error_recheck_plan.md")
    try:
        plan_text = plan_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CertificationError(f"cannot generate blocked fallback: {exc}") from exc
    assigned = None
    for headers, rows, _line in registers.parse_tables(plan_text):
        if "Assigned IDs" not in headers or "Shard File" not in headers:
            continue
        for row in rows:
            if len(row) != len(headers):
                continue
            data = dict(zip(headers, row))
            planned = _resolve_shard_path(
                package_root, audit, data["Shard File"].strip().strip("`"))
            if planned.resolve() == shard_path.resolve():
                assigned = sorted(set(registers.ids_in(data["Assigned IDs"], "E")))
                break
    if assigned is None:
        raise CertificationError(
            f"cannot generate blocked fallback: {shard_path} is not assigned in {plan_path}"
        )
    register_path = audit / "code_error_register.md"
    parsed = registers.load_register(registers.Lint(), register_path, registers.ERROR_COLS)
    if parsed is None:
        raise CertificationError(
            f"cannot generate blocked fallback: code-error register is missing or malformed"
        )
    current = {dict(zip(registers.ERROR_COLS, row))["Error ID"]:
               dict(zip(registers.ERROR_COLS, row)) for row in parsed[1]}
    mapped_sources = {}
    mapping_path = audit / "_run/detector_mapping.md"
    if mapping_path.is_file():
        try:
            _declared, _display, mapping_rows = detector_mapping.load_mapping(mapping_path)
        except detector_mapping.MappingError as exc:
            raise CertificationError(
                f"cannot generate blocked fallback: {exc}") from exc
        for mapping_row in mapping_rows:
            mapped_sources.setdefault(
                mapping_row["Error ID"], set()).add(mapping_row["Source ID"])
    rows = []
    normalized_reason = " ".join(reason.split())
    for error_id in assigned:
        if error_id not in current:
            raise CertificationError(
                f"cannot generate blocked fallback: assigned ID {error_id} is absent from the register"
            )
        before = current[error_id]
        severity = before["Severity"] or "—"
        sources = sorted(mapped_sources.get(error_id, ()))
        evidence = ("blocked fallback; mapped sources: " + ", ".join(sources)
                    + "; reason: " + normalized_reason) if sources else (
                    "blocked fallback; reason: " + normalized_reason)
        rows.append([
            error_id, before["Status"], severity, evidence,
            "blocked_documented", "blocked", normalized_reason, "—",
            normalized_reason, "blocked", severity, "—", "—", "—", "—",
            "—", "—",
        ])
    payload = (
        "# Conductor blocked fallback\n\n"
        + _md_table(registers.CODE_LEDGER_COLS, rows)
        + "\n### Witness outcomes\n\n"
        + _md_table(registers.WITNESS_OUTCOME_COLS, [])
        + "\n### Verification records\n\nNo verification records.\n"
        + "\n### Coverage\n\nEvery assigned row was dispositioned or blocked.\n"
        + "\n### Footer dispositions\n\n"
        + _md_table(registers.FOOTER_COLS, [])
    )
    _write_text_atomic(shard_path, payload)


def verify_done_stages(package_root, manifest):
    failures = _certified_evidence_root_failures(manifest)
    stages = manifest.get("stages")
    if not isinstance(stages, dict):
        return ["manifest stages block is missing or not an object"]
    for stage, entry in stages.items():
        if isinstance(entry, dict) and entry.get("status") == "done":
            for failure in resolve_stage_obligations(
                    package_root, manifest, stage,
                    use_certified_evidence=True):
                failures.append(f"stage {stage!r}: {failure}")
    return failures


def _done_stage_summary(manifest, evidence_failures):
    stages = manifest.get("stages", {})
    done = [stage for stage, entry in stages.items()
            if isinstance(entry, dict) and entry.get("status") == "done"]
    failed = {
        stage for stage in done
        if any(failure.startswith(f"stage {stage!r}:")
               for failure in evidence_failures)
    }
    passed = [stage for stage in done if stage not in failed]
    return "recorded passes still hold: " + (", ".join(passed) if passed else "none")


def verify_run(package_root):
    manifest = read_manifest(package_root)
    failures = _identity_failures(package_root, manifest, check_fingerprint=True)
    evidence_failures = verify_done_stages(package_root, manifest)
    summary = _done_stage_summary(manifest, evidence_failures)
    failures.extend(evidence_failures)
    if failures:
        raise CertificationError(
            "verification failed: " + " | ".join(failures) + " | " + summary
        )
    return summary


def resume_check(package_root, clear_stale_marker=False, conductor_pid=None):
    manifest = read_manifest(package_root)
    replace_running_marker(package_root, clear_stale_marker, conductor_pid)
    failures = _identity_failures(package_root, manifest, check_fingerprint=True)
    evidence_failures = verify_done_stages(package_root, manifest)
    summary = _done_stage_summary(manifest, evidence_failures)
    failures.extend(evidence_failures)
    if failures:
        raise CertificationError(
            "resume check failed: " + " | ".join(failures) + " | " + summary
        )
    return summary


def demote_stage(package_root, stage, reason=None):
    manifest = read_manifest(package_root)
    require_canonical_identity(package_root, manifest)
    entry = stage_entry(manifest, stage)
    if entry["status"] != "done":
        raise CertificationError(
            f"stage {stage!r} is {entry['status']!r}; demote permits only done -> pending"
        )
    entry["status"] = "pending"
    # A pending stage has no times; the demoted attempt's pair is discarded
    # rather than left to describe work the run no longer credits.
    entry.pop("started_at", None)
    entry.pop("ended_at", None)
    if reason is None or not reason.strip():
        entry["note"] = "demoted after failed verification"
    else:
        entry["note"] = " ".join(reason.split())
    write_manifest_atomic(package_root, manifest)


def close_run(package_root):
    manifest = read_manifest(package_root)
    require_canonical_identity(package_root, manifest)
    _refuse_pending_late_observations(package_root)
    _refuse_pending_handoff_obligations(package_root, manifest)
    _refuse_pending_severity_token_rulings(package_root, manifest)
    remove_running_marker(package_root)


def _refuse_pending_severity_token_rulings(package_root, manifest):
    """U8b completion gate: rejected severity tokens need operator rulings."""
    if manifest.get("mode") != "replication":
        return
    audit = package_root / "audit"
    severe_rows = severity_tokens._load_register_error_rows(audit)
    activated = (
        (audit / "_run/code_b6b/token_receipts.md").is_file()
        or (audit / evidence_views.WORKLIST_PATH).is_file()
        or severity_tokens.gate_required(severe_rows.values())
    )
    if not activated:
        return
    stages = manifest.get("stages", {})
    entry = stages.get("severity_token_rulings") if isinstance(stages, dict) else None
    if not isinstance(entry, dict) or entry.get("status") != "done":
        raise CertificationError(
            "close-run refused: severity_token_rulings is not done")
    failures = resolve_stage_obligations(
        package_root, manifest, "severity_token_rulings")
    if failures:
        raise CertificationError(
            "close-run refused: pending severity-token ruling(s): "
            + " | ".join(failures))


def _refuse_pending_handoff_obligations(package_root, manifest):
    """U7 completion gate; U7a intentionally has no legal terminalizer yet."""
    if manifest.get("mode") != "replication" or not manifest.get("paper_source_set"):
        return
    failures = []
    stages = manifest.get("stages", {})
    for stage in ("claims_adjudication", "claims_adjudication_lineage"):
        entry = stages.get(stage) if isinstance(stages, dict) else None
        status = entry.get("status") if isinstance(entry, dict) else None
        if status not in {"done", "blocked"}:
            failures.append(f"stage {stage} is {status or 'absent'}, not terminal")
        elif status == "done":
            stage_failures = resolve_stage_obligations(package_root, manifest, stage)
            failures.extend(f"stage {stage}: {failure}" for failure in stage_failures)
        elif status == "blocked":
            result = subprocess.run([
                sys.executable, str(SCRIPT_DIR / "claims_adjudication.py"),
                str(package_root), "--audit-dir", str(package_root / "audit"),
                "--stage", stage, "--check-blocked",
            ], capture_output=True, text=True, cwd=package_root)
            if result.returncode:
                failures.append(
                    f"stage {stage}: blocked-path re-derivation failed: "
                    + (result.stdout + result.stderr).strip()
                )
    audit, run_dir, _, _ = audit_paths(package_root)
    ledger_path = run_dir / "handoff_ledger.json"
    try:
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failures.append(f"handoff ledger missing or invalid: {exc}")
        ledger = {"H": [], "X": []}
    entries = ledger.get("H", []) + ledger.get("X", [])
    if not all(isinstance(entry, dict) for entry in entries):
        failures.append("handoff ledger H/X sections must contain objects")
        entries = []
    by_id = {entry.get("id"): entry for entry in entries}
    decisions_path = run_dir / "handoff_blocked_decisions.json"
    decisions = []
    if decisions_path.is_file():
        try:
            decisions = json.loads(decisions_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            failures.append(f"invalid handoff_blocked_decisions.json: {exc}")
            decisions = []
    if not isinstance(decisions, list):
        failures.append("handoff_blocked_decisions.json must be a JSON array")
        decisions = []
    decision_by_id = {}
    for index, decision in enumerate(decisions, start=1):
        if not isinstance(decision, dict) or set(decision) != {
                "id", "decision", "reason", "date"}:
            failures.append(f"blocked decision {index} has fields other than id/decision/reason/date")
            continue
        obligation_id = decision["id"]
        if obligation_id in decision_by_id:
            failures.append(f"duplicate blocked decision for {obligation_id}")
        decision_by_id[obligation_id] = decision
        if decision["decision"] != "accept_blocked":
            failures.append(f"blocked decision for {obligation_id} must be accept_blocked")
        if not isinstance(decision["reason"], str) or not decision["reason"].strip():
            failures.append(f"blocked decision for {obligation_id} requires a reason")
        try:
            datetime.fromisoformat(str(decision["date"]))
        except ValueError:
            failures.append(f"blocked decision for {obligation_id} has a non-ISO date")
    decision_ids = [item.get("id") for item in decisions if isinstance(item, dict)]
    if any(not isinstance(item, str) for item in decision_ids):
        failures.append("handoff_blocked_decisions.json entries require string ids")
    elif decision_ids != sorted(decision_ids):
        failures.append("handoff_blocked_decisions.json must be sorted by id")
    for obligation_id, entry in by_id.items():
        final = ({"satisfied", "resolved", "disposition_accepted"}
                 if entry.get("kind") == "H"
                 else {"covered", "resolved", "disposition_accepted"})
        state = entry.get("state")
        if state == "blocked_fallback":
            if obligation_id not in decision_by_id:
                failures.append(f"blocked_fallback {obligation_id} has no operator decision")
        elif state not in final:
            failures.append(f"handoff obligation {obligation_id} remains {state!r}")
    for obligation_id in decision_by_id:
        if obligation_id not in by_id:
            failures.append(f"blocked decision names unknown obligation {obligation_id}")
        elif by_id[obligation_id].get("state") != "blocked_fallback":
            failures.append(f"blocked decision names non-blocked obligation {obligation_id}")
    lineage_path = run_dir / "claims_adjudication_lineage_verdicts.md"
    lineage_verdict_ids = set()
    if lineage_path.is_file():
        for headers, rows, _line in registers.parse_tables(
                lineage_path.read_text(encoding="utf-8")):
            if headers == ["Obligation ID", "Verdict", "Reason"]:
                lineage_verdict_ids.update(row[0] for row in rows if len(row) == 3)
                refused = [row[0] for row in rows if len(row) == 3
                           and row[1] == "equivalence_refused"]
                if refused:
                    failures.append(
                        "lineage equivalence refused for " + ", ".join(sorted(refused))
                    )
    # N1: re-derive the dead-carrier refusal from the certified worklist
    # artifact itself — a hand-confirmed verdict table is not trusted here.
    lineage_worklist_path = run_dir / "claims_adjudication_lineage_worklist.json"
    if lineage_worklist_path.is_file():
        try:
            lineage_worklist = json.loads(
                lineage_worklist_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            failures.append(f"cannot read lineage worklist: {exc}")
            lineage_worklist = {}
        lineage_blocked = (
            stages.get("claims_adjudication_lineage", {}).get("status") == "blocked"
            if isinstance(stages, dict) else False
        )
        for item in lineage_worklist.get("items", []) or []:
            if not isinstance(item, dict) or item.get("terminal_c_id") is not None:
                continue
            item_id = item.get("id")
            blocked_release = (
                lineage_blocked and item_id not in lineage_verdict_ids
                and by_id.get(item_id, {}).get("state") == "blocked_fallback"
            )
            if not blocked_release:
                failures.append(
                    f"lineage dead-end with no live carrier: {item_id} "
                    f"({item.get('reason', 'dead chain')})"
                )
    if failures:
        raise CertificationError(
            "close-run refused: pending handoff obligation(s): " + " | ".join(failures)
        )


def _refuse_pending_late_observations(package_root):
    """The completion-report gate (checklist U6 §9).

    The Phase-4 first disposition batch must replace every ``pending`` state
    before the run closes.  b9 deliberately does not enforce this — the
    export publishes pending rows on the explicitly unverified sheet.
    """
    audit, _, _, _ = audit_paths(package_root)
    lint = registers.Lint()
    pending = []
    for stream in ("claims", "code"):
        if not (audit / f"late_observations_{stream}.md").is_file():
            continue
        _path, _rows, dispositions = registers._late_observation_rows(
            lint, audit, stream)
        pending.extend(row["LO ID"] for row in dispositions
                       if row["State"] == "pending")
    if pending:
        raise CertificationError(
            "close-run refused: late-observation disposition(s) still pending: "
            + ", ".join(sorted(pending))
            + " — the Phase-4 first disposition batch replaces every pending "
            "state before the run closes"
        )


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    def command(name):
        subparser = subparsers.add_parser(name)
        subparser.add_argument(
            "--package-root", type=Path, default=Path.cwd(),
            help="audited package root (default: current working directory)",
        )
        return subparser

    def conductor_pid_argument(subparser):
        subparser.add_argument(
            "--conductor-pid", type=int, default=None,
            help="PID of the long-lived conductor process to record in "
                 "audit/_run/RUNNING (omit when it cannot be resolved)",
        )

    init = command("init")
    init.add_argument("--clear-stale-marker", action="store_true")
    conductor_pid_argument(init)

    start = command("start")
    start.add_argument("--stage", required=True)

    finish = command("finish")
    finish.add_argument("--stage", required=True)
    finish.add_argument("--outcome", required=True, choices=("done", "blocked"))
    finish.add_argument("--reason")

    shard = command("set-shard")
    shard.add_argument("--stage", required=True)
    shard.add_argument("--shard", required=True)
    shard.add_argument("--status", required=True, choices=("done", "blocked"))
    shard.add_argument("--reason")

    command("verify-run")

    demote = command("demote")
    demote.add_argument("--stage", required=True)
    demote.add_argument("--reason")

    resume = command("resume-check")
    resume.add_argument("--clear-stale-marker", action="store_true")
    conductor_pid_argument(resume)

    command("close-run")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    detail = None
    try:
        package_root = canonical_package_root(args.package_root)
        if args.command == "init":
            init_run(package_root, args.clear_stale_marker, args.conductor_pid)
        elif args.command == "start":
            start_stage(package_root, args.stage)
        elif args.command == "finish":
            finish_stage(package_root, args.stage, args.outcome, args.reason)
        elif args.command == "set-shard":
            set_shard(package_root, args.stage, args.shard, args.status, args.reason)
        elif args.command == "verify-run":
            detail = verify_run(package_root)
        elif args.command == "demote":
            demote_stage(package_root, args.stage, args.reason)
        elif args.command == "resume-check":
            detail = resume_check(
                package_root, args.clear_stale_marker, args.conductor_pid)
        elif args.command == "close-run":
            close_run(package_root)
    except CertificationError as exc:
        print(f"CERTIFICATION REFUSED: {exc}", file=sys.stderr)
        return 1
    print(f"CERTIFICATION OK: {args.command}" + (f"; {detail}" if detail else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
