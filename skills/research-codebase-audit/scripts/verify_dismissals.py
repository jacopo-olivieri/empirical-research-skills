#!/usr/bin/env python3
"""Re-execute proposed mapped dismissals and issue conductor receipts."""

import argparse
import hashlib
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import build_detector_mapping as detector_mapping
import check_manifests as manifests
import lint_registers as registers
import severity_tokens


CODE_LEDGER_COLS = registers.LEDGER_COLS + [
    "Proposed Status", "Proposed Severity", "Accepted Error Type",
    "Accepted Mechanism", "Outcome Witness IDs", "Duplicate Target",
    "Proposed Field Patches", "Verification Record IDs",
]
MF_RECORD_COLS = [
    "Channel", "Record ID", "Source ID", "Witness ID",
    "File Digest (sha256)", "Consumer", "Consumer Version", "Invocation",
    "Observed Result", "Whole-File Acceptance (yes/no)",
]
PROBE_RECORD_COLS = [
    "Channel", "Record ID", "Source ID", "Witness ID",
    "Proposition Tested", "Harness / Input Domain", "Observed Result",
    "Scope Anchor", "Excluded-Class Input",
]
RECEIPT_COLS = [
    "Channel", "Receipt ID", "Source ID", "Witness ID", "Record ID",
    "Tool", "Tool Version", "Input Digest (sha256)", "Invocation",
    "Exit Status", "Accepted (yes/no)", "Result Digest (sha256)",
]
ZERO_RECEIPTS = "No mapped not_error dismissal receipts were required."
SUPPLEMENTARY_ZERO_RECEIPTS = "No supplementary dismissal receipts were required."


class VerificationError(RuntimeError):
    """A proposed dismissal cannot be re-executed safely."""


def _clean(value):
    return str(value).strip().strip("`").strip()


def _list_cell(value):
    value = _clean(value)
    if value in {"", "-", "—"}:
        return []
    return [_clean(part) for part in value.split(";") if _clean(part)]


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def result_digest(returncode, stdout, stderr):
    preimage = f"exit={returncode}\n".encode("ascii") + stdout + b"\0" + stderr
    return hashlib.sha256(preimage).hexdigest()


def accepted_result(returncode, stderr):
    return returncode == 0 or manifests.CONDA_SOLVE_FAILURE.encode() in stderr


def _rows(path, columns):
    text = path.read_text(encoding="utf-8")
    found = []
    for headers, rows, _line in registers.parse_tables(text):
        if headers != columns:
            continue
        for index, row in enumerate(rows, start=1):
            if len(row) != len(columns):
                raise VerificationError(f"{path}: malformed table row {index}")
            found.append(dict(zip(columns, map(_clean, row))))
    return found


def load_shards(audit, supplementary=False):
    ledgers, records = [], {}
    root = audit / ("_code_error_recheck_supplementary"
                    if supplementary else "_code_error_recheck")
    if not root.is_dir():
        return ledgers, records
    for path in sorted(root.rglob("*.md")):
        for row in _rows(path, CODE_LEDGER_COLS):
            ledgers.append((path, row))
        for columns in (MF_RECORD_COLS, PROBE_RECORD_COLS):
            for row in _rows(path, columns):
                record_id = row["Record ID"]
                if record_id in records:
                    raise VerificationError(f"duplicate verification Record ID {record_id}")
                records[record_id] = (path, row)
    return ledgers, records


def _mapped_dismissal_obligations(audit, ledgers, supplementary=False):
    if supplementary:
        lint = registers.Lint()
        mappings = registers.supplementary_detector_mappings(lint, audit)
        if lint.errors:
            raise VerificationError(" | ".join(lint.errors))
    else:
        _declared, _display, mappings = detector_mapping.load_mapping(
            audit / "_run/detector_mapping.md")
    ledger_by_id = {}
    for path, row in ledgers:
        ledger_by_id.setdefault(row["ID"], []).append((path, row))
    manifest_rules = {}
    manifest_path = audit / "_run/manifest_check.md"
    if manifest_path.is_file():
        columns = [
            "Source ID", "Witness ID", "Site Anchor", "Rule Slug",
            "Offending Text", "Problem",
        ]
        for row in _rows(manifest_path, columns):
            manifest_rules[("MF", row["Source ID"], row["Witness ID"])] = (
                row["Rule Slug"])
    obligations = []
    for mapping in mappings:
        dispositions = ledger_by_id.get(mapping["Error ID"], [])
        if len(dispositions) != 1:
            continue
        verdict = dispositions[0][1]["Verdict"]
        key = (mapping["Channel"], mapping["Source ID"], mapping["Witness ID"])
        if (verdict == "not_error"
                or (verdict == "confirmed_error"
                    and manifest_rules.get(key) == "conda-malformed-line")):
            obligations.append((mapping, dispositions[0]))
    return obligations


def _safe_package_file(package_root, site_anchor):
    relative = reldoc = site_anchor.rsplit(":", 1)[0]
    candidate = (package_root / relative).resolve()
    if not candidate.is_relative_to(package_root.resolve()) or not candidate.is_file():
        raise VerificationError(f"MF Site Anchor does not name a package file: {reldoc}")
    return candidate


def _conda_run(path):
    oracle = manifests.require_oracle()
    scrubbed = {k: v for k, v in os.environ.items()
                if not k.startswith(("CONDA_", "MAMBA_"))}
    scrubbed["MAMBA_NO_BANNER"] = "1"
    with tempfile.TemporaryDirectory(prefix="rca-dismiss-conda-") as tmp:
        prefix = Path(tmp) / "env"
        command = [
            str(oracle), "env", "create", "--dry-run", "--offline", "--yes",
            "--no-rc", "--no-env", "--prefix", str(prefix), "--file", str(path),
        ]
        result = subprocess.run(command, capture_output=True, env=scrubbed)
    invocation = " ".join(shlex.quote(part) for part in command).replace(
        str(prefix), "<temporary-prefix>")
    version = subprocess.run(
        [str(oracle), "--version"], capture_output=True, text=True,
        env=scrubbed).stdout.strip() or "unknown"
    return "micromamba", version, invocation, result


def _manifest_run(path, consumer):
    suffix = path.suffix.lower()
    if path.name.lower() in manifests.CONDA_NAMES or "mamba" in consumer.lower():
        return _conda_run(path)
    if suffix == ".toml" or "toml" in consumer.lower():
        code = "import pathlib,tomllib,sys;tomllib.loads(pathlib.Path(sys.argv[1]).read_text())"
        command = [sys.executable, "-I", "-c", code, str(path)]
        result = subprocess.run(command, capture_output=True)
        return "python-tomllib", sys.version.split()[0], " ".join(map(shlex.quote, command)), result
    command = [sys.executable, "-m", "pip", "install", "--dry-run", "--no-index",
               "--no-deps", "-r", str(path)]
    result = subprocess.run(command, capture_output=True,
                            env={"PATH": os.environ.get("PATH", "")})
    return "pip", "python-" + sys.version.split()[0], " ".join(map(shlex.quote, command)), result


def _probe_run(shard, harness):
    relative = Path(_clean(harness))
    if relative.is_absolute() or ".." in relative.parts:
        raise VerificationError(f"probe path must stay under its shard directory: {harness}")
    source = (shard.parent / relative).resolve()
    if not source.is_relative_to(shard.parent.resolve()) or not source.is_file():
        raise VerificationError(f"persisted probe is missing: {source}")
    with tempfile.TemporaryDirectory(prefix="rca-dismiss-probe-") as tmp:
        target = Path(tmp) / source.name
        shutil.copy2(source, target)
        if target.suffix == ".py":
            command = [sys.executable, "-I", target.name]
            tool, version = "python", sys.version.split()[0]
        elif target.suffix in {".sh", ".bash"}:
            command = ["/bin/sh", target.name]
            tool, version = "sh", "POSIX"
        else:
            command = [str(target)]
            tool, version = target.name, "recorded-probe"
        env = {"PATH": "/usr/bin:/bin", "HOME": str(Path(tmp) / "home"),
               "LC_ALL": "C", "NO_PROXY": "*", "no_proxy": "*"}
        result = subprocess.run(command, cwd=tmp, capture_output=True, env=env)
    return source, tool, version, " ".join(map(shlex.quote, command)), result


def _receipt_id(key, record_id):
    raw = "\0".join((*key, record_id)).encode("utf-8")
    return "RCP-" + hashlib.sha256(raw).hexdigest()[:12]


def verify(package_root, audit, supplementary=False):
    ledgers, records = load_shards(audit, supplementary)
    receipts = []
    for mapping, (ledger_path, ledger) in _mapped_dismissal_obligations(
            audit, ledgers, supplementary):
        key = (mapping["Channel"], mapping["Source ID"], mapping["Witness ID"])
        record_ids = _list_cell(ledger["Verification Record IDs"])
        matching = []
        for record_id in record_ids:
            item = records.get(record_id)
            if item and tuple(item[1][field] for field in
                              ("Channel", "Source ID", "Witness ID")) == key:
                matching.append((record_id, *item))
        if len(matching) != 1:
            raise VerificationError(
                f"{ledger_path}: mapped dismissal {'/'.join(key)} requires exactly one verification record"
            )
        record_id, shard, record = matching[0]
        if key[0] == "MF":
            input_path = _safe_package_file(package_root, mapping["Site Anchor"])
            tool, version, invocation, result = _manifest_run(
                input_path, record.get("Consumer", ""))
        else:
            input_path, tool, version, invocation, result = _probe_run(
                shard, record["Harness / Input Domain"])
        receipts.append({
            "Channel": key[0], "Receipt ID": _receipt_id(key, record_id),
            "Source ID": key[1], "Witness ID": key[2], "Record ID": record_id,
            "Tool": tool, "Tool Version": version,
            "Input Digest (sha256)": _sha256(input_path), "Invocation": invocation,
            "Exit Status": str(result.returncode),
            "Accepted (yes/no)": "yes" if accepted_result(result.returncode, result.stderr) else "no",
            "Result Digest (sha256)": result_digest(
                result.returncode, result.stdout, result.stderr),
        })
    return receipts


def render(receipts, supplementary=False):
    lines = ["# Supplementary dismissal receipts" if supplementary
             else "# Dismissal receipts", ""]
    if not receipts:
        zero = SUPPLEMENTARY_ZERO_RECEIPTS if supplementary else ZERO_RECEIPTS
        return "\n".join(lines + [zero, ""])
    lines += ["| " + " | ".join(RECEIPT_COLS) + " |",
              "| " + " | ".join(["---"] * len(RECEIPT_COLS)) + " |"]
    for row in sorted(receipts, key=lambda item: (
            item["Channel"], item["Source ID"], item["Witness ID"])):
        lines.append("| " + " | ".join(str(row[col]).replace("|", "\\|")
                                           for col in RECEIPT_COLS) + " |")
    return "\n".join(lines) + "\n"


def _write_atomic(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
        os.replace(temp_name, path)
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_root", type=Path)
    parser.add_argument("--audit-dir", type=Path)
    parser.add_argument("--supplementary", action="store_true")
    parser.add_argument(
        "--tokens", action="store_true",
        help="verify token_verification records and write token-receipts/v1",
    )
    parser.add_argument(
        "--token-stage", choices=("code_b6a", "code_b6b", "bC"),
        help="token receipt home (default follows --supplementary)",
    )
    args = parser.parse_args()
    root = args.package_root.expanduser().resolve()
    audit = (args.audit_dir or root / "audit").expanduser().resolve()
    if args.token_stage and not args.tokens:
        parser.error("--token-stage requires --tokens")
    if args.tokens:
        token_stage = args.token_stage or (
            "code_b6b" if args.supplementary else "code_b6a")
        output = severity_tokens.receipt_path(audit, token_stage)
    else:
        output = audit / ("_run/code_b6b/dismissal_receipts.md"
                          if args.supplementary
                          else "_run/code_b6a/dismissal_receipts.md")
    try:
        if args.tokens:
            manifest_path = audit / "_run/manifest.json"
            try:
                manifest = __import__("json").loads(
                    manifest_path.read_text(encoding="utf-8"))
            except (__import__("json").JSONDecodeError, OSError) as exc:
                raise VerificationError(f"cannot read token verifier manifest: {exc}") from exc
            receipts, failures = severity_tokens.verify_token_records(
                root, audit, manifest, token_stage, prefer_staging=True)
            if failures:
                raise VerificationError(" | ".join(failures))
            severity_tokens.write_atomic(
                output, severity_tokens.render_receipts(receipts))
        else:
            receipts = verify(root, audit, args.supplementary)
            _write_atomic(output, render(receipts, args.supplementary))
    except (VerificationError, detector_mapping.MappingError,
            manifests.OracleError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    kind = "token" if args.tokens else "dismissal"
    print(f"wrote {len(receipts)} {kind} receipt(s): {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
