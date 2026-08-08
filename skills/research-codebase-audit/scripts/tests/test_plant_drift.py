"""Plant-drift check: the planted fixture files must not change silently.

An accidental "fix" to a planted bug would show up as a mysterious 13/14 in
the next fixture re-score; this test catches it at test time instead. If a
fixture change is INTENTIONAL, regenerate the manifest:

    python - <<'EOF'
    import hashlib, json
    from pathlib import Path
    skill = Path("skills/research-codebase-audit")
    planted = skill / "fixture" / "planted"
    hashes = {
        str(p.relative_to(planted)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(planted.rglob("*")) if p.is_file()
    }
    out = skill / "scripts" / "tests" / "data" / "planted_sha256.json"
    out.write_text(json.dumps(hashes, indent=2) + "\n")
    EOF

The U18 chain plants get the same protection with their OWN manifest
(``chain_plants_sha256.json``), covering every file under
``fixture/chain_plants/*/package/`` plus each ``expected.json``. If a
chain-plant change is INTENTIONAL, regenerate that manifest:

    python - <<'EOF'
    import hashlib, json
    from pathlib import Path
    skill = Path("skills/research-codebase-audit")
    chain = skill / "fixture" / "chain_plants"
    files = []
    for plant in sorted(p for p in chain.iterdir() if p.is_dir()):
        expected = plant / "expected.json"
        if expected.is_file():
            files.append(expected)
        files.extend(p for p in sorted((plant / "package").rglob("*"))
                     if p.is_file())
    hashes = {
        str(p.relative_to(chain)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in files
    }
    out = skill / "scripts" / "tests" / "data" / "chain_plants_sha256.json"
    out.write_text(json.dumps(hashes, indent=2) + "\n")
    EOF
"""

import hashlib
import json

import pytest

import regbuild as rb

MANIFEST = rb.TESTS_DIR / "data" / "planted_sha256.json"
PLANTED = rb.FIXTURE_DIR / "planted"
CHAIN_MANIFEST = rb.TESTS_DIR / "data" / "chain_plants_sha256.json"
CHAIN_PLANTS = rb.FIXTURE_DIR / "chain_plants"


def test_planted_files_unchanged():
    expected = json.loads(MANIFEST.read_text(encoding="utf-8"))
    actual = {
        str(p.relative_to(PLANTED)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(PLANTED.rglob("*")) if p.is_file()
    }
    assert actual == expected, (
        "fixture/planted/ differs from the committed hash manifest — a "
        "planted bug may have been 'fixed'. If the change is intentional, "
        "regenerate scripts/tests/data/planted_sha256.json (see module "
        "docstring)."
    )


def _chain_plant_files():
    """Every package file plus each plant's answer key, in a stable order."""
    files = []
    for plant in sorted(p for p in CHAIN_PLANTS.iterdir() if p.is_dir()):
        expected = plant / "expected.json"
        if expected.is_file():
            files.append(expected)
        files.extend(p for p in sorted((plant / "package").rglob("*"))
                     if p.is_file())
    return files


@pytest.mark.u18
def test_chain_plant_files_unchanged():
    expected = json.loads(CHAIN_MANIFEST.read_text(encoding="utf-8"))
    actual = {
        str(p.relative_to(CHAIN_PLANTS)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in _chain_plant_files()
    }
    assert actual == expected, (
        "fixture/chain_plants/ differs from the committed hash manifest — a "
        "planted chain defect may have been 'fixed'. If the change is "
        "intentional, regenerate scripts/tests/data/chain_plants_sha256.json "
        "(see module docstring)."
    )
