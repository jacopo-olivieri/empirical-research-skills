"""Pytest configuration for the research-codebase-audit script tests.

Run from the skill folder with:

    uv run --no-project --with pytest --with openpyxl -- pytest scripts/tests/

(or plain ``python -m pytest scripts/tests/`` if pytest and openpyxl are
installed). Shared builders live in ``regbuild.py``.
"""

import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "u1: unit U1 — mechanism schema and canonicalizer (issue #14)")
    config.addinivalue_line(
        "markers", "u2: unit U2 — descoped stage certification core")
    config.addinivalue_line(
        "markers", "u3: unit U3 — detector channels and adjudication")
    config.addinivalue_line(
        "markers", "u4: unit U4 — thinking effort and CV activation")
    config.addinivalue_line(
        "markers", "u5: unit U5 — trimmed replay harness")
    config.addinivalue_line(
        "markers", "u6: unit U6 — clean-file recall and supplementary lifecycle")
    config.addinivalue_line(
        "markers", "u7: unit U7 — anchor-preserving claim handoffs")
    config.addinivalue_line(
        "markers", "u8: unit U8 — severity and argument contracts")
    config.addinivalue_line(
        "markers", "u9: unit U9 — acceptance campaign contracts")
    config.addinivalue_line(
        "markers", "u11: unit U11 — Stata analysis extensions (DU producer "
        "groups, AC macro-fronted interpreters)")
    config.addinivalue_line(
        "markers", "u12: unit U12 — the path/import idiom-closure channel")
    config.addinivalue_line(
        "markers", "u13: unit U13 — the DU comment-closure adjudication "
        "contract")
    config.addinivalue_line(
        "markers", "u14: unit U14 — register lints and severity (the closed "
        "footer reason vocabulary and the severity-4 target-type join)")
    config.addinivalue_line(
        "markers", "u15: unit U15 — the open-reading budget protection policy "
        "(phase-note partition and second-read block coverage)")
    config.addinivalue_line(
        "markers", "u16: unit U16 — usage-limit resilience and manifest stage "
        "timestamps (conductor-PID marker liveness, the guarded resume "
        "launcher, the usage feed, started_at/ended_at)")
    config.addinivalue_line(
        "markers", "u17: unit U17 — Opus 5 + medium-effort defaults and the "
        "author-facing workbook cut (three sheets, 11 visible Paper Claims "
        "columns, independent b9 hidden-column mirror)")
    config.addinivalue_line(
        "markers", "u18: unit U18 — campaign-close chain plants and their "
        "scorer (three fail-closed gate legs: register pass condition, "
        "workbook shape, effort map; plant-tree drift protection)")
