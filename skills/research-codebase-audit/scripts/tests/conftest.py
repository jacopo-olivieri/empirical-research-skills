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
