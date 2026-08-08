# Replication package — Interlibrary Loan Volumes in the Pinewood Regional Library Network, 2024

## Contents

- `paper/paper.md` — the manuscript.
- `data/loans.csv` — the current monthly interlibrary loan counts for 2024:
  one row per month with `month` (`2024-01` … `2024-12`) and `loans`.
- `loans.csv` (package root) — a deprecated export of the monthly series
  kept for reference; superseded by `data/loans.csv`.
- `py/tools/make_totals.py` — sums the monthly counts and writes
  `artifacts/totals.txt`.
- `artifacts/totals.txt` — the shipped annual total.

## How to run

From the package root:

1. `python py/tools/make_totals.py`

The script rewrites `artifacts/totals.txt` and prints the annual total.
