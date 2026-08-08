"""Compute the annual interlibrary loan total reported in the paper.

Reads the monthly loan counts and writes the annual total to
``artifacts/totals.txt``.  Run with: python py/tools/make_totals.py
"""

import csv
import os

PRIMARY = os.path.join(os.path.dirname(__file__), "..", "..", "..",
                       "data", "loans.csv")
FALLBACK = os.path.join(os.path.dirname(__file__), "..", "..", "loans.csv")
OUT_PATH = os.path.join(os.path.dirname(__file__), "..", "..",
                        "artifacts", "totals.txt")


def main():
    try:
        handle = open(PRIMARY, newline="")
    except OSError:
        handle = open(FALLBACK, newline="")
    with handle:
        reader = csv.DictReader(handle)
        total = sum(int(row["loans"]) for row in reader)
    with open(OUT_PATH, "w") as out:
        out.write("annual_loan_total %d\n" % total)
    print("annual_loan_total %d" % total)


if __name__ == "__main__":
    main()
