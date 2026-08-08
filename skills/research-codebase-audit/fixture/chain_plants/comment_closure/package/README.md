# Replication package — Protein Intake Among Meal-Program Students in the Kestrel Valley School District

## Contents

- `paper/paper.md` — the manuscript.
- `data/students.csv` — the district student nutrition census: one row per
  student with `student_id`, `meal_plan` (`standard` or `reduced`),
  `enrolled_full_year` (1 = enrolled for the full school year), and
  `protein_g` (measured mean daily protein intake in grams).
- `do/build_sample.do` — builds the analysis sample of program-eligible
  students (`output/analysis_sample.dta`).
- `do/make_tab1.do` — computes the Table 1 mean and writes
  `artifacts/tab1.tex`.
- `artifacts/tab1.tex` — the shipped Table 1 panel.

## How to run

From the package root, in order:

1. `stata-se -b do do/build_sample.do`
2. `stata-se -b do do/make_tab1.do`

The scripts create `output/` for the intermediate sample and rewrite
`artifacts/tab1.tex`.
