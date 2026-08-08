# Replication package — Air-Quality Exceedance Monitoring in the City of Alder Bay

## Contents

- `paper/paper.md` — the station report.
- `data/readings.csv` — daily monitor readings: one row per station-day with
  `station_id` (ST01–ST04), `day` (1–12), `pm25` (micrograms per cubic
  meter), and `ozone` (parts per billion, daily maximum 8-hour).
- `do/build_flags.do` — builds the station-day exceedance flags
  (`output/station_days.dta`).
- `do/make_tab1.do` — computes the Table 1 share and writes
  `artifacts/tab1.tex`.
- `artifacts/tab1.tex` — the shipped Table 1 panel.

## How to run

From the package root, in order:

1. `stata-se -b do do/build_flags.do`
2. `stata-se -b do do/make_tab1.do`

The scripts create `output/` for the intermediate station-day file and
rewrite `artifacts/tab1.tex`.
