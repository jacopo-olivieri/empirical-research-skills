* make_tab1.do — Table 1: share of station-days exceeding any pollutant
* threshold.  Run from the package root after do/build_flags.do.
version 17
clear all

use "output/station_days.dta", clear
summarize exceed_any
local share : display %4.1f r(mean) * 100

file open tab using "artifacts/tab1.tex", write replace
file write tab "\begin{tabular}{lc}" _n
file write tab "\hline" _n
file write tab "Station-days exceeding any pollutant threshold (\%) & `share' \\" _n
file write tab "\hline" _n
file write tab "\end{tabular}" _n
file close tab
