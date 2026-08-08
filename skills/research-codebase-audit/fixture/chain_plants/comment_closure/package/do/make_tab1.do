* make_tab1.do — Table 1: mean daily protein intake among program-eligible
* students.  Run from the package root after do/build_sample.do.
version 17
clear all

use "output/analysis_sample.dta", clear
summarize protein_g
local mean_protein : display %4.1f r(mean)

file open tab using "artifacts/tab1.tex", write replace
file write tab "\begin{tabular}{lc}" _n
file write tab "\hline" _n
file write tab "Mean daily protein intake (g) & `mean_protein' \\" _n
file write tab "\hline" _n
file write tab "\end{tabular}" _n
file close tab
