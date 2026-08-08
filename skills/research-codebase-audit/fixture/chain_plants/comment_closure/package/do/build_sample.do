* build_sample.do — build the analysis sample of program-eligible students.
* Run from the package root: stata-se -b do do/build_sample.do
version 17
clear all

import delimited using "data/students.csv", clear varnames(1)

* eligible_flag covers full-year students on the standard and
* reduced-price meal plans
gen byte eligible_flag = enrolled_full_year == 1
keep if eligible_flag == 1 & meal_plan == "standard"

cap mkdir output
save "output/analysis_sample.dta", replace
