* build_flags.do — build station-day exceedance flags from the raw monitor
* readings.  Run from the package root: stata-se -b do do/build_flags.do
version 17
clear all

import delimited using "data/readings.csv", clear varnames(1)

* Regulatory daily thresholds: PM2.5 35 ug/m3, ozone 70 ppb.
local lim_pm25 35
local lim_ozone 70

* exceed_any marks station-days exceeding any pollutant threshold
gen byte exceed_any = 0
foreach p in pm25 ozone {
    replace exceed_any = `p' > `lim_`p''
}

cap mkdir output
save "output/station_days.dta", replace
