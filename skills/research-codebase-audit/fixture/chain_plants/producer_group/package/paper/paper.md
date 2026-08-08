# Air-Quality Exceedance Monitoring in the City of Alder Bay: 2024 Station Report

## Abstract

We report exceedance rates from the City of Alder Bay's four continuous
air-quality monitoring stations over a twelve-day summer monitoring window.
12.5 percent of station-days exceeded at least one regulatory pollutant
threshold.

## 1. Monitoring network and data

The city operates four continuous monitoring stations (ST01–ST04), each
reporting a daily PM2.5 concentration (micrograms per cubic meter) and a
daily maximum 8-hour ozone concentration (parts per billion). The monitoring
window covers twelve consecutive days, giving 48 station-days. The
regulatory daily thresholds are 35 micrograms per cubic meter for PM2.5 and
70 parts per billion for ozone.

## 2. Exceedance definition

A station-day is an exceedance day when at least one pollutant exceeds its
regulatory threshold — that is, when the PM2.5 reading exceeds 35 or the
ozone reading exceeds 70. Flags are built by `do/build_flags.do` from
`data/readings.csv`; Table 1 is produced by `do/make_tab1.do`.

## 3. Results

Table 1 reports the share of station-days exceeding any pollutant threshold.

**Table 1.** Exceedance summary, twelve-day monitoring window, 2024.

| Quantity | Value |
| --- | --- |
| Station-days exceeding any pollutant threshold (%) | 12.5 |

One in eight station-days exceeded at least one regulatory threshold during
the monitoring window.
