# Interlibrary Loan Volumes in the Pinewood Regional Library Network, 2024

## Abstract

We report annual interlibrary loan volume for the Pinewood Regional Library
Network. The network completed 15,875 interlibrary loans in 2024.

## 1. Data

The network's circulation system records the number of completed
interlibrary loans in each calendar month. The monthly series for 2024 is
shipped as `data/loans.csv`, with one row per month (`month`, `loans`).

## 2. Method

The annual total is the sum of the twelve monthly loan counts. It is
computed by `py/tools/make_totals.py`, which writes the shipped
`artifacts/totals.txt`.

## 3. Results

The Pinewood Regional Library Network completed 15,875 interlibrary loans in
2024. Monthly volume peaked in December and was lowest in August.
