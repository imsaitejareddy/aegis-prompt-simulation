# Aegis Protocol Prompt‑Based Simulation

This repository contains a self‑contained experiment that approximates the
evaluation of the **Aegis Protocol** (as described in Section 5 of the
corresponding paper) using lightweight simulation techniques instead of a
full network simulator such as **ns‑3** or direct access to large language
model (LLM) APIs.  The goal of this experiment is to demonstrate how
prompt engineering concepts can be used to model multi‑agent interactions
and security mechanisms in a controlled environment, quantify performance
metrics, and reproduce the qualitative findings of the Aegis paper.

## Contents

* `simulate_aegis.py` — A Python script that generates synthetic interaction
  records for six scenarios: normal, spoofing, and policy‑violation
  interactions under both a baseline protocol and an Aegis‑style protocol.
  It produces a CSV file containing latency measurements and an indicator
  of whether an attack was successful.  Latencies are drawn from
  log‑normal distributions calibrated to approximate those reported in the
  paper (≈0.5 s for the baseline and ≈2.8 s for Aegis).

* `analysis.py` — A companion script that reads the simulation output,
  computes summary statistics (median/mean latency and attack success rate
  per scenario), and generates two plots: a box plot of latencies and a
  bar chart of attack success rates.

* `plots/` — When `analysis.py` is executed, this directory will contain
  the generated figures (`latency_boxplot.png` and
  `attack_success_rates.png`) as well as a `summary_statistics.csv` file.

## Running the simulation

1. **Generate synthetic results.** From the root of the repository, run:

   ```bash
   python simulate_aegis.py --interactions 10000 --output results.csv
   ```

   Adjust the `--interactions` argument to change the number of
   interactions per scenario.  With 10,000 interactions per scenario, the
   script will produce 60,000 records across six scenarios.

2. **Analyse the results.** Then run:

   ```bash
   python analysis.py --input results.csv --output-dir plots
   ```

   This will print a summary of the median and mean latencies as well as
   attack success rates, save those metrics to `plots/summary_statistics.csv`,
   and produce two PNG files visualising the distributions.

## Notes

* **Approximation of LLM interactions:** The original Aegis evaluation
  involves issuing real LLM calls to generate proofs and enforce policies.
  In this repository we **approximate** those interactions using
  statistical models (log‑normal latency distributions and fixed attack
  success probabilities) because network access and API keys may be
  unavailable in the execution environment.  The constants in
  `simulate_aegis.py` can be adjusted to explore different parameter
  regimes.

* **Security insights:** The simulation demonstrates that integrating
  cryptographic and policy enforcement layers (as in the Aegis protocol)
  significantly increases the median latency of agent interactions but
  entirely prevents the spoofing and policy‑violation attacks modelled
  here.  Conversely, a simple baseline protocol has lower latency but
  suffers from high attack success rates.

## License

This code is released under the MIT License.  See `LICENSE` for details.