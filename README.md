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

* `simulate_network_aegis.py` — A more detailed simulation of the Aegis
  evaluation that constructs a random peer‑to‑peer network of agents (up to
  1,000) and models their interactions under both the baseline and Aegis
  protocols.  It simulates post‑quantum cryptographic primitives (ML‑KEM
  and ML‑DSA) and zero‑knowledge proofs with realistic latency
  distributions (median ≈2.8 s, p95 ≈4.1 s).  Two attack scenarios are
  considered — agent spoofing and policy‑violation via malicious input —
  and the script reports median/p95 latencies and attack success rates.
  Running this script with the default parameters replicates the 20,000
  interactions described in the paper’s evaluation.  Use the `--histogram`
  option to generate a histogram of ZKP proof times.

* `simulate_network_aegis_v2.py` — An **enhanced** network simulation that
  explicitly models the cryptographic workflow of the Aegis protocol.  In
  addition to generating a random graph of agents, this script performs
  mock key derivation, encryption and signature operations for each
  message, and simulates zero‑knowledge proof generation and
  verification using log‑normal and normal distributions, respectively.
  Attack scenarios (spoofing and policy violation) are represented by
  forged signatures or proofs; the baseline protocol omits PQC and ZKP
  layers and thus exhibits lower latency but higher attack success rates.
  The default configuration runs 10,000 interactions per protocol and
  attack type (40,000 total).  Use the `--output` and `--histogram`
  flags to control file names.

* `plots/` — When `analysis.py` is executed, this directory will contain
  the generated figures (`latency_boxplot.png` and
  `attack_success_rates.png`) as well as a `summary_statistics.csv` file.

## Running the simulation

1. **Generate synthetic results (simplified simulation).** From the root
   of the repository, run:

   ```bash
   python simulate_aegis.py --interactions 10000 --output results.csv
   ```

   Adjust the `--interactions` argument to change the number of
   interactions per scenario.  With 10,000 interactions per scenario, the
   script will produce 60,000 records across six scenarios.

   Alternatively, to run the detailed network simulation with explicit
   cryptographic mocks, invoke:

   ```bash
   python simulate_network_aegis_v2.py --agents 1000 --interactions 10000 --output detailed_results.csv --histogram detailed_hist.png
   ```

   This command simulates a network of 1,000 agents, performs 10,000
   interactions per protocol/attack combination (a total of 40,000
   interactions), writes results to `detailed_results.csv` and saves a
   histogram of Aegis proof times to `detailed_hist.png`.  Expect the
   median proof time to be around 2.8 seconds and the p95 around
   4.1 seconds.

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