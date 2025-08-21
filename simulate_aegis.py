"""
simulate_aegis.py
===================

This module contains a lightweight simulation of the evaluation described in
the Aegis Protocol paper (Section 5), adapted for environments where access
to a full network simulator (such as ns-3) and large language models (LLMs)
is limited or unavailable.  Instead of issuing API calls to an LLM,
the simulation uses configurable random draws to approximate the behaviour
of agents communicating under both a baseline protocol and a fortified
"Aegis" protocol with additional security layers.  The simulation produces
synthetic measurements for each interaction, including a simulated latency
for generating a zero‑knowledge proof (ZKP) and an indicator of whether a
malicious attacker succeeded in bypassing the security mechanism.

Usage:
    python simulate_aegis.py --output results.csv

The script writes a CSV containing one row per interaction with the
following columns:

    scenario:        The combination of protocol (baseline or aegis) and
                     threat model (normal, spoof, or policy_violation).
    latency:         Simulated latency in seconds for the agent to
                     generate its ZKP.  The latency distribution is
                     controlled via constants below.
    attack_success:  1 if an attacker was able to compromise the system,
                     0 otherwise.  Normal (non‑attack) scenarios always
                     record 0.

After running the simulation, you can analyse the results using the
analysis script provided in this repository.

The simulation parameters — numbers of interactions, latency statistics and
attack success probabilities — are defined at the top of this file.  They
can be tuned to explore different operational envelopes.
"""

from __future__ import annotations

import argparse
import csv
import random
import time
import math
from dataclasses import dataclass
from typing import List, Tuple

# Seed the random number generator for reproducibility.  Changing this seed
# will yield different pseudo‑random draws.
RANDOM_SEED = 42
random.seed(RANDOM_SEED)

##############################################################################
# Simulation parameters
#
# You can adjust these constants to tweak the size and properties of the
# simulation.  For example, increasing ``INTERACTIONS_PER_SCENARIO`` will
# produce more data points and therefore smoother statistics, at the cost
# of longer run times.
#
INTERACTIONS_PER_SCENARIO = 10_000

# Latency distributions (in seconds) for the baseline and Aegis protocols.
# In the Aegis paper, the authors report a median proof generation latency of
# approximately 2.8 seconds for the zero‑knowledge proof used to enforce
# policy compliance.  The baseline protocol is assumed to have a shorter
# processing time because it does not perform ZKP generation or signature
# verification.  We model these latencies as log‑normally distributed
# random variables, which reflect real‑world latencies better than a strict
# normal distribution (latencies are always positive and often skewed).

BASELINE_LATENCY_MEAN = 0.5  # seconds, approximate mean for baseline
BASELINE_LATENCY_STD = 0.1   # standard deviation in seconds

AEGIS_LATENCY_MEAN = 2.8     # seconds, approximate median for Aegis proof
AEGIS_LATENCY_STD = 0.4      # standard deviation in seconds

# Attack success probabilities.  These determine the chance that an
# adversarial interaction will bypass the security mechanisms.  The Aegis
# protocol should, in principle, block all attacks, while the baseline
# protocol is highly vulnerable.  These values are intentionally chosen to
# highlight the difference between the two protocols; the exact numbers
# can be tuned to mimic specific test conditions or to explore sensitivity.

BASELINE_SPOOF_SUCCESS_RATE = 0.7        # 70 % success rate for spoofing
BASELINE_POLICY_SUCCESS_RATE = 0.8       # 80 % success rate for policy violation
AEGIS_ATTACK_SUCCESS_RATE = 0.0          # 0 % success rate for all attacks


@dataclass
class InteractionResult:
    """Structure representing a single simulated interaction."""
    scenario: str
    latency: float
    attack_success: int  # 1 for success, 0 for failure


def lognormal_latency(mean: float, stddev: float) -> float:
    """Draw a latency from a log-normal distribution.

    Args:
        mean: Desired mean of the underlying normal distribution.
        stddev: Desired standard deviation of the underlying normal.

    Returns:
        A non-negative float representing the simulated latency.

    The log-normal distribution is parameterised by the mean and
    standard deviation of the underlying normal distribution.  To
    obtain a log-normal with an approximate mean equal to the desired
    latency mean, we solve for the parameters `mu` and `sigma` of
    the underlying normal distribution.  See https://en.wikipedia.org/wiki/Log-normal_distribution#Arithmetic_moment.
    """
    # Convert the desired arithmetic mean and standard deviation of the
    # log‑normally distributed variable into the parameters of the
    # underlying normal distribution.  For a log‑normal variable X with
    # arithmetic mean m and variance v, the parameters of the normal
    # distribution Y=ln(X) satisfy:
    # sigma^2 = ln(1 + v/m^2) ; mu = ln(m) - 0.5 * sigma^2
    # See https://en.wikipedia.org/wiki/Log-normal_distribution#Arithmetic_moment
    variance = stddev ** 2
    # Protect against division by zero or negative values.
    if mean <= 0:
        raise ValueError("mean must be positive for log-normal distribution")
    sigma_sq = max(0.0, math.log(1.0 + variance / (mean ** 2)))
    sigma = math.sqrt(sigma_sq)
    mu = math.log(mean) - 0.5 * sigma_sq
    # Draw from the normal distribution and exponentiate to obtain
    # the log-normal value.  In the unlikely event of numerical
    # underflow/overflow, guard by returning a minimum positive value.
    normal_sample = random.normalvariate(mu, sigma)
    latency = math.exp(normal_sample)
    return max(latency, 0.0)


def simulate_scenario(protocol: str, threat: str, n: int) -> List[InteractionResult]:
    """Run a batch of simulated interactions for a specific scenario.

    Args:
        protocol: Either ``"baseline"`` or ``"aegis"``.  Determines
            latency distribution and attack success probability.
        threat: One of ``"normal"``, ``"spoof"``, or ``"policy_violation"``.
            ``"normal"`` corresponds to a benign interaction, while
            the others model attacker behaviours.
        n: Number of interactions to simulate.

    Returns:
        A list of ``InteractionResult`` objects representing the
        simulated interactions.

    Raises:
        ValueError: If an unknown protocol or threat is specified.
    """
    results: List[InteractionResult] = []
    # Select latency parameters based on protocol
    if protocol == "baseline":
        lat_mean, lat_std = BASELINE_LATENCY_MEAN, BASELINE_LATENCY_STD
    elif protocol == "aegis":
        lat_mean, lat_std = AEGIS_LATENCY_MEAN, AEGIS_LATENCY_STD
    else:
        raise ValueError(f"Unknown protocol: {protocol}")

    # Determine attack success probability
    if threat == "normal":
        attack_prob = 0.0  # no attacker in normal scenario
    elif threat == "spoof":
        if protocol == "baseline":
            attack_prob = BASELINE_SPOOF_SUCCESS_RATE
        else:
            attack_prob = AEGIS_ATTACK_SUCCESS_RATE
    elif threat == "policy_violation":
        if protocol == "baseline":
            attack_prob = BASELINE_POLICY_SUCCESS_RATE
        else:
            attack_prob = AEGIS_ATTACK_SUCCESS_RATE
    else:
        raise ValueError(f"Unknown threat type: {threat}")

    scenario_name = f"{protocol}_{threat}"
    for _ in range(n):
        # Simulate latency from log-normal distribution
        latency = lognormal_latency(lat_mean, lat_std)
        # Simulate attack success; random.random returns [0,1)
        attack_success = 1 if random.random() < attack_prob else 0
        results.append(InteractionResult(scenario=scenario_name,
                                         latency=latency,
                                         attack_success=attack_success))
    return results


def run_simulation(interactions_per_scenario: int) -> List[InteractionResult]:
    """Run the full suite of scenarios and return aggregated results."""
    all_results: List[InteractionResult] = []
    scenarios = [
        ("baseline", "normal"),
        ("baseline", "spoof"),
        ("baseline", "policy_violation"),
        ("aegis", "normal"),
        ("aegis", "spoof"),
        ("aegis", "policy_violation"),
    ]
    for protocol, threat in scenarios:
        batch = simulate_scenario(protocol, threat, interactions_per_scenario)
        all_results.extend(batch)
    return all_results


def write_results_csv(results: List[InteractionResult], output_path: str) -> None:
    """Write the simulation results to a CSV file."""
    with open(output_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["scenario", "latency", "attack_success"])
        for result in results:
            writer.writerow([result.scenario, f"{result.latency:.4f}", result.attack_success])


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Run Aegis protocol simulation")
    parser.add_argument(
        "--output",
        type=str,
        default="aegis_simulation_results.csv",
        help="Path to the CSV file where results will be stored",
    )
    parser.add_argument(
        "--interactions",
        type=int,
        default=INTERACTIONS_PER_SCENARIO,
        help="Number of interactions to simulate per scenario",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    # Start timer for the simulation (useful to measure run time)
    start_time = time.time()
    results = run_simulation(args.interactions)
    # Write results to CSV
    write_results_csv(results, args.output)
    duration = time.time() - start_time
    print(f"Simulation completed in {duration:.2f} seconds.")
    print(f"Generated {len(results)} interaction records across scenarios.")
    print(f"Results saved to: {args.output}")


if __name__ == "__main__":
    main()
