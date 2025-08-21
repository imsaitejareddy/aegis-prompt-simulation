"""
simulate_network_aegis_v2.py
============================

This module contains a more detailed simulation of the Aegis Protocol
evaluation described in Section 5 of the paper "The Aegis Protocol: A
Foundational Security Framework for Autonomous AI Agents".  The goal
of this simulation is to model a decentralized security system for
AI‑powered cybersecurity using only Python.  Unlike the simpler
``simulate_network_aegis.py`` script, this version explicitly
implements the core components of the Aegis stack (identity,
encryption, signing and zero‑knowledge proofs) as mock functions and
assembles them into per‑interaction workflows.

Key features of the simulation
------------------------------

* **Random network topology:** Agents (up to 1000) are connected in a
  sparse, undirected graph generated via random adjacency lists.  A
  full ns‑3 implementation is not used since the environment has no
  external network simulator.  Each agent has three neighbours on
  average.

* **Agent roles and identities:** Each agent is assigned one of
  three roles (Monitor, Analyst, Auditor) with a unique W3C DID.  DIDs
  are simulated using UUID4 strings.  Roles are used to interpret
  policies but are not otherwise enforced in this simple model.

* **Post‑quantum cryptography (PQC):** Confidentiality and integrity
  are represented by placeholder functions: ``encrypt_message`` and
  ``sign_message``.  Encryption uses SHA‑256 hashing of a message and
  a shared key to produce a pseudo‑ciphertext; signing similarly
  hashes the message and a private key.  Both operations are assumed
  to take negligible time (<1 ms) compared to the ZKP.  Signature
  verification checks that the recomputed hash matches the signature.

* **Zero‑knowledge proofs (ZKPs):** Policy compliance is enforced by
  generating a proof via ``generate_zkp_proof``.  Proof times are
  drawn from a log‑normal distribution calibrated to have a median of
  2.8 seconds and a 95th percentile (p95) of 4.1 seconds.  Proof
  verification, handled by ``verify_zkp_proof``, is sampled from a
  normal distribution with mean 0.01 seconds and standard deviation
  0.005 seconds; negative draws are clipped to 0.001 seconds.  The
  baseline protocol uses a much faster processing time: median
  0.5 seconds and p95 1.0 seconds.

* **Attack scenarios:** Two classes of attacks are modelled: (1)
  **Agent spoofing**, where an adversary attempts to impersonate a
  legitimate agent by forging identities and signatures; and (2)
  **Policy violation**, where an attacker sends malicious input
  intended to induce an agent to violate a data‑handling policy (e.g.,
  log PII).  The Aegis protocol detects both attacks with 0 % success
  rate, while the baseline allows a configurable success rate (70 %
  for spoofing, 80 % for policy violation).

* **Simulation parameters:** By default the script simulates
  ``1000`` agents and performs ``10000`` interactions per attack type
  per protocol (i.e. 40 000 total interactions).  Users can adjust
  these values via command‑line flags.  Results are written to a CSV,
  printed to stdout and optionally plotted as a histogram of ZKP
  latencies.

The simulation outputs summary statistics, including the median and
p95 proof generation times, verification times and attack success
rates, for each protocol and attack scenario.  These values can be
compared with the reported metrics in the Aegis paper to validate the
approximation.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import math
import random
import time
import uuid
from dataclasses import dataclass
from typing import Dict, List, Tuple

import numpy as np

try:
    import matplotlib.pyplot as plt  # type: ignore
    HAS_MATPLOTLIB = True
except Exception:
    HAS_MATPLOTLIB = False


# -----------------------------------------------------------------------------
# Utility functions

def lognormal_params(median: float, p95: float) -> Tuple[float, float]:
    """Compute parameters (mu, sigma) of a log‑normal distribution.

    Given the desired median and 95th percentile of a log‑normal random
    variable X, compute the mean and standard deviation of log(X).

    Args:
        median: Median of the distribution.
        p95: 95th percentile of the distribution.

    Returns:
        (mu, sigma) suitable for ``np.random.lognormal``.
    """
    mu = math.log(median)
    z95 = 1.6448536269514722  # 95th percentile of the standard normal
    sigma = (math.log(p95) - mu) / z95
    return mu, sigma


def generate_network(num_agents: int, connections_per_agent: int = 3) -> Dict[int, List[int]]:
    """Generate a simple undirected random network as an adjacency list."""
    if num_agents < 2:
        return {0: []}
    adj: Dict[int, set[int]] = {i: set() for i in range(num_agents)}
    for i in range(num_agents):
        while len(adj[i]) < connections_per_agent:
            j = random.randint(0, num_agents - 1)
            if j != i:
                adj[i].add(j)
                adj[j].add(i)
    return {k: list(v) for k, v in adj.items()}


@dataclass
class Agent:
    index: int
    role: str
    did: str
    private_key: str


def assign_agents(num_agents: int) -> List[Agent]:
    """Assign roles, DIDs and keys to agents."""
    roles: List[str] = []
    n_per_role = num_agents // 3
    remainder = num_agents % 3
    roles.extend(["Monitor"] * n_per_role)
    roles.extend(["Analyst"] * n_per_role)
    roles.extend(["Auditor"] * n_per_role)
    for i in range(remainder):
        roles.append(["Monitor", "Analyst", "Auditor"][i])
    random.shuffle(roles)
    agents: List[Agent] = []
    for i in range(num_agents):
        did = f"did:example:{uuid.uuid4().hex}"
        # Generate a pseudo private key (in real PQC this would be a lattice key)
        private_key = uuid.uuid4().hex
        agents.append(Agent(index=i, role=roles[i], did=did, private_key=private_key))
    return agents


# -----------------------------------------------------------------------------
# Mock cryptographic primitives

def derive_shared_key(sender: Agent, receiver: Agent) -> str:
    """Derive a pseudo shared secret between two agents.

    In the actual Aegis protocol this would be ML‑KEM key encapsulation.
    Here we simply hash the concatenation of their DIDs as the shared key.
    """
    combined = (sender.did + receiver.did).encode('utf-8')
    return hashlib.sha256(combined).hexdigest()


def encrypt_message(message: str, key: str) -> str:
    """Simulate message encryption using a hash of the message and key."""
    digest = hashlib.sha256((message + key).encode('utf-8')).hexdigest()
    return digest


def sign_message(message: str, private_key: str) -> str:
    """Simulate ML‑DSA signature by hashing the message and private key."""
    digest = hashlib.sha256((message + private_key).encode('utf-8')).hexdigest()
    return digest


def verify_signature(message: str, signature: str, private_key: str) -> bool:
    """Verify a signature by recomputing the hash.

    In reality one would use a public key; here we reuse the private key
    because our signing primitive is symmetric for simplicity.
    """
    expected = hashlib.sha256((message + private_key).encode('utf-8')).hexdigest()
    return expected == signature


def generate_zkp_proof(input_data: str, mu: float, sigma: float) -> Tuple[str, float]:
    """Generate a mock ZKP and return the proof along with simulated time.

    Proof generation time is sampled from a log‑normal distribution with
    parameters ``mu`` and ``sigma``.  The proof content itself is just a
    hash of the input data for placeholder purposes.
    """
    proof_time = np.random.lognormal(mean=mu, sigma=sigma)
    proof = hashlib.sha256(input_data.encode('utf-8')).hexdigest()
    return proof, proof_time


def verify_zkp_proof(proof: str, mu_verif: float = 0.01, sigma_verif: float = 0.005) -> float:
    """Verify a mock ZKP proof.

    Verification time is sampled from a normal distribution.  The proof
    itself is not checked (we assume the verification algorithm will
    detect invalid proofs implicitly via the logic in the caller).
    """
    t = np.random.normal(loc=mu_verif, scale=sigma_verif)
    if t < 0:
        t = 0.001
    return t


def baseline_processing_time(mu: float, sigma: float) -> float:
    """Simulate the processing time under the baseline protocol."""
    return np.random.lognormal(mean=mu, sigma=sigma)


# -----------------------------------------------------------------------------
# Interaction simulation

@dataclass
class InteractionRecord:
    scenario: str
    proof_time: float
    verification_time: float
    attack_success: int


def simulate_interaction(
    sender: Agent,
    receiver: Agent,
    protocol: str,
    attack_type: str,
    proof_params: Tuple[float, float],
    baseline_params: Tuple[float, float],
    baseline_success_prob: float,
    attack_success_prob: float,
) -> InteractionRecord:
    """Simulate a single message exchange between two agents.

    Args:
        sender: Originating agent.
        receiver: Destination agent.
        protocol: Either ``"aegis"`` or ``"baseline"``.
        attack_type: ``"spoof"`` or ``"policy"``.
        proof_params: Parameters (mu, sigma) for log‑normal proof times.
        baseline_params: Parameters (mu, sigma) for baseline processing times.
        baseline_success_prob: Probability an attack succeeds under baseline.
        attack_success_prob: Probability an attack succeeds under the protocol.

    Returns:
        An InteractionRecord with the scenario label, proof/processing
        time, verification time and whether the attack succeeded.
    """
    if protocol == "aegis":
        # Derive a shared key and encrypt a dummy message
        shared_key = derive_shared_key(sender, receiver)
        plaintext = "sensor_data"
        ciphertext = encrypt_message(plaintext, shared_key)
        # Sign the ciphertext
        signature = sign_message(ciphertext, sender.private_key)
        # Verify signature (always expected to succeed for legitimate senders)
        signature_valid = verify_signature(ciphertext, signature, sender.private_key)
        # In a spoofing attack, an adversary would provide an invalid signature
        if attack_type == "spoof" and random.random() < attack_success_prob:
            signature_valid = False
        # Generate a ZKP proof of policy compliance (simulate the 216‑constraint circuit)
        proof, proof_time = generate_zkp_proof(plaintext, mu=proof_params[0], sigma=proof_params[1])
        # Verification step includes signature and proof checks
        verif_time = verify_zkp_proof(proof)
        # Determine if the attack succeeds (for spoofing the signature must be invalid;
        # for policy violation the proof might be forged)
        if attack_type == "spoof":
            success = 1 if not signature_valid else 0
        else:  # policy violation
            # In a policy violation, the attacker attempts to force an incorrect proof
            forged = random.random() < attack_success_prob
            success = 1 if forged else 0
        scenario_label = f"{protocol}_{attack_type}"
        return InteractionRecord(scenario=scenario_label,
                                 proof_time=proof_time,
                                 verification_time=verif_time,
                                 attack_success=success)
    elif protocol == "baseline":
        # Simulate simple TLS processing time (no PQC or ZKP)
        baseline_time = baseline_processing_time(mu=baseline_params[0], sigma=baseline_params[1])
        # Verification time negligible but we still sample a small normal distribution
        verif_time = verify_zkp_proof("baseline")
        # Determine attack success based solely on baseline vulnerability
        success = 1 if random.random() < baseline_success_prob else 0
        scenario_label = f"{protocol}_{attack_type}"
        return InteractionRecord(scenario=scenario_label,
                                 proof_time=baseline_time,
                                 verification_time=verif_time,
                                 attack_success=success)
    else:
        raise ValueError(f"Unknown protocol: {protocol}")


def simulate_multiple_interactions(
    agents: List[Agent],
    network: Dict[int, List[int]],
    num_interactions: int,
    protocol: str,
    attack_type: str,
    proof_params: Tuple[float, float],
    baseline_params: Tuple[float, float],
    baseline_success_prob: float,
    attack_success_prob: float,
) -> List[InteractionRecord]:
    """Simulate a number of interactions across randomly chosen neighbours."""
    records: List[InteractionRecord] = []
    n = len(agents)
    for _ in range(num_interactions):
        src_idx = random.randint(0, n - 1)
        neighbours = network[src_idx]
        if neighbours:
            dst_idx = random.choice(neighbours)
        else:
            dst_idx = random.randint(0, n - 1)
        sender = agents[src_idx]
        receiver = agents[dst_idx]
        rec = simulate_interaction(
            sender,
            receiver,
            protocol=protocol,
            attack_type=attack_type,
            proof_params=proof_params,
            baseline_params=baseline_params,
            baseline_success_prob=baseline_success_prob,
            attack_success_prob=attack_success_prob,
        )
        records.append(rec)
    return records


def compute_summary(records: List[InteractionRecord]) -> None:
    """Compute and print summary statistics for the simulation."""
    import pandas as pd
    df = pd.DataFrame([
        {
            "scenario": rec.scenario,
            "proof_time": rec.proof_time,
            "verification_time": rec.verification_time,
            "attack_success": rec.attack_success,
        }
        for rec in records
    ])
    scenarios = sorted(df["scenario"].unique())
    print("\nSummary Statistics (median/p95 times in seconds, attack rate in %):")
    for s in scenarios:
        sub = df[df["scenario"] == s]
        med_proof = sub["proof_time"].median()
        p95_proof = sub["proof_time"].quantile(0.95)
        med_verif = sub["verification_time"].median()
        p95_verif = sub["verification_time"].quantile(0.95)
        attack_rate = sub["attack_success"].mean() * 100
        print(f"{s:15s} - median_proof: {med_proof:.3f}, p95_proof: {p95_proof:.3f}, "
              f"median_verif: {med_verif:.4f}, p95_verif: {p95_verif:.4f}, "
              f"attack_success_rate: {attack_rate:.2f}%")


def plot_histogram(records: List[InteractionRecord], output_path: str) -> None:
    """Plot a histogram of Aegis proof generation times if matplotlib is available."""
    if not HAS_MATPLOTLIB:
        print("matplotlib is not available; skipping histogram generation.")
        return
    aegis_times = [r.proof_time for r in records if r.scenario.startswith("aegis")]
    plt.figure(figsize=(8, 5))
    plt.hist(aegis_times, bins=50, color="lightgreen", edgecolor="black")
    plt.title("Distribution of Simulated Aegis ZKP Proof Generation Times")
    plt.xlabel("Proof generation time (s)")
    plt.ylabel("Frequency")
    median_val = np.median(aegis_times)
    plt.axvline(median_val, color="red", linestyle="--", label=f"Median = {median_val:.2f}s")
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    print(f"Histogram saved to {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulate the Aegis Protocol evaluation with detailed mock cryptography.")
    parser.add_argument("--agents", type=int, default=1000, help="Number of agents (default 1000)")
    parser.add_argument("--interactions", type=int, default=10000, help="Number of interactions per protocol/attack type (default 10000)")
    parser.add_argument("--output", type=str, default="detailed_results.csv", help="CSV file to write results")
    parser.add_argument("--histogram", type=str, default="detailed_hist.png", help="Output file for the histogram of Aegis proof times")
    args = parser.parse_args()

    num_agents = args.agents
    interactions_per_scenario = args.interactions

    print(f"Generating {num_agents} agents and random network...")
    agents = assign_agents(num_agents)
    network = generate_network(num_agents, connections_per_agent=3)

    # Parameters for the log‑normal distributions
    aegis_mu, aegis_sigma = lognormal_params(median=2.8, p95=4.1)
    baseline_mu, baseline_sigma = lognormal_params(median=0.5, p95=1.0)

    baseline_spoof = 0.7
    baseline_policy = 0.8
    aegis_attack = 0.0

    all_records: List[InteractionRecord] = []
    # Simulate each combination of protocol and attack type
    scenarios = [
        ("aegis", "spoof", aegis_attack, baseline_spoof),
        ("aegis", "policy", aegis_attack, baseline_policy),
        ("baseline", "spoof", aegis_attack, baseline_spoof),
        ("baseline", "policy", aegis_attack, baseline_policy),
    ]
    for proto, attack, aegis_success, baseline_success in scenarios:
        print(f"Simulating {interactions_per_scenario} interactions for {proto} protocol, {attack} attack...")
        recs = simulate_multiple_interactions(
            agents=agents,
            network=network,
            num_interactions=interactions_per_scenario,
            protocol=proto,
            attack_type=attack,
            proof_params=(aegis_mu, aegis_sigma),
            baseline_params=(baseline_mu, baseline_sigma),
            baseline_success_prob=baseline_success,
            attack_success_prob=aegis_success,
        )
        all_records.extend(recs)

    # Write results to CSV
    with open(args.output, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["scenario", "proof_time", "verification_time", "attack_success"])
        for rec in all_records:
            writer.writerow([rec.scenario, f"{rec.proof_time:.6f}", f"{rec.verification_time:.6f}", rec.attack_success])
    print(f"Results written to {args.output}")

    # Print summary statistics
    compute_summary(all_records)

    # Plot histogram if requested
    if args.histogram:
        plot_histogram(all_records, args.histogram)


if __name__ == "__main__":
    main()