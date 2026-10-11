"""Synthetic SMF-like NF monitoring, NOT a 3GPP protocol implementation."""
import numpy as np
import pandas as pd

LOCAL = ["reported_rps", "reported_success_rate", "local_latency_ms", "cpu_percent"]
TEMPORAL = ["reported_success_std", "reported_rps_std"]
KIE = ["kie_rtt_ms", "kie_timeout_rate", "kie_age_ms"]
ZONE = ["zone_witness_deviation", "zone_kie_deviation"]
CAUSAL = ["witness_report_disagreement", "procedure_order_disagreement"]
FEATURE_GROUPS = {
    "local": LOCAL,
    "local_temporal": LOCAL + TEMPORAL,
    "plus_kie": LOCAL + TEMPORAL + KIE,
    "plus_zone": LOCAL + TEMPORAL + KIE + ZONE,
    "full": LOCAL + TEMPORAL + KIE + ZONE + CAUSAL,
}

def generate_frame(seed, *, zones=4, replicas=8, steps=240, shift=False):
    """Generate independent network realization with contiguous scenario episodes.

    Assumption: a trusted independent witness sees actual procedure completions.
    A compromised NF may falsify its local counters but not the witness.
    """
    if zones < 1 or replicas < 2 or steps < 2:
        raise ValueError("Need at least one zone, two replicas and two steps")
    rng = np.random.default_rng(seed)
    rows = []
    for zone in range(zones):
        phase = rng.uniform(-np.pi, np.pi)
        wave = 94 + 22 * np.sin(np.arange(steps) / 21 + phase) + rng.normal(0, 5, steps)
        for node in range(replicas):
            episodes = []
            while len(episodes) < steps:
                state = str(rng.choice(["normal", "benign_burst", "dos", "stealth"],
                                       p=[.70, .12, .07, .11]))
                episodes.extend([(state, rng.uniform(.6, 1.0))] * int(rng.integers(12, 33)))
            offset = rng.uniform(-9, 9)
            for t, (scenario, severity) in enumerate(episodes[:steps]):
                demand = max(25.0, wave[t] + offset + rng.normal(0, 7))
                if scenario == "benign_burst":
                    demand *= 1.35 + .25 * severity
                if scenario == "dos":
                    true_success = rng.uniform(.53, .72)
                elif scenario == "stealth":
                    true_success = rng.uniform(.86, .945) if shift else rng.uniform(.70, .88)
                elif scenario == "benign_burst":
                    true_success = rng.uniform(.88, .965)
                else:
                    true_success = rng.uniform(.961, .992)
                report = (rng.normal(.977, .009) if scenario == "stealth"
                          else true_success + rng.normal(0, .012 if shift else .008))
                report = float(np.clip(report, 0, 1))
                latency = float(max(1, rng.normal(29, 5)
                    + (85 * severity if scenario == "dos" else 0)
                    + (31 * severity if scenario == "benign_burst" else 0)))
                cpu = float(np.clip(36 + (demand - 94) * .17 + rng.normal(0, 5)
                    + (22 * severity if scenario == "dos" else 0)
                    + (19 * severity if scenario == "benign_burst" else 0), 0, 100))
                kie_rtt = float(max(1, rng.normal(24, 9 if shift else 5)
                    + (60 * severity if scenario == "dos" else 0)
                    + (10 * severity if scenario == "stealth" else 0)
                    + (18 * severity if scenario == "benign_burst" else 0)))
                kie_timeout = float(np.clip(rng.normal(.016, .027 if shift else .013)
                    + (.30 * severity if scenario == "dos" else 0)
                    + (.04 * severity if scenario == "stealth" else 0)
                    + (.035 * severity if scenario == "benign_burst" else 0), 0, 1))
                witness = float(np.clip(true_success
                    + rng.normal(0, .028 if shift else .014), 0, 1))
                order_disagreement = float(np.clip(
                    rng.normal(.009, .017 if shift else .008)
                    + ((1 - true_success) * .42 if scenario == "stealth" else 0)
                    + ((1 - true_success) * .06 if scenario == "dos" else 0), 0, 1))
                rows.append(dict(
                    seed=seed, zone=zone, node=node, time_step=t,
                    scenario=scenario, y_attack=int(scenario in ("stealth", "dos")),
                    reported_rps=float(demand * report), reported_success_rate=report,
                    local_latency_ms=latency, cpu_percent=cpu,
                    kie_rtt_ms=kie_rtt, kie_timeout_rate=kie_timeout,
                    kie_age_ms=float(max(0, kie_rtt + rng.normal(9, 14 if shift else 6))),
                    witness_success_rate=witness,
                    witness_report_disagreement=abs(report - witness),
                    procedure_order_disagreement=order_disagreement,
                ))
    df = pd.DataFrame(rows)
    for source, dest in (("reported_rps", "reported_rps_std"),
                         ("reported_success_rate", "reported_success_std")):
        df[dest] = (df.groupby(["seed", "zone", "node"], sort=False)[source]
                      .transform(lambda s: s.rolling(6, min_periods=2).std().fillna(0)))
    grouping = ["seed", "zone", "time_step"]
    df["zone_witness_deviation"] = abs(df.witness_success_rate
        - df.groupby(grouping).witness_success_rate.transform("median"))
    df["zone_kie_deviation"] = abs(df.kie_rtt_ms
        - df.groupby(grouping).kie_rtt_ms.transform("median"))
    assert df[FEATURE_GROUPS["full"]].notna().all().all()
    return df
