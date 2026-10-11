"""Threat-model sensitivity tests for synthetic hierarchical 5G-like monitoring.

IMPORTANT: malicious alterations are inserted into *simulated feature rows*
using ground-truth scenario identities. This is an oracle-targeted stress
experiment, not a deployment-ready attack detector and not real 5G data.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from .experiment import TRAIN_SEEDS, VALID_SEEDS, TEST_SEEDS, TARGET_FPR, dataset, threshold, metrics
from .simulate import FEATURE_GROUPS

FEATURES = FEATURE_GROUPS["full"]
SEED = 20261011


def corrupt_observations(frame: pd.DataFrame, *, strategy: str, fraction: float, seed: int) -> pd.DataFrame:
    """Adversarial influence on telemetry at evaluation time; *not* re-training.

    witness_suppression: compromised nodes spoof their two consistency checks.
    observer_capture: above plus peer-median witness context corruption.
    total_blinding: above plus manipulated KIE data and zone KIE deviations.
    false_testimony: benign NF falsely accused by manipulated witness observations.
    """
    if strategy not in ("witness_suppression", "observer_capture", "total_blinding", "false_testimony"):
        raise ValueError(strategy)
    if not 0 <= fraction <= 1:
        raise ValueError("fraction must be between 0 and 1")
    out = frame.copy(deep=True)
    rng = np.random.default_rng(seed)
    target = out.scenario.eq("normal") if strategy == "false_testimony" else out.scenario.eq("stealth")
    indices = np.flatnonzero(target.to_numpy())
    chosen = rng.choice(indices, size=int(round(len(indices) * fraction)), replace=False)
    if not len(chosen):
        return out
    if strategy == "false_testimony":
        out.loc[chosen, "witness_report_disagreement"] = .24
        out.loc[chosen, "procedure_order_disagreement"] = .13
        out.loc[chosen, "zone_witness_deviation"] = .20
        return out
    out.loc[chosen, ["witness_report_disagreement", "procedure_order_disagreement"]] = 0.005
    if strategy in ("observer_capture", "total_blinding"):
        out.loc[chosen, "zone_witness_deviation"] = 0.003
    if strategy == "total_blinding":
        out.loc[chosen, "kie_rtt_ms"] = 24.
        out.loc[chosen, "kie_timeout_rate"] = .012
        out.loc[chosen, "kie_age_ms"] = 32.
        out.loc[chosen, "zone_kie_deviation"] = 3.
    return out


def run(out_dir: Path, *, quick=False) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    steps = 80 if quick else 240
    training = dataset(TRAIN_SEEDS, steps=steps)
    validation = dataset(VALID_SEEDS, steps=steps)
    testing = dataset(TEST_SEEDS, steps=steps)
    model = RandomForestClassifier(
        n_estimators=60 if quick else 120, max_depth=13, min_samples_leaf=12,
        class_weight="balanced_subsample", n_jobs=2, random_state=2026,
    )
    model.fit(training[FEATURES], training.y_attack)
    reference_limit = threshold(
        validation.y_attack.to_numpy(), model.predict_proba(validation[FEATURES])[:, 1]
    )
    records = []
    for strategy in ["none", "witness_suppression", "observer_capture", "total_blinding", "false_testimony"]:
        fractions = [0.] if strategy == "none" else [0., .25, .5, .75, 1.]
        for frac in fractions:
            sample = testing if strategy == "none" else corrupt_observations(
                testing, strategy=strategy, fraction=frac, seed=SEED
            )
            score = model.predict_proba(sample[FEATURES])[:, 1]
            records.append({
                "strategy": strategy, "fraction_targeted": frac,
                "scope": "synthetic only; oracle-targeted at experiment-design level",
                **metrics(sample, score, reference_limit),
            })
    pd.DataFrame(records).to_csv(out_dir / "robustness_metrics.csv", index=False)
    meta = {
        "dataset": "synthetic feature-level simulator, not actual 5G Core",
        "training_seeds": TRAIN_SEEDS, "validation_seeds": VALID_SEEDS, "test_seeds": TEST_SEEDS,
        "fixed_validation_threshold": reference_limit,
        "compromised_fraction": "fraction of stealth or normal rows deliberately manipulated",
        "assumptions": ["witness is initially independent", "compromised entities can falsify specified observation features", "classifier is frozen"],
        "limitation": "Attacker selected rows using ground truth; injected values are artificial; no production NF control evaluated.",
    }
    (out_dir / "robustness_metadata.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"runs": len(records), "metrics": records}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, default=Path("results"))
    parser.add_argument("--quick", action="store_true")
    a = parser.parse_args()
    answer = run(a.out_dir, quick=a.quick)
    for row in answer["metrics"]:
        if row["fraction_targeted"] in (0., 1.):
            print("{strategy} fraction={fraction_targeted:.2f} fpr={fpr:.4f} stealth_recall={stealth_recall:.4f}".format(**row))


if __name__ == "__main__":
    main()
