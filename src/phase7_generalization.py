"""Phase 7 external validity: data-mining trained on actual fail-stop PDU trials
evaluated on *truthful* healthy-SMF, invalid-DNN PDU failures.

Training reports include OFFLINE falsifications from real prior phase-4 PDU
events. Validation is disjoint deployment 202. The held-out negative
control was measured later from live Open5GS and is NOT a cyberattack.
This tests false alarms under an untrained legitimate failure mode.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from .phase4_eval import (
    ABLATIONS, fabricate_pair, read_deployment, calibration_limit
)


def full_run(sources: Path, healthy_dnn_csv: Path, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    train = fabricate_pair(read_deployment(sources / "phase4-real-101"), seed=101)
    valid = fabricate_pair(read_deployment(sources / "phase4-real-202"), seed=202)
    hold = fabricate_pair(read_deployment(sources / "phase4-real-303"), seed=303)
    new = pd.read_csv(healthy_dnn_csv)
    if set(new.phase) != {"normal", "invalid_dnn", "recovery"}:
        raise ValueError("Only measured baseline, legitimate unsupported DNN and recovery accepted")
    if len(new) < 9 or (new.smf_running_witness != 1).any():
        raise ValueError("Real healthy SMF throughout is an absolute requirement")
    if new.loc[new.phase == "invalid_dnn", "ue_pdu_session_accepted"].any():
        raise ValueError("Negative control is invalid: PDU succeeded with mismatched DNN")
    if not new.loc[new.phase == "invalid_dnn", "ue_registration_seen"].any():
        raise ValueError("No valid UE registration during DNN scenario")
    new = new.copy()
    new["deployment"] = "707"  # sample origin label only, never ML input
    pairs = fabricate_pair(new, seed=707)
    report = []
    for name, columns in ABLATIONS.items():
        model = RandomForestClassifier(
            n_estimators=120, min_samples_leaf=2, max_depth=5,
            class_weight="balanced", random_state=2026, n_jobs=2
        )
        model.fit(train[columns], train.tampered)
        limit = calibration_limit(
            valid.tampered.to_numpy(),
            model.predict_proba(valid[columns])[:, 1]
        )
        for cohort, data in (("original_heldout_failstop", hold), ("new_healthy_dnn", pairs)):
            scores = model.predict_proba(data[columns])[:, 1]
            flagged = scores > limit
            for phase, view in data.groupby("phase", sort=False):
                choose = data.phase.to_numpy() == phase
                truthful = choose & (data.tampered.to_numpy() == 0)
                false_report = choose & (data.tampered.to_numpy() == 1)
                report.append({
                    "model": "RF_" + name,
                    "cohort": cohort,
                    "phase": phase,
                    "n_real_trials": int(len(view)//2),
                    "n_truthful": int(truthful.sum()),
                    "fpr_truthful": float(flagged[truthful].mean()),
                    "n_artificially_falsified": int(false_report.sum()),
                    "recall_fabricated_reports": float(flagged[false_report].mean()),
                    "threshold_fixed_validation": limit,
                })
    # An explainable, measurement-based rule (no ML) as an essential baseline.
    for cohort, data in (("original_heldout_failstop", hold), ("new_healthy_dnn", pairs)):
        # Witnesses: independent UE PDU outcome and NRF advertised SMF state.
        outcome_mismatch = data.kie_ue_outcome_mismatch > 0
        nrf_mismatch = data.nrf_health_mismatch > 0
        flagged = (outcome_mismatch | nrf_mismatch).to_numpy(dtype=bool)
        for phase, group in data.groupby("phase", sort=False):
            yes = (data.phase == phase).to_numpy()
            truthful = yes & (data.tampered.to_numpy() == 0)
            falsified = yes & (data.tampered.to_numpy() == 1)
            report.append({
                "model": "Rule_UE_NRF_disagreement",
                "cohort": cohort,
                "phase": phase,
                "n_real_trials": int(len(group)//2),
                "n_truthful": int(truthful.sum()),
                "fpr_truthful": float(flagged[truthful].mean()),
                "n_artificially_falsified": int(falsified.sum()),
                "recall_fabricated_reports": float(flagged[falsified].mean()),
                "threshold_fixed_validation": 0.,
            })
    pd.DataFrame(report).to_csv(out/"negative_control_fpr.csv", index=False)
    summary = {
        "design": "Train 101 / validate 202 / held-out 303 (fail-stop) versus separate live healthy-SMF unsupported DNN",
        "real_healthy_dnn_trials": len(new),
        "truthful_test_reports": len(new),
        "artificial_test_reports": len(new),
        "test_attack_claim": False,
        "measured_negative_control": "Unprovisioned requested DNN with healthy SMF",
        "labels": "Artificial report falsification, NOT real malicious NF compromise",
        "critical_limitations": [
            "Small and highly correlated per-phase observations",
            "The wrong DNN is a legitimate error condition, not compromise",
            "Offline fabricated reports are constructed to contradict UE/NRF witnesses",
            "No network-domain independent master architecture deployed",
            "Cannot estimate real operator attack prevalence or confidence bounds",
        ],
    }
    (out/"negative_control_metadata.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return pd.DataFrame(report)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source-dir", type=Path, default=Path("phase4_inputs"))
    p.add_argument("--healthy-dnn", type=Path, default=Path("phase7_inputs/real_pdu_windows.csv"))
    p.add_argument("--out-dir", type=Path, default=Path("results/phase7-analysis"))
    x = p.parse_args()
    df = full_run(x.source_dir, x.healthy_dnn, x.out_dir)
    print(df.to_string(index=False))


if __name__ == "__main__":
    main()
