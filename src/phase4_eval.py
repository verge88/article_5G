"""Real-measurement-derived KIE and telemetry-falsification study (phase 4).

Network events come from a real Open5GS/ UERANSIM lab. Falsified *monitoring
reports* are constructed AFTER measurement and never alter real SBA messages.
This does not validate detection of a malicious SMF or 3GPP-level intrusion.

Training/validation/test are separated by different GitHub Action deployment
instances, not randomly divided rows from the same PDU trial.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

# The local report is not assumed trusted. 'reported_latency_s' is copied
# from genuine UE outcomes only as a plausible local service-quality field.
LOCAL = ["reported_healthy", "reported_pdu_success", "reported_latency_s"]
KIE = LOCAL + ["kie_ue_outcome_mismatch", "kie_elapsed_s"]
NETWORK = KIE + [
    "nrf_health_mismatch", "amf_sm_context_log_lines", "ue_registration_seen"
]
PRIVILEGED = NETWORK + ["docker_smf_health_mismatch"]
ABLATIONS = {
    "local_only": LOCAL,
    "with_kie": KIE,
    "kie_and_network": NETWORK,
    "with_privileged_lab_witness": PRIVILEGED,
}
TRAIN_DEPLOYMENTS = ("101",)
VALID_DEPLOYMENTS = ("202",)
TEST_DEPLOYMENTS = ("303",)
TARGET_FPR = 0.05
TAMPER_TYPES = ("false_health", "false_outcome", "false_both")


def read_deployment(directory: Path) -> pd.DataFrame:
    frame = pd.read_csv(directory / "pdu_trials.csv")
    must = {
        "phase", "trial", "elapsed_s", "ue_pdu_session_accepted",
        "smf_running_witness", "nrf_advertised_smf_profiles",
        "amf_sm_context_log_lines", "ue_registration_seen",
        "ue_pdu_time_s",
    }
    missing = must - set(frame.columns)
    if missing:
        raise ValueError(f"Missing real PDU columns: {sorted(missing)}")
    if set(frame.phase) != {"normal", "smf_failstop", "recovery"}:
        raise ValueError("Data must contain the three genuinely observed phases")
    for phase in ("normal", "recovery"):
        if not frame.loc[frame.phase == phase, "ue_pdu_session_accepted"].all():
            raise ValueError(f"Unsuccessful real baseline/recovery in {directory}")
    if frame.loc[frame.phase == "smf_failstop", "ue_pdu_session_accepted"].any():
        raise ValueError(f"Real fail-stop not reproduced in {directory}")
    if (frame.loc[frame.phase == "smf_failstop", "smf_running_witness"] != 0).any():
        raise ValueError("Expected independent evidence that lab SMF was stopped")
    frame = frame.copy()
    frame["deployment"] = directory.name.split("-")[-1]
    return frame


def fabricate_pair(frame: pd.DataFrame, *, seed: int) -> pd.DataFrame:
    """For each *real* observation, retain truthful report and fabricate one lie.

    Attacker claims success/health status inconsistent with measured outcome.
    Type selected independently of true status via fixed seed. No ground-truth
    'phase' or 'tampered' field is passed into the detector.
    """
    rng = np.random.default_rng(seed)
    pairs = []
    for _, record in frame.iterrows():
        real_ok = int(record.ue_pdu_session_accepted)
        real_up = int(record.smf_running_witness)
        reported_latency = float(
            record.ue_pdu_time_s if np.isfinite(record.ue_pdu_time_s) else 0
        )
        for tampered in (0, 1):
            claimed_health = real_up
            claimed_outcome = real_ok
            kind = "truthful"
            if tampered:
                kind = TAMPER_TYPES[int(rng.integers(0, len(TAMPER_TYPES)))]
                if kind in ("false_health", "false_both"):
                    claimed_health = 1 - real_up
                if kind in ("false_outcome", "false_both"):
                    claimed_outcome = 1 - real_ok
            # Same trace-derived control variables in truthful and falsified
            # twins; only untrusted report columns are changed.
            nrf = int(record.nrf_advertised_smf_profiles > 0)
            pairs.append({
                "deployment": str(record.deployment),
                "phase": record.phase,  # for audit, never a feature
                "trial": int(record.trial),
                "tampering_kind": kind,  # for audit, never a feature
                "tampered": int(tampered),
                "reported_healthy": claimed_health,
                "reported_pdu_success": claimed_outcome,
                "reported_latency_s": reported_latency,
                "kie_ue_outcome_mismatch": abs(claimed_outcome - real_ok),
                "kie_elapsed_s": float(record.elapsed_s),
                "nrf_health_mismatch": abs(claimed_health - nrf),
                "amf_sm_context_log_lines": float(record.amf_sm_context_log_lines),
                "ue_registration_seen": int(record.ue_registration_seen),
                # Privileged laboratory-only Docker witness, not standardized SBA:
                "docker_smf_health_mismatch": abs(claimed_health - real_up),
            })
    return pd.DataFrame(pairs)


def calibration_limit(y: np.ndarray, scores: np.ndarray) -> float:
    truthful = np.asarray(scores)[np.asarray(y) == 0]
    if len(truthful) < 10:
        raise ValueError("Insufficient independent truthful validation trials")
    return float(np.quantile(truthful, 1 - TARGET_FPR))


def evaluate(df: pd.DataFrame, score: np.ndarray, limit: float) -> dict:
    truth = df.tampered.to_numpy(dtype=int)
    decision = (np.asarray(score) > limit).astype(int)
    clean = truth == 0
    attacked = truth == 1
    metrics = {
        "n_network_trials": int(len(df) // 2),
        "n_augmented_rows": int(len(df)),
        "n_true_attacks": int(attacked.sum()),
        "fpr_on_truthful_reports": float(decision[clean].mean()),
        "tamper_recall": float(decision[attacked].mean()),
        "precision_at_constructed_prevalence": float(
            precision_score(truth, decision, zero_division=0)
        ),
        "f1_at_constructed_prevalence": float(
            f1_score(truth, decision, zero_division=0)
        ),
        "auprc_at_constructed_prevalence": float(
            average_precision_score(truth, score)
        ),
        "auroc": float(roc_auc_score(truth, score)),
    }
    for typ in TAMPER_TYPES:
        mask = df.tampering_kind.to_numpy() == typ
        if mask.any():
            metrics[f"recall_{typ}"] = float(decision[mask].mean())
            metrics[f"n_{typ}"] = int(mask.sum())
    return metrics


def run(input_dir: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    data = {}
    for dep in (*TRAIN_DEPLOYMENTS, *VALID_DEPLOYMENTS, *TEST_DEPLOYMENTS):
        source = input_dir / f"phase4-real-{dep}"
        data[dep] = fabricate_pair(read_deployment(source), seed=int(dep))
    train = pd.concat([data[x] for x in TRAIN_DEPLOYMENTS], ignore_index=True)
    valid = pd.concat([data[x] for x in VALID_DEPLOYMENTS], ignore_index=True)
    test = pd.concat([data[x] for x in TEST_DEPLOYMENTS], ignore_index=True)
    if set(train.deployment) & set(test.deployment):
        raise ValueError("Deployment leakage: overlapping test and train networks")
    records = []
    test_preds = test[["deployment", "phase", "trial", "tampering_kind", "tampered"]].copy()
    calibration = {}
    for label, cols in ABLATIONS.items():
        model = RandomForestClassifier(
            n_estimators=120, min_samples_leaf=2, max_depth=5,
            class_weight="balanced", random_state=2026, n_jobs=2
        )
        model.fit(train[cols], train.tampered)
        score_val = model.predict_proba(valid[cols])[:, 1]
        lim = calibration_limit(valid.tampered.to_numpy(), score_val)
        score_test = model.predict_proba(test[cols])[:, 1]
        observed = evaluate(test, score_test, lim)
        records.append({"model": f"RF_{label}", "threshold": lim, **observed})
        test_preds[f"score_{label}"] = score_test
        test_preds[f"alarm_{label}"] = (score_test > lim).astype(int)
        calibration[label] = lim

    # Transparent comparison to non-ML cross-observer consistency rule.
    # If no independent KIE is available, it cannot detect health-only lies.
    rule_score = test.kie_ue_outcome_mismatch.to_numpy(dtype=float)
    rule_val = valid.kie_ue_outcome_mismatch.to_numpy(dtype=float)
    rule_lim = calibration_limit(valid.tampered.to_numpy(), rule_val)
    records.append({"model": "Rule_KIE_disagreement", "threshold": rule_lim,
                    **evaluate(test, rule_score, rule_lim)})
    test_preds["score_rule_kie"] = rule_score
    test_preds["alarm_rule_kie"] = (rule_score > rule_lim).astype(int)

    # Another transparent rule uses a privileged Docker witness and can only
    # be cited as an upper-bound LAB ORACLE, not a deployable 5G mechanism.
    oracle_score = np.maximum(
        test.kie_ue_outcome_mismatch.to_numpy(float),
        test.docker_smf_health_mismatch.to_numpy(float),
    )
    oracle_val = np.maximum(
        valid.kie_ue_outcome_mismatch.to_numpy(float),
        valid.docker_smf_health_mismatch.to_numpy(float),
    )
    oracle_lim = calibration_limit(valid.tampered.to_numpy(), oracle_val)
    records.append({"model": "Rule_lab_oracle_two_witness", "threshold": oracle_lim,
                    **evaluate(test, oracle_score, oracle_lim)})

    pd.DataFrame(records).to_csv(out_dir / "tamper_metrics.csv", index=False)
    test_preds.to_csv(out_dir / "test_paired_predictions.csv", index=False)
    config = {
        "study": "Real Open5GS/PDU observations, OFFLINE artificially falsified monitor reports",
        "not_studied": [
            "live maliciously compromised SMF",
            "tampering with Nsmf SBI protocol messages",
            "in-band KIE transport",
            "generalization across operators",
        ],
        "train_deployments": TRAIN_DEPLOYMENTS,
        "validation_deployments": VALID_DEPLOYMENTS,
        "test_deployments": TEST_DEPLOYMENTS,
        "ablation_columns": ABLATIONS,
        "validation_target_fpr": TARGET_FPR,
        "thresholds": calibration,
        "attack_construction": "Each real PDU trial forms truthful/falsified report twins; lie type randomly selected without changing source network observations",
        "critical_limitation": "Paired outcome mismatches mathematically expose the artificially constructed lie. A strong score does NOT prove real intruder detection.",
        "privileged_witness_note": "Docker container state is not a 3GPP network function's independently attested field.",
        "real_PDU_trials_per_deployment": {
            key: int(len(frame) // 2) for key, frame in data.items()
        },
    }
    (out_dir / "tamper_protocol_metadata.json").write_text(
        json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return {"results": records, "configuration": config}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, default=Path("phase4_inputs"))
    parser.add_argument("--out-dir", type=Path, default=Path("results/phase4-analysis"))
    args = parser.parse_args()
    results = run(args.input_dir, args.out_dir)
    print(json.dumps(results["results"], ensure_ascii=False, indent=2))
