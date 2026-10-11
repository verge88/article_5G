"""Phase 5: measured PDU outcomes with OFFLINE corruption of independent witnesses.

NOT an attack on real 5G Core. This probes detection limits when KIE, NRF and
AMF-derived reports are missing, stale or falsified. Two corroborating
observations do not guarantee Byzantine resilience.
"""
import argparse
import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from .phase4_eval import ABLATIONS, read_deployment, fabricate_pair, calibration_limit

SCENARIOS = (
    "clean", "ue_flip", "ue_missing", "amf_flip", "ue_and_amf_flip",
    "nrf_flip", "nrf_missing", "nrf_stale",
    "docker_flip", "nrf_and_docker_flip", "all_witnesses_flip",
)
FRACTIONS = (0., .25, .5, .75, 1.)


def measured_pairs(raw, seed):
    pairs = fabricate_pair(raw, seed=seed)
    source = raw[["deployment", "phase", "trial", "ue_pdu_session_accepted",
                  "smf_running_witness", "nrf_advertised_smf_profiles",
                  "amf_sm_context_log_lines", "ue_registration_seen"]].copy()
    source["deployment"] = source.deployment.astype(str)
    source = source.rename(columns={
        "ue_pdu_session_accepted": "ue_truth",
        "smf_running_witness": "docker_truth",
        "nrf_advertised_smf_profiles": "nrf_count",
        "amf_sm_context_log_lines": "amf_count",
        "ue_registration_seen": "registered",
    })
    if source.duplicated(["deployment", "phase", "trial"]).any():
        raise ValueError("Non-unique original real PDU-trial ID")
    pairs = pairs.merge(source, on=["deployment", "phase", "trial"], validate="many_to_one")
    if len(pairs) != 2 * len(raw):
        raise ValueError("Failed real-trial pairing")
    return pairs


def fit_amf(train, validation):
    """Lab-only surrogate trained from AMF lines, NOT independent proof."""
    keys = ["amf_count", "registered"]
    t = train.drop_duplicates(["deployment", "phase", "trial"])
    v = validation.drop_duplicates(["deployment", "phase", "trial"])
    model = DecisionTreeClassifier(max_depth=2, min_samples_leaf=2, random_state=2026)
    model.fit(t[keys], t.ue_truth)
    return model, float(np.mean(model.predict(v[keys]) == v.ue_truth))


def select_trials(frame, fraction, seed):
    """Corrupt whole real PDU-trial clusters, not truth/lie rows individually."""
    ids = frame[["deployment", "phase", "trial"]].drop_duplicates()
    rng = np.random.default_rng(seed)
    picked = ids.iloc[rng.choice(len(ids), size=round(len(ids) * fraction), replace=False)]
    chosen = set(picked.itertuples(index=False, name=None))
    return np.array([key in chosen for key in
        frame[["deployment", "phase", "trial"]].itertuples(index=False, name=None)])


def inject(frame, scenario, fraction, seed=2026):
    """Artificially modify sensor outputs after genuine 5G measurements."""
    if scenario not in SCENARIOS or not 0 <= fraction <= 1:
        raise ValueError("Invalid stress case")
    out = frame.copy(deep=True)
    selected = select_trials(out, fraction, seed) if scenario != "clean" else np.zeros(len(out), bool)
    out["ue_seen"] = out.ue_truth.astype(float)
    out["amf_seen"] = out.amf_prediction.astype(float)
    out["nrf_seen"] = (out.nrf_count > 0).astype(float)
    out["docker_seen"] = out.docker_truth.astype(float)
    column_for_flip = {
        "ue_flip": ("ue_seen",), "amf_flip": ("amf_seen",),
        "ue_and_amf_flip": ("ue_seen", "amf_seen"),
        "nrf_flip": ("nrf_seen",), "docker_flip": ("docker_seen",),
        "nrf_and_docker_flip": ("nrf_seen", "docker_seen"),
        "all_witnesses_flip": ("ue_seen", "amf_seen", "nrf_seen", "docker_seen"),
    }
    for col in column_for_flip.get(scenario, ()):
        out.loc[selected, col] = 1 - out.loc[selected, col]
    if scenario == "ue_missing":
        out.loc[selected, "ue_seen"] = np.nan
    if scenario == "nrf_missing":
        out.loc[selected, "nrf_seen"] = np.nan
    if scenario == "nrf_stale":
        unique = out.drop_duplicates(["deployment", "phase", "trial"]).copy()
        unique["phase_order"] = unique.phase.map({"normal": 0, "smf_failstop": 1, "recovery": 2})
        unique = unique.sort_values(["deployment", "phase_order", "trial"], kind="stable")
        stale_values = unique.nrf_seen.shift(1).fillna(unique.nrf_seen.iloc[0])
        stale_map = dict(zip(unique[["deployment", "phase", "trial"]].itertuples(index=False, name=None), stale_values))
        for idx, key in zip(out.index[selected],
                            out.loc[selected, ["deployment", "phase", "trial"]].itertuples(index=False, name=None)):
            out.at[idx, "nrf_seen"] = float(stale_map[key])
    out["targeted_fault"] = selected.astype(int)
    return out


def mismatch_only_if_sources_agree(reported, witness_a, witness_b):
    agreement = witness_a.notna() & witness_b.notna() & witness_a.eq(witness_b)
    result = pd.Series(np.nan, index=reported.index, dtype=float)
    result.loc[agreement] = reported.loc[agreement].ne(witness_a.loc[agreement]).astype(float)
    return result


def quorum(frame, lab_oracle=False):
    """1=alarm, 0=clear, -1=abstain; Docker assistance is LAB-ONLY."""
    outcome = mismatch_only_if_sources_agree(
        frame.reported_pdu_success, frame.ue_seen, frame.amf_seen)
    prediction = np.full(len(frame), -1, dtype=int)
    if lab_oracle:
        health = mismatch_only_if_sources_agree(
            frame.reported_healthy, frame.nrf_seen, frame.docker_seen)
        alarm = outcome.eq(1) | health.eq(1)
        clear = outcome.eq(0) & health.eq(0)
    else:
        health_contradiction = frame.nrf_seen.notna() & frame.reported_healthy.ne(frame.nrf_seen)
        alarm = outcome.eq(1)
        clear = outcome.eq(0) & frame.nrf_seen.notna() & ~health_contradiction
    prediction[alarm.to_numpy()] = 1
    prediction[(clear & ~alarm).to_numpy()] = 0
    return prediction


def any_disagreement(frame):
    ue_mismatch = frame.ue_seen.notna() & frame.reported_pdu_success.ne(frame.ue_seen)
    nrf_mismatch = frame.nrf_seen.notna() & frame.reported_healthy.ne(frame.nrf_seen)
    return (ue_mismatch | nrf_mismatch).astype(int).to_numpy()


def rf_inputs(frame, keys):
    temp = frame.copy()
    temp["kie_ue_outcome_mismatch"] = (temp.reported_pdu_success - temp.ue_seen).abs()
    temp["nrf_health_mismatch"] = (temp.reported_healthy - temp.nrf_seen).abs()
    temp["docker_smf_health_mismatch"] = (temp.reported_healthy - temp.docker_seen).abs()
    return temp[keys].fillna(-1.)


def evaluate(frame, pred):
    truth = frame.tampered.to_numpy(dtype=int)
    pred = np.asarray(pred, dtype=int)
    good = truth == 0
    attacked = truth == 1
    decided = pred >= 0
    return {
        "n_actual_pdu_trials": int(len(frame) // 2),
        "n_true_reports": int(good.sum()),
        "n_fabricated_reports": int(attacked.sum()),
        "n_corrupted_trial_clusters": int(frame.targeted_fault.sum() // 2),
        "decision_coverage": float(decided.mean()),
        "benign_coverage": float(decided[good].mean()),
        "attack_coverage": float(decided[attacked].mean()),
        "unconditional_recall": float((pred[attacked] == 1).mean()),
        "unconditional_fpr": float((pred[good] == 1).mean()),
        "conditional_recall": float((pred[attacked & decided] == 1).mean()) if (attacked & decided).any() else None,
        "conditional_fpr": float((pred[good & decided] == 1).mean()) if (good & decided).any() else None,
        "abstained_attacks": int((pred[attacked] == -1).sum()),
        "abstained_truthful_reports": int((pred[good] == -1).sum()),
    }


def experiment(inputs, output, fast=False):
    output.mkdir(parents=True, exist_ok=True)
    original = {d: read_deployment(inputs / f"phase4-real-{d}") for d in ("101", "202", "303")}
    pairs = {d: measured_pairs(f, int(d)) for d, f in original.items()}
    amf_model, amf_validation_acc = fit_amf(pairs["101"], pairs["202"])
    for df in pairs.values():
        df["amf_prediction"] = amf_model.predict(df[["amf_count", "registered"]]).astype(int)
    train = inject(pairs["101"], "clean", 0)
    validation = inject(pairs["202"], "clean", 0)
    test = pairs["303"]
    rf_models = {}
    rf_thresholds = {}
    for name in ("local_only", "with_kie", "kie_and_network"):
        features = ABLATIONS[name]
        rf = RandomForestClassifier(
            n_estimators=60 if fast else 160, min_samples_leaf=2,
            max_depth=5, class_weight="balanced", random_state=2026, n_jobs=2)
        rf.fit(rf_inputs(train, features), train.tampered)
        rf_thresholds[name] = calibration_limit(validation.tampered.to_numpy(),
            rf.predict_proba(rf_inputs(validation, features))[:, 1])
        rf_models[name] = rf
    cases = ("clean", "ue_flip", "nrf_flip", "ue_and_amf_flip") if fast else SCENARIOS
    levels = (0., .5, 1.) if fast else FRACTIONS
    records = []
    for scenario in cases:
        for frac in ((0.,) if scenario == "clean" else levels):
            case = inject(test, scenario, frac)
            decisions = {
                "Rule_any_disagreement": any_disagreement(case),
                "Quorum_network_UE_AMF": quorum(case, lab_oracle=False),
                "Quorum_lab_Docker_oracle": quorum(case, lab_oracle=True),
            }
            for name, rf in rf_models.items():
                prob = rf.predict_proba(rf_inputs(case, ABLATIONS[name]))[:, 1]
                decisions["RF_" + name] = (prob > rf_thresholds[name]).astype(int)
            for name, pred in decisions.items():
                records.append({"corruption": scenario, "fraction": frac, "method": name,
                                **evaluate(case, pred)})
    pd.DataFrame(records).to_csv(output / "metrics.csv", index=False)
    metadata = {
        "origin": "Measured PDU session events, Open5GS/UERANSIM Action run 38136404527",
        "input_artifacts": [f"phase4-real-{x}" for x in ("101", "202", "303")],
        "intervention": "OFFLINE manipulated reporting and sensor signals, not a live SMF compromise",
        "train_deployment": "101", "validation_deployment": "202", "test_deployment": "303",
        "test_real_pdu_trials": int(len(original["303"])),
        "test_paired_reports": int(len(test)),
        "amf_surrogate_validation_accuracy": amf_validation_acc,
        "amf_surrogate_test_accuracy": float(np.mean(test.amf_prediction == test.ue_truth)),
        "thresholds_calibrated_on_clean_validation": rf_thresholds,
        "limitations": [
            "Three releases of one lab topology, not independent network operators",
            "Small test set: 24 actual PDU attempts and correlated false/truthful twins",
            "Artificial source compromise, simulated missing and stale telemetry only",
            "AMF log-derived outcome classifier is imperfect and lab-specific",
            "Docker state is privileged lab oracle, not independently trusted 3GPP NF telemetry",
            "Two corroborating signals are not Byzantine-tolerant under collusion",
            "Abstentions reduce alarm FPR but may make coverage unusably small",
            "No real malicious SMF or Nsmf message alteration was performed",
        ],
    }
    (output / "metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    data = pd.DataFrame(records)
    selected = data[data.fraction.eq(1) & data.method.isin(
        ["RF_with_kie", "RF_kie_and_network", "Rule_any_disagreement",
         "Quorum_network_UE_AMF", "Quorum_lab_Docker_oracle"])]
    lines = [
        "# Phase 5: trust-limited consistency monitoring of 5G PDU reports",
        "",
        "**Real Open5GS PDU measurements; monitoring faults are introduced OFFLINE.**",
        "",
        "Test: 24 PDU trials, 24 truthful and 24 artificially falsified monitor reports.",
        f"AMF-only surrogate agreement with UE outcome on independent validation: {amf_validation_acc:.3f}.",
        "",
        "| Corrupted witness | Detector | Coverage | Recall all | FPR all |",
        "|---|---|---:|---:|---:|",
    ]
    for _, rec in selected.iterrows():
        lines.append(f"| {rec.corruption} | {rec.method} | {rec.decision_coverage:.3f} | {rec.unconditional_recall:.3f} | {rec.unconditional_fpr:.3f} |")
    lines += ["", "## Interpretation and restrictions",
        "- Recall all counts abstentions as missed tampering; coverage is fraction with decisions.",
        "- Zero FPR from abstention alone is not useful without reported coverage.",
        "- Docker-based results are upper bound for this **lab**, not deployable operator security.",
        "- Colluding witness corruption can make two agreeing sources wrong.",
        "- Synthetic corruption is designed from controlled trial identities, not observed live attack.",
        "- F1 at an artificial 50% tampering prevalence would not estimate operator precision.",
    ]
    (output / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return records, metadata


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-dir", type=Path, default=Path("phase4_inputs"))
    ap.add_argument("--out-dir", type=Path, default=Path("results/phase5"))
    ap.add_argument("--fast", action="store_true")
    args = ap.parse_args()
    rows, meta = experiment(args.input_dir, args.out_dir, fast=args.fast)
    print(json.dumps({"cases": len(rows), "meta": meta}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
