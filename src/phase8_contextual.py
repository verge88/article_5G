"""Phase 8 — context-aware, selective verification of logical KIE reports.

Measured origins:
  * three real Open5GS PDU-session deployments from phase 4;
  * a separate real healthy-SMF/invalid-DNN deployment from phase 7.

Tampered local reports and compromised witnesses are constructed OFFLINE.
This is a verification prototype; no live NF compromise, cryptographic
attestation, Byzantine guarantee or production 5G detection is shown.

Labels, lab phase names and Docker truth NEVER enter deployable inference.
A lab Docker-assisted method is reported separately as a non-deployable oracle.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score

from .phase4_eval import ABLATIONS, fabricate_pair, read_deployment, calibration_limit
from .phase5_reliability import measured_pairs, fit_amf, select_trials

SCENARIOS = ("clean", "ue_flip", "ue_missing", "amf_flip",
             "ue_amf_flip", "nrf_flip", "nrf_missing",
             "context_missing", "context_flip")
LEVELS = (0., .5, 1.)


def paired_real(df, seed, surrogate):
    """Construct report pairs on real PDU observations and retain witnesses."""
    data = measured_pairs(df, seed=seed)
    data["amf_prediction"] = surrogate.predict(
        data[["amf_count", "registered"]]).astype(float)
    # Context is derived from the requesting UE configuration and the
    # provisioning database — not the measured outcome or attack label.
    data["dnn_authorized"] = (data["requested_dnn_category"] ==
                              "subscriber_provisioned").astype(float)
    return data


def sources(raw, scenario="clean", fraction=0.0, seed=2026):
    if scenario not in SCENARIOS or not 0 <= fraction <= 1:
        raise ValueError("Invalid corruption experiment")
    data = raw.copy(deep=True)
    data["ue_seen"] = data.ue_truth.astype(float)
    data["amf_seen"] = data.amf_prediction.astype(float)
    data["nrf_seen"] = (data.nrf_count > 0).astype(float)
    data["docker_seen"] = data.docker_truth.astype(float)
    data["context_seen"] = data.dnn_authorized.astype(float)
    chosen = (np.zeros(len(data), dtype=bool) if scenario == "clean" else
              select_trials(data, fraction, seed))
    to_flip = {"ue_flip": "ue_seen", "amf_flip": "amf_seen",
               "nrf_flip": "nrf_seen", "context_flip": "context_seen"}
    if scenario in to_flip:
        col = to_flip[scenario]
        data.loc[chosen, col] = 1.0 - data.loc[chosen, col]
    if scenario == "ue_amf_flip":
        for col in ("ue_seen", "amf_seen"):
            data.loc[chosen, col] = 1.0 - data.loc[chosen, col]
    to_remove = {"ue_missing": "ue_seen", "nrf_missing": "nrf_seen",
                 "context_missing": "context_seen"}
    if scenario in to_remove:
        data.loc[chosen, to_remove[scenario]] = np.nan
    data["corrupted_trial"] = chosen.astype(int)
    return data


def tri_state_policy(data, *, use_context=False, lab_oracle=False):
    """1=verified contradiction, 0=consistent, -1=insufficient evidence.

    UE is a procedure-outcome witness; AMF is a low-trust log-derived
    surrogate, NOT a second independent cryptographically verified source.
    NRF confirms registry advertisement, NOT process health. Therefore
    a health/NRF mismatch alone NEVER yields a confirmed compromise alarm.

    Context override accepts an otherwise ambiguous *expected denial*
    only if the DNN authorization attribute has trustworthy provenance;
    this trust assumption is NOT provided by the current lab measurement.
    """
    decision = np.full(len(data), -1, dtype=int)
    reasons = []
    for i, rec in enumerate(data.itertuples(index=False)):
        ue, amf, nrf = rec.ue_seen, rec.amf_seen, rec.nrf_seen
        claimed_outcome, claimed_health = int(rec.reported_pdu_success), int(rec.reported_healthy)
        if pd.isna(ue):
            reasons.append("missing_procedure_witness")
            continue
        # Context tells which denial is *allowed*, not whether a local
        # report is true; never equate PDU failure with compromise.
        if use_context and not pd.isna(rec.context_seen):
            if rec.context_seen == 0 and claimed_outcome == 0 and ue == 0 and nrf == 1:
                # Only the context-aware extension uses this evidence.
                decision[i] = 0
                reasons.append("documented_dnn_denial_consistent")
                continue
        if pd.isna(amf) or amf != ue:
            reasons.append("independent_outcome_sources_disagree")
            continue
        if ue != claimed_outcome:
            decision[i] = 1
            reasons.append("corroborated_outcome_contradiction")
            continue
        if pd.isna(nrf):
            reasons.append("missing_registry_witness")
            continue
        if lab_oracle:
            if pd.isna(rec.docker_seen):
                reasons.append("missing_privileged_witness")
                continue
            if claimed_health != rec.docker_seen:
                decision[i] = 1
                reasons.append("lab_process_state_contradiction")
                continue
        # Registry != process state: differences are ambiguous when no
        # privileged lab witness is available, not malicious by default.
        if claimed_health != nrf:
            reasons.append("registry_versus_claim_unresolved")
            continue
        decision[i] = 0
        reasons.append("consistent_outcome_and_registration")
    return decision, reasons


def simple_rule(df):
    # Prior paper baseline: unqualified direct comparison, no abstention.
    mismatched_outcome = df.ue_seen.notna() & df.reported_pdu_success.ne(df.ue_seen)
    mismatched_nrf = df.nrf_seen.notna() & df.reported_healthy.ne(df.nrf_seen)
    return (mismatched_outcome | mismatched_nrf).astype(int).to_numpy()


def rf_features(df, cols):
    x = df.copy()
    x["kie_ue_outcome_mismatch"] = (x.reported_pdu_success - x.ue_seen).abs()
    x["nrf_health_mismatch"] = (x.reported_healthy - x.nrf_seen).abs()
    x["docker_smf_health_mismatch"] = (x.reported_healthy - x.docker_seen).abs()
    return x[cols].fillna(-1.)


def outcomes(df, pred):
    truth = df.tampered.to_numpy(dtype=int)
    pos, neg = truth == 1, truth == 0
    p = np.asarray(pred, dtype=int)
    selected = p != -1
    res = {
        "n_real_pdu_trials": int(len(df)//2),
        "n_truthful_reports": int(neg.sum()),
        "n_offline_falsified_reports": int(pos.sum()),
        "decision_coverage": float(selected.mean()),
        "alarm_recall_unconditional": float((p[pos] == 1).mean()),
        "alarm_fpr_unconditional": float((p[neg] == 1).mean()),
        "truthful_abstained_n": int((p[neg] == -1).sum()),
        "falsified_abstained_n": int((p[pos] == -1).sum()),
        "recall_conditional": (
            float((p[pos & selected] == 1).mean()) if (pos & selected).any() else None),
        "fpr_conditional": (
            float((p[neg & selected] == 1).mean()) if (neg & selected).any() else None),
    }
    return res


def run(real_dir, dnn_path, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    real = {idx: read_deployment(real_dir / f"phase4-real-{idx}")
            for idx in (101, 202, 303)}
    for idx in real:
        real[idx] = real[idx].assign(requested_dnn_category="subscriber_provisioned")
    dnn = pd.read_csv(dnn_path).copy()
    if len(dnn) != 18 or not (dnn.smf_running_witness == 1).all():
        raise ValueError("Phase 7 real healthy-SMF negative-control source invalid")
    if set(dnn.requested_dnn_category) != {"subscriber_provisioned", "not_provisioned"}:
        raise ValueError("Missing measured DNN authorization context")
    if not dnn.loc[dnn.requested_dnn_category == "not_provisioned",
                   "ue_pdu_session_accepted"].eq(0).all():
        raise ValueError("Unsupported DNN was not rejected in real lab")
    dnn["deployment"] = "707"
    raw_train, raw_valid, raw_original = real[101], real[202], real[303]
    # Estimate lower-trust AMF witness from an earlier deployment, not from
    # the new DNN cohort. It is not equivalent to a direct protocol witness.
    amf_raw_train = measured_pairs(raw_train, seed=101)
    amf_raw_valid = measured_pairs(raw_valid, seed=202)
    surrogate, surrogate_valid_acc = fit_amf(amf_raw_train, amf_raw_valid)
    datasets = {
        "train": paired_real(raw_train, 101, surrogate),
        "valid": paired_real(raw_valid, 202, surrogate),
        "original_303": paired_real(raw_original, 303, surrogate),
        "healthy_dnn_707": paired_real(dnn, 707, surrogate),
    }
    train, valid = datasets["train"], datasets["valid"]
    rf = {}
    for name in ("local_only", "with_kie", "kie_and_network"):
        cols = ABLATIONS[name]
        model = RandomForestClassifier(
            n_estimators=120, min_samples_leaf=2, max_depth=5,
            class_weight="balanced", random_state=2026, n_jobs=2)
        model.fit(rf_features(sources(train), cols), train.tampered)
        threshold = calibration_limit(
            valid.tampered.to_numpy(),
            model.predict_proba(rf_features(sources(valid), cols))[:, 1])
        rf[name] = (model, threshold)

    results = []
    rows_audit = []
    for cohort_name in ("original_303", "healthy_dnn_707"):
        raw = datasets[cohort_name]
        for scenario in SCENARIOS:
            fracs = (0.,) if scenario == "clean" else LEVELS
            for frac in fracs:
                frame = sources(raw, scenario, frac)
                methods = {"Rule_direct_UE_NRF": simple_rule(frame)}
                for name, (model, limit) in rf.items():
                    prob = model.predict_proba(rf_features(frame, ABLATIONS[name]))[:, 1]
                    methods["RF_" + name] = (prob > limit).astype(int)
                strict, strict_reasons = tri_state_policy(frame)
                context, context_reasons = tri_state_policy(frame, use_context=True)
                oracle, oracle_reasons = tri_state_policy(frame, use_context=True, lab_oracle=True)
                methods.update({
                    "Policy_strict_UE_AMF": strict,
                    "Policy_contextual_UE_AMF": context,
                    "Policy_contextual_Docker_lab_oracle": oracle,
                })
                for name, decisions in methods.items():
                    selected = frame.requested_dnn_category.eq("not_provisioned").to_numpy()
                    for subset, mask in (("all", np.ones(len(frame), dtype=bool)),
                                         ("unsupported_DNN", selected),
                                         ("provisioned_DNN", ~selected)):
                        if not mask.any():
                            continue
                        results.append({
                            "cohort": cohort_name,
                            "source_fault": scenario,
                            "fault_fraction_of_real_trials": frac,
                            "method": name,
                            "subset": subset,
                            **outcomes(frame.loc[mask], np.asarray(decisions)[mask]),
                        })
                if scenario in ("clean", "ue_flip", "ue_amf_flip", "context_missing") and frac in (0., 1.):
                    for policy, decisions, reasons in (
                        ("strict", strict, strict_reasons),
                        ("contextual", context, context_reasons),
                    ):
                        for reason in sorted(set(reasons)):
                            rows_audit.append({
                                "cohort": cohort_name, "fault": scenario,
                                "fraction": frac, "policy": policy,
                                "decision_reason": reason,
                                "n_report_rows": reasons.count(reason),
                            })
    frame = pd.DataFrame(results)
    frame.to_csv(out_dir / "method_comparison.csv", index=False)
    pd.DataFrame(rows_audit).to_csv(out_dir / "decision_reasons.csv", index=False)
    metadata = {
        "origin": "72 real Open5GS PDU outcomes in phase 4 and 18 independent real PDU outcomes in phase 7",
        "real_network_measurements_total": 90,
        "offline_report_pairing": "Each real PDU outcome produces truthful and artificially falsified reports",
        "offline_source_interventions": SCENARIOS,
        "train_real_deployment": 101,
        "validation_real_deployment": 202,
        "original_test_real_deployment": 303,
        "unseen_legitimate_negative_control": "Healthy SMF, unsupported requested DNN, phase 7",
        "model_fpr_threshold": {k: float(x[1]) for k,x in rf.items()},
        "surrogate_amf_validation_accuracy": surrogate_valid_acc,
        "surrogate_amf_external_test_accuracy": float(
            (datasets["healthy_dnn_707"].amf_prediction ==
             datasets["healthy_dnn_707"].ue_truth).mean()),
        "critical_caveats": [
            "Source falsification is OFFLINE, not a live compromised NF",
            "Reported true PDU outcome witness is intentionally independent, and is an explicit trust assumption",
            "AMF surrogate trained from aggregate lines is not a trusted protocol-specific witness",
            "DNN request/subscriber authorization classification is lab metadata; no cryptographic provenance",
            "Contextual exception may improve coverage but loses trust if context itself is falsified",
            "Lab Docker oracle is not deployable 3GPP attestation",
            "Reject/clear/abstain categories are about report consistency, NOT classification of cyberattacks",
            "No independent field sample, concurrent UEs, SLA latency bounds, or adversarial NF semantics",
        ],
    }
    (out_dir/"metadata.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "# Phase 8 — contextual verification of untrusted control reports",
        "",
        "**Measured PDU events from real Open5GS; falsifications and source faults introduced OFFLINE.**",
        "",
        "The selective policy may abstain. An abstained report is neither an alarm nor a proof of healthy behavior.",
        "Always report decision coverage with false-alarm and recall rates.",
        "",
        "| Source cohort | Source perturbation | Method | Coverage | False alarm rate | Recall |",
        "|---|---|---|---:|---:|---:|",
    ]
    selected = frame[(frame.subset == "all") & (frame.source_fault.isin(
        ("clean", "ue_flip", "ue_amf_flip", "context_missing"))) &
        (frame.fault_fraction_of_real_trials.isin((0., 1.))) &
        (frame.method.isin(("RF_with_kie", "Rule_direct_UE_NRF",
                            "Policy_strict_UE_AMF", "Policy_contextual_UE_AMF")))]
    for rec in selected.to_dict("records"):
        lines.append("| {cohort} | {source_fault} | {method} | {decision_coverage:.3f} | {alarm_fpr_unconditional:.3f} | {alarm_recall_unconditional:.3f} |".format(**rec))
    lines += [
        "", "## What is and is not demonstrated",
        "- A contextual denial with an authorized-but-unprovisioned DNN is legitimate, not a malicious compromise.",
        "- Any improvement against RF is strongly constrained by the simple direct-consistency baseline.",
        "- Low FPR can result from abstaining; coverage and conditional FPR/Recall are necessary.",
        "- A two-source rule has no immunity to correlated compromise or collusion.",
        "- If a context authorization claim is untrusted, a context-based clear result is not a proof of integrity.",
    ]
    (out_dir/"REPORT.md").write_text("\n".join(lines)+"\n", encoding="utf-8")
    return frame, metadata


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--real-dir", type=Path, default=Path("phase4_inputs"))
    p.add_argument("--dnn-path", type=Path, default=Path("phase7_inputs/real_pdu_windows.csv"))
    p.add_argument("--out-dir", type=Path, default=Path("results/phase8"))
    args=p.parse_args()
    measurements, meta=run(args.real_dir, args.dnn_path, args.out_dir)
    print(json.dumps({"number_of_comparisons":len(measurements),
                      "provenance":meta["origin"]}, ensure_ascii=False, indent=2))


if __name__=="__main__":
    main()
