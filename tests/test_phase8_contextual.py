"""Unit tests for the phase-8 three-valued contextual policy.

Tests distinguish coherent benign denial, independently contradicted reports,
missing witnesses, collusion, and context forgery.
"""
import numpy as np
import pandas as pd

from src.phase8_contextual import tri_state_policy, sources, outcomes, simple_rule


def demonstration():
    data = []
    # Two real-PDU-inspired attempts; each truthful/lied pair shares *all*
    # witnesses and source evidence, not just the same tampering label.
    for i, (ue_ok, nrf, authorized, amf) in enumerate([
        (1, 1, 1, 1), (0, 1, 0, 1), (0, 0, 1, 0)]):
        for tamper in (0, 1):
            data.append({
                "deployment": "303",
                "phase": "unused_audit_tag",
                "trial": i,
                "tampered": tamper,
                "reported_healthy": nrf,
                "reported_pdu_success": (1-ue_ok if tamper else ue_ok),
                "ue_truth": ue_ok,
                "amf_prediction": amf,
                "nrf_count": nrf,
                "docker_truth": nrf,
                "dnn_authorized": authorized,
                "requested_dnn_category": (
                    "subscriber_provisioned" if authorized else "not_provisioned"),
            })
    return pd.DataFrame(data)


def test_direct_consistency_rule_has_expected_clean_label_behavior():
    data = sources(demonstration())
    alarms = simple_rule(data)
    assert np.array_equal(alarms, data.tampered.to_numpy())


def test_contextual_denial_with_imperfect_amf_can_be_cleared():
    data = sources(demonstration())
    strict, _ = tri_state_policy(data)
    contextual, _ = tri_state_policy(data, use_context=True)
    bad_dnn_truth = (data.trial == 1) & (data.tampered == 0)
    assert strict[bad_dnn_truth.to_numpy()].tolist() == [-1]
    assert contextual[bad_dnn_truth.to_numpy()].tolist() == [0]


def test_context_does_not_override_reported_success_contradiction():
    data = sources(demonstration())
    contextual, _ = tri_state_policy(data, use_context=True)
    invalid_dnn_fake = (data.trial == 1) & (data.tampered == 1)
    assert contextual[invalid_dnn_fake.to_numpy()].tolist() == [1]  # independent subscription context corroborates UE


def test_ue_missing_abstains_unless_no_other_independent_evidence():
    data = sources(demonstration(), "ue_missing", 1.0)
    pred, reasons = tri_state_policy(data, use_context=True)
    assert np.all(pred == -1)
    assert set(reasons) == {"missing_procedure_witness"}


def test_corrupting_both_witnesses_can_create_false_alarms():
    data = sources(demonstration(), "ue_amf_flip", 1.0)
    pred, _ = tri_state_policy(data)
    normal_truth = (data.trial == 0) & (data.tampered == 0)
    assert pred[normal_truth.to_numpy()].tolist() == [1]


def test_corruption_targets_whole_real_trial_not_only_fabricated_report():
    x = sources(demonstration(), "ue_flip", 1.0)
    assert x.groupby("trial").ue_seen.nunique().eq(1).all()
    assert x.tampered.equals(demonstration().tampered)


def test_abstention_not_miscounted_as_true_negative():
    data = sources(demonstration(), "ue_missing", 1.0)
    pred, _ = tri_state_policy(data)
    result = outcomes(data, pred)
    assert result["decision_coverage"] == 0.
    assert result["alarm_recall_unconditional"] == 0.
    assert result["alarm_fpr_unconditional"] == 0.
    assert result["truthful_abstained_n"] == 3


def test_no_phase_attack_or_deployment_labels_drive_policy():
    a = sources(demonstration())
    b = a.copy()
    b["phase"] = "completely_different_audit_phase"
    b["tampered"] = 1 - b["tampered"]
    b["deployment"] = "totally_other_network"
    assert np.array_equal(tri_state_policy(a, use_context=True)[0],
                          tri_state_policy(b, use_context=True)[0])


def test_context_forgery_is_not_cryptographically_verified():
    data = sources(demonstration(), "context_flip", 1.0)
    # Deliberate safety property: provenance is only simulated; policy
    # cannot prove context correctness from these observations.
    assert (data.context_seen != data.dnn_authorized).all()


def test_contextual_policy_does_not_clear_false_health_report():
    data = demonstration()
    # DNN denial is true, but the NF report is falsely 'unhealthy' while
    # the independently observed NRF registry still advertises it.
    mask = (data.trial == 1) & (data.tampered == 1)
    data.loc[mask, "reported_pdu_success"] = 0
    data.loc[mask, "reported_healthy"] = 0
    probe = sources(data)
    pred, _ = tri_state_policy(probe, use_context=True)
    assert pred[mask.to_numpy()].tolist() == [-1]
