"""Phase-4 falsification analysis safeguards: no accidental claim of real attack."""
from __future__ import annotations
import numpy as np
import pandas as pd
from src.phase4_eval import (
    LOCAL, KIE, NETWORK, PRIVILEGED, fabricate_pair,
    calibration_limit, evaluate, TAMPER_TYPES,
)


def observations():
    out = []
    for phase in ("normal", "smf_failstop", "recovery"):
        for i in range(7):
            down = phase == "smf_failstop"
            out.append({
                "deployment": "101", "phase": phase, "trial": i,
                "smf_running_witness": 0 if down else 1,
                "ue_pdu_session_accepted": 0 if down else 1,
                "ue_pdu_time_s": np.nan if down else 1.9 + i * .02,
                "elapsed_s": 8.0 if down else 2.1,
                "nrf_advertised_smf_profiles": 0 if down else 1,
                "amf_sm_context_log_lines": 12 if down else 3,
                "ue_registration_seen": 1,
            })
    return pd.DataFrame(out)


def test_pairs_retain_real_kie_and_are_reproducible():
    frame = observations()
    a = fabricate_pair(frame, seed=27)
    b = fabricate_pair(frame, seed=27)
    assert a.equals(b)
    assert len(a) == 2 * len(frame)
    assert int(a.tampered.sum()) == len(frame)
    for _, sample in a.groupby(["deployment", "phase", "trial"]):
        assert len(sample) == 2
        assert sample["kie_elapsed_s"].nunique() == 1
        assert sample["amf_sm_context_log_lines"].nunique() == 1
        clean = sample.loc[sample.tampered == 0].iloc[0]
        assert clean.kie_ue_outcome_mismatch == 0
        assert clean.docker_smf_health_mismatch == 0


def test_local_fields_are_self_consistent_when_reports_falsified():
    pairs = fabricate_pair(observations(), seed=9)
    assert (pairs.loc[pairs.reported_pdu_success == 0, "reported_latency_s"] == 0).all()
    assert (pairs.loc[pairs.reported_pdu_success == 1, "reported_latency_s"] > 0).all()


def test_permitted_features_exclude_ground_truth():
    all_features = set(PRIVILEGED)
    assert set(LOCAL) < set(KIE) < set(NETWORK) < all_features
    assert not {"tampered", "phase", "tampering_kind", "trial", "deployment"} & all_features


def test_truthful_validation_threshold_and_metrics():
    df = fabricate_pair(observations(), seed=13)
    scores = df.kie_ue_outcome_mismatch.to_numpy()
    lim = calibration_limit(df.tampered.to_numpy(), scores)
    m = evaluate(df, scores, lim)
    assert 0 <= lim <= 1
    assert m["fpr_on_truthful_reports"] == 0
    assert 0 <= m["tamper_recall"] <= 1
    assert sum(m.get("n_" + t, 0) for t in TAMPER_TYPES) == len(df) // 2
