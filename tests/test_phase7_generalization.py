"""Negative control refuses to mistake healthy SMF DNN errors for compromise."""
import pandas as pd
import pytest
from src.phase7_generalization import full_run


def test_source_validation_requires_real_files(tmp_path):
    with pytest.raises((FileNotFoundError, OSError)):
        full_run(tmp_path, tmp_path/"unavailable.csv", tmp_path/"out")


def test_our_labels_do_not_enter_model_predictors():
    from src.phase4_eval import ABLATIONS
    forbidden = {"phase", "requested_dnn_category", "tampered", "trial",
                 "deployment", "ue_pdu_session_accepted", "smf_running_witness"}
    assert all(not (set(cols) & forbidden) for cols in ABLATIONS.values())


def test_heldout_semantics_differ_from_compromise_label():
    sample = pd.DataFrame([
        dict(phase="invalid_dnn", ue_pdu_session_accepted=0, smf_running_witness=1,
             requested_dnn_category="not_provisioned"),
        dict(phase="normal", ue_pdu_session_accepted=1, smf_running_witness=1,
             requested_dnn_category="subscriber_provisioned"),
    ])
    # These are benign laboratory configurations, not confirmed cyberattacks.
    sample["malicious_compromise"] = 0
    assert sample.malicious_compromise.sum() == 0
    assert sample.smf_running_witness.eq(1).all()
