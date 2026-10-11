"""Phase-10 strict scientific design checks, no live network needed."""
import numpy as np
import pandas as pd
import pytest

from src.phase10_policy import (
    FEATURES,BUDGET,TRIALS,eligible_features,select_probes,planned_next_trial,
)
from src.phase10_live import PLANS,AGENTS,run


class MockRisk:
    def predict_proba(self,x):
        # deterministic stand-in for pretrained RF; test no phase labels used
        success=float(x.iloc[0]["ue_pdu_session_accepted"])
        dnn=float(x.iloc[0]["dnn_authorized"])
        score=1 if success==0 and dnn==1 else 0
        return np.array([[1-score,score]],dtype=float)


def observation(success, authorized):
    return eligible_features({
        "ue_pdu_session_accepted":success,"ue_registration_seen":1,
        "elapsed_s":5.,"amf_sm_context_log_lines":2,
        "smf_running_witness":0,"phase":"simulated", # forbidden
    },authorized)


def test_model_features_exclude_ground_truth_and_phase():
    forbidden={"phase","trial","smf_running_witness","nrf_advertised_smf_profiles",
               "scenario_for_audit_only","lab_docker_smf_running_audit_only"}
    assert not (set(FEATURES)&forbidden)
    x=observation(0,True)
    assert not (set(x)&forbidden)


def test_budget_selector_blind_to_phase_or_lab_docker_state():
    normal=observation(0,True)
    selected,score=select_probes(4,normal,MockRisk(),.5,
                                 {"fixed":4,"heuristic":4,"ml":4})
    assert selected=={"fixed":True,"heuristic":True,"ml":True}
    assert score==1
    dnn=observation(0,False)
    selected,score=select_probes(7,dnn,MockRisk(),.5,
                                 {"fixed":4,"heuristic":4,"ml":4})
    assert selected=={"fixed":False,"heuristic":False,"ml":False}
    assert score==0


def test_fallback_only_fills_remaining_trials_and_never_exceeds_quota():
    assert not planned_next_trial(2,4)
    assert planned_next_trial(12,4)
    assert planned_next_trial(15,1)
    with pytest.raises(ValueError):
        planned_next_trial(15,2)
    selected,_=select_probes(15,observation(1,True),MockRisk(),.9,
                             {"fixed":0,"heuristic":1,"ml":1})
    assert selected=={"fixed":False,"heuristic":True,"ml":True}


def test_three_preregistered_phase_orders_without_reference_to_labels_in_predictor():
    assert len(PLANS)==3 and len(AGENTS)==3
    assert all(set(plan)==set(("normal","invalid_dnn","smf_failstop","recovery"))
               for plan in PLANS.values())
    assert all(len(plan)==4 for plan in PLANS.values())


def test_no_active_lab_without_explicit_guard(tmp_path,monkeypatch):
    monkeypatch.delenv("ALLOW_PHASE10_DISPOSABLE_5GC",raising=False)
    with pytest.raises(RuntimeError,match="isolated 5GC lab"):
        run(tmp_path/"upstream_open5gs",tmp_path/"sources",
            tmp_path/"no.csv",tmp_path/"output",replica="11")
