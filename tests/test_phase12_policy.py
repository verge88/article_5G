"""12th stage: explicit negative control for SMF availability inference."""
import numpy as np
import pandas as pd
import pytest
from src.phase12_policy import select, eligible_context, ARMS, BUDGET, TRIALS
from src.phase12_live import PLANS, AGENTS, run

class SmallRisk:
    def predict_proba(self,frame):
        return np.array([[.45,.55]])

SUPPORT={
    "elapsed_s":{"min":.1,"max":20.},
    "amf_sm_context_log_lines":{"min":0,"max":20},
}

def x(success,context_lines):
    return {
        "ue_pdu_session_accepted":success,
        "ue_registration_seen":1,
        "elapsed_s":5.,
        "amf_sm_context_log_lines":2.,
        "dnn_authorized":1.,
    }, {"smf_context_lines":context_lines}

def test_ambiguous_failed_pdu_distinguished_only_by_untrusted_smf_logs():
    budget=dict.fromkeys(ARMS,4)
    stopped,log_absent=x(0,0)
    upf_outage,smf_active=x(0,3)
    a,_,ma=select(6,stopped,log_absent,SmallRisk(),.99,SUPPORT,budget)
    b,_,mb=select(6,upf_outage,smf_active,SmallRisk(),.99,SUPPORT,budget)
    assert a["heuristic"] and b["heuristic"]
    assert a["smf_context"] and not b["smf_context"]
    assert ma["semantic_failure"]==mb["semantic_failure"]==1
    assert not a["ml"] and not b["ml"]

def test_no_inference_from_docker_nrf_or_known_lab_phase():
    f,smf=x(0,1)
    f.update({"phase":"smf_failstop","smf_running_witness":0,
              "upf_running_witness":1,"nrf_advertised_smf_profiles":0})
    baseline,_,_=select(3,f,smf,SmallRisk(),.99,SUPPORT,dict.fromkeys(ARMS,4))
    f["phase"]="upf_failstop"
    f["smf_running_witness"]=1
    f["upf_running_witness"]=0
    f["nrf_advertised_smf_profiles"]=1
    new,_,_=select(3,f,smf,SmallRisk(),.99,SUPPORT,dict.fromkeys(ARMS,4))
    assert baseline==new

def test_fixed_5_stride_and_all_20_rounds_preserve_equal_budgets():
    budgets=dict.fromkeys(ARMS,BUDGET)
    chosen={a:[] for a in ARMS}
    for i in range(TRIALS):
        features, smf=x(0, 0) if 12<=i<16 else x(1,2)
        choices,_,_=select(i,features,smf,SmallRisk(),.99,SUPPORT,budgets)
        for arm,flag in choices.items():
            if flag:
                budgets[arm]-=1
                chosen[arm].append(i)
            assert budgets[arm]>=0
    assert all(q==0 for q in budgets.values())
    assert chosen["fixed"]==[0,5,10,15]
    assert len(chosen["heuristic"])==len(chosen["smf_context"])==4
    assert len(chosen["hybrid"])==4
    assert chosen["hybrid"][0]==0
    assert len(chosen["ml"])==4  # quota filling, not RF success

def test_do_not_assume_upf_failstop_pdu_result():
    assert set(PLANS)=={"11","22","33"}
    assert len(AGENTS)==5
    assert all(len(v)==5 and set(v)=={
        "normal","upf_failstop","recovery_upf","smf_failstop","recovery_smf"
    } for v in PLANS.values())

def test_lab_guard_prevents_unapproved_intervention(tmp_path,monkeypatch):
    monkeypatch.delenv("ALLOW_PHASE12_DISPOSABLE_5GC",raising=False)
    with pytest.raises(RuntimeError,match="isolated 5GC lab"):
        run(tmp_path/"upstream_open5gs",tmp_path/"past",
            tmp_path/"dnn.csv",tmp_path/"out",replica="11")
