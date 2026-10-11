"""Phase 11 precommitted hybrid: semantic override + one exploration KIE."""
import numpy as np
import pandas as pd
import pytest

from src.phase10_policy import FEATURES
from src.phase11_policy import decide, out_of_support
from src.phase11_live import PLANS, AGENTS, run


class LowConfidence:
    """Mimics real phase-10 RF score shift, intentionally below fixed threshold."""
    def predict_proba(self, x):
        return np.array([[.40,.60]],dtype=float)


LIMITS={
    "elapsed_s":{"min":0.1,"max":10.},
    "amf_sm_context_log_lines":{"min":0.,"max":20.},
}


def feature(*, success=1, authorized=1, elapsed=4.):
    return dict(ue_pdu_session_accepted=success,ue_registration_seen=1.,
                elapsed_s=elapsed,amf_sm_context_log_lines=2.,
                dnn_authorized=authorized)


def test_one_reserved_early_exploration_even_for_healthy_ue():
    q={"fixed":4,"heuristic":4,"ml":4,"hybrid":4}
    selection,score,meta=decide(0,feature(),LowConfidence(),.99,LIMITS,q)
    assert selection["hybrid"] and selection["fixed"]
    assert not selection["ml"] and not selection["heuristic"]
    assert meta["reasons"]["hybrid"]=="exploratory_sentinel"


def test_semantic_safety_override_when_rf_is_below_threshold():
    quota=dict(fixed=3,heuristic=3,ml=3,hybrid=3)
    flags,score,diag=decide(8,feature(success=0),LowConfidence(),.99,LIMITS,quota)
    assert score<.99 and flags["hybrid"] and flags["heuristic"]
    assert not flags["ml"]
    assert diag["reasons"]["hybrid"]=="below_threshold_semantic_safety_override"


def test_out_of_training_support_is_diagnostic_not_retrained_on_test():
    quota=dict(fixed=2,heuristic=2,ml=2,hybrid=2)
    obs=feature(success=0,elapsed=13.)
    assert out_of_support(obs,LIMITS)
    selected,_,diag=decide(9,obs,LowConfidence(),.99,LIMITS,quota)
    assert selected["hybrid"]
    assert diag["ood"]==1
    assert diag["reasons"]["hybrid"]=="out_of_training_support_semantic_override"


def test_reserved_exploration_causes_explicit_failure_coverage_tradeoff():
    quota=dict(fixed=4,heuristic=4,ml=4,hybrid=4)
    selected=[]
    for i in range(16):
        obs=feature(success=0 if 8<=i<12 else 1,
                    authorized=0 if 4<=i<8 else 1)
        flags,_,diag=decide(i,obs,LowConfidence(),.99,LIMITS,quota)
        if flags["hybrid"]:
            selected.append((i,diag["reasons"]["hybrid"]))
        for k,v in flags.items():
            quota[k]-=int(v)
            assert quota[k]>=0
    assert quota=={"fixed":0,"heuristic":0,"ml":0,"hybrid":0}
    assert sum(8<=i<12 for i,_ in selected)==3
    assert sum(i==0 for i,_ in selected)==1
    assert len(selected)==4


def test_no_host_state_phase_label_or_future_outcome_is_a_feature():
    forbidden={"phase","trial","smf_running_witness",
               "nrf_advertised_smf_profiles","audit_phase_not_in_policy",
               "actual_smf_running_docker_audit_only"}
    assert not set(FEATURES)&forbidden
    assert not set(feature())&forbidden
    assert len(PLANS)==3 and len(AGENTS)==4


def test_no_live_lab_without_explicit_authorization(tmp_path,monkeypatch):
    monkeypatch.delenv("ALLOW_PHASE11_DISPOSABLE_5GC",raising=False)
    with pytest.raises(RuntimeError,match="isolated 5GC lab"):
        run(tmp_path/"upstream_open5gs",tmp_path/"historical",
            tmp_path/"old.csv",tmp_path/"out",replica="11")
