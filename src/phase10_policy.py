"""Phase 10: prespecified active-KIE policies on REAL Open5GS PDU histories.

The supervised label for offline training is a controlled laboratory
SMF process outage, NOT a cyberattack. At online decision time only
UE outcome, local UE timing, AMF log counters and coordinator DNN context
are available. No Docker or NRF ground truth, phase ID or future trials.
"""
from __future__ import annotations

from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score

from .phase4_eval import read_deployment

FEATURES = (
    "ue_pdu_session_accepted", "ue_registration_seen",
    "elapsed_s", "amf_sm_context_log_lines", "dnn_authorized",
)
BUDGET = 4
TRIALS = 16


def eligible_features(observed:dict, authorized:bool) -> dict:
    keys = FEATURES[:-1]
    if not all(k in observed for k in keys):
        raise ValueError("Missing measured pre-probe, pre-NRF observations")
    return {
        **{k: float(observed[k]) for k in keys},
        "dnn_authorized":float(authorized),
    }


def read_training_sources(previous:Path, denial_csv:Path):
    train=read_deployment(previous/"phase4-real-101")
    valid=read_deployment(previous/"phase4-real-202")
    heldout=read_deployment(previous/"phase4-real-303")
    dnn=pd.read_csv(denial_csv)
    if len(dnn)!=18 or (dnn.smf_running_witness!=1).any():
        raise ValueError("Negative-control DNN source must be genuine healthy SMF")
    if set(dnn.requested_dnn_category)!={"subscriber_provisioned","not_provisioned"}:
        raise ValueError("DNN subscription context missing")
    dnn=dnn.copy()
    dnn["dnn_authorized"]=(dnn.requested_dnn_category=="subscriber_provisioned").astype(int)
    for frame in (train,valid,heldout):
        frame["dnn_authorized"]=1
    return pd.concat([train,dnn],ignore_index=True),valid,heldout


def fit_risk_model(previous:Path, denial_csv:Path):
    train,valid,heldout=read_training_sources(previous,denial_csv)
    model=RandomForestClassifier(
        n_estimators=160,min_samples_leaf=2,max_depth=4,
        class_weight="balanced",random_state=2026,n_jobs=2,
    )
    y=(train.smf_running_witness==0).astype(int)
    if set(y)!={0,1}:
        raise ValueError("Training must contain actual healthy and stopped SMF labels")
    model.fit(train[list(FEATURES)],y)
    val_y=(valid.smf_running_witness==0).astype(int)
    val_score=model.predict_proba(valid[list(FEATURES)])[:,1]
    hold_y=(heldout.smf_running_witness==0).astype(int)
    hold_score=model.predict_proba(heldout[list(FEATURES)])[:,1]
    # Frozen before any phase-10 real attempts. This is a *ranking*
    # threshold tuned only on the older, distinct 202 deployment.
    threshold=float(np.quantile(val_score,0.75))
    audit={
        "target":"actual lab-controlled SMF process fail-stop, not compromise",
        "train_sources":["phase4-real-101","phase7-healthy-DNN"],
        "validation_source":"phase4-real-202",
        "heldout_quality_check":"phase4-real-303",
        "features":FEATURES,
        "forbidden_at_inference":["phase","smf_running_witness","nrf_advertised_smf_profiles",
                                  "trial_number","known_fault_label"],
        "n_training_trials":len(train),"n_validation_trials":len(valid),
        "n_original_heldout_trials":len(heldout),
        "threshold_calibrated_on_202":threshold,
        "validation_auc":float(roc_auc_score(val_y,val_score)),
        "original_heldout_auc":float(roc_auc_score(hold_y,hold_score)),
        "feature_importance":dict(zip(FEATURES,model.feature_importances_.tolist())),
    }
    return model,threshold,audit


def planned_next_trial(index:int, remaining_budget:int, total:int=TRIALS) -> bool:
    """Budget-preserving fallback without knowing future outcomes."""
    if remaining_budget<0 or remaining_budget>total-index:
        raise ValueError("Impossible quota, prior online decisions exhausted budget")
    return remaining_budget==total-index


def select_probes(index:int, features:dict, model, threshold:float, remaining:dict) -> tuple[dict,float]:
    """Three policies, each capacity B=4. Choices use only current observations."""
    if set(remaining)!={"fixed","heuristic","ml"}:
        raise ValueError("Missing policy budget")
    if index<0 or index>=TRIALS:
        raise ValueError("Bad trial index")
    available = {k:remaining[k] > 0 for k in remaining}
    fixed=available["fixed"] and index%4==0
    heuristic=available["heuristic"] and (
        features["ue_pdu_session_accepted"]==0 and features["dnn_authorized"]==1)
    prediction=float(model.predict_proba(pd.DataFrame([features],columns=FEATURES))[0,1])
    ml=available["ml"] and (prediction>=threshold)
    selection={"fixed":fixed,"heuristic":heuristic,"ml":ml}
    for arm in selection:
        if not selection[arm] and planned_next_trial(index,remaining[arm]):
            # ensures exactly equal actual budgets; fallback is recorded
            # rather than secretly claiming that ML chose all of them.
            selection[arm]=True
    return selection,prediction
