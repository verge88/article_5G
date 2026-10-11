"""Phase 11: prespecified hybrid of semantic priority, RF and a probe reserve.

Everything is selected *online after an actual UE procedure*, not ahead of
NF outage. No phase label, Docker state, NRF result or future outcome is used.
Training-only feature ranges are an OOD diagnostic, not a statistical
guarantee of drift or calibrated confidence.

At four probes per sixteen real UE attempts, one exploratory/sentinel poll is
reserved at the first measured UE attempt; at most three other polls target
semantic anomalous outcomes. This necessarily can miss one of four fail-stop
trials even if the semantic rule is perfect. RF scores and OOD flags are
retained to identify why the safety override fired.
"""
from __future__ import annotations
from pathlib import Path
import numpy as np
import pandas as pd

from .phase10_policy import (
    BUDGET, TRIALS, FEATURES, fit_risk_model, select_probes,
    planned_next_trial, read_training_sources
)


def training_support(prior:Path, dnn:Path) -> dict:
    """Limits fitted ONLY on previously measured training and calibration runs."""
    train, val, _=read_training_sources(prior,dnn)
    pooled=pd.concat([train,val],ignore_index=True)
    result={}
    for key in ("elapsed_s","amf_sm_context_log_lines"):
        values=pooled[key].dropna().astype(float).to_numpy()
        if len(values)<20 or not np.isfinite(values).all():
            raise ValueError("Insufficient trustworthy historical monitoring values")
        # A conservative empirical support check rather than fitted model
        # recalibration or future-test leakage.
        result[key]={"min":float(values.min()),"max":float(values.max())}
    return result


def out_of_support(feat:dict, support:dict) -> bool:
    return any(
        not np.isfinite(float(feat[key])) or
        float(feat[key]) < support[key]["min"] or
        float(feat[key]) > support[key]["max"]
        for key in support
    )


def decide(index:int, features:dict, model, threshold:float,
           support:dict, quotas:dict) -> tuple[dict,float,dict]:
    """Return real probe decisions, original model score and reasons.

    All methods use equal B=4 request budgets. Candidate labels are NEVER
    set from the actual host SMF state, NRF response, or phase label.
    """
    old_names={"fixed","heuristic","ml"}
    if set(quotas)!=(old_names|{"hybrid"}):
        raise ValueError("Exactly four controlled arms are required")
    base,score=select_probes(index,features,model,threshold,
                             {k:quotas[k] for k in old_names})
    semantic=features["ue_pdu_session_accepted"]==0 and features["dnn_authorized"]==1
    drift=out_of_support(features,support)
    selected=dict(base)
    hybrid=quotas["hybrid"]>0 and (index==0 or semantic)
    forced=quotas["hybrid"]>0 and planned_next_trial(index,quotas["hybrid"])
    selected["hybrid"]=bool(hybrid or forced)
    reasons={}
    for arm,chosen in selected.items():
        if not chosen:
            reasons[arm]="not_selected"
        elif arm=="fixed":
            reasons[arm]="periodic" if index%4==0 else "quota_fallback"
        elif arm=="heuristic":
            reasons[arm]="semantic_gate" if semantic else "quota_fallback"
        elif arm=="ml":
            reasons[arm]="frozen_rf_threshold" if score>=threshold else "quota_fallback"
        elif index==0:
            reasons[arm]="exploratory_sentinel"
        elif semantic and score>=threshold:
            reasons[arm]="model_supported_semantic_priority"
        elif semantic and drift:
            reasons[arm]="out_of_training_support_semantic_override"
        elif semantic:
            reasons[arm]="below_threshold_semantic_safety_override"
        else:
            reasons[arm]="quota_fallback"
    return selected,score,{"reasons":reasons,"ood":int(drift),
                            "semantic_gate":int(semantic),"exploratory":int(index==0)}
