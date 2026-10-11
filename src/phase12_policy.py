"""Phase 12: preregistered source-differentiation negative control.

The previously excellent UE_failure + authorized_DNN heuristic can indicate
EITHER missing SMF or missing UPF. A new weak diagnostic rule reads SMF logs
collected after the UE procedure: missing SMF-side procedure activity.
This is NOT independent evidence under an adversarially compromised SMF.

All five policies spend at most 4 live NRF queries across 20 real UE attempts.
Inference has no Docker process status, intervention-phase label, NRF response
or future UE outcomes. Frozen Random Forest learned an SMF lab fail-stop,
not cyber intrusion, and is NEVER refit on phase-10/11 observations.
"""
from __future__ import annotations
import pandas as pd
from .phase10_policy import FEATURES, planned_next_trial
from .phase11_policy import out_of_support

BUDGET=4
TRIALS=20
ARMS=("fixed","heuristic","ml","hybrid","smf_context")


def eligible_context(record:dict) -> dict:
    if "smf_sm_context_log_lines" not in record:
        raise ValueError("Actual SMF-side procedure log count is required")
    if not isinstance(record["smf_sm_context_log_lines"], (int,float)):
        raise ValueError("SMF log counter must be a measured scalar")
    if record["smf_sm_context_log_lines"]<0:
        raise ValueError("Negative log count invalid")
    return {"smf_context_lines":int(record["smf_sm_context_log_lines"])}


def select(index:int, features:dict, smf_context:dict,
           model, threshold:float, support:dict,
           budget:dict) -> tuple[dict,float,dict]:
    if set(budget)!=set(ARMS) or index<0 or index>=TRIALS:
        raise ValueError("Invalid phase-12 policy or trial")
    if any(v<0 or v>TRIALS-index for v in budget.values()):
        raise ValueError("Budget infeasible")
    x=pd.DataFrame([features],columns=FEATURES)
    score=float(model.predict_proba(x)[0,1])
    semantic=(features["ue_pdu_session_accepted"]==0 and
              features["dnn_authorized"]==1)
    smf_inactive=smf_context["smf_context_lines"]==0
    outlier=out_of_support(features,support)
    criteria={
        "fixed": index%5==0,
        "heuristic": semantic,
        "ml": score>=threshold,
        "hybrid": index==0 or semantic,
        "smf_context": semantic and smf_inactive,
    }
    result={}
    reasons={}
    for arm in ARMS:
        if budget[arm]==0:
            result[arm]=False
            reasons[arm]="budget_exhausted"
            continue
        quota_fallback=planned_next_trial(index,budget[arm],total=TRIALS)
        result[arm]=bool(criteria[arm] or quota_fallback)
        if not result[arm]:
            reasons[arm]="not_selected"
        elif arm=="hybrid" and index==0:
            reasons[arm]="exploration_reserve"
        elif criteria[arm]:
            reasons[arm]={
                "fixed":"periodic",
                "heuristic":"authorized_failed_pdu",
                "ml":"frozen_rf_above_threshold",
                "hybrid":"semantic_override" if score<threshold else "semantic_and_rf",
                "smf_context":"no_smf_context_log_activity",
            }[arm]
        else:
            reasons[arm]="quota_fallback"
    return result,score,{
        "reasons":reasons,
        "semantic_failure":int(semantic),
        "no_smf_context_log":int(smf_inactive),
        "outside_training_support":int(outlier),
    }
