"""Phase 10 LIVE equal-budget comparison on isolated Open5GS/UERANSIM.

Each independent GitHub runner hosts its *own* entire Docker 5G Core and three
different local NRF-polling signer processes. The three GitHub runners are
isolated compute environments within one repository/administrative domain;
they are not Byzantine-independent authorities.

Phases are controlled legitimate failures, not malicious NF compromise.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
import secrets
import tempfile
import time
from collections import Counter

from .pdu_lab import cmd, state, trial
from .phase7_healthy_smf import GOOD, BAD, replace_ue_dnn
from .phase9_receipts import create_ephemeral_key, verify_receipt
from .phase9_live import live_agent_call
from .phase10_policy import (fit_risk_model, eligible_features,
                             select_probes, BUDGET, TRIALS)

AGENTS={"fixed":"nrf_fixed","heuristic":"nrf_adaptive","ml":"nrf_ml"}
PLANS={
    "11":("normal","invalid_dnn","smf_failstop","recovery"),
    "22":("invalid_dnn","normal","smf_failstop","recovery"),
    "33":("normal","smf_failstop","recovery","invalid_dnn"),
}


def csv_write(path:Path, items:list[dict]):
    if not items:
        raise ValueError(f"No real measurements for {path}")
    with path.open("w",newline="",encoding="utf-8") as f:
        writer=csv.DictWriter(f,fieldnames=list(items[0]))
        writer.writeheader()
        writer.writerows(items)


def run(compose_dir:Path, past:Path, dnn_file:Path, out_dir:Path, *,
        replica:str, endpoint:str="http://172.22.0.12:7777",
        normal_timeout:int=18, invalid_timeout:int=14, failstop_timeout:int=12):
    if os.environ.get("ALLOW_PHASE10_DISPOSABLE_5GC")!="yes":
        raise RuntimeError("Only explicitly approved isolated 5GC lab can run fault trials")
    if "upstream_open5gs" not in str(compose_dir.resolve()):
        raise RuntimeError("Refusing to mutate a non-laboratory UE or SMF")
    if replica not in PLANS:
        raise ValueError("Unknown preregistered replica")
    if not all(state(n) for n in ("nrf","amf","smf","upf","nr_gnb")):
        raise RuntimeError("Actual Open5GS and gNB must be up")
    cfg=compose_dir/"ueransim"/"ueransim-ue.yaml"
    original=cfg.read_text(encoding="utf-8")
    if original.count(GOOD)!=1 or BAD in original:
        raise ValueError("Open5GS UE config is not at expected authorized baseline")
    out_dir.mkdir(parents=True,exist_ok=True)
    model,threshold,model_audit=fit_risk_model(past,dnn_file)
    (out_dir/"model_training_audit.json").write_text(
        json.dumps(model_audit,indent=2,ensure_ascii=False),encoding="utf-8")
    quotas={arm:BUDGET for arm in AGENTS}
    seq={agent:0 for agent in AGENTS.values()}
    pending={}
    accepted={}
    measurements=[]
    requests=[]
    signed_receipts=[]
    t_start=time.monotonic()
    phase_to_dnn={"normal":GOOD,"invalid_dnn":BAD,"smf_failstop":GOOD,"recovery":GOOD}
    with tempfile.TemporaryDirectory(prefix="phase10_signing_keys_") as temporary:
        private={arm:Path(temporary)/(arm+".pem") for arm in AGENTS}
        keys={AGENTS[arm]:create_ephemeral_key(path) for arm,path in private.items()}
        try:
            for phase in PLANS[replica]:
                target=phase_to_dnn[phase]
                cfg.write_text(replace_ue_dnn(original,target),encoding="utf-8")
                if phase=="smf_failstop":
                    cmd(["docker","stop","-t","1","smf"],timeout=20)
                    if state("smf"):
                        raise RuntimeError("SMF did not stop for controlled lab fail-stop")
                else:
                    if not state("smf"):
                        cmd(["docker","start","smf"],timeout=25)
                        time.sleep(12)
                    if not state("smf"):
                        raise RuntimeError("Expected healthy SMF unavailable")
                for phase_trial in range(4):
                    index=len(measurements)
                    if state("smf") != (phase!="smf_failstop"):
                        raise RuntimeError("SMF state inconsistent with preregistered lab intervention")
                    timeout=(failstop_timeout if phase=="smf_failstop" else
                             invalid_timeout if phase=="invalid_dnn" else normal_timeout)
                    record=trial(compose_dir,phase,phase_trial,timeout,1.)
                    # Current trial outcome and AMF counters ARE available
                    # to these scheduling methods, but Docker status, audit
                    # intervention labels and NRF discovery are NOT.
                    obs=eligible_features(record,target==GOOD)
                    decisions,prob=select_probes(index,obs,model,threshold,quotas)
                    row={
                        "trial_token":f"rep{replica}_trial{index:03d}",
                        "audit_phase_not_in_policy":phase,
                        "trial_index":index,
                        "ue_pdu_success_observed":int(record["ue_pdu_session_accepted"]),
                        "ue_registration_observed":int(record["ue_registration_seen"]),
                        "dnn_authorized_coordinator_context":int(target==GOOD),
                        "actual_smf_running_docker_audit_only":int(state("smf")),
                        "ml_score":round(prob,6),
                        "ml_threshold_frozen":threshold,
                        "amf_sm_context_log_lines":int(record["amf_sm_context_log_lines"]),
                        "elapsed_ue_observation_seconds":round(float(record["elapsed_s"]),4),
                        **{f"probed_{name}":0 for name in AGENTS},
                        **{f"fallback_{name}":0 for name in AGENTS},
                    }
                    receipt_clock=time.monotonic()
                    for arm in AGENTS:
                        if not decisions[arm]:continue
                        if quotas[arm]<1:
                            raise RuntimeError("Exceeded equal active query budget")
                        agent=AGENTS[arm]
                        seq[agent]+=1
                        challenge=secrets.token_hex(16)
                        pending[challenge]=(agent,row["trial_token"],seq[agent])
                        envelope,proc_ms=live_agent_call(
                            private[arm],agent,challenge,row["trial_token"],
                            seq[agent],endpoint)
                        verified=verify_receipt(envelope,registered_keys=keys,
                            pending=pending,accepted_sequences=accepted,max_age_s=20.)
                        if not verified:
                            raise RuntimeError("Live Ed25519-signed NRF receipt failed verification")
                        signed_receipts.append(envelope)
                        nrf=envelope["payload"]["observation"]
                        requests.append({
                            "replica":replica,
                            "arm":arm,
                            "trial_token":row["trial_token"],
                            "audit_phase_not_in_policy":phase,
                            "verified":int(verified),
                            "http2":int(nrf["http_version"]=="2"),
                            "http_status":nrf["http_status"],
                            "advertised_smf_profiles":nrf["advertised_smf_profiles"],
                            "nrf_registry_absence":int(
                                nrf["http_version"]=="2" and (
                                    (nrf["http_status"]==200 and nrf["advertised_smf_profiles"]==0)
                                    or nrf["http_status"]==404
                                )),
                            "response_body_bytes":nrf["response_body_bytes"],
                            "curl_response_ms":nrf["latency_ms"],
                            "agent_process_ms":proc_ms,
                            "time_since_ue_observation_ms":round(1000*(time.monotonic()-receipt_clock),3),
                            "nonce_hex":challenge,
                            "sequence":seq[agent],
                            "key_id":envelope["payload"]["key_id"],
                        })
                        row[f"probed_{arm}"]=1
                        # Forced filling is explicit and never counted as
                        # a genuine risk trigger.
                        context_trigger=(obs["ue_pdu_session_accepted"]==0 and
                                         obs["dnn_authorized"]==1)
                        direct_trigger=(arm=="fixed" and index%4==0) or (
                            arm=="heuristic" and context_trigger) or (
                            arm=="ml" and prob>=threshold)
                        row[f"fallback_{arm}"]=int(not direct_trigger)
                        quotas[arm]-=1
                    measurements.append(row)
        finally:
            cfg.write_text(original,encoding="utf-8")
            if not state("smf"):
                cmd(["docker","start","smf"],timeout=25)
                time.sleep(6)
        (out_dir/"public_agent_keys.json").write_text(json.dumps(keys,indent=2),encoding="utf-8")
    if len(measurements)!=TRIALS or any(quotas.values()):
        raise RuntimeError(f"Incomplete real UE trials or unmatched live query budgets: {quotas}")
    for phase in PLANS[replica]:
        block=[row for row in measurements if row["audit_phase_not_in_policy"]==phase]
        success=sum(row["ue_pdu_success_observed"] for row in block)
        expected=4 if phase in ("normal","recovery") else 0
        if success!=expected:
            raise RuntimeError(f"Real UE phase {phase}: {success} successes, expected {expected}")
        if any(row["actual_smf_running_docker_audit_only"] !=
               int(phase!="smf_failstop") for row in block):
            raise RuntimeError(f"Lab state inconsistent in {phase}")
    csv_write(out_dir/"live_trial_schedule.csv",measurements)
    csv_write(out_dir/"live_active_nrf_probes.csv",requests)
    (out_dir/"signed_receipts.jsonl").write_text(
        "".join(json.dumps(env,sort_keys=True)+"\n" for env in signed_receipts),encoding="utf-8")
    arms={}
    for arm in AGENTS:
        rs=[x for x in requests if x["arm"]==arm]
        if len(rs)!=BUDGET:
            raise RuntimeError("Unauditable unequal budget")
        arms[arm]={
            "n_actual_live_http2_requests":len(rs),
            "n_http2_responses":sum(x["http2"] for x in rs),
            "n_signed_receipts":sum(x["verified"] for x in rs),
            "failstop_trials_polled":sum(x["audit_phase_not_in_policy"]=="smf_failstop" for x in rs),
            "failstop_registry_absence_evidence":sum(
                x["nrf_registry_absence"] for x in rs if x["audit_phase_not_in_policy"]=="smf_failstop"),
            "healthy_trials_polled":sum(x["audit_phase_not_in_policy"]!="smf_failstop" for x in rs),
            "healthy_registry_absence_evidence":sum(
                x["nrf_registry_absence"] for x in rs if x["audit_phase_not_in_policy"]!="smf_failstop"),
            "n_forced_budget_fallbacks":sum(x[f"fallback_{arm}"] for x in measurements),
            "sum_http_response_body_bytes":sum(x["response_body_bytes"] for x in rs),
            "sum_curl_http_time_ms":round(sum(x["curl_response_ms"] for x in rs),3),
            "sum_poll_agent_process_ms":round(sum(x["agent_process_ms"] for x in rs),3),
            "schedule_by_phase":dict(Counter(x["audit_phase_not_in_policy"] for x in rs)),
        }
    summary={
        "experimental_basis":"REAL Open5GS/ UERANSIM PDU outcomes and actual HTTP/2 NRF requests",
        "replica":replica,
        "runner":"one independent ephemeral GitHub runner; same repo administrative authority",
        "n_ue_attempts":len(measurements),
        "n_controlled_smf_outages":4,
        "n_active_requests":len(requests),
        "budget_per_arm":BUDGET,
        "wall_experiment_elapsed_s":round(time.monotonic()-t_start,3),
        "arms":arms,
        "ml_validation_auc_prior_network":model_audit["validation_auc"],
        "ml_original_heldout_auc_prior_network":model_audit["original_heldout_auc"],
        "critical_caveats":[
            "All three local agents and their NRF backend share one ephemeral runner, not separate trust domains",
            "Three runners in one GitHub repository are still under one administrative authority",
            "SMF fail-stop and unsupported DNN are legitimate controlled failures, not cyberattacks",
            "Actual laboratory SMF-running witness used for AUDIT only, not inference",
            "ML supervised target is controlled process outage, not compromise",
            "NRF registry absence is neither authenticated semantic proof of NF health nor proof of compromise",
            "Only HTTP payload bytes counted; no request, TLS, transport, or network-wide overhead",
            "A new signed receipt proves origin of that agent key, not that the underlying measurement is truthful",
            "All controls are sent after UE procedure observation; no time-to-first-failure detection is established",
            "All 3 policies query the SAME NRF and can influence each other's timing",
            "Budget-preserving ML/heuristic fallbacks must be reported separately from genuine high-priority selections",
            "No concurrent subscribers, attacks, or independent key administrators were tested",
        ],
    }
    (out_dir/"live_summary.json").write_text(
        json.dumps(summary,indent=2,ensure_ascii=False),encoding="utf-8")
    return summary


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--replica",choices=tuple(PLANS),required=True)
    p.add_argument("--compose-dir",type=Path,default=Path("upstream_open5gs"))
    p.add_argument("--previous-data",type=Path,default=Path("phase4_inputs"))
    p.add_argument("--dnn-measurements",type=Path,default=Path("phase7_inputs/real_pdu_windows.csv"))
    p.add_argument("--out",type=Path,default=Path("results/phase10"))
    a=p.parse_args()
    print(json.dumps(run(a.compose_dir,a.previous_data,a.dnn_measurements,a.out,
                         replica=a.replica),indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()
