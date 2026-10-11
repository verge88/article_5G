"""Phase 13 cross-runner verification; production independence NOT established.

Audits ONLY authenticated observations and known laboratory stop labels.
Two-source inference is conditional on the toy competing set {SMF,UPF}.
No malicious compromise or 3GPP N4 association attestation is measured.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import pandas as pd

from .phase13_policy import ARMS, BUDGET
from .phase13_probe import SERVICES
from .phase9_receipts import verify_receipt

REPLICAS=("11","22","33")


def witness_classification(source:str,row):
    if source=="nrf":
        if row.nrf_http2!=1:return "unknown"
        if row.nrf_http_status==200:
            if row.nrf_smf_profiles==0:return "smf_failstop"
            if row.nrf_smf_profiles>0:return "upf_failstop"
        if row.nrf_http_status==404:return "smf_failstop"
        return "unknown"
    accessible=str(row.UPF_namespace_accessible).lower()=="true"
    val=str(row.UPF_PFCP_udp8805_socket_present).lower()
    if not accessible or val not in ("true","false"):
        return "unknown"
    return "smf_failstop" if val=="true" else "upf_failstop"


def privileged_lab_oracle_source_classification(source:str,row):
    if source=="nrf":
        return witness_classification(source,row)
    runtime=str(row.UPF_docker_runtime_privileged_only).lower()
    if runtime=="true":return "smf_failstop"
    if runtime=="false":return "upf_failstop"
    return "unknown"


def audit_one(folder:Path,replica:str):
    summary=json.loads((folder/"real_summary.json").read_text())
    if summary["replica"]!=replica or summary["n_real_pdu_trials"]!=20:
        raise RuntimeError("Original real 5GC trial provenance missing")
    trial=pd.read_csv(folder/"real_pdu_trials.csv")
    requests=pd.read_csv(folder/"real_kie_queries.csv",keep_default_na=False)
    docs=[json.loads(line) for line in (folder/"signed_receipts.jsonl").read_text().splitlines() if line]
    keys=json.loads((folder/"public_agent_keys.json").read_text())
    if len(trial)!=20 or len(requests)!=16 or len(docs)!=16 or len(keys)!=4:
        raise RuntimeError("Incomplete live lab or original signed data")
    if len(set(k["key_id"] for k in keys.values()))!=4:
        raise RuntimeError("Agent signing keys were not separated")
    if set(trial.audit_phase_NOT_policy_input)!={
        "normal","upf_failstop","recovery_upf","smf_failstop","recovery_smf"}:
        raise RuntimeError("Not every observed NF control phase is present")
    for phase in ("normal","upf_failstop","recovery_upf","smf_failstop","recovery_smf"):
        x=trial.loc[trial.audit_phase_NOT_policy_input==phase]
        if len(x)!=4:
            raise RuntimeError("Incorrect PDU trials per lab phase")
        success=int(x.real_pdu_success.sum())
        if success != (0 if "failstop" in phase else 4):
            raise RuntimeError("Real UE success not consistent with validated lab intervention")
        if not x.smf_docker_running_AUDIT_ONLY.eq(int(phase!="smf_failstop")).all():
            raise RuntimeError("Incorrect SMF audit state")
        if not x.upf_docker_running_AUDIT_ONLY.eq(int(phase!="upf_failstop")).all():
            raise RuntimeError("Incorrect UPF audit state")

    pending={}
    for doc in docs:
        p=doc["payload"]
        pending[p["nonce"]]=(p["agent_id"],p["trial_token"],p["sequence"])
    if len(pending)!=16:
        raise RuntimeError("Repeated challenge found in real KIE data")
    accepted={}
    results=[]
    for doc in docs:
        p=doc["payload"]
        if p["source_kind"] not in SERVICES or p["service"]!=SERVICES[p["source_kind"]]:
            raise RuntimeError("Signed KIE source label/service mismatch")
        ok=verify_receipt(doc,registered_keys=keys,pending=pending,
            accepted_sequences=accepted,now=p["measured_at_unix"]+1,
            allowed_services=tuple(SERVICES.values()))
        if not ok:
            raise RuntimeError("A true live signed KIE failed independent verification")
        replay=verify_receipt(doc,registered_keys=keys,pending=pending,
            accepted_sequences=accepted,now=p["measured_at_unix"]+1,
            allowed_services=tuple(SERVICES.values()))
        if replay:raise RuntimeError("Replay of a signed control unit was accepted")
        results.append({"replica":replica,"agent":p["agent_id"],
                        "service":p["service"],"signed":1,"replay_rejected":1})
    if pending:raise RuntimeError("Not every issued nonce consumed")

    observations={(x["payload"]["agent_id"],x["payload"]["trial_token"],
                   x["payload"]["source_kind"]) for x in docs}
    listed={("phase13_"+r.arm,r.token,r.source) for r in requests.itertuples()}
    if observations!=listed:
        raise RuntimeError("Published observations not identical to signed KIE records")
    rows=[]
    for arm in ARMS:
        q=requests.loc[requests.arm==arm].copy()
        if len(q)!=BUDGET or trial[f"selected_{arm}"].sum()!=BUDGET:
            raise RuntimeError("Active source budget unequal")
        q["classified"]=q.apply(
            lambda row:witness_classification(row.source,row),axis=1)
        q["oracle_classified"]=q.apply(
            lambda row:privileged_lab_oracle_source_classification(row.source,row),axis=1)
        truth=q.audit_phase_NOT_policy_input
        determinate=q.classified!="unknown"
        oracle_det=q.oracle_classified!="unknown"
        rows.append({
            "replica":replica,"arm":arm,"n_real_KIE":len(q),
            "n_NRF_requests":int(q.source.eq("nrf").sum()),
            "n_UPF_requests":int(q.source.eq("upf").sum()),
            "SMF_stopped_trials_queried":int(truth.eq("smf_failstop").sum()),
            "UPF_stopped_trials_queried":int(truth.eq("upf_failstop").sum()),
            "socket_or_nrf_determinate":int(determinate.sum()),
            "socket_or_nrf_correct":int((determinate & q.classified.eq(truth)).sum()),
            "socket_or_nrf_abstained":int((~determinate).sum()),
            "privileged_oracle_determinate":int(oracle_det.sum()),
            "privileged_oracle_correct":int((oracle_det & q.oracle_classified.eq(truth)).sum()),
            "UPF_namespace_unobservable":int((
                q.source.eq("upf") & q.UPF_namespace_accessible.astype(str).str.lower().ne("true")).sum()),
            "UPF_PFCP_socket_observed":int((
                q.source.eq("upf") & q.UPF_PFCP_udp8805_socket_present.astype(str).str.lower().eq("true")).sum()),
            "nrf_body_bytes":int(q.body_bytes_only.sum()),
            "sum_probe_wall_ms":round(float(q.agent_process_wall_ms.sum()),3),
        })
    return rows,results,summary


def run(root:Path,out:Path):
    out.mkdir(parents=True,exist_ok=True)
    rows=[];signed=[];real={}
    for r in REPLICAS:
        x,y,metadata=audit_one(root/f"phase13-real-{r}",r)
        rows.extend(x);signed.extend(y);real[r]=metadata["phases"]
    pd.DataFrame(rows).to_csv(out/"per_replica_source_comparison.csv",index=False)
    pd.DataFrame(signed).to_csv(out/"receipt_verification.csv",index=False)
    aggregate=[]
    for arm in ARMS:
        x=[r for r in rows if r["arm"]==arm]
        aggregate.append({
            "arm":arm,"real_requests":sum(y["n_real_KIE"] for y in x),
            "NRF_requests":sum(y["n_NRF_requests"] for y in x),
            "UPF_namespace_requests":sum(y["n_UPF_requests"] for y in x),
            "SMF_stop_trials_sampled":sum(y["SMF_stopped_trials_queried"] for y in x),
            "UPF_stop_trials_sampled":sum(y["UPF_stopped_trials_queried"] for y in x),
            "strict_socket_or_nrf_determinate":sum(y["socket_or_nrf_determinate"] for y in x),
            "strict_socket_or_nrf_correct":sum(y["socket_or_nrf_correct"] for y in x),
            "strict_abstained":sum(y["socket_or_nrf_abstained"] for y in x),
            "privileged_lab_oracle_determinate":sum(y["privileged_oracle_determinate"] for y in x),
            "privileged_lab_oracle_correct":sum(y["privileged_oracle_correct"] for y in x),
            "UPF_namespace_unobservable":sum(y["UPF_namespace_unobservable"] for y in x),
            "UPF_PFCP_socket_observed":sum(y["UPF_PFCP_socket_observed"] for y in x),
            "NRF_response_body_bytes_only":sum(y["nrf_body_bytes"] for y in x),
            "total_agent_process_ms":round(sum(y["sum_probe_wall_ms"] for y in x),3),
        })
    summary={
        "source":"60 measured real 5GC PDU attempts and 48 live signed dual-surface checks",
        "two_observation_surfaces":["Nnrf_NFDiscovery_SMF","UPF namespace PFCP UDP 8805"],
        "same_administrative_trust_domain":True,
        "different_nf_observation_surfaces":True,
        "UPF_privileged_lab_oracle_prohibited_as_deployable_NF_attestation":True,
        "signed_receipts_independently_rechecked":len(signed),
        "replay_rejections":len(signed),
        "real_pdu_phase_results_by_runner":real,
        "arms":aggregate,
        "limitations":[
            "UPF socket probe requires privileged access to container namespace, not a 3GPP N4 NF procedure",
            "Container namespace inaccessible is UNKNOWN socket state, not a proved absent UDP/PFCP listener",
            "Docker runtime status is explicitly a lab privileged oracle, not independent semantic NF integrity",
            "One host per 5G Core and same GitHub administrator across runners",
            "Likelihood and redundancy coefficients of information policy are assumptions, not estimated or calibrated",
            "No confirmed PFCP Association state, no adversarial NF compromise, no certified 3GPP identity",
            "Two preselected fail-stop causes form an artificial closed hypothesis set",
            "Signed source data authenticates the agent key but not observation truth",
            "All polls after UE PDU observation; time-to-detection not established",
        ],
    }
    (out/"audited_summary.json").write_text(json.dumps(summary,indent=2))
    lines=[
        "# Phase 13 — separately signed NRF and UPF/PFCP network-namespace witnesses",
        "",
        "All KIE sources are signed laboratory observations, not independent administrative trust domains.",
        "",
        "| Source policy | Actual KIE | NRF | UPF namespace | Strict determinate | Strict abstention | Privileged-oracle determinate |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for x in aggregate:
        lines.append(f"| {x['arm']} | {x['real_requests']} | {x['NRF_requests']} | "
                     f"{x['UPF_namespace_requests']} | {x['strict_socket_or_nrf_determinate']} | "
                     f"{x['strict_abstained']} | {x['privileged_lab_oracle_determinate']} |")
    lines.extend(["","**Strict UPF namespace unavailable => ABSTAIN, never classify it as proven absent PFCP.**",
                  "A privileged Docker-running field can fill that gap only as a lab-only oracle.",
                  "No experiment constitutes malicious NF compromise detection."])
    (out/"REPORT.md").write_text("\n".join(lines)+"\n")
    return summary


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,default=Path("phase13_inputs"))
    p.add_argument("--out",type=Path,default=Path("results/phase13-audit"))
    a=p.parse_args()
    print(json.dumps(run(a.root,a.out),indent=2))


if __name__=="__main__":
    main()
