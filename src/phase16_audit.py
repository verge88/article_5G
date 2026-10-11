"""Phase16 independent signed tri-plane audit; never infer identity joins from time."""
from __future__ import annotations
import argparse,json
from pathlib import Path
from .phase9_receipts import verify_receipt
from .phase16_live import AGENT,SERVICE,PHASES

REPLICAS=("11","22","33")

def audit_one(base:Path,replica:str)->dict:
    rows=json.loads((base/"real_threeplane_trial_rows.json").read_text())
    receipts=[json.loads(x) for x in (base/"signed_threeplane_receipts.jsonl").read_text().splitlines() if x]
    pub=json.loads((base/"public_keys.json").read_text())
    original=json.loads((base/"original_real_threeplane_summary.json").read_text())
    if original["replica"]!=replica or len(rows)!=9 or len(receipts)!=9 or len(pub)!=1:
        raise ValueError("Incomplete genuine lab artifact")
    tokens={x["trial_token"] for x in rows}
    if len(tokens)!=9:raise ValueError("Duplicate UE windows")
    pending={}
    for doc in receipts:
        p=doc["payload"]
        if p["nonce"] in pending:
            raise ValueError("Duplicate nonce")
        pending[p["nonce"]]=(p["agent_id"],p["trial_token"],p["sequence"])
    accepted={}
    signed={}
    for doc in receipts:
        p=doc["payload"]
        if not (p["agent_id"]==AGENT and p["service"]==SERVICE
                and p["source_kind"]=="threeplane_host_capture"):
            raise ValueError("Wrong source of cross-plane report")
        if not verify_receipt(doc,registered_keys=pub,pending=pending,
                              accepted_sequences=accepted,now=p["measured_at_unix"]+1,
                              allowed_services=(SERVICE,)):
            raise ValueError("Invalid original Ed25519 KIE")
        if verify_receipt(doc,registered_keys=pub,pending=pending,
                          accepted_sequences=accepted,now=p["measured_at_unix"]+1,
                          allowed_services=(SERVICE,)):
            raise ValueError("Cryptographic replay was accepted")
        if p["trial_token"] not in tokens or p["trial_token"] in signed:
            raise ValueError("Missing or duplicated KIE bound to a trial")
        signed[p["trial_token"]]=p["observation"]
    if pending or len(signed)!=9:
        raise ValueError("Not all nonce challenges reconciled")
    phases={}
    for phase in PHASES:
        block=[x for x in rows if x["phase_audit_only"]==phase]
        if len(block)!=3:
            raise ValueError("Not all real UE attempts measured")
        if not all(x["SMF_and_UPF_running_lab"]==1 for x in block):
            raise ValueError("One NF stopped instead of N4-only fault")
        for row in block:
            obs=signed[row["trial_token"]]
            cross=obs["identity"]
            if cross["cross_protocol_identity_join_proven"]:
                raise ValueError("Identity join was invented from time co-observation")
            comparisons={
                "ue_pdu_success_observed":"real_UE_PDU_success",
                "lab_n4_egress_drop_packets":"host_n4_actual_drop_packets",
            }
            for k,v in comparisons.items():
                if obs[k]!=row[v]:raise ValueError("Original row differs from signed source")
            if (obs["ngap"]["ngap_pdu_id_distinct_count"]!=row["NGAP_PDU_ID_cardinality"]
                or obs["nsmf"]["nsmf_http2_unique_request_streams"]!=row["Nsmf_HTTP2_requests"]
                or obs["pfcp"]["session_establishment_matched_pairs"]!=row["PFCP_session_pairs"]):
                raise ValueError("Original crossplane observations not verified by signed KIE")
            if obs["lab_rule_installed"]!=(phase=="n4_full_drop"):
                raise ValueError("N4-only firewall intervention did not match expectation")
        phases[phase]={
            "real_UE_pdu_trials":3,
            "real_UE_PDU_success":sum(x["real_UE_PDU_success"] for x in block),
            "visible_NGAP_PDU_ID_windows":sum(x["NGAP_PDU_ID_visible"] for x in block),
            "visible_Nsmf_HTTP2_windows":sum(x["Nsmf_HTTP2_requests"]>0 for x in block),
            "visible_PFCP_pairs_windows":sum(x["PFCP_session_pairs"]>0 for x in block),
            "naive_3_source_time_join_claims":sum(x["naive_time_only_join_overconfidence"] for x in block),
            "legitimate_cross_protocol_identity_joins":sum(x["cross_protocol_identity_join_proven"] for x in block),
            "real_host_n4_drop_packets":sum(x["host_n4_actual_drop_packets"] for x in block),
        }
        if phases[phase]["real_UE_PDU_success"]!=original["real_UE_PDU_success_by_phase"][phase]:
            raise ValueError("Real UE outcomes inconsistent with original experiment")
    return {"replica":replica,"phases":phases,
            "signatures_verified":9,"replay_rejections":9,"real_UE_attempts":9}

def audit(root:Path,out:Path)->dict:
    out.mkdir(parents=True,exist_ok=True)
    labs=[audit_one(root/f"phase16-real-{r}",r) for r in REPLICAS]
    phases={p:{
        k:sum(lab["phases"][p][k] for lab in labs)
        for k in labs[0]["phases"][p]} for p in PHASES}
    summary={
        "real_UE_trials":27,
        "signed_KIE_checked":27,
        "replays_rejected":27,
        "per_lab":labs,
        "combined_by_phase":phases,
        "cross_protocol_identity_mapping_proven":False,
        "trust_limit":"All three protocol decoders and signing agent under one GitHub administrator",
        "interpretation":"Co-observation and per-protocol pairing do not prove NGAP PDU ID ↔ PFCP SEID",
    }
    (out/"verified_threeplane_summary.json").write_text(json.dumps(summary,indent=2))
    report=[
        "# Phase 16 — actual signed N2/Nsmf/N4 observations and identity non-join",
        "",
        "| Measured state | Real UE successes | NGAP PDU ID visible windows | Nsmf HTTP2 visible | PFCP transaction pair visible | Naively overconfident time-only joins | Proven cross-protocol joins |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name,x in phases.items():
        report.append(f"| {name} | {x['real_UE_PDU_success']}/{x['real_UE_pdu_trials']} | "
                      f"{x['visible_NGAP_PDU_ID_windows']} | "
                      f"{x['visible_Nsmf_HTTP2_windows']} | {x['visible_PFCP_pairs_windows']} | "
                      f"{x['naive_3_source_time_join_claims']} | {x['legitimate_cross_protocol_identity_joins']} |")
    report.append("\nNo protected SMF mapping of NGAP PDU session identity to PFCP SEID was supplied: all asserted inter-protocol identity joins MUST abstain.")
    (out/"REPORT.md").write_text("\n".join(report)+"\n")
    return summary


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,default=Path("phase16_inputs"))
    p.add_argument("--out",type=Path,default=Path("results/phase16-verified"))
    a=p.parse_args()
    print(json.dumps(audit(a.root,a.out),indent=2))


if __name__=="__main__":
    main()
