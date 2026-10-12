"""Independent verifier of actual dual-UERANSIM UE and private PDML summaries.

Runs in a distinct GitHub-hosted job. It can recompute published signed
evidence and reject replay, but remains the SAME administrative trust owner.
"""
from __future__ import annotations
import argparse,json
from pathlib import Path
from .phase19_live import AGENT,SERVICE,PHASES
from .phase9_receipts import verify_receipt

REPLICAS=("11","22","33")
FIELDS=("real_UE1_PDU_success","real_UE2_PDU_success",
        "numeric_UL_candidates","numeric_DL_candidates",
        "endpoint_role_UL_candidates","endpoint_role_DL_candidates",
        "NGAP_TEID_tunnel_nodes","NGAP_request_transfer_nodes",
        "NGAP_response_transfer_nodes","NGAP_same_ancestry_TEID_IP",
        "PFCP_same_ancestry_TEID_IP",
        "UL_same_numeric_IP_wrong_NGAP_role",
        "DL_same_numeric_IP_wrong_NGAP_role","host_N4_drop_packets")


def verify_lab(base:Path,replica:str)->dict:
    rows=json.loads((base/"real_two_UE_windows.json").read_text())
    reports=[json.loads(x) for x in
             (base/"signed_PDML_dual_UE_receipts.jsonl").read_text().splitlines()
             if x.strip()]
    pub=json.loads((base/"public_agent_keys.json").read_text())
    original=json.loads((base/"original_two_UE_summary.json").read_text())
    if len(rows)!=9 or len(reports)!=9 or original["replica"]!=replica:
        raise ValueError("Incomplete real dual UE source artifacts")
    if set(pub)!={AGENT}:
        raise ValueError("Unknown agent key")
    if len({r["trial_token"] for r in rows})!=9:
        raise ValueError("Repeated real dual UE trial")
    by_token={r["trial_token"]:r for r in rows}
    pending={}
    for report in reports:
        p=report["payload"]
        if p["nonce"] in pending:
            raise ValueError("Reused original signer nonce")
        pending[p["nonce"]]=(p["agent_id"],p["trial_token"],p["sequence"])
    seen={};seq={}
    verified=0
    replays=0
    for report in reports:
        payload=report["payload"]
        if payload["agent_id"]!=AGENT or payload["service"]!=SERVICE or payload["source_kind"]!="two_UE_host_capture":
            raise ValueError("Wrong lab evidence signer provenance")
        token=payload["trial_token"]
        if token not in by_token or token in seen:
            raise ValueError("Signed evidence not bound to one real dual UE window")
        if not verify_receipt(report,registered_keys=pub,pending=pending,
            accepted_sequences=seq,now=payload["measured_at_unix"]+1,
            allowed_services=(SERVICE,)):
            raise ValueError("One original signed dual UE witness invalid")
        verified+=1
        if not verify_receipt(report,registered_keys=pub,pending=pending,
            accepted_sequences=seq,now=payload["measured_at_unix"]+1,
            allowed_services=(SERVICE,)):
            replays+=1
        seen[token]=payload["observation"]
    if pending or len(seen)!=9 or verified!=9 or replays!=9:
        raise ValueError("Signature, nonce or replay audit incomplete")
    phases={}
    for phase in PHASES:
        group=[x for x in rows if x["phase_audit_only"]==phase]
        if len(group)!=3 or set(x["window_index"] for x in group)!={0,1,2}:
            raise ValueError("Missing real two-UE phase windows")
        for row in group:
            obs=seen[row["trial_token"]]
            ue=obs["two_distinct_UE_outcomes"]
            k=obs["n3_role_endpoint_bridge"]
            teid=obs["n3_teid_candidate_bridge"]
            ng=obs["private_ie_tree_census"]["ngap"]
            pf=obs["private_ie_tree_census"]["pfcp"]
            matrix=obs["private_direction_role_matrix"]
            expected={
                "real_UE1_PDU_success":ue["real_UE1_PDU_success"],
                "real_UE2_PDU_success":ue["real_UE2_PDU_success"],
                "numeric_UL_candidates":teid["direction_gated_unique_numeric_ul_teid_candidates"],
                "numeric_DL_candidates":teid["direction_gated_unique_numeric_dl_teid_candidates"],
                "endpoint_role_UL_candidates":k["ul_upf"]["strict_ipv4_teid_role_candidates"],
                "endpoint_role_DL_candidates":k["dl_gnb"]["strict_ipv4_teid_role_candidates"],
                "NGAP_TEID_tunnel_nodes":ng["gtp_tunnel_element_nodes"],
                "NGAP_request_transfer_nodes":ng["request_transfer_element_nodes"],
                "NGAP_response_transfer_nodes":ng["response_transfer_element_nodes"],
                "NGAP_same_ancestry_TEID_IP":ng["same_named_IE_subtree_TEID_IP_pair_occurrences"],
                "PFCP_same_ancestry_TEID_IP":pf["same_named_IE_subtree_TEID_IP_pair_occurrences"],
                "UL_same_numeric_IP_wrong_NGAP_role":matrix["NGAP_dl_gnb_vs_PFCP_ul_upf"],
                "DL_same_numeric_IP_wrong_NGAP_role":matrix["NGAP_ul_upf_vs_PFCP_dl_gnb"],
                "host_N4_drop_packets":obs["host_N4_packets_dropped"],
            }
            for key in FIELDS:
                if row[key]!=expected[key]:
                    raise ValueError("Original real trial outcome changed from signed PDML witness: "+key)
            if not (row["two_UE_concurrently_running"]==1
                    and ue["both_UE_containers_running_concurrently"]==1
                    and row["UE_start_delta_ms"]<1250
                    and row["SMF_UPF_running"]==1 and row["NRF_SMF_profile_present"]==1):
                raise ValueError("UEs not demonstrably present together in healthy SMF/UPF")
            if any((obs["cross_protocol_identity_join_proven"],
                    k["cross_protocol_identity_join_proven"],
                    teid["cross_protocol_identity_join_proven"],
                    obs["identity"]["cross_protocol_identity_join_proven"])):
                raise ValueError("False untrusted session attribution")
            if obs["host_N4_drop_active"]!=(phase=="n4_full_drop"):
                raise ValueError("Unfaithful N4 fault evidence")
            if row["endpoint_role_UL_candidates"]>row["numeric_UL_candidates"] or row["endpoint_role_DL_candidates"]>row["numeric_DL_candidates"]:
                raise ValueError("Stronger endpoint result exceeds TEID-only upper bound")
        per={
            "real_overlapping_UE_windows":3,
            "two_distinct_real_UE_attempts":6,
            "real_UE1_PDU_success":sum(x["real_UE1_PDU_success"] for x in group),
            "real_UE2_PDU_success":sum(x["real_UE2_PDU_success"] for x in group),
            "real_PDU_success_total":sum(x["real_UE1_PDU_success"]+x["real_UE2_PDU_success"] for x in group),
            "host_PFCP_drop_packets":sum(x["host_N4_drop_packets"] for x in group),
            "PFCP_session_establishment_pairs":sum(x["PFCP_req_rsp_pairs"] for x in group),
            "numeric_UL_candidates":sum(x["numeric_UL_candidates"] for x in group),
            "numeric_DL_candidates":sum(x["numeric_DL_candidates"] for x in group),
            "endpoint_role_UL_candidates":sum(x["endpoint_role_UL_candidates"] for x in group),
            "endpoint_role_DL_candidates":sum(x["endpoint_role_DL_candidates"] for x in group),
            "NGAP_PDML_GTP_tunnel_IE_nodes":sum(x["NGAP_TEID_tunnel_nodes"] for x in group),
            "NGAP_PDML_RequestTransfer_nodes":sum(x["NGAP_request_transfer_nodes"] for x in group),
            "NGAP_PDML_ResponseTransfer_nodes":sum(x["NGAP_response_transfer_nodes"] for x in group),
            "NGAP_PDML_same_ancestry_TEID_IP":sum(x["NGAP_same_ancestry_TEID_IP"] for x in group),
            "PFCP_PDML_same_ancestry_TEID_IP":sum(x["PFCP_same_ancestry_TEID_IP"] for x in group),
            "reversed_role_UL_matched_tuples":sum(x["UL_same_numeric_IP_wrong_NGAP_role"] for x in group),
            "reversed_role_DL_matched_tuples":sum(x["DL_same_numeric_IP_wrong_NGAP_role"] for x in group),
            "proven_UE_PDU_to_PFCP_SEID_mapping":0,
        }
        if per["real_UE1_PDU_success"]!=original["phases"][phase]["real_UE1_success"] or per["real_UE2_PDU_success"]!=original["phases"][phase]["real_UE2_success"]:
            raise ValueError("Original original PDU success counts differ")
        if phase in ("normal","recovery") and per["real_PDU_success_total"]!=6:
            raise ValueError("Real dual UE baseline/recovery not proven")
        if phase=="n4_full_drop" and per["real_PDU_success_total"]!=0:
            raise ValueError("Some PDU succeeded while full SMF PFCP blocked")
        phases[phase]=per
    return {"replica":replica,"phases":phases,
            "signature_verifications":verified,
            "replay_rejections":replays}


def audit(root:Path,out:Path)->dict:
    out.mkdir(parents=True,exist_ok=True)
    labs=[verify_lab(root/f"phase19-real-{x}",x) for x in REPLICAS]
    totals={phase:{
        k:sum(lab["phases"][phase][k] for lab in labs)
        for k in labs[0]["phases"][phase]} for phase in PHASES}
    result={
        "source":"27 actually measured overlapping TWO-UE windows in 3 new disposable Open5GS real cores",
        "real_window_count":27,
        "real_separately_started_and_provisioned_UE_PDU_attempts":54,
        "ed25519_signed_original_KIE_verified":sum(x["signature_verifications"] for x in labs),
        "replay_rejections":sum(x["replay_rejections"] for x in labs),
        "by_replica":labs,
        "by_phase":totals,
        "proven_cross_protocol_UE_session_identity_joins":0,
        "critical_limit":"PDML ancestry shows field nesting; no independently protected UE PDU ID->SM Context->PFCP SEID mapping",
        "trust_limit":"same GitHub administrator; independent verifier is compute-only",
    }
    (out/"verified_dual_UE_PDML_results.json").write_text(json.dumps(result,indent=2))
    lines=[
        "# Phase 19 — real concurrent two-UE Open5GS, private NGAP/PFCP PDML ancestry",
        "",
        "| Phase | Real UE success | Numeric UL/DL candidates | Endpoint role UL/DL | NGAP subtree TEID+IP | PFCP subtree TEID+IP | PFCP kernel drops |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for phase,q in totals.items():
        lines.append(
            f"| {phase} | {q['real_PDU_success_total']}/{q['two_distinct_real_UE_attempts']} | "
            f"{q['numeric_UL_candidates']}/{q['numeric_DL_candidates']} | "
            f"{q['endpoint_role_UL_candidates']}/{q['endpoint_role_DL_candidates']} | "
            f"{q['NGAP_PDML_same_ancestry_TEID_IP']} | {q['PFCP_PDML_same_ancestry_TEID_IP']} | "
            f"{q['host_PFCP_drop_packets']} |")
    lines.extend(["",
        "All source IPs, TEIDs, PDU IDs, SEIDs, subscriber identifiers and PCAP were excluded from the signed data.",
        "Even when two UE are concurrent, protocol IE ancestry and numeric/endpoint overlaps cannot prove UE-to-PFCP session attribution.",
        "Signing and verification are under the same GitHub administrative owner, not independent NF attestation.",
        ])
    (out/"REPORT.md").write_text("\n".join(lines)+"\n")
    return result


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,default=Path("phase19_inputs"))
    p.add_argument("--out",type=Path,default=Path("results/phase19-verified"))
    a=p.parse_args()
    print(json.dumps(audit(a.root,a.out),indent=2))


if __name__=="__main__":
    main()
