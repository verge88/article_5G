"""Phase 15 verifier: distinct PFCP transactions inside real UE trial windows.

Run on second GitHub runner and recheck every original Ed25519 receipt,
firewall witness, NRF and UPF presence. These observations are independent
computations but not independent administrative trust domains.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

from .phase14_n4_live import ALL_SERVICES,PFCP_SVC
from .phase13_probe import SERVICES
from .phase15_live import PHASES
from .phase9_receipts import verify_receipt

REPLICAS=("11","22","33")
ISSUERS={"nrf":"phase13_nrf","upf":"phase13_upf",
         "pfcp_host_capture":"phase14_pfcp_host_capture"}


def audit_replica(folder:Path,replica:str)->dict:
    trials=json.loads((folder/"real_per_UE_PFCP_windows.json").read_text())
    reports=[json.loads(line) for line in (folder/"signed_pfcp_receipts.jsonl").read_text().splitlines() if line]
    pub=json.loads((folder/"public_agent_keys.json").read_text())
    result=json.loads((folder/"original_phase15_report.json").read_text())
    if result["replica"]!=replica or len(trials)!=16 or len(reports)!=24 or len(pub)!=3:
        raise ValueError("Incomplete original real 5GC per-UE capture experiment")
    by_phase={}
    for phase in PHASES:
        block=[x for x in trials if x["audit_phase_NOT_model_input"]==phase]
        if len(block)!=4 or set(x["trial_idx"] for x in block)!={0,1,2,3}:
            raise ValueError("Missing original UE procedure windows")
        if any(x["both_smfs_up_running_lab_audit"]!=1 for x in block):
            raise ValueError("A network function was not running")
        if any(x["nrf_smf_registered_during_trial_lab"]!=1 for x in block):
            raise ValueError("NRF failed to observe SMF profile")
        if phase in ("normal","recovery") and sum(x["real_ueransim_pdu_success"] for x in block)!=4:
            raise ValueError("Healthy baseline/recovery not observed in genuine UE logs")
        by_phase[phase]={
            "real_ue_attempts":4,
            "successful_PDU":sum(x["real_ueransim_pdu_success"] for x in block),
            "real_PFCP_session_requests_in_window":sum(x["observed_pfcp_sessions_requests"] for x in block),
            "real_PFCP_session_responses_in_window":sum(x["observed_pfcp_sessions_responses"] for x in block),
            "within_trial_matched_PFCP_request_response_pairs":sum(x["observed_pfcp_matched_pairs"] for x in block),
            "unmatched_request_occurrences":sum(x["observed_pfcp_unmatched_requests"] for x in block),
            "lab_firewall_dropped_packet_count":sum(x["pfcp_packets_dropped_lab_counter"] for x in block),
            "PDU_success_with_no_observed_pair":sum(
                x["real_ueransim_pdu_success"] and x["observed_pfcp_matched_pairs"]==0 for x in block),
            "PDU_failure_with_real_lab_drop_counter":sum(
                x["real_ueransim_pdu_success"]==0 and x["pfcp_packets_dropped_lab_counter"]>0 for x in block),
        }
        src=result["phases"][phase]
        if src["real_pdu_success"]!=by_phase[phase]["successful_PDU"]:
            raise ValueError("Reported PDU outcome differs from original row data")
        if src["PFCP_pairs_in_capture_windows"]!=by_phase[phase]["within_trial_matched_PFCP_request_response_pairs"]:
            raise ValueError("Report does not match observed PFCP matched pairs")
    pending={}
    for d in reports:
        p=d["payload"]
        if p["nonce"] in pending:
            raise ValueError("Duplicate signed challenge in actual PFCP experiment")
        pending[p["nonce"]]=(p["agent_id"],p["trial_token"],p["sequence"])
    consumed={}
    total=0
    replay=0
    phase_presence={p:{} for p in PHASES}
    signed_pfcp={}
    for d in reports:
        p=d["payload"]
        source=p["source_kind"]
        if source not in ISSUERS or p["agent_id"]!=ISSUERS[source]:
            raise ValueError("Wrong control source identity")
        should=PFCP_SVC if source=="pfcp_host_capture" else SERVICES[source]
        if p["service"]!=should:
            raise ValueError("Signed service does not match KIE source")
        valid=verify_receipt(d,registered_keys=pub,pending=pending,
            accepted_sequences=consumed,now=p["measured_at_unix"]+1,
            allowed_services=ALL_SERVICES)
        if not valid:
            raise ValueError("One actual signed KIE failed cross-runner verification")
        total+=1
        if not verify_receipt(d,registered_keys=pub,pending=pending,
            accepted_sequences=consumed,now=p["measured_at_unix"]+1,
            allowed_services=ALL_SERVICES):
            replay+=1
        if source=="pfcp_host_capture":
            if p["trial_token"] in signed_pfcp:
                raise ValueError("Repeated signed PFCP data for UE window")
            signed_pfcp[p["trial_token"]]=p["observation"]
        else:
            recognized=[phase for phase in PHASES
                        if p["trial_token"]==f"r{replica}_{phase}_nf"]
            if len(recognized)!=1:
                raise ValueError("NF presence KIE not bound to measured phase")
            phase_presence[recognized[0]][source]=p["observation"]
    if pending or total!=24 or replay!=24:
        raise ValueError("Nonce, signature or replay result invalid")
    if len(signed_pfcp)!=16 or any(len(v)!=2 for v in phase_presence.values()):
        raise ValueError("Absent genuine PFCP trial KIE or phase NRF/UPF receipt")
    for x in trials:
        obs=signed_pfcp.get(x["trial_token"])
        if not obs:
            raise ValueError("One real PDU attempt has no authentic PFCP measurement")
        for left,right in (
            ("session_establishment_matched_pairs","observed_pfcp_matched_pairs"),
            ("session_establishment_requests","observed_pfcp_sessions_requests"),
            ("session_establishment_responses","observed_pfcp_sessions_responses"),
            ("pfcp_packets_dropped_by_host_lab_firewall","pfcp_packets_dropped_lab_counter"),
        ):
            if obs[left]!=x[right]:
                raise ValueError("Original PFCP row not supported by its signed KIE")
        if not (0<=obs["session_establishment_matched_pairs"]<=
                min(obs["session_establishment_requests"],obs["session_establishment_responses"])):
            raise ValueError("Impossible actual Request/Response PFCP pairing")
        if obs["actual_loss_rule"] != ({
            "normal":"none","n4_half_drop":"half","n4_full_drop":"full","recovery":"none"
        }[x["audit_phase_NOT_model_input"]]):
            raise ValueError("Firewall intervention label not bound to signed capture")
    for phase,inputs in phase_presence.items():
        nrf=inputs["nrf"]
        upf=inputs["upf"]
        if not(nrf["http_status"]==200 and nrf["http_version"]=="2"
               and nrf["advertised_smf_profiles"]>=1
               and upf["namespace_accessible"] and
               upf["pfcp_udp_8805_socket_present"]):
            raise ValueError("Signed NF presence witness does not support healthy-running controls")
    return {
        "replica":replica,
        "phase_metrics":by_phase,
        "valid_signed_cryptographic_receipts":total,
        "verified_replay_rejections":replay,
        "n_real_UE_PDU_attempts":len(trials),
        "n_signed_per_trial_PFCP_KIE":len(signed_pfcp),
        "n_signed_phase_NF_presence_KIE":sum(len(q) for q in phase_presence.values()),
    }


def audit(root:Path,out:Path):
    out.mkdir(parents=True,exist_ok=True)
    per=[audit_replica(root/f"phase15-real-{x}",x) for x in REPLICAS]
    combined={}
    for phase in PHASES:
        metrics=per[0]["phase_metrics"][phase].keys()
        combined[phase]={k:sum(r["phase_metrics"][phase][k] for r in per)
                          for k in metrics}
    final={
        "scope":"Three separate real Open5GS+UERANSIM compute runners sharing GitHub admin; NO malicious compromise",
        "report_type":"per-UE-window PFCP sequence/direction matches and partial/full real N4 packet loss",
        "per_runner":per,
        "aggregated_real_UE_outcomes":combined,
        "n_real_UE_attempts":sum(r["n_real_UE_PDU_attempts"] for r in per),
        "n_cryptographically_verified_KIE":sum(r["valid_signed_cryptographic_receipts"] for r in per),
        "n_replay_rejections":sum(r["verified_replay_rejections"] for r in per),
        "n_real_PFCP_capture_window_KIE":sum(r["n_signed_per_trial_PFCP_KIE"] for r in per),
        "n_NRF_and_UPF_KIE":sum(r["n_signed_phase_NF_presence_KIE"] for r in per),
        "causal_and_trust_limits":[
            "PFCP seqno and reversed UDP endpoints are matched within each real UE time window only",
            "No cryptographic/session-ID binding to NAS PDU; co-occurring PFCP may originate from other UE or background process",
            "Dropped packets were observed by a privileged host namespace firewall counter, not signed by SMF",
            "Response may be absent due to packet-capture losses; no reliable source truth or independent administrative NF",
            "Observation windows include UE restart plus controller log polling and cleanup",
            "No malicious NF compromise or hidden tampering; packet loss is laboratory infrastructure fault",
            "Kernel packet loss is deterministic every second selected outgoing datagram, not guaranteed 50% PDU failures",
        ],
    }
    (out/"verified_trial_pfcp_results.json").write_text(json.dumps(final,indent=2))
    lines=[
        "# Phase 15 — true per-UE PFCP N4 packet captures and partial loss",
        "",
        "These are measured disposable Open5GS faults and authenticated lab observations, not intrusion-detection results.",
        "",
        "| Phase | UE PDU success | PFCP requests in windows | PFCP responses | Matched PFCP pairs | Lab packets dropped | UE successes with no observed PFCP pair |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for phase,x in combined.items():
        lines.append(f"| {phase} | {x['successful_PDU']}/{x['real_ue_attempts']} | "
                     f"{x['real_PFCP_session_requests_in_window']} | "
                     f"{x['real_PFCP_session_responses_in_window']} | "
                     f"{x['within_trial_matched_PFCP_request_response_pairs']} | "
                     f"{x['lab_firewall_dropped_packet_count']} | "
                     f"{x['PDU_success_with_no_observed_pair']} |")
    lines.extend(["",
        f"Verified {final['n_cryptographically_verified_KIE']} signed KIE, "
        f"rejected {final['n_replay_rejections']} replays.",
        "",
        "The PFCP transaction matching used in this report is bounded by a UE time window, not a session-identifier join.",
        "N4 firewall counters and capture originate from a privileged host, not an independently administered trusted domain.",
    ])
    (out/"REPORT.md").write_text("\n".join(lines)+"\n")
    return final


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,default=Path("phase15_inputs"))
    p.add_argument("--out",type=Path,default=Path("results/phase15-independent"))
    a=p.parse_args()
    print(json.dumps(audit(a.root,a.out),indent=2))


if __name__=="__main__":
    main()
