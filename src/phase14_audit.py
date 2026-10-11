"""Independent phase14 actual PFCP packet and signed KIE audit.

Treat socket status, NRF Discovery, passive PFCP frames and host firewall
counter as separate evidence types. Never claim cryptographic independence
of sources or malicious NF behavior from fault injection.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

from .phase14_n4_live import ALL_SERVICES,PHASES,PFCP_SVC
from .phase13_probe import SERVICES
from .phase9_receipts import verify_receipt

REPLICAS=("11","22","33")
CATEGORIES=("nrf","upf","pfcp_host_capture")
ISSUERS={"nrf":"phase13_nrf","upf":"phase13_upf",
         "pfcp_host_capture":"phase14_pfcp_host_capture"}


def parse(folder:Path,replica:str):
    measurements=json.loads((folder/"phase14_real_ue_trials.json").read_text())
    phases=json.loads((folder/"phase14_pfcp_n4_phase_summary.json").read_text())
    report=json.loads((folder/"phase14_lab_report.json").read_text())
    documents=[json.loads(s) for s in (folder/"signed_receipts.jsonl").read_text().splitlines() if s]
    pub=json.loads((folder/"public_agent_keys.json").read_text())
    if not (len(measurements)==12 and len(phases)==3 and len(documents)==9
            and len(pub)==3 and report["replica"]==replica):
        raise ValueError("Incomplete original real 5GC trace or signature evidence")
    if set(report["phases"])!=set(PHASES):
        raise ValueError("Missing real network procedure phase")
    for phase in PHASES:
        rows=[r for r in measurements if r["phase_AUDIT_ONLY"]==phase]
        s=next((p for p in phases if p["phase"]==phase),None)
        if s is None or len(rows)!=4:
            raise ValueError("Malformed real PFCP impairment phase")
        if not (all(r["smf_running"] and r["upf_running"] for r in rows)
                and s["smf_alive"] and s["upf_alive"]):
            raise ValueError("SMF/UPF process left running state during controlled N4 impairment")
        if report["phases"][phase]!=sum(int(r["ue_pdu_success"]) for r in rows):
            raise ValueError("True UE PDU procedure counts not reproducible")
        if phase=="n4_pfcp_drop" and not s["firewall_drop_rule_installed"]:
            raise ValueError("No installed actual N4 packet drop")
        if phase!="n4_pfcp_drop" and s["firewall_drop_rule_installed"]:
            raise ValueError("N4 firewall was not restored outside active phase")
        if not (s["nrf_http2"] and s["nrf_http_status"]==200
                and s["nrf_advertised_smf_profiles"]>0
                and s["upf_namespace_accessible"]
                and s["upf_pfcp_socket_present"]):
            raise ValueError("NRF/UPF baseline control surfaces became unavailable")
        if s["pfcp_decoded_message_occurrences"]<0 or s["n4_udp_8805_drop_counter"]<0:
            raise ValueError("Invalid packet observation")
        if sum(s["pfcp_type_occurrences"].values())!=s["pfcp_decoded_message_occurrences"]:
            raise ValueError("Real packet message family counts inconsistent")
    pending={}
    for d in documents:
        p=d["payload"]
        if p["nonce"] in pending:
            raise ValueError("Duplicate issued nonce")
        pending[p["nonce"]]=(p["agent_id"],p["trial_token"],p["sequence"])
    accepted={}
    valid=0
    replays=0
    for d in documents:
        p=d["payload"]
        source=p["source_kind"]
        if source not in CATEGORIES or p["agent_id"]!=ISSUERS[source]:
            raise ValueError("Claimed KIE issuer does not match expected separate public key")
        expected=PFCP_SVC if source=="pfcp_host_capture" else SERVICES[source]
        if p["service"]!=expected:
            raise ValueError("KIE signature service identifier mismatches source")
        if not verify_receipt(d,registered_keys=pub,pending=pending,
            accepted_sequences=accepted,now=p["measured_at_unix"]+1,
            allowed_services=ALL_SERVICES):
            raise ValueError("Authentic original network KIE failed verification")
        valid+=1
        if not verify_receipt(d,registered_keys=pub,pending=pending,
            accepted_sequences=accepted,now=p["measured_at_unix"]+1,
            allowed_services=ALL_SERVICES):
            replays+=1
    if pending:
        raise ValueError("Not all issued challenges were accounted for")
    return {
        "replica":replica,
        "real_ue_pdu_attempts":len(measurements),
        "normal_real_success":report["phases"]["normal"],
        "n4_packet_drop_real_success":report["phases"]["n4_pfcp_drop"],
        "recovery_real_success":report["phases"]["recovery"],
        "genuine_pfcp_message_occurrences":{s["phase"]:s["pfcp_decoded_message_occurrences"] for s in phases},
        "pfcp_family_counts":{s["phase"]:s["pfcp_type_occurrences"] for s in phases},
        "dropped_n4_pfcp_packets_in_smf_namespace":next(s["n4_udp_8805_drop_counter"] for s in phases if s["phase"]=="n4_pfcp_drop"),
        "nrf_registered_smf_at_all_phase_checks":True,
        "upf_pfcp_udp8805_socket_present_at_all_checks":True,
        "valid_signed_KIE":valid,
        "replay_rejected":replays,
    }


def audit(root:Path,out:Path):
    out.mkdir(parents=True,exist_ok=True)
    results=[parse(root/f"phase14-real-{r}",r) for r in REPLICAS]
    summary={
        "source":"36 real UE PDU procedures in 3 new, separate Open5GS+UERANSIM runner labs",
        "results_per_runner":results,
        "total_actual_ue_pdu_attempts":sum(x["real_ue_pdu_attempts"] for x in results),
        "total_smf_n4_egress_dropped_udp8805_packets":sum(x["dropped_n4_pfcp_packets_in_smf_namespace"] for x in results),
        "total_signed_reports_accepted":sum(x["valid_signed_KIE"] for x in results),
        "total_replays_rejected":sum(x["replay_rejected"] for x in results),
        "real_pdu_success_by_phase":{
            phase:sum(x[phase_key] for x in results)
            for phase,phase_key in (("normal","normal_real_success"),
                                    ("n4_pfcp_drop","n4_packet_drop_real_success"),
                                    ("recovery","recovery_real_success"))
        },
        "limits":[
            "PFCP message counts are actual capture occurrences, not UE sessions",
            "Packet-loss/drop counter is privileged SMF namespace host audit, not independent NF-signed or standard N4 integrity attestation",
            "SMF/UPF alive + NRF registered + UPF UDP8805 listening does not guarantee active PFCP exchange",
            "Capture device 'any' may include duplicate frames; counter interpretation is separate",
            "All signature keys share same GitHub administrative trust domain",
            "No NF malicious compromise, no deception by actual NFs",
            "One lab Open5GS implementation and 4 trials per phase per runner",
        ],
    }
    (out/"verified_pfcp_results.json").write_text(json.dumps(summary,indent=2))
    report=[
        "# Phase 14 — verified actual PFCP/N4 packet interruption with SMF and UPF running",
        "",
        "These are legitimate fault-injection measurements, not proof of attack detection.",
        "",
        "| Runner | Healthy PDU successes /4 | N4 UDP drop successes /4 | Recovery /4 | Actually dropped N4 packets | Signed KIE | Replays rejected |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in results:
        report.append(f"| {r['replica']} | {r['normal_real_success']} | "
                      f"{r['n4_packet_drop_real_success']} | {r['recovery_real_success']} | "
                      f"{r['dropped_n4_pfcp_packets_in_smf_namespace']} | "
                      f"{r['valid_signed_KIE']} | {r['replay_rejected']} |")
    report.extend(["",
        "SMF and UPF processes remained running in every phase; NRF advertised SMF and UPF retained a PFCP listening socket.",
        "The actual additional witness is a local privileged N4 egress packet-drop counter and passively captured PFCP types.",
        "All witnesses are operated under the same GitHub administrative authority.",
        "No raw PCAP, SUPI, IMSI, subscriber secrets, PFCP SEIDs or IPs are published.",
    ])
    (out/"REPORT.md").write_text("\n".join(report)+"\n")
    return summary


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,default=Path("phase14_inputs"))
    p.add_argument("--out",type=Path,default=Path("results/phase14_audit"))
    a=p.parse_args()
    print(json.dumps(audit(a.root,a.out),indent=2))


if __name__=="__main__":
    main()
