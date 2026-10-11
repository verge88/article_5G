"""Phase 15: actual per-PDU PFCP windows under healthy, 50% packet loss,
complete N4 outage and recovery. Both NF processes remain UP.

Faults are permitted only on disposable GitHub runner SMF netns. Capture is
read-only real PFCP traffic; raw PCAP never enters public artifact.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time

from .pdu_lab import cmd,state,trial
from .phase7_healthy_smf import GOOD,BAD,replace_ue_dnn
from .phase9_receipts import create_ephemeral_key, verify_receipt
from .phase14_n4_live import (
    ALL_SERVICES, namespace_pid, ensure_firewall_supported,
    insert_rule, remove_rule, start_capture, end_capture,
    sign_capture, sign_active
)
from .phase15_pfcp_windows import decode_trial_pcap

PHASES=("normal","n4_half_drop","n4_full_drop","recovery")
N_TRIALS_PER_PHASE=4
# Restrict all interventions to outgoing PFCP UDP port 8805 in the SMF
# network namespace of the disposable lab, no other host/network traffic.
PARTIAL_MATCH=["-p","udp","--dport","8805","-m","statistic",
               "--mode","nth","--every","2","--packet","0","-j","DROP"]


def partial_cmd(pid:int,action:str)->list[str]:
    if action not in ("-I","-C","-D"):
        raise ValueError("Unexpected firewall change")
    return ["sudo","-n","nsenter","-t",str(pid),"-n",
            "iptables",action,"OUTPUT",*(["1"] if action=="-I" else []),
            *PARTIAL_MATCH]


def has_partial_rule(pid:int)->bool:
    return subprocess.run(partial_cmd(pid,"-C"),capture_output=True,timeout=12).returncode==0


def install_partial(pid:int)->None:
    ensure_firewall_supported(pid)
    if has_partial_rule(pid):
        raise RuntimeError("Refusing duplicate PFCP loss rule")
    cmd(partial_cmd(pid,"-I"),timeout=15)
    if not has_partial_rule(pid):
        raise RuntimeError("Partial PFCP packet loss was not installed")


def remove_partial(pid:int)->None:
    if has_partial_rule(pid):
        cmd(partial_cmd(pid,"-D"),timeout=15)
    if has_partial_rule(pid):
        raise RuntimeError("Partial PFCP loss still active")


def kernel_drop_count(pid:int)->int:
    rules=cmd(["sudo","-n","nsenter","-t",str(pid),"-n",
              "iptables","-nvx","-L","OUTPUT"],timeout=12)
    # Both full & nth statistic DROP only target SMF egress UDP 8805.
    matches=[int(m.group(1)) for m in re.finditer(
        r"(?mi)^\s*(\d+)\s+\d+\s+DROP\s+udp\s+.*\bdpt:8805\b",rules)]
    if len(matches)!=1:
        raise RuntimeError(f"Expected exactly one active, measurable PFCP egress rule; got {len(matches)}")
    return matches[0]


def run(compose_dir:Path,out:Path,replica:str)->dict:
    if os.environ.get("ALLOW_PHASE15_DISPOSABLE_LAB")!="yes":
        raise RuntimeError("Explicit authorization for throwaway lab required")
    if replica not in ("11","22","33") or "upstream_open5gs" not in str(compose_dir.resolve()):
        raise RuntimeError("Only preregistered isolated Open5GS supported")
    if not all(state(n) for n in ("nrf","amf","smf","upf","nr_gnb")):
        raise RuntimeError("Real lab network is not ready")
    cfg=compose_dir/"ueransim"/"ueransim-ue.yaml"
    original=cfg.read_text(encoding="utf-8")
    if original.count(GOOD)!=1 or BAD in original:
        raise RuntimeError("Expected authorized DNN not provisioned")
    pid=namespace_pid()
    ensure_firewall_supported(pid)
    if has_partial_rule(pid):
        raise RuntimeError("Unexpected preexisting PFCP statistic rule")
    out.mkdir(parents=True,exist_ok=True)
    rows=[]
    receipts=[]
    active_rule=None
    pending={}
    accepted={}
    with tempfile.TemporaryDirectory(prefix="phase15_private_keys_") as d:
        key_paths={s:Path(d)/(s+".pem") for s in ("pfcp","nrf","upf")}
        key_ids={"pfcp":"phase14_pfcp_host_capture",
                 "nrf":"phase13_nrf","upf":"phase13_upf"}
        publics={key_ids[s]:create_ephemeral_key(k) for s,k in key_paths.items()}
        sequence={"pfcp":0,"nrf":0,"upf":0}
        try:
            for phase in PHASES:
                cfg.write_text(replace_ue_dnn(original,GOOD),encoding="utf-8")
                if active_rule=="partial":
                    remove_partial(pid)
                    active_rule=None
                elif active_rule=="full":
                    remove_rule(pid)
                    active_rule=None
                if phase=="n4_half_drop":
                    install_partial(pid)
                    active_rule="partial"
                elif phase=="n4_full_drop":
                    insert_rule(pid)
                    active_rule="full"
                elif phase=="recovery":
                    time.sleep(16)
                if not (state("smf") and state("upf")):
                    raise RuntimeError("Both SMF and UPF must stay alive")
                for trial_idx in range(N_TRIALS_PER_PHASE):
                    token=f"r{replica}_{phase}_{trial_idx}"
                    # One PCAP lifetime per UE attempt, never cross phase boundaries.
                    with tempfile.TemporaryDirectory(prefix="phase15_real_pfcp_capture_") as td:
                        pcap=Path(td)/"pfcp.pcap"
                        capture=start_capture(pcap)
                        try:
                            drops_before=kernel_drop_count(pid) if active_rule else 0
                            ue=trial(compose_dir,phase,trial_idx,
                                     18 if not active_rule else 15,1.)
                            drops_after=kernel_drop_count(pid) if active_rule else 0
                        finally:
                            end_capture(capture)
                        observation=decode_trial_pcap(pcap)
                    if not (state("smf") and state("upf")):
                        raise RuntimeError("SMF/UPF process stopped during N4-only impairment")
                    nrf_profile=ue["nrf_advertised_smf_profiles"]
                    observation.update({
                        "pfcp_packets_dropped_by_host_lab_firewall":drops_after-drops_before,
                        "actual_loss_rule":"half" if active_rule=="partial" else
                                           "full" if active_rule=="full" else "none",
                        "capture_window":"exactly one UERANSIM PDU trial; include UE restart, NF log reads and 2s stop",
                        "capture_monitor_provenance":"privileged host tcpdump, not trusted NF attestation",
                    })
                    sequence["pfcp"]+=1
                    nonce=secrets.token_hex(16)
                    pending[nonce]=(key_ids["pfcp"],token,sequence["pfcp"])
                    signed=sign_capture(key_paths["pfcp"],nonce,token,
                                        sequence["pfcp"],observation)
                    if not verify_receipt(signed,registered_keys=publics,
                        pending=pending,accepted_sequences=accepted,
                        allowed_services=ALL_SERVICES):
                        raise RuntimeError("Per-trial genuine PFCP packet KIE failed live Ed25519 check")
                    receipts.append(signed)
                    rows.append({
                        "replica":replica,"trial_token":token,
                        "audit_phase_NOT_model_input":phase,"trial_idx":trial_idx,
                        "real_ueransim_pdu_success":int(ue["ue_pdu_session_accepted"]),
                        "real_registration":int(ue["ue_registration_seen"]),
                        "both_smfs_up_running_lab_audit":int(state("smf") and state("upf")),
                        "nrf_smf_registered_during_trial_lab":int(nrf_profile>0),
                        "elapsed_ue_seconds":ue["elapsed_s"],
                        "observed_pfcp_matched_pairs":observation["session_establishment_matched_pairs"],
                        "observed_pfcp_unmatched_requests":observation["session_establishment_unmatched_requests"],
                        "observed_pfcp_unmatched_responses":observation["session_establishment_unmatched_responses"],
                        "observed_pfcp_sessions_requests":observation["session_establishment_requests"],
                        "observed_pfcp_sessions_responses":observation["session_establishment_responses"],
                        "captured_pfcp_frame_observations_raw":observation["captured_pfcp_frame_observations_raw"],
                        "pfcp_packets_dropped_lab_counter":observation["pfcp_packets_dropped_by_host_lab_firewall"],
                        "per_trial_signature_key_id":signed["payload"]["key_id"],
                    })
                    # Preserve anonymized original trial and signed KIE even if a later
                    # intervention fails; upload-artifact is marked if:always().
                    (out/"real_per_UE_PFCP_windows.json").write_text(json.dumps(rows,indent=2))
                    (out/"signed_pfcp_receipts.jsonl").write_text(
                        "".join(json.dumps(d,sort_keys=True)+"\n" for d in receipts))
                # True positive physical presence controls once per phase,
                # not used to assign any real PDU outcome or select source.
                for source in ("nrf","upf"):
                    sequence[source]+=1
                    token=f"r{replica}_{phase}_nf"
                    nonce=secrets.token_hex(16)
                    pending[nonce]=(key_ids[source],token,sequence[source])
                    doc=sign_active(source,key_paths[source],nonce,token,sequence[source])
                    if not verify_receipt(doc,registered_keys=publics,pending=pending,
                        accepted_sequences=accepted,allowed_services=ALL_SERVICES):
                        raise RuntimeError("Lab NF presence signed receipt failed")
                    receipts.append(doc)
        finally:
            cfg.write_text(original,encoding="utf-8")
            if active_rule=="partial":
                remove_partial(pid)
            elif active_rule=="full":
                remove_rule(pid)
            # Do not delete any subscriber private keys until the keypair has
            # been used; raw private keys stay in temporary directory only.
        (out/"public_agent_keys.json").write_text(json.dumps(publics,indent=2))
    (out/"signed_pfcp_receipts.jsonl").write_text(
        "".join(json.dumps(d,sort_keys=True)+"\n" for d in receipts))
    phase_results={p:{
        "n_real_UE_trials":sum(x["audit_phase_NOT_model_input"]==p for x in rows),
        "real_pdu_success":sum(x["real_ueransim_pdu_success"] for x in rows
                               if x["audit_phase_NOT_model_input"]==p),
        "PFCP_pairs_in_capture_windows":sum(x["observed_pfcp_matched_pairs"] for x in rows
                                             if x["audit_phase_NOT_model_input"]==p),
        "PFCP_requests_in_capture_windows":sum(x["observed_pfcp_sessions_requests"] for x in rows
                                                if x["audit_phase_NOT_model_input"]==p),
        "PFCP_responses_in_capture_windows":sum(x["observed_pfcp_sessions_responses"] for x in rows
                                                 if x["audit_phase_NOT_model_input"]==p),
        "lab_firewall_drop_packets":sum(x["pfcp_packets_dropped_lab_counter"] for x in rows
                                        if x["audit_phase_NOT_model_input"]==p),
    } for p in PHASES}
    result={
        "replica":replica,"n_real_UE_procedures":len(rows),
        "signed_total_nrf_upf_pfcp_reports":len(receipts),
        "phases":phase_results,
        "cause_assertion":"Authorized UDP/8805 SMF namespace egress fault ONLY; not attack",
        "per_trial_correlation_scope":"PFCP frame sequence/direction pairing inside each actual UE timing window; no NAS/PDU ID join",
        "physical_oracle":"iptables counter in privileged SMF netns; not independent trust domain",
    }
    (out/"original_phase15_report.json").write_text(json.dumps(result,indent=2))
    if len(rows)!=16 or len(receipts)!=24:
        raise RuntimeError("Incomplete 16 real PDU windows or 24 signed controls")
    if phase_results["normal"]["real_pdu_success"]!=4 or phase_results["recovery"]["real_pdu_success"]!=4:
        raise RuntimeError("Independent baseline/recovery PDU outcomes not established")
    return result


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--replica",choices=("11","22","33"),required=True)
    p.add_argument("--compose-dir",type=Path,default=Path("upstream_open5gs"))
    p.add_argument("--out",type=Path,default=Path("results/phase15"))
    a=p.parse_args()
    print(json.dumps(run(a.compose_dir,a.out,a.replica),indent=2))


if __name__=="__main__":
    main()
