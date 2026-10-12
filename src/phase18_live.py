"""Phase18: real UE attempts, simultaneous N2/SBI/N4 packet evidence.

Only isolated disposable 5GC; only SMF PFCP output fault.
Raw packets and all protocol identifiers stay in temporary directory.
"""
from __future__ import annotations
import argparse,base64,hashlib,json,os,secrets,signal,subprocess,tempfile,time
from datetime import datetime,timezone
from pathlib import Path
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from .pdu_lab import cmd,state,trial
from .phase7_healthy_smf import GOOD,BAD,replace_ue_dnn
from .phase9_receipts import create_ephemeral_key,read_private_key,compact_json,verify_receipt,SCHEMA
from .phase14_n4_live import namespace_pid,ensure_firewall_supported,insert_rule,remove_rule
from .phase15_live import kernel_drop_count
from .phase18_endpoints import analyze

SERVICE="Lab_NGAP_PFCP_N3_Endpoint_Role_Candidate"
AGENT="phase18_n3_endpoint_host_capture"
PHASES=("normal","n4_full_drop","recovery")
TRIALS=3


def start_capture(pcap:Path)->subprocess.Popen:
    # Capture all bytes LOCALLY so NGAP and HTTP2 headers can be decoded.
    # The disposable PCAP is never published.
    command=["sudo","-n","tcpdump","-i","any","-n","-s","0","-U",
             "-w",str(pcap),
             "sctp or tcp port 7777 or udp port 8805"]
    p=subprocess.Popen(command,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,
                       start_new_session=True)
    time.sleep(1.4)
    if p.poll() is not None:
        raise RuntimeError("Real N3 endpoint and role network capture failed to start")
    return p


def stop_capture(p:subprocess.Popen):
    if p.poll() is None:
        os.killpg(p.pid,signal.SIGINT)
    try:
        p.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid,signal.SIGKILL)
        p.communicate(timeout=5)


def sign(key:Path,nonce:str,token:str,sequence:int,observation:dict)->dict:
    private=read_private_key(key)
    public=private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    payload={
        "schema":SCHEMA,"service":SERVICE,"source_kind":"endpoint_host_capture",
        "agent_id":AGENT,"key_id":hashlib.sha256(public).hexdigest()[:24],
        "trial_token":token,"nonce":nonce,"sequence":sequence,
        "timestamp_utc":datetime.now(timezone.utc).isoformat(),
        "measured_at_unix":round(time.time(),3),
        "observation":observation,
    }
    return {"payload":payload,
            "signature_b64":base64.b64encode(private.sign(compact_json(payload))).decode("ascii")}


def run(compose_dir:Path,out:Path,replica:str)->dict:
    if os.environ.get("ALLOW_PHASE18_DISPOSABLE_LAB")!="yes":
        raise RuntimeError("No explicit authorization for disposable real 5GC")
    if replica not in ("11","22","33") or "upstream_open5gs" not in str(compose_dir.resolve()):
        raise RuntimeError("Refusing outside preregistered isolated lab")
    if not all(state(name) for name in ("nrf","smf","upf","amf","nr_gnb")):
        raise RuntimeError("Real 5GC NF and gNB not present")
    cfg=compose_dir/"ueransim"/"ueransim-ue.yaml"
    original=cfg.read_text(encoding="utf-8")
    if original.count(GOOD)!=1 or BAD in original:
        raise RuntimeError("Expected controlled authorized DNN")
    pid=namespace_pid()
    ensure_firewall_supported(pid)
    out.mkdir(parents=True,exist_ok=True)
    rows=[];receipts=[]
    firewall=False
    nonce_issued={};accepted={}
    with tempfile.TemporaryDirectory(prefix="phase18_signing_key_") as d:
        k=Path(d)/"endpoint_key.pem"
        pub={AGENT:create_ephemeral_key(k)}
        try:
            for phase in PHASES:
                cfg.write_text(replace_ue_dnn(original,GOOD),encoding="utf-8")
                if phase=="n4_full_drop":
                    insert_rule(pid)
                    firewall=True
                if phase=="recovery":
                    if firewall:
                        remove_rule(pid)
                        firewall=False
                    time.sleep(17)
                if not all(state(name) for name in ("smf","upf")):
                    raise RuntimeError("SMF and UPF must be running in all phases")
                for ix in range(TRIALS):
                    token=f"r{replica}_{phase}_{ix}"
                    with tempfile.TemporaryDirectory(prefix="phase18_PCAP_") as temp:
                        pcap=Path(temp)/"endpoint.pcap"
                        capt=start_capture(pcap)
                        try:
                            counter_before=kernel_drop_count(pid) if firewall else 0
                            actual=trial(compose_dir,phase,ix,
                                         18 if not firewall else 15,1.)
                            counter_after=kernel_drop_count(pid) if firewall else 0
                        finally:
                            stop_capture(capt)
                        observation=analyze(pcap)
                    # Never allow missing capture to look like a negative result.
                    if not all(state(name) for name in ("smf","upf")):
                        raise RuntimeError("Both NF containers must remain running")
                    observation["lab_n4_egress_drop_packets"]=counter_after-counter_before
                    observation["lab_rule_installed"]=bool(firewall)
                    observation["ue_pdu_success_observed"]=int(actual["ue_pdu_session_accepted"])
                    observation["nrf_advertised_smf_profiles_lab"]=actual["nrf_advertised_smf_profiles"]
                    observation["source_trust"]="one privileged host capture; not attested by NGAP, SMF or UPF"
                    nonce=secrets.token_hex(16)
                    seq=len(receipts)+1
                    nonce_issued[nonce]=(AGENT,token,seq)
                    signed=sign(k,nonce,token,seq,observation)
                    if not verify_receipt(signed,registered_keys=pub,
                            pending=nonce_issued,accepted_sequences=accepted,
                            allowed_services=(SERVICE,)):
                        raise RuntimeError("Failed Ed25519 verification of actual N2/N4/SBI and N3-TEID data")
                    receipts.append(signed)
                    rows.append({
                        "replica":replica,"trial_token":token,
                        "phase_audit_only":phase,
                        "trial_index":ix,
                        "real_UE_PDU_success":int(actual["ue_pdu_session_accepted"]),
                        "real_UE_registered":int(actual["ue_registration_seen"]),
                        "SMF_and_UPF_running_lab":int(state("smf") and state("upf")),
                        "NGAP_PDU_ID_visible":int(observation["ngap"]["ngap_pdu_id_visible"]),
                        "NGAP_PDU_ID_cardinality":observation["ngap"]["ngap_pdu_id_distinct_count"],
                        "Nsmf_HTTP2_requests":observation["nsmf"]["nsmf_http2_unique_request_streams"],
                        "Nsmf_HTTP2_paired_responses":observation["nsmf"]["nsmf_http2_matched_responses"],
                        "PFCP_session_pairs":observation["pfcp"]["session_establishment_matched_pairs"],
                        "PFCP_nonzero_SEID_visible":int(observation["pfcp_seid_cardinality"]["pfcp_header_seid_visible"]),
                        "cross_protocol_identity_join_proven":int(observation["identity"]["cross_protocol_identity_join_proven"]),
                        "n3_teid_ul_unique_numeric_candidates":observation["n3_teid_candidate_bridge"]["direction_gated_unique_numeric_ul_teid_candidates"],
                        "n3_teid_dl_unique_numeric_candidates":observation["n3_teid_candidate_bridge"]["direction_gated_unique_numeric_dl_teid_candidates"],
                        "n3_teid_ambiguous_candidates":observation["n3_teid_candidate_bridge"]["direction_gated_ambiguous_ul_teids"]+observation["n3_teid_candidate_bridge"]["direction_gated_ambiguous_dl_teids"],
                        "n3_teid_any_numeric_overlap":observation["n3_teid_candidate_bridge"]["direction_free_numeric_overlap_distinct"],
                        "n3_UL_endpoint_role_candidates":observation["n3_role_endpoint_bridge"]["ul_upf"]["strict_ipv4_teid_role_candidates"],
                        "n3_DL_endpoint_role_candidates":observation["n3_role_endpoint_bridge"]["dl_gnb"]["strict_ipv4_teid_role_candidates"],
                        "n3_endpoint_collision_abstentions":observation["n3_role_endpoint_bridge"]["ul_upf"]["same_endpoint_collision_abstentions"]+observation["n3_role_endpoint_bridge"]["dl_gnb"]["same_endpoint_collision_abstentions"],
                        "n3_NGAP_TEID_frames":observation["n3_role_endpoint_bridge"]["ngap_frame_observability"]["NGAP_frames_with_TEID_field"],
                        "n3_NGAP_single_IPv4_frames":observation["n3_role_endpoint_bridge"]["ngap_frame_observability"]["NGAP_frames_with_single_IPv4_endpoint"],
                        "n3_PFCP_single_IPv4_frames":observation["n3_role_endpoint_bridge"]["pfcp_frame_observability"]["PFCP_frames_with_single_IPv4_endpoint"],
                        "naive_time_only_join_overconfidence":int(observation["identity"]["naive_three_source_time_only_join_would_claim_identity"]),
                        "host_n4_actual_drop_packets":observation["lab_n4_egress_drop_packets"],
                        "receipt_key_id":signed["payload"]["key_id"],
                    })
                    (out/"real_endpoint_trial_rows.json").write_text(json.dumps(rows,indent=2))
                    (out/"signed_endpoint_receipts.jsonl").write_text(
                        "".join(json.dumps(q,sort_keys=True)+"\n" for q in receipts))
        finally:
            cfg.write_text(original,encoding="utf-8")
            if firewall:
                remove_rule(pid)
        (out/"public_keys.json").write_text(json.dumps(pub,indent=2))
    summary={
        "replica":replica,"n_actual_UE_attempts":len(rows),
        "n_signed_endpoint_KIE":len(receipts),
        "real_UE_PDU_success_by_phase":{
            p:sum(x["real_UE_PDU_success"] for x in rows if x["phase_audit_only"]==p)
            for p in PHASES},
        "identity_join_proved":0,
        "n3_endpoint_role_observation_only":"role+ipv4+TEID candidate, NOT a proven SM Context / PDU session mapping",
        "limit":"No authenticated bridge NGAP PDU ID -> Nsmf SM Context -> PFCP SEID",
    }
    (out/"original_real_endpoint_summary.json").write_text(json.dumps(summary,indent=2))
    if len(rows)!=9 or len(receipts)!=9:
        raise RuntimeError("Incomplete 9 real UE crossplane windows")
    if summary["real_UE_PDU_success_by_phase"]["normal"]!=3 or summary["real_UE_PDU_success_by_phase"]["recovery"]!=3:
        raise RuntimeError("No baseline or N4 recovery; genuine UE data still saved")
    return summary


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--replica",choices=("11","22","33"),required=True)
    p.add_argument("--compose-dir",type=Path,default=Path("upstream_open5gs"))
    p.add_argument("--out",type=Path,default=Path("results/phase18"))
    a=p.parse_args()
    print(json.dumps(run(a.compose_dir,a.out,a.replica),indent=2))


if __name__=="__main__":
    main()
