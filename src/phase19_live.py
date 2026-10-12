"""Phase19: TWO real concurrent UERANSIM UE in ONE Open5GS gNB/5GC trial window.

Unlike preceding stages, a window starts nr_ue and nr_ue2 from distinct
containers, configuration mounts and pre-provisioned synthetic subscriber
entries. Both process startups are launched asynchronously and separately
observed in real Docker logs. Neither subscriber data nor raw PCAP is
exported. Authorized isolated GitHub-runner lab ONLY.
"""
from __future__ import annotations
import argparse,base64,hashlib,json,os,secrets,subprocess,tempfile,time
from datetime import datetime,timezone
from pathlib import Path
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

from .pdu_lab import cmd,state,docker_logs,REG_PAT,SUCCESS_PAT,discovery_smf
from .phase9_receipts import (
    create_ephemeral_key,read_private_key,compact_json,verify_receipt,SCHEMA,
)
from .phase14_n4_live import (
    namespace_pid,ensure_firewall_supported,insert_rule,remove_rule
)
from .phase15_live import kernel_drop_count
from .phase18_live import start_capture,stop_capture
from .phase19_pdml import analyze

AGENT="phase19_two_ue_pdml_lab_agent"
SERVICE="Lab_TwoConcurrent_UE_NGAP_PFCP_PDML"
PHASES=("normal","n4_full_drop","recovery")
UE_NAMES=("nr_ue","nr_ue2")
WINDOWS_PER_PHASE=3


def sign(key:Path,nonce:str,token:str,seq:int,obs:dict)->dict:
    private=read_private_key(key)
    pub=private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    payload={
        "schema":SCHEMA,"service":SERVICE,"source_kind":"two_UE_host_capture",
        "agent_id":AGENT,"key_id":hashlib.sha256(pub).hexdigest()[:24],
        "trial_token":token,"nonce":nonce,"sequence":seq,
        "timestamp_utc":datetime.now(timezone.utc).isoformat(),
        "measured_at_unix":round(time.time(),3),"observation":obs,
    }
    return {
        "payload":payload,
        "signature_b64":base64.b64encode(private.sign(compact_json(payload))).decode("ascii")
    }


def dual_ue_trial(compose_dir:Path,phase:str,index:int,timeout_s:float=22)->dict:
    """Start TWO distinct UE containers in overlapping time windows.

    Return genuine observed NAS success for each independently. Never
    substitute one UE log for another and never infer success from phase.
    """
    for name in UE_NAMES:
        if state(name):
            cmd(["docker","stop","-t","2",name],timeout=15)
    since=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cmds=[
        ["docker","compose","-f","nr-ue.yaml","up","-d","--force-recreate","nr_ue"],
        ["docker","compose","-f","nr-ue2.yaml","up","-d","--force-recreate","nr_ue2"],
    ]
    started=time.monotonic()
    tasks=[]
    try:
        for command in cmds:
            t=time.monotonic()
            p=subprocess.Popen(command,cwd=compose_dir,stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,text=True)
            tasks.append((p,t))
        launch_delta_ms=round((tasks[1][1]-tasks[0][1])*1000,3)
        if launch_delta_ms>1250:
            raise RuntimeError("Two UE commands not dispatched within concurrent start window")
        for p,_ in tasks:
            stdout,stderr=p.communicate(timeout=90)
            if p.returncode:
                raise RuntimeError("UE container startup failed: "+stderr[-220:])
        both_running_at_start=all(state(name) for name in UE_NAMES)
        if not both_running_at_start:
            raise RuntimeError("Not two running UE containers")
        got={name:False for name in UE_NAMES}
        registration={name:False for name in UE_NAMES}
        while time.monotonic()-started<timeout_s:
            for name in UE_NAMES:
                raw=docker_logs(name,since=since)
                got[name]=got[name] or bool(SUCCESS_PAT.search(raw))
                registration[name]=registration[name] or bool(REG_PAT.search(raw))
            if all(got.values()):
                break
            time.sleep(0.9)
        return {
            "real_UE1_PDU_success":int(got["nr_ue"]),
            "real_UE2_PDU_success":int(got["nr_ue2"]),
            "real_UE1_registration":int(registration["nr_ue"]),
            "real_UE2_registration":int(registration["nr_ue2"]),
            "both_UE_containers_running_concurrently":int(both_running_at_start),
            "two_UE_start_dispatch_delta_ms":launch_delta_ms,
            "elapsed_window_s":round(time.monotonic()-started,3),
            "SMF_and_UPF_running":int(state("smf") and state("upf")),
            "NRF_advertised_SMF_count":discovery_smf(),
        }
    finally:
        for p,_ in tasks:
            if p.poll() is None:
                p.kill()
                p.communicate(timeout=10)
        for name in UE_NAMES:
            if state(name):
                cmd(["docker","stop","-t","2",name],timeout=15)
        time.sleep(1.5)


def run(compose_dir:Path,out:Path,replica:str)->dict:
    if os.environ.get("ALLOW_PHASE19_DISPOSABLE_LAB")!="yes":
        raise RuntimeError("Missing explicit authorization of isolated laboratory")
    if replica not in ("11","22","33") or "upstream_open5gs" not in str(compose_dir.resolve()):
        raise RuntimeError("Lab path or repeat identity not allowed")
    required=("nrf","amf","smf","upf","nr_gnb")
    if not all(state(name) for name in required):
        raise RuntimeError("Both UE cannot operate without real Open5GS 5GC")
    if not (compose_dir/"nr-ue2.yaml").exists():
        raise RuntimeError("Second distinct, pre-provisioned UE not configured")
    pid=namespace_pid()
    ensure_firewall_supported(pid)
    out.mkdir(parents=True,exist_ok=True)
    rows=[];docs=[];pending={};accepted={}
    drop=False
    with tempfile.TemporaryDirectory(prefix="phase19_ephemeral_ed25519_") as keydir:
        key=Path(keydir)/"observer.pem"
        pubs={AGENT:create_ephemeral_key(key)}
        try:
            for phase in PHASES:
                if phase=="n4_full_drop":
                    insert_rule(pid)
                    drop=True
                elif phase=="recovery":
                    if drop:
                        remove_rule(pid)
                        drop=False
                    time.sleep(17)
                for ix in range(WINDOWS_PER_PHASE):
                    token=f"r{replica}_{phase}_{ix}"
                    with tempfile.TemporaryDirectory(prefix="phase19_private_PCAP_") as td:
                        pcap=Path(td)/"genuine_two_UE_N2_N4.pcap"
                        capture=start_capture(pcap)
                        try:
                            before=kernel_drop_count(pid) if drop else 0
                            ue=dual_ue_trial(compose_dir,phase,ix,
                                              25 if not drop else 19)
                            after=kernel_drop_count(pid) if drop else 0
                        finally:
                            stop_capture(capture)
                        measured=analyze(pcap)
                    if ue["both_UE_containers_running_concurrently"]!=1:
                        raise RuntimeError("No real simultaneous UE")
                    if ue["SMF_and_UPF_running"]!=1:
                        raise RuntimeError("SMF/UPF process stopped during controlled N4 fault")
                    if ue["NRF_advertised_SMF_count"]<1:
                        raise RuntimeError("SMF not registered in NRF")
                    measured["two_distinct_UE_outcomes"]=ue
                    measured["host_N4_packets_dropped"]=after-before
                    measured["host_N4_drop_active"]=drop
                    measured["cross_protocol_identity_join_proven"]=False
                    nonce=secrets.token_hex(16)
                    seq=len(docs)+1
                    pending[nonce]=(AGENT,token,seq)
                    doc=sign(key,nonce,token,seq,measured)
                    if not verify_receipt(doc,registered_keys=pubs,
                         pending=pending,accepted_sequences=accepted,
                         allowed_services=(SERVICE,)):
                        raise RuntimeError("Real two-UE host evidence signature failed")
                    docs.append(doc)
                    x=measured["n3_role_endpoint_bridge"]
                    y=measured["n3_teid_candidate_bridge"]
                    ng=measured["private_ie_tree_census"]["ngap"]
                    pf=measured["private_ie_tree_census"]["pfcp"]
                    matrix=measured["private_direction_role_matrix"]
                    row={
                        "replica":replica,"trial_token":token,
                        "phase_audit_only":phase,"window_index":ix,
                        "real_UE1_PDU_success":ue["real_UE1_PDU_success"],
                        "real_UE2_PDU_success":ue["real_UE2_PDU_success"],
                        "real_UE1_registration":ue["real_UE1_registration"],
                        "real_UE2_registration":ue["real_UE2_registration"],
                        "two_UE_concurrently_running":ue["both_UE_containers_running_concurrently"],
                        "UE_start_delta_ms":ue["two_UE_start_dispatch_delta_ms"],
                        "NRF_SMF_profile_present":int(ue["NRF_advertised_SMF_count"]>=1),
                        "SMF_UPF_running":ue["SMF_and_UPF_running"],
                        "PFCP_req_rsp_pairs":measured["pfcp"]["session_establishment_matched_pairs"],
                        "numeric_UL_candidates":y["direction_gated_unique_numeric_ul_teid_candidates"],
                        "numeric_DL_candidates":y["direction_gated_unique_numeric_dl_teid_candidates"],
                        "endpoint_role_UL_candidates":x["ul_upf"]["strict_ipv4_teid_role_candidates"],
                        "endpoint_role_DL_candidates":x["dl_gnb"]["strict_ipv4_teid_role_candidates"],
                        "NGAP_TEID_tunnel_nodes":ng["gtp_tunnel_element_nodes"],
                        "NGAP_request_transfer_nodes":ng["request_transfer_element_nodes"],
                        "NGAP_response_transfer_nodes":ng["response_transfer_element_nodes"],
                        "NGAP_same_ancestry_TEID_IP":ng["same_named_IE_subtree_TEID_IP_pair_occurrences"],
                        "PFCP_same_ancestry_TEID_IP":pf["same_named_IE_subtree_TEID_IP_pair_occurrences"],
                        "UL_same_numeric_IP_wrong_NGAP_role":matrix["NGAP_dl_gnb_vs_PFCP_ul_upf"],
                        "DL_same_numeric_IP_wrong_NGAP_role":matrix["NGAP_ul_upf_vs_PFCP_dl_gnb"],
                        "host_N4_drop_packets":measured["host_N4_packets_dropped"],
                        "cross_protocol_identity_join_proven":False,
                    }
                    rows.append(row)
                    (out/"real_two_UE_windows.json").write_text(json.dumps(rows,indent=2))
                    (out/"signed_PDML_dual_UE_receipts.jsonl").write_text(
                       "".join(json.dumps(z,sort_keys=True)+"\n" for z in docs))
        finally:
            if drop:
                remove_rule(pid)
            for name in UE_NAMES:
                if state(name):
                    cmd(["docker","stop","-t","2",name],timeout=15)
        (out/"public_agent_keys.json").write_text(json.dumps(pubs,indent=2))
    by_phase={phase:{
        "real_windows":sum(x["phase_audit_only"]==phase for x in rows),
        "real_UE1_success":sum(x["real_UE1_PDU_success"] for x in rows if x["phase_audit_only"]==phase),
        "real_UE2_success":sum(x["real_UE2_PDU_success"] for x in rows if x["phase_audit_only"]==phase),
        "real_N4_drop_packets":sum(x["host_N4_drop_packets"] for x in rows if x["phase_audit_only"]==phase),
    } for phase in PHASES}
    report={"replica":replica,"real_dual_UE_windows":len(rows),
            "real_distinct_UE_PDU_attempts":len(rows)*2,
            "signed_lab_KIE_count":len(docs),
            "phases":by_phase,
            "identity_proof":"not established without authenticated SM Context bridge",
            "source_trust":"privileged single-admin GitHub host observation; not attested NF"}
    (out/"original_two_UE_summary.json").write_text(json.dumps(report,indent=2))
    if len(rows)!=9 or len(docs)!=9:
        raise RuntimeError("Incomplete genuine dual-UE concurrent procedure cohort")
    for phase in ("normal","recovery"):
        if by_phase[phase]["real_UE1_success"]!=3 or by_phase[phase]["real_UE2_success"]!=3:
            raise RuntimeError("No complete genuine dual-UE baseline/recovery")
    if sum(row["real_UE1_PDU_success"]+row["real_UE2_PDU_success"]
           for row in rows if row["phase_audit_only"]=="n4_full_drop")!=0:
        raise RuntimeError("N4 drop did not prevent UE PDU: do not assign fault outcome")
    return report


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--replica",required=True,choices=("11","22","33"))
    p.add_argument("--compose-dir",type=Path,default=Path("upstream_open5gs"))
    p.add_argument("--out",type=Path,default=Path("results/phase19"))
    a=p.parse_args()
    print(json.dumps(run(a.compose_dir,a.out,a.replica),indent=2))


if __name__=="__main__":
    main()
