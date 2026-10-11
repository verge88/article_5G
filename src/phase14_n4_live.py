"""Phase 14 — running SMF and UPF, controlled egress PFCP/N4 interruption.

ONLY ephemeral GitHub-hosted Open5GS lab. Runs read-only capture of the
disposable bridge plus one UDP/8805 OUTPUT rule in SMF network namespace.
Preserves real UE outcomes and never maps failures to a cyberattack label.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from .phase9_receipts import create_ephemeral_key, compact_json, read_private_key, verify_receipt, SCHEMA
from .phase13_probe import SERVICES as PFCP_UPF_SVC
from .pdu_lab import cmd, state, trial
from .phase7_healthy_smf import GOOD, BAD, replace_ue_dnn

PFCP_SVC="Lab_PFCP_Captured_PacketCounts_and_SMFEgressDrop"
ALL_SERVICES=tuple(PFCP_UPF_SVC.values())+(PFCP_SVC,)
PHASES=("normal","n4_pfcp_drop","recovery")
N_TRIALS=4
SMF_DROP=["-p","udp","--dport","8805","-j","DROP"]
DROP_COUNTER_RE=re.compile(r"^\s*(\d+)\s+(\d+)\s+DROP\s+.*\budp\b.*\bdpt:8805\b",re.I|re.M)
MESSAGE_TYPES={"1":"heartbeat_request","2":"heartbeat_response",
               "5":"association_setup_request","6":"association_setup_response",
               "50":"session_establishment_request","51":"session_establishment_response",
               "52":"session_modification_request","53":"session_modification_response",
               "54":"session_deletion_request","55":"session_deletion_response"}


def rule_cmd(pid:int, action:str):
    if action not in ("-C","-I","-D"):
        raise ValueError("Only check, insert, delete PFCP namespace rule")
    flags=["1"] if action=="-I" else []
    return ["sudo","-n","nsenter","-t",str(pid),"-n",
            "iptables",action,"OUTPUT",*flags,*SMF_DROP]


def namespace_pid()->int:
    if not state("smf"):
        raise RuntimeError("SMF must remain running")
    pid=int(cmd(["docker","inspect","-f","{{.State.Pid}}","smf"]))
    if pid<100:
        raise RuntimeError("Invalid SMF namespace PID")
    return pid


def ensure_firewall_supported(pid:int)->None:
    result=subprocess.run(["sudo","-n","nsenter","-t",str(pid),"-n","iptables","-nvx","-L","OUTPUT"],
                          capture_output=True,text=True,timeout=10)
    if result.returncode:
        raise RuntimeError("No sandbox permission to inspect SMF namespace iptables: "+result.stderr[-200:])
    already=subprocess.run(rule_cmd(pid,"-C"),capture_output=True,timeout=10)
    if already.returncode==0:
        raise RuntimeError("An indistinguishable PFCP DROP rule already exists; refusing alteration")


def insert_rule(pid:int)->None:
    ensure_firewall_supported(pid)
    cmd(rule_cmd(pid,"-I"),timeout=12)
    if subprocess.run(rule_cmd(pid,"-C"),capture_output=True,timeout=10).returncode:
        raise RuntimeError("PFCP-only OUTPUT DROP insertion did not hold")


def dropped_packets(pid:int)->int:
    result=cmd(["sudo","-n","nsenter","-t",str(pid),"-n",
                "iptables","-nvx","-L","OUTPUT"],timeout=10)
    m=DROP_COUNTER_RE.search(result)
    if not m:
        raise RuntimeError("Cannot identify SMF PFCP firewall DROP counter")
    return int(m.group(1))


def remove_rule(pid:int)->None:
    p=subprocess.run(rule_cmd(pid,"-C"),capture_output=True,timeout=10)
    if p.returncode==0:
        cmd(rule_cmd(pid,"-D"),timeout=12)
    if subprocess.run(rule_cmd(pid,"-C"),capture_output=True,timeout=10).returncode==0:
        raise RuntimeError("Intervention rule still present; refusing to claim restoration")


def start_capture(pcap:Path)->subprocess.Popen:
    # Host's 'any' covers Docker bridges. Export only derived frame-family counts.
    args=["sudo","-n","tcpdump","-i","any","-n","-s","128","-U",
          "-w",str(pcap),"udp port 8805"]
    proc=subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,
                          start_new_session=True)
    time.sleep(1.5)
    if proc.poll() is not None:
        raise RuntimeError("Passive tcpdump ended before a single real procedure")
    return proc


def end_capture(proc:subprocess.Popen)->None:
    if proc.poll() is None:
        os.killpg(proc.pid,signal.SIGINT)
    try:
        proc.communicate(timeout=14)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid,signal.SIGKILL)
        proc.communicate(timeout=8)


def decode_capture(pcap:Path)->dict:
    if not pcap.exists() or pcap.stat().st_size<24:
        raise RuntimeError("No actual PFCP capture header available")
    p=subprocess.run([
        "tshark","-r",str(pcap),"-d","udp.port==8805,pfcp",
        "-Y","pfcp","-T","fields","-e","pfcp.msg_type"
    ],capture_output=True,text=True,timeout=80)
    if p.returncode:
        raise RuntimeError("Passive PFCP decoder error: "+p.stderr[-350:])
    tokens=[]
    for line in p.stdout.splitlines():
        tokens.extend(s.strip() for s in re.split("[,;]",line) if s.strip())
    by_type=Counter(MESSAGE_TYPES.get(k,"other_type") for k in tokens)
    return {
        "pfcp_decoded_message_occurrences":len(tokens),
        "pfcp_type_occurrences":dict(sorted(by_type.items())),
        "capture_type":"passive genuine N4 UDP 8805 frames; host interface any",
        "capture_caveat":"Frame occurrences (potential capture duplicates), not sessions, associations, or UE causality",
    }


def sign_capture(key:Path,nonce:str,trial_token:str,seq:int,observation:dict)->dict:
    if len(nonce)!=32:
        raise ValueError("Missing random challenge")
    pvt=read_private_key(key)
    pub=pvt.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    doc={
        "schema":SCHEMA,"service":PFCP_SVC,"source_kind":"pfcp_host_capture",
        "agent_id":"phase14_pfcp_host_capture",
        "key_id":hashlib.sha256(pub).hexdigest()[:24],
        "trial_token":trial_token,
        "nonce":nonce,"sequence":seq,
        "timestamp_utc":datetime.now(timezone.utc).isoformat(),
        "measured_at_unix":round(time.time(),3),
        "observation":observation,
    }
    return {"payload":doc,
            "signature_b64":base64.b64encode(pvt.sign(compact_json(doc))).decode()}


def sign_active(source:str,key:Path,nonce:str,token:str,seq:int)->dict:
    args=[sys.executable,"-m","src.phase13_probe","--key",str(key),
          "--agent","phase13_"+source,"--source",source,
          "--challenge",nonce,"--trial-token",token,"--sequence",str(seq)]
    process=subprocess.run(args,text=True,capture_output=True,timeout=18)
    if process.returncode:
        raise RuntimeError("Signed live control source failed: "+process.stderr[-320:])
    return json.loads(process.stdout)


def run(compose_dir:Path,out:Path,replica:str):
    if os.environ.get("ALLOW_PHASE14_DISPOSABLE_5GC")!="yes":
        raise RuntimeError("Explicit isolated 5GC authorization required")
    if "upstream_open5gs" not in str(compose_dir.resolve()) or replica not in ("11","22","33"):
        raise RuntimeError("Unapproved or non-ephemeral laboratory")
    if not all(state(n) for n in ("nrf","amf","smf","upf","nr_gnb")):
        raise RuntimeError("Real Open5GS+UERANSIM lab must be running")
    cfg=compose_dir/"ueransim"/"ueransim-ue.yaml"
    original=cfg.read_text()
    if original.count(GOOD)!=1 or BAD in original:
        raise RuntimeError("Wrong authorized DNN baseline")
    out.mkdir(parents=True,exist_ok=True)
    pid=namespace_pid()
    ensure_firewall_supported(pid)
    summaries,measurements,receipts=[],[],[]
    pending,accepted={},{}
    key_ids={"nrf":"phase13_nrf","upf":"phase13_upf","pfcp_host_capture":"phase14_pfcp_host_capture"}
    inserted=False
    with tempfile.TemporaryDirectory(prefix="phase14_live_signing_keys_") as private_dir:
        keys={s:Path(private_dir)/(s+".pem") for s in key_ids}
        pubs={key_ids[s]:create_ephemeral_key(k) for s,k in keys.items()}
        try:
            for phase_index,phase in enumerate(PHASES):
                cfg.write_text(replace_ue_dnn(original,GOOD))
                if phase=="n4_pfcp_drop":
                    insert_rule(pid)
                    inserted=True
                if phase=="recovery":
                    if inserted:
                        remove_rule(pid)
                        inserted=False
                    # Allow real PFCP peer recovery; no NF container restart.
                    time.sleep(16)
                if not (state("smf") and state("upf")):
                    raise RuntimeError("A running NF exited unexpectedly during N4-only impairment")
                token=f"r{replica}_phase{phase_index}"
                with tempfile.TemporaryDirectory(prefix="phase14_capture_private_") as capture_dir:
                    pcap=Path(capture_dir)/"pfcp.pcap"
                    capture=start_capture(pcap)
                    try:
                        first_drop=dropped_packets(pid) if inserted else 0
                        for i in range(N_TRIALS):
                            ue=trial(compose_dir,phase,i,18 if phase!="n4_pfcp_drop" else 15,1.)
                            if not (state("smf") and state("upf")):
                                raise RuntimeError("Both NF processes must stay alive in every phase")
                            measurements.append({
                                "replica":replica,"phase_AUDIT_ONLY":phase,
                                "trial_index":i,
                                "ue_pdu_success":int(ue["ue_pdu_session_accepted"]),
                                "ue_registered":int(ue["ue_registration_seen"]),
                                "smf_running":int(state("smf")),
                                "upf_running":int(state("upf")),
                                "nrf_smf_profiles_observed_during_ue_window":
                                    ue["nrf_advertised_smf_profiles"],
                                "ue_elapsed_s":ue["elapsed_s"],
                            })
                        time.sleep(3)
                        end_drop=dropped_packets(pid) if inserted else 0
                    finally:
                        end_capture(capture)
                    packet_summary=decode_capture(pcap)
                packet_summary["phase_drop_packets"]=end_drop-first_drop
                packet_summary["firewall_drop_rule_installed"]=bool(inserted)
                # Capture evidence is not an N4 peer assertion. Runtime
                # counters are privileged lab facts from SMF namespace.
                summary={"replica":replica,"phase":phase,
                         "smf_alive":bool(state("smf")),
                         "upf_alive":bool(state("upf")),
                         "n4_udp_8805_drop_counter":end_drop-first_drop,
                         **packet_summary}
                for seq,source in enumerate(("nrf","upf","pfcp_host_capture"),start=1):
                    challenge=secrets.token_hex(16)
                    issuer=key_ids[source]
                    pending[challenge]=(issuer,token,phase_index+1)
                    doc=(sign_capture(keys[source],challenge,token,phase_index+1,summary)
                         if source=="pfcp_host_capture" else
                         sign_active(source,keys[source],challenge,token,phase_index+1))
                    if not verify_receipt(doc,registered_keys=pubs,pending=pending,
                        accepted_sequences=accepted,allowed_services=ALL_SERVICES):
                        raise RuntimeError("An authentic laboratory receipt failed live verification")
                    receipts.append(doc)
                    if source=="nrf":
                        ob=doc["payload"]["observation"]
                        summary["nrf_http_status"]=ob["http_status"]
                        summary["nrf_advertised_smf_profiles"]=ob["advertised_smf_profiles"]
                        summary["nrf_http2"]=ob["http_version"]=="2"
                    if source=="upf":
                        ob=doc["payload"]["observation"]
                        summary["upf_pfcp_socket_present"]=ob["pfcp_udp_8805_socket_present"]
                        summary["upf_namespace_accessible"]=ob["namespace_accessible"]
                summaries.append(summary)
        finally:
            cfg.write_text(original)
            if inserted:
                remove_rule(pid)
                inserted=False
        (out/"public_agent_keys.json").write_text(json.dumps(pubs,indent=2))
    (out/"phase14_real_ue_trials.json").write_text(json.dumps(measurements,indent=2))
    (out/"phase14_pfcp_n4_phase_summary.json").write_text(json.dumps(summaries,indent=2))
    (out/"signed_receipts.jsonl").write_text("".join(json.dumps(d,sort_keys=True)+"\n" for d in receipts))
    report={
        "replica":replica,"n_actual_pdu_attempts":len(measurements),
        "phases":{p:sum(row["ue_pdu_success"] for row in measurements if row["phase_AUDIT_ONLY"]==p)
                  for p in PHASES},
        "captured_packet_occurrences":{x["phase"]:x["pfcp_decoded_message_occurrences"] for x in summaries},
        "n4_drop_packets":next(x["n4_udp_8805_drop_counter"] for x in summaries
                               if x["phase"]=="n4_pfcp_drop"),
        "n_signed_receipts":len(receipts),
        "critical_limits":[
            "Only disposable SMF network namespace egress UDP/8805 is dropped",
            "Both NF containers must remain running and NRF discovery recorded",
            "Passive tshark message counts do not establish per-UE causality",
            "Firewall packet counters are privileged host laboratory oracle",
            "UPF listening socket is not a confirmed live PFCP Association",
            "No cyber intrusion, tampered NF binary, or independent trust domain",
        ],
    }
    (out/"phase14_lab_report.json").write_text(json.dumps(report,indent=2))
    if len(measurements)!=12 or len(receipts)!=9:
        raise RuntimeError("Incomplete actual PDU or signed PFCP evidence")
    if report["phases"]["normal"]!=4 or report["phases"]["recovery"]!=4:
        raise RuntimeError("Real baseline or PFCP recovery did not establish all 4 PDU sessions")
    # Measured negative outcomes are saved even if the hypothesis fails.
    return report


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--compose-dir",type=Path,default=Path("upstream_open5gs"))
    ap.add_argument("--out",type=Path,default=Path("results/phase14"))
    ap.add_argument("--replica",choices=("11","22","33"),required=True)
    a=ap.parse_args()
    print(json.dumps(run(a.compose_dir,a.out,a.replica),indent=2))


if __name__=="__main__":
    main()
