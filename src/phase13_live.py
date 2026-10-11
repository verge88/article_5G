"""Phase 13: ACTUAL NRF/UPF active observations on three throwaway 5G Cores.

The UPF PFCP socket probe uses privileged docker exec and is not
cryptographic UPF NF attestation or a deployable independent trust source.
Never interpret lab fail-stop as an adversarial intrusion.
"""
from __future__ import annotations
import argparse
import csv
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

from .pdu_lab import cmd, state, trial
from .phase7_healthy_smf import GOOD, BAD, replace_ue_dnn
from .phase9_receipts import create_ephemeral_key, verify_receipt
from .phase13_probe import SERVICES
from .phase13_policy import ARMS, BUDGET, Chooser, N_TRIALS

PLANS={
    "11":("normal","upf_failstop","recovery_upf","smf_failstop","recovery_smf"),
    "22":("normal","smf_failstop","recovery_smf","upf_failstop","recovery_upf"),
    "33":("upf_failstop","recovery_upf","normal","smf_failstop","recovery_smf"),
}
AGENTS={a:"phase13_"+a for a in ARMS}


def active_probe(key:Path,agent:str,source:str,nonce:str,token:str,seq:int):
    args=[sys.executable,"-m","src.phase13_probe","--key",str(key),
          "--agent",agent,"--source",source,"--challenge",nonce,
          "--trial-token",token,"--sequence",str(seq)]
    t=time.monotonic()
    proc=subprocess.run(args,capture_output=True,text=True,timeout=18)
    duration=round(1000*(time.monotonic()-t),3)
    if proc.returncode:
        raise RuntimeError("Live signed evidence agent failed: "+proc.stderr[-350:])
    return json.loads(proc.stdout),duration


def absence_from_receipt(payload:dict)->bool|None:
    obs=payload["observation"]
    if payload["source_kind"]=="nrf":
        if obs["http_version"]=="2" and obs["http_status"]==200:
            return bool(obs["advertised_smf_profiles"]==0)
        if obs["http_version"]=="2" and obs["http_status"]==404:
            return True
        return None
    # PRIVILEGED Docker runtime oracle, NOT UPF socket evidence.
    runtime=obs["docker_runtime_running_privileged_lab_only"]
    if runtime is False:return True
    if runtime is True:
        if obs["namespace_accessible"] and obs["pfcp_udp_8805_socket_present"] is not None:
            return not obs["pfcp_udp_8805_socket_present"]
        return None
    return None


def run(compose_dir:Path,out:Path,replica:str)->dict:
    if os.environ.get("ALLOW_PHASE13_LAB_ONLY")!="yes":
        raise RuntimeError("Explicit disposable 5GC authorization required")
    if replica not in PLANS or "upstream_open5gs" not in str(compose_dir.resolve()):
        raise RuntimeError("Only approved isolated lab repo and preregistered plans")
    if not all(state(s) for s in ("smf","upf","nrf","amf","nr_gnb")):
        raise RuntimeError("Real 5G Core plus gNB not up")
    config=compose_dir/"ueransim"/"ueransim-ue.yaml"
    original=config.read_text()
    if original.count(GOOD)!=1 or BAD in original:
        raise RuntimeError("Incorrect initial subscriber DNN configuration")
    out.mkdir(parents=True,exist_ok=True)
    chooser=Chooser()
    sequences={a:0 for a in ARMS}
    pending,accepted={},{}
    trials,queries,receipts=[],[],[]
    phase_names=PLANS[replica]
    with tempfile.TemporaryDirectory(prefix="phase13_private_keys_") as temporary:
        private={a:Path(temporary)/(a+".pem") for a in ARMS}
        public={AGENTS[a]:create_ephemeral_key(private[a]) for a in ARMS}
        try:
            for phase in phase_names:
                config.write_text(replace_ue_dnn(original,GOOD))
                if not state("smf"):
                    cmd(["docker","start","smf"],timeout=25)
                    time.sleep(18)
                if not state("upf"):
                    cmd(["docker","start","upf"],timeout=25)
                    time.sleep(24)
                if phase=="smf_failstop":
                    cmd(["docker","stop","-t","1","smf"],timeout=20)
                if phase=="upf_failstop":
                    cmd(["docker","stop","-t","1","upf"],timeout=20)
                assert state("smf")==(phase!="smf_failstop")
                assert state("upf")==(phase!="upf_failstop")
                for i in range(4):
                    index=len(trials)
                    timeout=18 if phase in ("normal","recovery_upf","recovery_smf") else 12
                    rec=trial(compose_dir,phase,i,timeout,1.)
                    good=int(rec["ue_pdu_session_accepted"])
                    select=chooser.decide(good,1)
                    token=f"r{replica}_t{index:03d}"
                    row={
                        "replica":replica,"token":token,
                        "trial_index":index,"audit_phase_NOT_policy_input":phase,
                        "real_pdu_success":good,
                        "real_ue_registered":int(rec["ue_registration_seen"]),
                        "smf_docker_running_AUDIT_ONLY":int(state("smf")),
                        "upf_docker_running_AUDIT_ONLY":int(state("upf")),
                        "UE_elapsed_seconds":rec["elapsed_s"],
                        "online_failure_episode":chooser.current_episode,
                        "number_kie_queries":len(select),
                        **{f"selected_{a}":int(a in select) for a in ARMS},
                    }
                    for a,source in select.items():
                        sequences[a]+=1
                        nonce=secrets.token_hex(16)
                        agent=AGENTS[a]
                        pending[nonce]=(agent,token,sequences[a])
                        receipt,process_ms=active_probe(private[a],agent,source,nonce,token,sequences[a])
                        if not verify_receipt(receipt,registered_keys=public,
                            pending=pending,accepted_sequences=accepted,
                            allowed_services=tuple(SERVICES.values())):
                            raise RuntimeError("Real signed dual-source observation failed verification")
                        obs=receipt["payload"]["observation"]
                        absence=absence_from_receipt(receipt["payload"])
                        if a=="information":
                            chooser.observe_information(source,absence)
                        queries.append({
                            "replica":replica,"token":token,"arm":a,
                            "audit_phase_NOT_policy_input":phase,
                            "source":source,"signed_service":receipt["payload"]["service"],
                            "confirmed_signature":1,
                            "observation_absence_WITH_LAB_ORACLE":
                                "unknown" if absence is None else int(absence),
                            "nrf_smf_profiles":obs.get("advertised_smf_profiles",-1),
                            "nrf_http_status":obs.get("http_status",0),
                            "nrf_http2":int(obs.get("http_version","")=="2"),
                            "UPF_namespace_accessible":obs.get("namespace_accessible",""),
                            "UPF_PFCP_udp8805_socket_present":
                                obs.get("pfcp_udp_8805_socket_present",""),
                            "UPF_docker_runtime_privileged_only":
                                obs.get("docker_runtime_running_privileged_lab_only",""),
                            "body_bytes_only":obs.get("response_body_bytes",0),
                            "source_measured_ms":obs.get("latency_ms",
                                obs.get("probe_elapsed_ms",0.)),
                            "agent_process_wall_ms":process_ms,
                            "nonce":nonce,"sequence":sequences[a],
                            "key_id":receipt["payload"]["key_id"],
                        })
                        receipts.append(receipt)
                    trials.append(row)
        finally:
            config.write_text(original)
            if not state("smf"):
                cmd(["docker","start","smf"],timeout=25)
            if not state("upf"):
                cmd(["docker","start","upf"],timeout=25)
        (out/"public_agent_keys.json").write_text(json.dumps(public,indent=2))

    def write_csv(name,items):
        if not items:return
        with (out/name).open("w",newline="",encoding="utf-8") as handle:
            writer=csv.DictWriter(handle,fieldnames=items[0].keys())
            writer.writeheader()
            writer.writerows(items)
    write_csv("real_pdu_trials.csv",trials)
    write_csv("real_kie_queries.csv",queries)
    (out/"signed_receipts.jsonl").write_text(
        "".join(json.dumps(x,sort_keys=True)+"\n" for x in receipts))
    phase_summary={phase:{
        "real_attempts":4,
        "observed_pdu_successes":sum(int(t["real_pdu_success"]) for t in trials if t["audit_phase_NOT_policy_input"]==phase),
    } for phase in phase_names}
    arm_summary={a:{
        "actual_queries":sum(q["arm"]==a for q in queries),
        "NRF_queries":sum(q["arm"]==a and q["source"]=="nrf" for q in queries),
        "UPF_queries":sum(q["arm"]==a and q["source"]=="upf" for q in queries),
        "SMF_stop_queries":sum(q["arm"]==a and q["audit_phase_NOT_policy_input"]=="smf_failstop" for q in queries),
        "UPF_stop_queries":sum(q["arm"]==a and q["audit_phase_NOT_policy_input"]=="upf_failstop" for q in queries),
    } for a in ARMS}
    report={
        "replica":replica,"source":"actual Open5GS UERANSIM PDU and real signed NRF/UPF namespace probes",
        "n_real_pdu_trials":len(trials),"phases":phase_summary,
        "n_actual_control_probes":len(queries),"n_signed_receipts":len(receipts),
        "online_failure_episodes":chooser.current_episode,
        "remaining_budget":chooser.remaining,"arms":arm_summary,
        "limitation":"UPF Docker runtime is privileged lab oracle, NOT independent NF/PFCP attestation",
    }
    (out/"real_summary.json").write_text(json.dumps(report,indent=2))
    if len(trials)!=N_TRIALS or chooser.current_episode!=2 or any(chooser.remaining.values()):
        raise RuntimeError("Two real UE failure episodes and equal real control budgets not obtained")
    if phase_summary["normal"]["observed_pdu_successes"]!=4 or any(
        phase_summary[p]["observed_pdu_successes"]!=4 for p in ("recovery_upf","recovery_smf")):
        raise RuntimeError("Recovery or baseline invalid, retain original measurements without claims")
    if any(phase_summary[p]["observed_pdu_successes"] for p in ("smf_failstop","upf_failstop")):
        raise RuntimeError("UPF or SMF controlled fault did not produce observed PDU failure")
    return report


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--replica",required=True,choices=tuple(PLANS))
    p.add_argument("--compose-dir",type=Path,default=Path("upstream_open5gs"))
    p.add_argument("--out",type=Path,default=Path("results/phase13"))
    a=p.parse_args()
    print(json.dumps(run(a.compose_dir,a.out,a.replica),indent=2))


if __name__=="__main__":
    main()
