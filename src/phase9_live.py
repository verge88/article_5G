"""Phase 9: two signed ACTIVE NFDiscovery polling schedules on actual 5G Core.

Runs a disposable Open5GS/UERANSIM stack. Both poll agents execute from
separate signing processes with different ephemeral Ed25519 keys, but share
the same GitHub runner, administrator and NRF backend. Therefore this
DOES NOT establish independent trust domains or withstand host compromise.

Control trial phases:
 normal -> legitimate unprovisioned DNN -> SMF fail-stop -> recovery.
Live extra NRF requests are sent during the experiment; costs are MEASURED.
No malicious SMF, real-world attacker, or security attack is emulated.
"""
from __future__ import annotations

import argparse
import copy
import csv
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
from collections import Counter

from .phase7_healthy_smf import GOOD, BAD, replace_ue_dnn
from .pdu_lab import state, trial, cmd
from .phase9_receipts import create_ephemeral_key, verify_receipt


def arm_plan(global_index, local_measurement, dnn_is_authorized, remaining):
    """No intervention label, Docker truth or future UE result is inspected."""
    fixed = global_index % 4 == 0
    # A reported legitimate DNN should normally establish a PDU.
    # The UE outcome here is actual UERANSIM evidence, not an attack label.
    adaptive = (remaining > 0 and dnn_is_authorized
                and int(local_measurement["ue_pdu_session_accepted"]) == 0)
    return fixed, adaptive


def live_agent_call(key_path, agent, nonce, trial_id, sequence, endpoint):
    args = [sys.executable, "-m", "src.phase9_receipts",
            "--key", str(key_path), "--agent", agent,
            "--challenge", nonce, "--trial-token", trial_id,
            "--sequence", str(sequence), "--endpoint", endpoint]
    start = time.monotonic()
    process = subprocess.run(args, text=True, capture_output=True, timeout=20)
    elapsed_ms = round(1000*(time.monotonic()-start),3)
    if process.returncode:
        raise RuntimeError("Local evidence-agent process failed: " + process.stderr[-350:])
    return json.loads(process.stdout), elapsed_ms


def negative_verification_tests(receipt, keys, pending_before, max_age=20):
    """Offline alterations to LIVE signed receipts; no network tampering."""
    payload = receipt["payload"]
    tests = {}
    def attempt(other, *, age=0):
        return verify_receipt(
            other, registered_keys=keys,
            pending=pending_before.copy(), accepted_sequences={},
            now=payload["measured_at_unix"]+age,
            max_age_s=max_age)
    altered=copy.deepcopy(receipt)
    altered["payload"]["observation"]["http_status"]=202
    tests["payload_tamper_rejected"]=not attempt(altered)
    altered=copy.deepcopy(receipt)
    altered["payload"]["observation"]["advertised_smf_profiles"]=999
    tests["nrf_profile_forgery_rejected"]=not attempt(altered)
    altered=copy.deepcopy(receipt)
    altered["payload"]["nonce"]=secrets.token_hex(16)
    tests["nonce_substitution_rejected"]=not attempt(altered)
    altered=copy.deepcopy(receipt)
    altered["payload"]["agent_id"]=(
        "nrf_fixed" if payload["agent_id"] == "nrf_adaptive" else "nrf_adaptive")
    tests["wrong_agent_rejected"]=not attempt(altered)
    tests["stale_signed_report_rejected"]=not attempt(receipt,age=60)
    assert all(tests.values()), "A negative crypto test was unexpectedly accepted"
    return tests


def run(compose_dir: Path, out_dir: Path, *, repeats=4,
        endpoint="http://172.22.0.12:7777", normal_timeout=18,
        denial_timeout=13, outage_timeout=12):
    if os.environ.get("ALLOW_PHASE9_DISPOSABLE_5GC") != "yes":
        raise RuntimeError("Isolated laboratory 5G Core authorization guard required")
    if "upstream_open5gs" not in str(compose_dir.resolve()):
        raise RuntimeError("Only the isolated upstream_open5gs lab checkout is supported")
    if repeats != 4:
        raise ValueError("Four trials per phase are registered for equal budget comparison")
    if not all(state(x) for x in ("nrf", "amf", "smf", "upf", "nr_gnb")):
        raise RuntimeError("A genuine NF laboratory core and gNB must be running")
    config=compose_dir/"ueransim"/"ueransim-ue.yaml"
    original=config.read_text(encoding="utf-8")
    if original.count(GOOD)!=1 or BAD in original:
        raise RuntimeError("Required authorized baseline UE DNN configuration absent")
    out_dir.mkdir(parents=True,exist_ok=True)
    measurements, verified, signed, rejected_tests=[], [], [], []
    sequences={"nrf_fixed":0,"nrf_adaptive":0}
    issued={}
    accepted_sequences={}
    plan=[
        ("normal",GOOD,normal_timeout),
        ("invalid_dnn",BAD,denial_timeout),
        ("smf_failstop",GOOD,outage_timeout),
        ("recovery",GOOD,normal_timeout),
    ]
    quota={"nrf_fixed":repeats,"nrf_adaptive":repeats}
    with tempfile.TemporaryDirectory(prefix="phase9_agent_keys_") as temp:
        private_files={a:Path(temp)/f"{a}.pem" for a in quota}
        keys={a:create_ephemeral_key(p) for a,p in private_files.items()}
        try:
            for phase, configured_dnn, timeout in plan:
                config.write_text(replace_ue_dnn(original,configured_dnn),encoding="utf-8")
                if phase=="smf_failstop":
                    cmd(["docker","stop","-t","1","smf"],timeout=20)
                    if state("smf"):
                        raise RuntimeError("Controlled fail-stop failed")
                if phase=="recovery":
                    if not state("smf"):
                        cmd(["docker","start","smf"],timeout=25)
                    time.sleep(12)
                    if not state("smf"):
                        raise RuntimeError("SMF recovery failed")
                for within in range(repeats):
                    idx=len(measurements)
                    observation=trial(compose_dir,phase,within,timeout,1.)
                    healthy=state("smf")
                    data={
                        "trial_token":f"trial_{idx:03d}",
                        "scenario_for_audit_only":phase,
                        "real_ue_pdu_success":int(observation["ue_pdu_session_accepted"]),
                        "real_ue_registered":int(observation["ue_registration_seen"]),
                        "dnn_authorized_from_coordinator":int(configured_dnn==GOOD),
                        "lab_docker_smf_running_audit_only":int(healthy),
                        "nrf_fixed_probed":0,
                        "nrf_adaptive_probed":0,
                    }
                    fixed, adaptive=arm_plan(
                        idx, observation,configured_dnn==GOOD,quota["nrf_adaptive"])
                    for agent, selected in (
                        ("nrf_fixed",fixed),("nrf_adaptive",adaptive)):
                        if not selected: continue
                        if quota[agent]<=0:
                            raise RuntimeError("Exceeded agent's registered live probe budget")
                        sequences[agent]+=1
                        nonce=secrets.token_hex(16)
                        issued[nonce]=(agent,data["trial_token"],sequences[agent])
                        pending_before=issued.copy()
                        envelope, external_wall_ms=live_agent_call(
                            private_files[agent], agent, nonce, data["trial_token"],
                            sequences[agent],endpoint)
                        valid=verify_receipt(
                            envelope,registered_keys=keys,
                            pending=issued,accepted_sequences=accepted_sequences,
                            max_age_s=20.)
                        if not valid:
                            raise RuntimeError("Real signed NRF KIE receipt rejected")
                        # A signed receipt is still potentially a false observation.
                        attacks=negative_verification_tests(
                            envelope,keys,pending_before)
                        accepted_again=verify_receipt(
                            envelope,registered_keys=keys,pending=issued,
                            accepted_sequences=accepted_sequences,max_age_s=20.)
                        attacks["replay_rejected"]=not accepted_again
                        assert attacks["replay_rejected"]
                        for k,v in attacks.items():
                            rejected_tests.append(dict(
                                trial_token=data["trial_token"],agent=agent,
                                check=k,rejected=bool(v)))
                        signed.append(envelope)
                        obs=envelope["payload"]["observation"]
                        verified.append({
                            "trial_token":data["trial_token"],
                            "scenario_for_audit_only":phase,
                            "arm":agent.replace("nrf_",""),
                            "verification":int(valid),
                            "http2":int(obs["http_version"]=="2"),
                            "http_status":obs["http_status"],
                            "advertised_smf_profiles":obs["advertised_smf_profiles"],
                            "http_latency_ms":obs["latency_ms"],
                            "http_response_body_bytes":obs["response_body_bytes"],
                            "agent_elapsed_ms":obs["agent_elapsed_ms"],
                            "end_to_end_agent_process_ms":external_wall_ms,
                            "key_fingerprint":envelope["payload"]["key_id"],
                        })
                        quota[agent]-=1
                        data[f"{agent}_probed"]=1
                    measurements.append(data)
        finally:
            # Every lab mutation is restored, even if crypto/probe gates fail.
            config.write_text(original,encoding="utf-8")
            if not state("smf"):
                cmd(["docker","start","smf"],timeout=25)
        # Secret key material exists only in the temporary directory and
        # is not exported. Public keys are retained for independent checking.
        with (out_dir/"lab_public_agent_keys.json").open("w") as f:
            json.dump(keys,f,indent=2)

    assert len(measurements)==4*repeats
    if any(quota.values()):
        raise RuntimeError(f"Unequal or unspent polling budgets: {quota}")
    for phase in ("normal","recovery"):
        if sum(x["real_ue_pdu_success"] for x in measurements
               if x["scenario_for_audit_only"]==phase) != repeats:
            raise RuntimeError("No fully successful real baseline/recovery UE phase")
    for phase in ("invalid_dnn","smf_failstop"):
        if sum(x["real_ue_pdu_success"] for x in measurements
               if x["scenario_for_audit_only"]==phase) != 0:
            raise RuntimeError("Negative control unexpectedly establishes PDU session")
    if not all(x["lab_docker_smf_running_audit_only"]==1
               for x in measurements if x["scenario_for_audit_only"]!="smf_failstop"):
        raise RuntimeError("SMF not healthy in expected phase")
    if not all(x["lab_docker_smf_running_audit_only"]==0
               for x in measurements if x["scenario_for_audit_only"]=="smf_failstop"):
        raise RuntimeError("SMF not stopped in fail-stop phase")

    for filename,records in (
        ("real_pdu_and_poll_schedule.csv",measurements),
        ("live_nrf_verified_probes.csv",verified),
        ("offline_verification_negative_tests.csv",rejected_tests),
    ):
        with (out_dir/filename).open("w",newline="",encoding="utf-8") as f:
            writer=csv.DictWriter(f,fieldnames=list(records[0]))
            writer.writeheader()
            writer.writerows(records)
    (out_dir/"signed_receipts.jsonl").write_text(
        "".join(json.dumps(r,sort_keys=True)+"\n" for r in signed),encoding="utf-8")

    arm_summary={}
    for arm in ("fixed","adaptive"):
        subset=[p for p in verified if p["arm"]==arm]
        fail=[p for p in subset if p["scenario_for_audit_only"]=="smf_failstop"]
        healthy=[p for p in subset if p["scenario_for_audit_only"]!="smf_failstop"]
        def missing_profile(s):
            # NRF 404 can indicate no matching instances in this lab, but it
            # is NOT proof of an SMF process failure or of compromise.
            return (s["http2"]==1 and (
                (s["http_status"]==200 and s["advertised_smf_profiles"]==0)
                or s["http_status"]==404))
        arm_summary[arm]={
            "actual_live_probes":len(subset),
            "probed_failstop_trials":len(fail),
            "failstop_trials_total":repeats,
            "failstop_registry_absence_observed":sum(missing_profile(s) for s in fail),
            "healthy_trials_probed":len(healthy),
            "healthy_registry_absence_observed":sum(missing_profile(s) for s in healthy),
            "http2_responses":sum(s["http2"] for s in subset),
            "response_body_bytes_downloaded":sum(s["http_response_body_bytes"] for s in subset),
            "sum_curl_http_latency_ms":round(sum(s["http_latency_ms"] for s in subset),3),
            "sum_agent_process_wall_ms":round(sum(s["end_to_end_agent_process_ms"] for s in subset),3),
            "probe_allocation_by_phase":dict(Counter(s["scenario_for_audit_only"] for s in subset)),
        }
    summary={
        "origin":"LIVE Open5GS Nnrf_NFDiscovery and UERANSIM PDU attempts",
        "lab_deployment":"one disposable Docker runner, one administrator",
        "n_real_ue_pdu_trials":len(measurements),
        "n_lab_signature_receipts":len(signed),
        "signature_algorithm":"Ed25519; ephemeral keys for the two polling processes",
        "signature_authenticity":"Agent key possession, NOT true NF integrity or independent trust domains",
        "challenge_and_sequence":"128-bit nonce issued per active poll, per-agent monotone sequence; replay cache",
        "off_network_cryptographic_negative_checks":len(rejected_tests),
        "negative_checks_rejected":sum(t["rejected"] for t in rejected_tests),
        "budget_per_agent":repeats,
        "polling_arms":arm_summary,
        "phases":{p:{"trials":repeats,
                      "successful_pdu":sum(x["real_ue_pdu_success"] for x in measurements
                                           if x["scenario_for_audit_only"]==p)}
                  for p,_,_ in plan},
        "critical_limitations":[
            "The signing agents are subprocesses sharing one GitHub runner, not separate trust domains",
            "Both agents poll the SAME NRF API and cannot offer independent semantic attestation",
            "Keys are ephemeral and created by the coordinating lab process, not an external PKI",
            "Plaintext local NRF SBI; app receipts do not provide standard 3GPP NF authentication",
            "DNN context taken from laboratory coordinator configuration, not independently authenticated subscription",
            "Fixed and adaptive schedules query at different instants; observable registry freshness can differ",
            "The adaptive trigger uses the actual UE result and expected subscription DNN; not an ML attack detector",
            "NF registration absence is not an attack indicator; SMF stop is legitimate controlled outage",
            "Only one run and 4 outage trials; results not suitable for statistical operator-level claims",
            "Request headers and full TCP overhead are not measured; byte count is response payload only",
            "No live malicious modification of an NF or PDU protocol message",
        ],
    }
    (out_dir/"live_summary.json").write_text(
        json.dumps(summary,indent=2,ensure_ascii=False),encoding="utf-8")
    return summary


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--compose-dir",type=Path,default=Path("upstream_open5gs"))
    p.add_argument("--out-dir",type=Path,default=Path("results/phase9"))
    p.add_argument("--repeats",type=int,default=4)
    a=p.parse_args()
    report=run(a.compose_dir,a.out_dir,repeats=a.repeats)
    print(json.dumps(report,indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()
