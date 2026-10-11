"""Controlled repeated UE/PDU trials on a running Docker Open5GS + UERANSIM lab.

Actual outputs are observed from UERANSIM and independent Open5GS NF logs.
No attack is emulated: fail-stop is a controlled infrastructure fault.
This is not an operator network and no subscriber/user traffic is exported.
"""
from __future__ import annotations
import argparse
import csv
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from .real_sbi import send_discovery

SUCCESS_PAT = re.compile(
    r"PDU Session establishment is successful|PDU session establishment is successful"
    r"|PDU Session Establishment Accept|PDU Session established|PDU session established",
    re.IGNORECASE,
)
REG_PAT = re.compile(r"Registration is successful|Registration Accept|registered successfully", re.IGNORECASE)
SMF_PAT = re.compile(r"nsmf.pdusession|sm.context|pdu.session", re.IGNORECASE)
CANDIDATE_PAT = re.compile(r"nsmf.pdusession|sm.context|pdu.session|PFCP", re.IGNORECASE)


def cmd(argv, *, cwd=None, timeout=30, check=True):
    p = subprocess.run(argv, cwd=cwd, timeout=timeout, capture_output=True, text=True)
    if check and p.returncode:
        raise RuntimeError(f"{argv[0]} returned {p.returncode}: {p.stderr[-450:]}")
    return p.stdout.strip()


def state(name):
    return cmd(["docker", "inspect", "-f", "{{.State.Running}}", name], timeout=10) == "true"


def docker_logs(name, *, since):
    # Logs stay local: only aggregated counters are published in GitHub artifacts.
    return cmd(["docker", "logs", "--since", since, name], timeout=20, check=False)


def discovery_smf():
    try:
        result = send_discovery("http://172.22.0.12:7777", "SMF")
        return result["matched_profiles"] if result["http_status"] == 200 else -1
    except (ValueError, RuntimeError, subprocess.TimeoutExpired):
        return -1


def trial(compose_dir, phase, index, timeout_s, poll_s):
    if state("nr_ue"):
        cmd(["docker", "stop", "-t", "2", "nr_ue"], timeout=15)
    # Restarting the UE creates another lab procedure; upstream image starts
    # nr-ue under bash. --force-recreate gives a fresh log window.
    start = datetime.now(timezone.utc)
    ts = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    cmd(["docker", "compose", "-f", "nr-ue.yaml", "up", "-d", "--force-recreate", "nr_ue"],
        cwd=compose_dir, timeout=90)
    started = time.monotonic()
    ue_success_at = None
    registration = False
    observed = ""
    while time.monotonic() - started < timeout_s:
        observed = docker_logs("nr_ue", since=ts)
        if REG_PAT.search(observed):
            registration = True
        if SUCCESS_PAT.search(observed):
            ue_success_at = time.monotonic() - started
            break
        time.sleep(poll_s)
    # Independently inspect every producer, not just a single self-report.
    elapsed = time.monotonic() - started
    smf_state = state("smf")
    upf_state = state("upf")
    amf_state = state("amf")
    nrf_profiles = discovery_smf()
    amf_text = docker_logs("amf", since=ts)
    smf_text = docker_logs("smf", since=ts)
    upf_text = docker_logs("upf", since=ts)
    # Don't publish raw logs; they can contain identifiers and security data.
    record = {
        "phase": phase,
        "trial": index,
        "started_utc": start.isoformat(),
        "elapsed_s": round(elapsed, 3),
        "ue_registration_seen": int(registration),
        "ue_pdu_session_accepted": int(ue_success_at is not None),
        "ue_pdu_time_s": round(ue_success_at, 3) if ue_success_at is not None else None,
        "smf_running_witness": int(smf_state),
        "upf_running_witness": int(upf_state),
        "amf_running_witness": int(amf_state),
        "nrf_advertised_smf_profiles": nrf_profiles,
        "nrf_smf_disagreement": int(nrf_profiles > 0 and not smf_state),
        "reported_available_but_pdu_failed": int(nrf_profiles > 0 and ue_success_at is None),
        "amf_sm_context_log_lines": sum(bool(SMF_PAT.search(x)) for x in amf_text.splitlines()),
        "smf_sm_context_log_lines": sum(bool(SMF_PAT.search(x)) for x in smf_text.splitlines()),
        "smf_pdu_pfcp_log_lines": sum(bool(CANDIDATE_PAT.search(x)) for x in smf_text.splitlines()),
        "upf_pfcp_log_lines": sum("PFCP" in x.upper() for x in upf_text.splitlines()),
        "ue_log_lines": len(observed.splitlines()),
    }
    cmd(["docker", "stop", "-t", "2", "nr_ue"], timeout=15)
    time.sleep(2)
    return record


def run(compose_dir, out_dir, *, repeats=3, normal_timeout=45,
        failure_timeout=20, probe_interval=2):
    if os.environ.get("ALLOW_LAB_ONLY_SMF_FAILURE") != "yes":
        raise RuntimeError("Refusing fault injection without explicit isolated-lab guard")
    if "upstream_open5gs" not in str(compose_dir.resolve()):
        raise RuntimeError("Only an upstream_open5gs isolated checkout can be used")
    out_dir.mkdir(parents=True, exist_ok=True)
    if not all(state(n) for n in ("nrf", "smf", "amf", "upf", "nr_gnb")):
        raise RuntimeError("5GC + gNB must be running before trial")
    rows = []
    try:
        for i in range(repeats):
            rows.append(trial(compose_dir, "normal", i, normal_timeout, probe_interval))
        cmd(["docker", "stop", "-t", "1", "smf"], timeout=20)
        if state("smf"):
            raise RuntimeError("SMF is unexpectedly still running")
        for i in range(repeats):
            rows.append(trial(compose_dir, "smf_failstop", i, failure_timeout, probe_interval))
    finally:
        if not state("smf"):
            cmd(["docker", "start", "smf"], timeout=25)
    # Allow SF registration and UPF association after recovery.
    time.sleep(12)
    for i in range(repeats):
        rows.append(trial(compose_dir, "recovery", i, normal_timeout, probe_interval))
    fields = list(rows[0])
    with (out_dir / "pdu_trials.csv").open("w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    summary = {"source": "actual Open5GS + UERANSIM Docker lab",
               "scenario": "repeated baseline, fail-stop, recovery",
               "repeats": repeats, "n": len(rows), "phases": {},
               "trust": "Docker runtime, UE logs, AMF and SMF logs, and NRF discovery",
               "labels": "fault phase assigned by controlled Docker SMF stop, not a malicious compromise",
               "limitations": [
                   "One node, one simulated subscriber and small repeat count",
                   "No confirmed adversarial false reporting or compromised trust domain",
                   "Success is inferred from UERANSIM log messages; HTTP/2 Nsmf packet evidence checked separately",
                   "A failed PDU attempt is not evidence of cyber compromise",
               ]}
    for phase in ("normal", "smf_failstop", "recovery"):
        rr = [x for x in rows if x["phase"] == phase]
        summary["phases"][phase] = {
            "n": len(rr),
            "registered_ue_count": sum(x["ue_registration_seen"] for x in rr),
            "pdu_success_count": sum(x["ue_pdu_session_accepted"] for x in rr),
            "amf_sm_context_lines": sum(x["amf_sm_context_log_lines"] for x in rr),
            "smf_sm_context_lines": sum(x["smf_sm_context_log_lines"] for x in rr),
            "nrf_stale_count": sum(x["nrf_smf_disagreement"] for x in rr),
        }
    (out_dir / "pdu_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    # Scientific success gate: require at least one real successful baseline PDU
    # procedure, otherwise there is no empirical validity for the PDU claim.
    if summary["phases"]["normal"]["pdu_success_count"] < 1:
        raise RuntimeError("No real UE PDU session acceptance seen in baseline; reject run")
    if summary["phases"]["smf_failstop"]["pdu_success_count"] != 0:
        raise RuntimeError("PDU succeeded in purported fail-stop; reject fault protocol")
    if summary["phases"]["recovery"]["pdu_success_count"] < 1:
        raise RuntimeError("PDU recovery not established; outcome incomplete")
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--compose-dir", type=Path, default=Path("upstream_open5gs"))
    ap.add_argument("--out-dir", type=Path, default=Path("results/phase3"))
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--normal-timeout", type=float, default=45)
    ap.add_argument("--failure-timeout", type=float, default=20)
    a = ap.parse_args()
    print(json.dumps(run(a.compose_dir, a.out_dir, repeats=a.repeats,
                         normal_timeout=a.normal_timeout,
                         failure_timeout=a.failure_timeout),
                     indent=2))


if __name__ == "__main__":
    main()
