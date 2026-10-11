"""Controlled *fail-stop* consistency experiment with a real Open5GS AUSF.

Never run this against production infrastructure: it intentionally SIGKILLs
the lab's AUSF container. Guarded by an explicit lab-only environment flag.
NRF HTTP/2 discovery (service report) is compared with the independent Docker
process-state witness. A crash is NOT a simulated stealth cyber-compromise.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from .real_sbi import send_discovery


def docker(args):
    cmd = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=10)
    if cmd.returncode:
        raise RuntimeError("docker command failed: " + (cmd.stderr or cmd.stdout)[-300:])
    return cmd.stdout.strip()


def get_ausf_running():
    return docker(["inspect", "-f", "{{.State.Running}}", "ausf"]).lower() == "true"


def record_discovery(endpoint, *, phase, t0):
    witness_up = get_ausf_running()
    try:
        sample = send_discovery(endpoint, "AUSF", timeout=3)
    except (RuntimeError, ValueError, subprocess.TimeoutExpired) as e:
        sample = dict(http_status=0, http_version="error", latency_ms=None,
                      matched_profiles=0, error_type=type(e).__name__)
    advertised = bool(sample["http_status"] == 200 and sample["matched_profiles"] > 0)
    return dict(
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        elapsed_seconds=round(time.monotonic() - t0, 4),
        phase=phase,
        witness_ausf_running=int(witness_up),
        nrf_advertises_ausf=int(advertised),
        witness_nrf_disagreement=int(witness_up != advertised),
        http_status=sample["http_status"],
        http_version=sample["http_version"],
        matched_profiles=sample["matched_profiles"],
        latency_ms=sample["latency_ms"],
        error_type=sample.get("error_type", ""),
    )


def run(endpoint: str, out: Path, down_seconds=12, recovery_seconds=12, interval=.3):
    if os.environ.get("ALLOW_KILL_AUSF_IN_ISOLATED_LAB") != "yes":
        raise RuntimeError("Requires explicit lab-only flag; never operate on production")
    if docker(["inspect", "-f", "{{.Config.Image}}", "ausf"]) not in ("docker_open5gs", "docker_open5gs:latest"):
        raise RuntimeError("Target is not the explicitly expected local Open5GS lab container")
    if not get_ausf_running():
        raise RuntimeError("AUSF must be running before the controlled fault")
    first = send_discovery(endpoint, "AUSF")
    if first["http_status"] != 200 or first["matched_profiles"] == 0:
        raise RuntimeError("AUSF must be registered before inducing fault")
    records = []
    t0 = time.monotonic()
    records.append(record_discovery(endpoint, phase="pre_fault", t0=t0))
    try:
        # Abrupt process stop prevents an orderly NF deregistration message.
        docker(["kill", "--signal=KILL", "ausf"])
        if get_ausf_running():
            raise RuntimeError("AUSF did not enter stopped state")
        end = time.monotonic() + down_seconds
        while time.monotonic() < end:
            records.append(record_discovery(endpoint, phase="stopped", t0=t0))
            time.sleep(interval)
    finally:
        # Always restore the laboratory service, even if probing fails.
        if not get_ausf_running():
            docker(["start", "ausf"])
    end = time.monotonic() + recovery_seconds
    while time.monotonic() < end:
        records.append(record_discovery(endpoint, phase="recovery", t0=t0))
        time.sleep(interval)
    out.parent.mkdir(parents=True, exist_ok=True)
    columns = ["timestamp_utc", "elapsed_seconds", "phase",
               "witness_ausf_running", "nrf_advertises_ausf",
               "witness_nrf_disagreement", "http_status",
               "http_version", "matched_profiles", "latency_ms", "error_type"]
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(records)
    stopped = [r for r in records if r["phase"] == "stopped"]
    recovered = [r for r in records if r["phase"] == "recovery"]
    mismatches = [r for r in stopped if r["witness_nrf_disagreement"]]
    summary = {
        "experiment": "controlled fail-stop of AUSF (not compromised SMF)",
        "witness": "Docker container State.Running (lab infrastructure ground truth)",
        "service_observation": "actual HTTP/2 NRF discovery",
        "n_pre_fault": 1,
        "n_stopped": len(stopped),
        "n_recovery": len(recovered),
        "stopped_process_confirmed_samples": sum(not r["witness_ausf_running"] for r in stopped),
        "stale_nrf_advertisement_count": len(mismatches),
        "stale_nrf_fraction": len(mismatches) / len(stopped) if stopped else None,
        "first_stale_observed_seconds_after_fault": (
            mismatches[0]["elapsed_seconds"] if mismatches else None),
        "nf_advertised_on_last_recovery_sample": bool(
            recovered[-1]["nrf_advertises_ausf"]) if recovered else None,
        "limitations": [
            "An abrupt process stop is not an intentional stealth compromise.",
            "Docker process state is a privileged independent observer, not an available 3GPP NF trust anchor.",
            "SBI NF discovery caching and heartbeat timings depend on this exact lab build.",
        ],
    }
    (out.parent / "real_fault_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    if not stopped or not all(not r["witness_ausf_running"] for r in stopped):
        raise RuntimeError("Induced fail-stop was not independently confirmed")
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", default="http://172.22.0.12:7777")
    parser.add_argument("--out", type=Path, default=Path("results/real_fault_probes.csv"))
    parser.add_argument("--down-seconds", type=float, default=12)
    parser.add_argument("--recovery-seconds", type=float, default=12)
    a = parser.parse_args()
    print(json.dumps(run(a.endpoint, a.out, a.down_seconds, a.recovery_seconds), indent=2))


if __name__ == "__main__":
    main()
