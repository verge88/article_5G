"""Live active probe of the standards-defined NRF discovery service (5G SBI).

This instrument requires a *running* Open5GS NRF endpoint. It does not inject
malformed signalling, manipulate subscriber records, or impersonate an NF.
A KIE is a local measurement record corresponding to one permitted HTTP/2
NFDiscovery GET, not a new standardized 3GPP protocol message.
"""
from __future__ import annotations
import argparse
import csv
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

MARKER = "\n--KIE-METADATA--"


def parse_curl_output(output: str) -> tuple[dict, str]:
    """Return NRF JSON payload and curl metadata; reject corrupt metadata."""
    if MARKER not in output:
        raise ValueError("Missing curl metadata marker")
    body, line = output.rsplit(MARKER, 1)
    pieces = line.strip().split()
    if len(pieces) != 3:
        raise ValueError(f"Invalid curl metadata: {line!r}")
    code, version, seconds = pieces
    info = {
        "http_status": int(code),
        "http_version": version,
        "latency_ms": 1000 * float(seconds),
    }
    try:
        payload = json.loads(body)
    except ValueError:
        payload = {}
    return info, payload


def send_discovery(endpoint: str, target: str, *, timeout=6) -> dict:
    """Query public-lab NRF discovery endpoint with HTTP/2 prior knowledge."""
    query = urlencode({"target-nf-type": target, "requester-nf-type": "AMF"})
    url = f"{endpoint.rstrip('/')}/nnrf-disc/v1/nf-instances?{query}"
    proc = subprocess.run(
        ["curl", "--noproxy", "*", "--http2-prior-knowledge",
         "-sS", "--connect-timeout", "3", "--max-time", str(timeout),
         "-w", MARKER + "%{http_code} %{http_version} %{time_total}\\n", url],
        capture_output=True, text=True, check=False, timeout=timeout + 3,
    )
    if proc.returncode:
        raise RuntimeError(f"curl exit={proc.returncode}: {proc.stderr[-300:]}")
    info, payload = parse_curl_output(proc.stdout)
    profiles = payload.get("nfInstances", []) if isinstance(payload, dict) else []
    info["matched_profiles"] = len(profiles) if isinstance(profiles, list) else 0
    info["target_nf_type"] = target
    # Do not store NRF NFProfile JSON, any identifiers, or network addresses.
    return info


def run(endpoint: str, target: str, path: Path, cycles=30, interval=.15, ready_seconds=120):
    path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + ready_seconds
    while True:
        try:
            info = send_discovery(endpoint, target)
            if info["http_status"] == 200 and info["http_version"] == "2" and info["matched_profiles"] > 0:
                break
        except (ValueError, RuntimeError, subprocess.TimeoutExpired):
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError(f"NRF never returned HTTP/2 200 with a registered {target} profile")
        time.sleep(3)
    data = []
    for i in range(cycles):
        stamp = datetime.now(timezone.utc).isoformat()
        try:
            info = send_discovery(endpoint, target)
            info["probe_success"] = int(
                info["http_status"] == 200 and info["http_version"] == "2" and info["matched_profiles"] > 0
            )
        except (ValueError, RuntimeError, subprocess.TimeoutExpired) as e:
            info = dict(http_status=0, http_version="error", latency_ms=0,
                        matched_profiles=0, target_nf_type=target, probe_success=0,
                        error_type=type(e).__name__)
        data.append(dict(kie_sequence=i, timestamp_utc=stamp, **info))
        time.sleep(interval)
    columns = ["kie_sequence", "timestamp_utc", "target_nf_type", "http_status",
               "http_version", "latency_ms", "matched_profiles", "probe_success", "error_type"]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(data)
    successes = sum(row["probe_success"] for row in data)
    latency = sorted(row["latency_ms"] for row in data if row["probe_success"])
    summary = dict(
        evidence_type="live HTTP/2 NRF discovery response",
        implementation="Open5GS (container lab)", operation="Nnrf_NFDiscovery GET",
        target_nf_type=target, n=len(data), success_count=successes,
        success_rate=successes / len(data) if data else None,
        p50_latency_ms=latency[len(latency) // 2] if latency else None,
        p95_latency_ms=latency[min(len(latency) - 1, int(.95 * len(latency)))] if latency else None,
        limitation="Does not exercise PDU-session setup, compromised SMF, or independent semantic verification.",
    )
    (path.parent / "real_sbi_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    if successes < max(8, int(.8 * cycles)):
        raise RuntimeError(f"Only {successes}/{cycles} standards-based discovery probes succeeded")
    return summary


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--endpoint", default="http://172.22.0.12:7777")
    p.add_argument("--target", default="AUSF")
    p.add_argument("--cycles", type=int, default=30)
    p.add_argument("--interval", type=float, default=.15)
    p.add_argument("--ready-seconds", type=int, default=120)
    p.add_argument("--out", type=Path, default=Path("results/real_sbi_probes.csv"))
    a = p.parse_args()
    print(json.dumps(run(a.endpoint, a.target, a.out,
                         a.cycles, a.interval, a.ready_seconds), indent=2))


if __name__ == "__main__":
    main()
