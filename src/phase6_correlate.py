"""Privacy-preserving HTTP/2 request/response time-window association.

Evidence is captured from actual Open5GS SBA traffic. HTTP/2 stream IDs
identify request-response exchanges within TCP connections, NOT the 3GPP
PDU-procedure ID or a globally unique identifier across UE, AMF, SMF.
The mapping to UE trials is by non-overlapping UTC observation windows.
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import subprocess
from pathlib import Path

import pandas as pd

COLUMNS = ("epoch", "tcp", "http2_stream", "path", "method", "status")


def decode_rows(raw: str) -> list[dict]:
    """Parse tab-delimited tshark -T fields -E occurrence=f output."""
    frames = []
    for line in raw.splitlines():
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 6:
            continue
        epoch, tcp, stream, path, method, status = parts[:6]
        if not epoch or not tcp or not stream:
            continue
        try:
            when = float(epoch)
        except ValueError:
            continue
        if not (path or status):
            continue
        frames.append(dict(
            epoch=when, tcp=tcp, http2_stream=stream,
            family="nsmf-pdusession" if "nsmf-pdusession" in path.lower() else "other",
            has_path=bool(path),
            method=method.strip().upper()[:12],
            status=int(status.strip()) if status.strip().isdigit() else None,
        ))
    return frames


def extraction(pcap: Path) -> list[dict]:
    command = [
        "tshark", "-r", str(pcap), "-d", "tcp.port==7777,http2",
        "-Y", "http2.headers.path || http2.headers.status",
        "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f",
        "-e", "frame.time_epoch", "-e", "tcp.stream",
        "-e", "http2.streamid", "-e", "http2.headers.path",
        "-e", "http2.headers.method", "-e", "http2.headers.status",
    ]
    p = subprocess.run(command, capture_output=True, text=True, timeout=135)
    if p.returncode:
        raise RuntimeError("HTTP/2 tshark decode failed: " + p.stderr[-450:])
    result = decode_rows(p.stdout)
    if not result:
        raise RuntimeError("No HTTP/2 request/response fields decoded")
    return result


def associate(frames: list[dict], trials: pd.DataFrame):
    necessary = {"phase", "trial", "window_start_epoch", "window_end_epoch",
                 "ue_pdu_session_accepted", "ue_registration_seen", "smf_running_witness"}
    if necessary - set(trials.columns):
        raise ValueError(f"Missing measured window data: {sorted(necessary - set(trials.columns))}")
    windows = trials.sort_values("window_start_epoch").to_dict("records")
    for a, b in zip(windows, windows[1:]):
        if float(a["window_end_epoch"]) >= float(b["window_start_epoch"]):
            raise ValueError("Temporal windows overlap, cannot attribute packets")

    # Each HTTP/2 logical stream can be represented by duplicate packets in
    # a host 'any' capture. Deduplicate by TCP conversation and stream ID.
    request_map = {}
    responses = {}
    for fr in frames:
        key = (fr["tcp"], fr["http2_stream"])
        if fr["has_path"] and fr["family"] == "nsmf-pdusession":
            if key not in request_map or fr["epoch"] < request_map[key]["epoch"]:
                request_map[key] = fr
        if fr["status"] is not None:
            responses.setdefault(key, []).append(fr)

    per = []
    all_windows = 0
    unassigned = 0
    for key, req in request_map.items():
        n_windows = sum(float(w["window_start_epoch"]) <= req["epoch"] <= float(w["window_end_epoch"]) for w in windows)
        if n_windows == 0:
            unassigned += 1
        elif n_windows == 1:
            all_windows += 1
        else:
            raise ValueError("Request matches more than one window")

    for w in windows:
        begin, end = float(w["window_start_epoch"]), float(w["window_end_epoch"])
        requests = [(key, req) for key, req in request_map.items() if begin <= req["epoch"] <= end]
        codes = []
        latencies = []
        paired = 0
        first_offset = None
        last_response_offset = None
        for key, req in requests:
            offset = req["epoch"] - begin
            first_offset = offset if first_offset is None else min(first_offset, offset)
            good = sorted((p for p in responses.get(key, []) if
                           p["epoch"] >= req["epoch"] - 0.001),
                          key=lambda p: p["epoch"])
            if good:
                paired += 1
                reply = good[0]
                codes.append(reply["status"])
                latency = max(0., 1000 * (reply["epoch"] - req["epoch"]))
                latencies.append(latency)
                offset_reply = reply["epoch"] - begin
                last_response_offset = (offset_reply if last_response_offset is None
                                        else max(last_response_offset, offset_reply))
        per.append({
            "phase": str(w["phase"]),
            "trial": int(w["trial"]),
            "ue_pdu_success": int(w["ue_pdu_session_accepted"]),
            "ue_registered": int(w["ue_registration_seen"]),
            "smf_running": int(w["smf_running_witness"]),
            "trial_duration_s": round(end - begin, 3),
            "nsmf_unique_request_streams": len(requests),
            "nsmf_paired_response_streams": paired,
            "nsmf_unanswered_streams": len(requests) - paired,
            "nsmf_status_2xx": sum(200 <= s < 300 for s in codes),
            "nsmf_status_4xx": sum(400 <= s < 500 for s in codes),
            "nsmf_status_5xx": sum(500 <= s < 600 for s in codes),
            "nsmf_first_request_offset_s": (round(first_offset, 4) if first_offset is not None else None),
            "nsmf_last_response_offset_s": (round(last_response_offset, 4) if last_response_offset is not None else None),
            "nsmf_median_response_ms": (round(statistics.median(latencies), 3) if latencies else None),
            "nsmf_evidence_present": int(bool(requests)),
        })
    if not per:
        raise ValueError("No real UE windows")
    return pd.DataFrame(per), {
        "all_nsmf_unique_request_streams": len(request_map),
        "nsmf_requests_attributed_to_one_window": all_windows,
        "nsmf_requests_outside_trials": unassigned,
        "unattributed_fraction": unassigned / len(request_map) if request_map else None,
    }


def run(pcap: Path, trials_path: Path, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    frames = extraction(pcap)
    windows = pd.read_csv(trials_path)
    data, coverage = associate(frames, windows)
    data.to_csv(out / "real_pdu_sbi_correlated.csv", index=False)
    summaries = {}
    for phase, group in data.groupby("phase", sort=False):
        summaries[phase] = {
            "n_trials": len(group),
            "ue_pdu_successes": int(group.ue_pdu_success.sum()),
            "with_nsmf_request": int(group.nsmf_evidence_present.sum()),
            "request_streams": int(group.nsmf_unique_request_streams.sum()),
            "response_streams": int(group.nsmf_paired_response_streams.sum()),
            "http_2xx": int(group.nsmf_status_2xx.sum()),
        }
    total = int(data.nsmf_unique_request_streams.sum())
    output = {
        "type": "Real HTTP/2 logical stream correlation within UERANSIM trial time windows",
        "scope": "Open5GS+UERANSIM; observation, not simulated malicious SMF",
        "n_trials": len(data),
        "nsmf_streams_attributed": total,
        "nsmf_streams_response_observed": int(data.nsmf_paired_response_streams.sum()),
        "stream_response_pairing_rate": float(data.nsmf_paired_response_streams.sum()/total) if total else None,
        "phases": summaries,
        "coverage": coverage,
        "limitations": [
            "No standardized end-to-end PDU correlation token linking UE NAS event to Nsmf stream",
            "Time-window association only; windows include UE lifecycle operations",
            "Host any-interface capture may repeat transport frames and miss reassembled traffic",
            "HTTP/2 stream ID is unique only within a TCP connection",
            "Multiple HTTP/2 streams can belong to one PDU attempt; do not treat streams as sessions",
            "No deliberate protocol-semantic compromise was performed",
        ],
    }
    (out / "real_sbi_correlated_summary.json").write_text(
        json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    if not total:
        raise RuntimeError("No Nsmf streams linked to real UE trial windows")
    if summaries.get("normal", {}).get("with_nsmf_request", 0) == 0:
        raise RuntimeError("No Nsmf traffic associated with normal UE trials")
    if summaries.get("recovery", {}).get("with_nsmf_request", 0) == 0:
        raise RuntimeError("No Nsmf traffic associated with recovery UE trials")
    return output


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--pcap", type=Path, required=True)
    p.add_argument("--trials", type=Path, required=True)
    p.add_argument("--out", type=Path, default=Path("results/phase6"))
    a = p.parse_args()
    print(json.dumps(run(a.pcap, a.trials, a.out), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
