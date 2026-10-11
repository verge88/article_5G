"""Phase 7: real, *healthy* Open5GS SMF with unsupported UE-requested DNN.

The intended perturbation is a legitimate configuration mismatch, NOT a
compromised SMF. This distinguishes NF availability from procedural success.
Every outcome is read from UERANSIM; no attack labels enter the observations.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import time
from pathlib import Path

from .pdu_lab import state, trial
from .real_sbi import send_discovery

GOOD = "apn: 'internet'"
BAD = "apn: 'lab-unprovisioned-dnn'"


def replace_ue_dnn(text: str, target: str) -> str:
    if text.count(GOOD) + text.count(BAD) != 1:
        raise ValueError("UE config must have exactly one supported lab DNN field")
    return text.replace(GOOD, target).replace(BAD, target)


def run(compose_dir: Path, out_dir: Path, *, repeats: int = 6,
        normal_timeout: int = 18, bad_timeout: int = 14):
    if os.environ.get("ALLOW_LAB_UE_DNN_CHANGE") != "yes":
        raise RuntimeError("Explicit disposable laboratory guard required")
    if "upstream_open5gs" not in str(compose_dir.resolve()):
        raise RuntimeError("Only isolated upstream_open5gs checkout supported")
    if repeats < 3:
        raise ValueError("At least three independent attempts per phase")
    if not all(state(name) for name in ("nrf","amf","smf","upf","nr_gnb")):
        raise RuntimeError("All 5G Core components must start healthy")
    config = compose_dir / "ueransim" / "ueransim-ue.yaml"
    original = config.read_text(encoding="utf-8")
    if original.count(GOOD) != 1 or BAD in original:
        raise ValueError("Expected original supported DNN")
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    try:
        for phase, target, duration in (
            ("normal", GOOD, normal_timeout),
            ("invalid_dnn", BAD, bad_timeout),
            ("recovery", GOOD, normal_timeout),
        ):
            config.write_text(replace_ue_dnn(original, target), encoding="utf-8")
            for index in range(repeats):
                # Record real wall-clock bounds of UE attempts to attribute
                # HTTP2 streams by window, rather than by a fabricated UE ID.
                if not state("smf"):
                    raise RuntimeError("SMF stopped unexpectedly: invalid semantic-fault test")
                start = time.time()
                record = trial(compose_dir, phase, index, duration, 1.)
                end = time.time()
                if not record["smf_running_witness"]:
                    raise RuntimeError("SMF stopped during attempt")
                try:
                    nrf = send_discovery("http://172.22.0.12:7777", "SMF", timeout=4)
                    record["nrf_http2_smf_present"] = int(
                        nrf["http_status"] == 200
                        and nrf["http_version"] == "2"
                        and nrf["matched_profiles"] > 0)
                except Exception:
                    record["nrf_http2_smf_present"] = -1
                record["window_start_epoch"] = start
                record["window_end_epoch"] = end
                record["window_duration_s"] = round(end-start, 3)
                record["requested_dnn_category"] = (
                    "subscriber_provisioned" if target == GOOD else "not_provisioned"
                )
                rows.append(record)
    finally:
        # Always restore the original lab UE configuration before cleanup.
        config.write_text(original, encoding="utf-8")

    filename = out_dir / "real_pdu_windows.csv"
    with filename.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    phases = {}
    for name in ("normal", "invalid_dnn", "recovery"):
        group = [x for x in rows if x["phase"] == name]
        phases[name] = {
            "attempts": len(group),
            "successful_pdu": sum(x["ue_pdu_session_accepted"] for x in group),
            "registered_ue": sum(x["ue_registration_seen"] for x in group),
            "smf_running": sum(x["smf_running_witness"] for x in group),
            "nrf_http2_smf_present": sum(x["nrf_http2_smf_present"] == 1 for x in group),
        }
    summary = {
        "source": "REAL Open5GS and UERANSIM, healthy SMF",
        "intervention": "Change only requested UE DNN to an unprovisioned value",
        "intervention_type": "benign lab configuration mismatch, NOT compromise",
        "phases": phases,
        "n_trials": len(rows),
        "limitations": [
            "The unsupported DNN can be rejected before an Nsmf service call",
            "A healthy SMF with a failed procedure does not imply malicious behaviour",
            "One Open5GS implementation and one UE per trial",
            "Only temporal association of HTTP2 streams, not unique 3GPP procedure identity",
            "No fraudulent NF logging, malicious protocol response or in-band KIE injected",
        ],
    }
    (out_dir / "real_healthy_smf_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    if phases["normal"]["successful_pdu"] < 1 or phases["recovery"]["successful_pdu"] < 1:
        raise RuntimeError("Failed to establish baseline/recovery PDU on real healthy SMF")
    if phases["invalid_dnn"]["successful_pdu"] != 0:
        raise RuntimeError("Unsupported requested DNN unexpectedly succeeds: test premise false")
    if phases["invalid_dnn"]["registered_ue"] == 0:
        raise RuntimeError("No UE registration during semantic scenario")
    if any(phases[x]["smf_running"] != repeats for x in phases):
        raise RuntimeError("Failed requirement: SMF must stay running throughout")
    return summary


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--compose-dir", type=Path, default=Path("upstream_open5gs"))
    p.add_argument("--out-dir", type=Path, default=Path("results/phase7"))
    p.add_argument("--repeats", type=int, default=6)
    a = p.parse_args()
    print(json.dumps(run(a.compose_dir, a.out_dir, repeats=a.repeats), indent=2))


if __name__ == "__main__":
    main()
