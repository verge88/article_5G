"""Summarize sanitized HTTP/2 SBI API paths from short-lived local PCAP.

No raw packet capture, request bodies, subscriber identifiers, tokens or IP
addresses are uploaded as artifacts. Capture occurs only in an isolated lab.
"""
import argparse
import json
import re
import subprocess
from collections import Counter
from pathlib import Path


KNOWN = (
    "nsmf-pdusession", "nnrf-disc", "nnrf-nfm", "nudm-sdm",
    "nudm-uecm", "nausf-auth", "npcf-smpolicycontrol",
    "nsmf-event-exposure", "nssf-nsselection",
)


def classify_paths(lines):
    out = Counter()
    for line in lines:
        for token in re.split(r"[,\t]", line):
            token = token.strip().lower()
            if not token:
                continue
            key = next((x for x in KNOWN if x in token), "other")
            # Only fixed-service-family token is stored, no raw path segments.
            out[key] += 1
    return dict(sorted(out.items()))


def audit_capture(capture: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    args = [
        "tshark", "-r", str(capture), "-d", "tcp.port==7777,http2",
        "-Y", "http2.headers.path", "-T", "fields",
        "-e", "http2.headers.path",
    ]
    p = subprocess.run(args, text=True, capture_output=True, timeout=110, check=False)
    if p.returncode:
        raise RuntimeError("HTTP/2 trace decoder failed: " + p.stderr[-250:])
    counts = classify_paths(p.stdout.splitlines())
    result = dict(
        evidence_type="passive HTTP/2 decoded paths, actual Open5GS SBI",
        method="tshark with explicit TCP/7777 HTTP/2 decode; sanitized service family counts",
        trace_frame_lines=len(p.stdout.splitlines()),
        family_counts=counts,
        observed_nsmf_pdu_session=counts.get("nsmf-pdusession", 0) > 0,
        caveat="This does not prove end-to-end PDU success, only observed 5G SBI path use.",
    )
    (out_dir / "sbi_trace_summary.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    if result["trace_frame_lines"] == 0:
        raise RuntimeError("No HTTP/2 paths decoded; trace evidence is unavailable")
    return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--capture", type=Path, required=True)
    p.add_argument("--out-dir", type=Path, default=Path("results/phase3"))
    a = p.parse_args()
    print(json.dumps(audit_capture(a.capture, a.out_dir), indent=2))


if __name__ == "__main__":
    main()
