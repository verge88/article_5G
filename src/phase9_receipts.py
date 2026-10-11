"""Phase 9: signed, replay-protected laboratory control information receipts.

A real HTTP/2 NFDiscovery observation is made in an ephemeral agent
subprocess. The agent emits only de-identified metadata signed by Ed25519.

Important limitations:
- Both ephemeral signing agents execute on ONE GitHub-hosted runner under
  the SAME administrative trust domain: separate keys != independent owners.
- The lab's Open5GS HTTP/2 is cleartext; this is NOT 3GPP TS 33.501 NF
  authentication, TLS or OAuth2 authorization.
- A valid signature authenticates the reporting key, NOT observation truth.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
from urllib.parse import urlencode
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)

MARKER = "\n--PHASE9-METADATA--"
SCHEMA = "lab-kie-receipt-v1"


def compact_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


def create_ephemeral_key(path: Path) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    pub = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"public_key_b64": base64.b64encode(pub).decode("ascii"),
            "key_id": hashlib.sha256(pub).hexdigest()[:24]}


def read_private_key(path: Path) -> Ed25519PrivateKey:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    private = load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise TypeError("Only Ed25519 keys are accepted")
    return private


def nrf_discovery(endpoint: str) -> dict:
    """Retrieve live NRF service status; never write NFProfile JSON."""
    query = urlencode({"target-nf-type": "SMF", "requester-nf-type": "AMF"})
    url = endpoint.rstrip("/") + "/nnrf-disc/v1/nf-instances?" + query
    args = [
        "curl", "--noproxy", "*", "--http2-prior-knowledge", "-sS",
        "--connect-timeout", "2", "--max-time", "6",
        "-w", MARKER + "%{http_code} %{http_version} %{time_total} %{size_download}\n",
        url,
    ]
    start = time.monotonic()
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=9)
    except subprocess.TimeoutExpired:
        return {"http_status": 0, "http_version": "none", "latency_ms": 0.,
                "response_body_bytes": 0, "advertised_smf_profiles": -1,
                "transport_success": False, "agent_elapsed_ms": round((time.monotonic()-start)*1000,3)}
    if proc.returncode:
        return {"http_status": 0, "http_version": "none", "latency_ms": 0.,
                "response_body_bytes": 0, "advertised_smf_profiles": -1,
                "transport_success": False, "agent_elapsed_ms": round((time.monotonic()-start)*1000,3)}
    if MARKER not in proc.stdout:
        raise ValueError("Missing HTTP/2 curl metadata")
    body, meta = proc.stdout.rsplit(MARKER,1)
    values = meta.strip().split()
    if len(values) != 4:
        raise ValueError("Unexpected HTTP/2 metadata")
    status, version, latency, bytes_count = values
    try:
        parsed = json.loads(body)
    except ValueError:
        parsed = {}
    profiles = parsed.get("nfInstances",[]) if isinstance(parsed,dict) else []
    if not isinstance(profiles,list):
        profiles = []
    return {
        "http_status": int(status),
        "http_version": version,
        "latency_ms": round(float(latency)*1000,3),
        "response_body_bytes": int(float(bytes_count)),
        "advertised_smf_profiles": len(profiles) if int(status)==200 else -1,
        "transport_success": int(status)==200 and version=="2",
        "agent_elapsed_ms": round((time.monotonic()-start)*1000,3),
    }


def produce_receipt(*, key_path:Path, agent_id:str, challenge:str,
                    trial_token:str, sequence:int, endpoint:str) -> dict:
    if agent_id not in ("nrf_fixed","nrf_adaptive","nrf_ml","nrf_hybrid"):
        raise ValueError("Unknown laboratory agent")
    if len(challenge) != 32 or any(c not in "0123456789abcdef" for c in challenge):
        raise ValueError("Expected a 128-bit random challenge as hexadecimal")
    if sequence < 1 or sequence > 10000 or len(trial_token)>48:
        raise ValueError("Invalid sequence or anonymized trial token")
    observed = nrf_discovery(endpoint)
    pub = read_private_key(key_path).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    data = {
        "schema": SCHEMA,
        "agent_id": agent_id,
        "key_id": hashlib.sha256(pub).hexdigest()[:24],
        "trial_token": trial_token,
        "sequence": sequence,
        "nonce": challenge,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "measured_at_unix": round(time.time(),3),
        "service": "Nnrf_NFDiscovery_SMF",
        "observation": observed,
    }
    sig = read_private_key(key_path).sign(compact_json(data))
    return {"payload":data, "signature_b64":base64.b64encode(sig).decode("ascii")}


def verify_receipt(receipt:dict, *, registered_keys:dict,
                   pending:dict, accepted_sequences:dict,
                   now:float|None=None, max_age_s:float=20.) -> bool:
    """Return False if signature, nonce, issuer, freshness or order fail.

    pending maps issued 128-bit challenge -> (agent_id, trial_token, sequence).
    A pending challenge is consumed only after successful verification.
    """
    try:
        payload=receipt["payload"]
        agent=payload["agent_id"]
        details=registered_keys[agent]
        if payload["schema"]!=SCHEMA or payload["service"]!="Nnrf_NFDiscovery_SMF":
            return False
        if payload["key_id"]!=details["key_id"]:
            return False
        sequence=payload["sequence"]
        if not isinstance(sequence,int) or isinstance(sequence,bool):
            return False
        if sequence <= accepted_sequences.get(agent,0):
            return False
        nonce=payload["nonce"]
        if pending.get(nonce)!=(agent,payload["trial_token"],sequence):
            return False
        current=time.time() if now is None else now
        drift=current-float(payload["measured_at_unix"])
        if drift < -2.0 or drift > max_age_s:
            return False
        pub=Ed25519PublicKey.from_public_bytes(base64.b64decode(details["public_key_b64"]))
        pub.verify(base64.b64decode(receipt["signature_b64"]),compact_json(payload))
    except (KeyError, TypeError, ValueError, InvalidSignature, OverflowError, AttributeError):
        return False
    pending.pop(nonce)
    accepted_sequences[agent]=sequence
    return True


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--key",type=Path,required=True)
    p.add_argument("--agent",required=True)
    p.add_argument("--challenge",required=True)
    p.add_argument("--trial-token",required=True)
    p.add_argument("--sequence",type=int,required=True)
    p.add_argument("--endpoint",default="http://172.22.0.12:7777")
    a=p.parse_args()
    result=produce_receipt(
        key_path=a.key,agent_id=a.agent,challenge=a.challenge,
        trial_token=a.trial_token,sequence=a.sequence,endpoint=a.endpoint)
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    main()
