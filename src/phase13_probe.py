"""Phase 13: actual two-surface, signed control-information-unit observation.

Surface N: live HTTP/2 Nnrf_NFDiscovery(SMF), as before.
Surface U: actual /proc/net/udp(6) from the running UPF's network
namespace (PFCP UDP 8805 = 0x2265). An inaccessible UPF namespace is
recorded separately from a process with no PFCP listening socket.

UPF socket evidence requires privileged lab Docker access and cannot
establish PFCP Association state; NOT an independent trust domain,
cryptographic NF attestation, or proof of malicious compromise.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from .phase9_receipts import (
    SCHEMA, compact_json, read_private_key, nrf_discovery
)

SVC_NRF="Nnrf_NFDiscovery_SMF"
SVC_UPF="Lab_UPF_PFCP_UDP8805_Socket"
SERVICES={"nrf":SVC_NRF, "upf":SVC_UPF}
PFCP_HEX="2265"
PFCP_PORT_PATTERN=re.compile(r"(?i):2265\s")


def upf_namespace_socket() -> dict:
    """Read a live UPF namespace's socket table, but never publish raw /proc."""
    start=time.monotonic()
    call=["docker","exec","upf","sh","-c","cat /proc/net/udp /proc/net/udp6 2>/dev/null"]
    try:
        p=subprocess.run(call,capture_output=True,text=True,timeout=6)
        accessible=p.returncode==0
        has_socket=bool(PFCP_PORT_PATTERN.search(p.stdout)) if accessible else None
    except (subprocess.TimeoutExpired, OSError):
        accessible=False
        has_socket=None
    return {
        "namespace_accessible":accessible,
        "pfcp_udp_8805_socket_present":has_socket,
        "probe_elapsed_ms":round((time.monotonic()-start)*1000,3),
        "observation_method":"privileged_docker_exec_upf_proc_net_udp",
    }


def sign_observation(key_path:Path, agent_id:str, source:str,
                     challenge:str, trial_token:str, sequence:int,
                     endpoint:str="http://172.22.0.12:7777")->dict:
    if source not in SERVICES:
        raise ValueError("Wrong laboratory evidence source")
    if not agent_id.startswith("phase13_") or len(agent_id)>64:
        raise ValueError("Wrong phase-13 agent")
    if (len(challenge)!=32 or any(x not in "0123456789abcdef" for x in challenge)
            or not (1<=sequence<=100) or len(trial_token)>48):
        raise ValueError("Bad nonce, sequence or pseudonymous token")
    observed=nrf_discovery(endpoint) if source=="nrf" else upf_namespace_socket()
    private=read_private_key(key_path)
    pub=private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    document={
        "schema":SCHEMA,
        "service":SERVICES[source],
        "source_kind":source,
        "agent_id":agent_id,
        "key_id":hashlib.sha256(pub).hexdigest()[:24],
        "trial_token":trial_token,
        "nonce":challenge,
        "sequence":sequence,
        "timestamp_utc":datetime.now(timezone.utc).isoformat(),
        "measured_at_unix":round(time.time(),3),
        "observation":observed,
    }
    return {
        "payload":document,
        "signature_b64":base64.b64encode(private.sign(compact_json(document))).decode("ascii"),
    }


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--key",type=Path,required=True)
    p.add_argument("--agent",required=True)
    p.add_argument("--source",choices=tuple(SERVICES),required=True)
    p.add_argument("--challenge",required=True)
    p.add_argument("--trial-token",required=True)
    p.add_argument("--sequence",type=int,required=True)
    p.add_argument("--endpoint",default="http://172.22.0.12:7777")
    a=p.parse_args()
    print(json.dumps(sign_observation(
        a.key,a.agent,a.source,a.challenge,a.trial_token,a.sequence,a.endpoint),
        sort_keys=True))


if __name__=="__main__":
    main()
