"""Phase16: privacy-preserving three-plane observation in ONE actual PDU time window.

Capture raw packet bytes only in a temporary file; parse raw identifiers
in process memory and export COUNTS ONLY. NGAP PDU ID, HTTP2 stream ID,
PFCP SEID/seqno are incompatible protocol namespaces. Their co-observation
does not authenticate or prove any NGAP ↔ PFCP identity mapping.
"""
from __future__ import annotations
from pathlib import Path
import re
import subprocess

from .phase15_pfcp_windows import decode_trial_pcap
from .phase6_correlate import decode_rows

def run_fields(pcap:Path, *, display_filter:str, fields:tuple[str,...],
               decode_as:tuple[str,...]=())->list[str]:
    command=["tshark","-r",str(pcap),*decode_as,
             "-Y",display_filter,"-T","fields",
             "-E","separator=/t","-E","occurrence=f"]
    for f in fields:
        command+=["-e",f]
    p=subprocess.run(command,capture_output=True,text=True,timeout=85)
    if p.returncode:
        raise RuntimeError("Protocol evidence decoder unavailable: "+
                           p.stderr[-280:].replace("\n"," "))
    return p.stdout.splitlines()


def ngap_counts(lines:list[str])->dict:
    ids=[]
    decoded=0
    for raw in lines:
        fields=raw.split("\t")
        if not fields:
            continue
        decoded+=1
        session=fields[0].strip()
        if session:
            for value in session.split(","):
                v=value.strip()
                if v.isdigit() and 0<int(v)<=255:
                    ids.append(int(v))
    return {"ngap_decoded_message_occurrences":decoded,
            "ngap_pdu_id_occurrences":len(ids),
            "ngap_pdu_id_distinct_count":len(set(ids)),
            "ngap_pdu_id_visible":bool(ids)}


def http2_nsmf_counts(raw:str)->dict:
    frames=decode_rows(raw)
    requests={}
    responses={}
    for f in frames:
        key=(f["tcp"],f["http2_stream"])
        if f["has_path"] and f["family"]=="nsmf-pdusession":
            if key not in requests or f["epoch"]<requests[key]["epoch"]:
                requests[key]=f
        if f["status"] is not None:
            responses.setdefault(key,[]).append(f)
    matched=0
    codes=[]
    for key,req in requests.items():
        possible=sorted((x for x in responses.get(key,[])
                         if x["epoch"]>=req["epoch"]-0.001),
                        key=lambda x:x["epoch"])
        if possible:
            matched+=1
            codes.append(possible[0]["status"])
    return {
        "nsmf_http2_unique_request_streams":len(requests),
        "nsmf_http2_matched_responses":matched,
        "nsmf_http2_unanswered_streams":len(requests)-matched,
        "nsmf_http2_responses_2xx":sum(200<=x<300 for x in codes),
        "nsmf_http2_responses_5xx":sum(500<=x<600 for x in codes),
    }


def seid_count(lines:list[str])->dict:
    # The unique cardinality is inside this one time window, NOT a join
    # to an NGAP PDU ID. Do not export the actual SEID or its hash.
    nonzero=[]
    for line in lines:
        for item in line.split(","):
            value=item.strip()
            if not value:
                continue
            try:
                number=int(value,0) if value.lower().startswith("0x") else int(value,10)
            except ValueError:
                continue
            if number>0:
                nonzero.append(number)
    return {
        "pfcp_header_nonzero_seid_occurrences":len(nonzero),
        "pfcp_header_distinct_nonzero_seids":len(set(nonzero)),
        "pfcp_header_seid_visible":bool(nonzero),
    }


def interpret_join(n2:dict,sbi:dict,n4:dict, *, bridge=None)->dict:
    """Deliberately reject observational identity joins without a trusted bridge.

    No trusted mapping is supplied by the phase16 lab. Future support requires
    *both* a source-authenticated bridge and verification of unique IDs; simply
    passing a dict or a single shared time window can NEVER prove identity.
    """
    if bridge is not None:
        raise ValueError("Phase16 does not implement a verified SMF correlation bridge")
    seen={
        "n2_ngap_pdu_id":bool(n2["ngap_pdu_id_visible"]),
        "sbi_nsmf_stream":bool(sbi["nsmf_http2_unique_request_streams"]),
        "n4_pfcp_pair":bool(n4["session_establishment_matched_pairs"]),
    }
    return {
        "sources_observed":seen,
        "observed_sources_count":sum(seen.values()),
        "naive_three_source_time_only_join_would_claim_identity":all(seen.values()),
        "cross_protocol_identity_join_proven":False,
        "causality_verdict":"insufficient_identity_binding",
        "specific_missing_link":"authenticated mapping NGAP PDU ID ↔ SM Context/Nsmf reference ↔ PFCP SEID",
    }


def analyze(pcap:Path)->dict:
    if not pcap.exists() or pcap.stat().st_size<24:
        raise RuntimeError("No genuine three-plane capture available")
    pfcp=decode_trial_pcap(pcap)
    ngap=ngap_counts(run_fields(
        pcap,display_filter="ngap",
        fields=("ngap.pDUSessionID","ngap.procedureCode"),
        decode_as=("-d","sctp.port==38412,ngap")))
    http=run_fields(
        pcap,display_filter="http2.headers.path || http2.headers.status",
        fields=("frame.time_epoch","tcp.stream","http2.streamid",
                "http2.headers.path","http2.headers.method","http2.headers.status"),
        decode_as=("-d","tcp.port==7777,http2"))
    nsmf=http2_nsmf_counts("\n".join(http))
    seids=seid_count(run_fields(
        pcap,display_filter="pfcp",
        fields=("pfcp.seid",),
        decode_as=("-d","udp.port==8805,pfcp")))
    output={
        "ngap":ngap,"nsmf":nsmf,"pfcp":pfcp,"pfcp_seid_cardinality":seids,
        "identity":interpret_join(ngap,nsmf,pfcp),
        "raw_packet_capture_exported":False,
        "privacy":"no SUPI/IMSI/IP/SEID/PDU-ID/stream-ID/HTTP headers or payload published",
    }
    return output
