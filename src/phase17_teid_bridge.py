"""Stage 17: examine N3 GTP-TEID consistency across real NGAP and PFCP frames.

Only candidate tunnel-number agreement, NEVER proof of UE PDU/SM Context
identity. Numeric TEID is not globally unique and MUST be qualified by
tunnel endpoint, direction, PDU session context and a trusted producer.
Raw IDs, IPs, SEIDs, protocol headers and PCAP never leave process memory.
"""
from __future__ import annotations
from collections import defaultdict
from pathlib import Path
import re

from .phase16_crossplane import analyze as stage16_analyze,run_fields

def parse_ngap_teid(value:str)->int|None:
    """Wireshark ngap.gTP_TEID is 4-byte OCTET STRING, NOT decimal text.

    Accept 0x01020304, 01:02:03:04, 01020304 or 01 02 03 04.
    Reject decimal-only 12345678? It is an 8-digit *hex byte string*;
    documenting this avoids pretending it is an integer encoded in
    decimal. Zero or invalid byte-length never forms an identity link.
    """
    raw=value.strip().lower()
    if raw.startswith("0x"):
        raw=raw[2:]
    if not re.fullmatch(r"[0-9a-f]{8}|(?:[0-9a-f]{2}:){3}[0-9a-f]{2}|(?:[0-9a-f]{2} ){3}[0-9a-f]{2}",raw):
        return None
    number=int(re.sub(r"[: ]","",raw),16)
    return number if number>0 else None

def parse_pfcp_teid(value:str)->int|None:
    """PFCP TEID is an unsigned INT in Wireshark -T fields (decimal)."""
    v=value.strip()
    if not v:
        return None
    if not re.fullmatch(r"(?:0x[0-9a-fA-F]{1,8}|\d{1,10})",v):
        return None
    number=int(v,16) if v.lower().startswith("0x") else int(v,10)
    return number if 0<number<=0xffffffff else None

def csv_tokens(value:str):
    return [x.strip() for x in value.split(",") if x.strip()]

def parse_ngap_lines(lines:list[str])->dict[int,set[tuple]]:
    """Return in-memory TEID → distinct (PDU ID, procedure code) contexts.

    None marks a missing PDU context, not a definite globally unique ID.
    """
    contexts=defaultdict(set)
    for line in lines:
        fields=line.split("\t")
        if len(fields)!=4:
            continue
        timestamp,pdu_ids,teids,procedure=fields
        ids=tuple(x for x in csv_tokens(pdu_ids) if x.isdigit())
        context=(ids,procedure.strip())
        for raw in csv_tokens(teids):
            teid=parse_ngap_teid(raw)
            if teid is not None:
                contexts[teid].add(context)
    return contexts

def parse_pfcp_lines(lines:list[str])->dict[str,dict[int,set[tuple]]]:
    """Only 51 F-TEID (UPF allocated UL) and 52 OuterHdr TEID (DL).

    Message-type partition is a *plausibility gate*, NOT proof that the
    decoded TEID is a N3 tunnel of this particular UE. Endpoint location,
    full hierarchical PFCP IE and SEID are not authenticated by tshark.
    """
    result={"ul_f_teid_in_51":defaultdict(set),
            "dl_outer_header_teid_in_52":defaultdict(set)}
    for line in lines:
        fields=line.split("\t")
        if len(fields)!=7:
            continue
        t,typ,seq,fteids,outer,src,dst=fields
        if typ not in ("51","52"):
            continue
        source="ul_f_teid_in_51" if typ=="51" else "dl_outer_header_teid_in_52"
        raw=fteids if typ=="51" else outer
        # Distinguish otherwise conflicting PFCP transactions using in-memory
        # sequence/direction. Packet mirroring retains same tuple and is collapsed.
        context=(typ,seq.strip(),src,dst)
        for value in csv_tokens(raw):
            key=parse_pfcp_teid(value)
            if key is not None:
                result[source][key].add(context)
    return result

def compare_teid_candidates(ngap:dict,pfcp:dict)->dict:
    """A verified identity bridge is NOT supplied: never promote candidates."""
    ngap_ids=set(ngap)
    numbers={}
    collisions={}
    for source,observed in pfcp.items():
        overlap=ngap_ids.intersection(observed)
        # Even unique number equality is only an untrusted candidate.
        candidate={t for t in overlap
                   if len(observed[t])==1 and len(ngap[t])==1
                   and any(context[0] for context in ngap[t])}
        ambiguous=overlap-candidate
        numbers[source]=len(candidate)
        collisions[source]=len(ambiguous)
    all_overlap=set(ngap).intersection(set().union(*(set(x) for x in pfcp.values())))
    all_candidates=sum(numbers.values())
    return {
        "ngap_distinct_nonzero_teid_values_in_window":len(ngap),
        "pfcp_distinct_f_teid_in_session_establishment_response":len(pfcp["ul_f_teid_in_51"]),
        "pfcp_distinct_outer_hdr_teid_in_session_modification_request":len(pfcp["dl_outer_header_teid_in_52"]),
        "direction_gated_unique_numeric_ul_teid_candidates":numbers["ul_f_teid_in_51"],
        "direction_gated_unique_numeric_dl_teid_candidates":numbers["dl_outer_header_teid_in_52"],
        "direction_gated_ambiguous_ul_teids":collisions["ul_f_teid_in_51"],
        "direction_gated_ambiguous_dl_teids":collisions["dl_outer_header_teid_in_52"],
        "direction_free_numeric_overlap_distinct":len(all_overlap),
        "numeric_tunnel_candidate_observed":bool(all_candidates),
        "verified_transport_endpoint_and_full_ie_context":False,
        "cryptographically_authenticated_sm_context_bridge":False,
        "cross_protocol_identity_join_proven":False,
        "identity_verdict":"candidate_only_not_pdu_session_identity"
            if all_candidates else "insufficient_identifier_evidence",
        "not_evidence_of":"malicious NF compromise, authentic association of NAS PDU ID and PFCP SEID",
    }

def analyze(pcap:Path)->dict:
    original=stage16_analyze(pcap)
    ngap=parse_ngap_lines(run_fields(
        pcap,display_filter="ngap.gTP_TEID",
        fields=("frame.time_epoch","ngap.pDUSessionID",
                "ngap.gTP_TEID","ngap.procedureCode"),
        decode_as=("-d","sctp.port==38412,ngap")))
    pfcp=parse_pfcp_lines(run_fields(
        pcap,display_filter="pfcp.msg_type == 51 || pfcp.msg_type == 52",
        fields=("frame.time_epoch","pfcp.msg_type","pfcp.seqno",
                "pfcp.f_teid.teid","pfcp.outer_hdr_creation.teid",
                "ip.src","ip.dst"),
        decode_as=("-d","udp.port==8805,pfcp")))
    extra=compare_teid_candidates(ngap,pfcp)
    original["n3_teid_candidate_bridge"]=extra
    # Never overwrite stage16's strict negative assertion.
    if original["identity"]["cross_protocol_identity_join_proven"]:
        raise RuntimeError("A time-only identity proof is not permitted")
    return original
