"""Phase18: cautious N3 tunnel (IPv4 endpoint, TEID, NGAP role) comparison.

This is a lab *candidate* bridge, not an authenticated UE PDU ID/SM Context
to PFCP SEID mapping. No subscriber ID, IP, TEID, SEID or raw packet data
may leave the transient analyst process. Flat Wireshark -T fields with
multiple TEIDs/IPs are NOT zipped by positional index, they are unknown.
"""
from __future__ import annotations
from collections import defaultdict
from ipaddress import IPv4Address,AddressValueError
from pathlib import Path

from .phase17_teid_bridge import (
    analyze as prior_analyze,run_fields,csv_tokens,
    parse_ngap_teid,parse_pfcp_teid
)

ROLES=("ul_upf","dl_gnb")


def ipv4_only(raw:str)->str|None:
    try:
        a=IPv4Address(raw.strip())
        if a.is_unspecified or a.is_multicast or a.is_loopback:
            return None
        return str(a)
    except (AddressValueError,ValueError):
        return None


def decode_ngap_endpoints(lines:list[str])->dict:
    """Accept one TEID, one IPv4, one PDU ID, one external NGAP role/frame.

    No ASN.1 IE-tree path proven: role is the outer initiating vs successful
    outcome. If this field is absent or a nested context is ambiguous, abstain.
    """
    candidates={x:defaultdict(set) for x in ROLES}
    metrics={"NGAP_frames_with_TEID_field":0,
             "NGAP_frames_with_single_IPv4_endpoint":0,
             "NGAP_unpaired_or_ambiguous_frames":0,
             "NGAP_no_IP_or_role_frames":0}
    for line in lines:
        fields=line.rstrip("\n").split("\t")
        if len(fields)!=7:
            continue
        ts,pdus,teids,addrs,init,success,proc=fields
        if not teids:
            continue
        metrics["NGAP_frames_with_TEID_field"]+=1
        ts_values=csv_tokens(teids)
        ips=csv_tokens(addrs)
        pdus_values=csv_tokens(pdus)
        roles=[bool(init.strip()),bool(success.strip())]
        if len(ips)==1 and ipv4_only(ips[0]):
            metrics["NGAP_frames_with_single_IPv4_endpoint"]+=1
        if not ips or roles[0]==roles[1]:
            metrics["NGAP_no_IP_or_role_frames"]+=1
        if (len(ts_values)!=1 or len(ips)!=1 or len(pdus_values)!=1 or
            not pdus_values[0].isdigit() or int(pdus_values[0])<=0 or
            roles[0]==roles[1]):
            metrics["NGAP_unpaired_or_ambiguous_frames"]+=1
            continue
        tid=parse_ngap_teid(ts_values[0])
        addr=ipv4_only(ips[0])
        if tid is None or addr is None:
            metrics["NGAP_unpaired_or_ambiguous_frames"]+=1
            continue
        role="ul_upf" if roles[0] else "dl_gnb"
        # No known equality to authenticated session metadata. Only restrict
        # repeated TEIDs across distinct local PDU/procedure codes.
        candidates[role][(tid,addr)].add((pdus_values[0],proc.strip()))
    return {"candidates":candidates,"metrics":metrics}


def decode_pfcp_endpoints(lines:list[str])->dict:
    """Only (51, F-TEID/IP) for UL and (52, OHC TEID/IP) for DL.

    Flat field output cannot identify which nested PFCP IE pairs values
    when a message contains >1 item. Such packets are intentionally ignored.
    """
    candidates={x:defaultdict(set) for x in ROLES}
    metrics={"PFCP_type51_or52_frames":0,
             "PFCP_frames_with_single_IPv4_endpoint":0,
             "PFCP_unpaired_or_ambiguous_frames":0}
    for line in lines:
        fields=line.rstrip("\n").split("\t")
        if len(fields)!=8:
            continue
        typ,seq,fteid,fipv4,ohcteid,ohcipv4,src,dst=fields
        if typ not in ("51","52"):
            continue
        metrics["PFCP_type51_or52_frames"]+=1
        role="ul_upf" if typ=="51" else "dl_gnb"
        teids=csv_tokens(fteid if role=="ul_upf" else ohcteid)
        ips=csv_tokens(fipv4 if role=="ul_upf" else ohcipv4)
        if len(ips)==1 and ipv4_only(ips[0]):
            metrics["PFCP_frames_with_single_IPv4_endpoint"]+=1
        if len(teids)!=1 or len(ips)!=1 or not seq.strip():
            metrics["PFCP_unpaired_or_ambiguous_frames"]+=1
            continue
        tid=parse_pfcp_teid(teids[0])
        addr=ipv4_only(ips[0])
        if tid is None or addr is None:
            metrics["PFCP_unpaired_or_ambiguous_frames"]+=1
            continue
        candidates[role][(tid,addr)].add((typ,seq.strip(),src.strip(),dst.strip()))
    return {"candidates":candidates,"metrics":metrics}


def compare_endpoints(ngap:dict,pfcp:dict,numeric:dict)->dict:
    """Every reported strict endpoint tuple must also have numeric equality."""
    n=ngap["candidates"];p=pfcp["candidates"]
    result={}
    for role in ROLES:
        shared=set(n[role]).intersection(p[role])
        unique=sum(len(n[role][x])==1 and len(p[role][x])==1
                   for x in shared)
        ambiguous=len(shared)-unique
        result[role]={
            "strict_ipv4_teid_role_candidates":unique,
            "same_endpoint_collision_abstentions":ambiguous,
            "ngap_single_field_endpoint_tuples":len(n[role]),
            "pfcp_single_field_endpoint_tuples":len(p[role]),
            "numeric_equal_but_ip_or_role_unverified":max(
                0,
                numeric["direction_gated_unique_numeric_ul_teid_candidates"
                        if role=="ul_upf" else
                        "direction_gated_unique_numeric_dl_teid_candidates"]-unique),
        }
        if unique>numeric["direction_gated_unique_numeric_ul_teid_candidates"
                          if role=="ul_upf" else
                          "direction_gated_unique_numeric_dl_teid_candidates"]:
            # Duplicate capture, stale context, multi-role alignment, or
            # inconsistent parser: never claim stronger evidence than weaker.
            raise ValueError("Endpoint matched more TEIDs than numeric-only control")
    return {
        "ul_upf":result["ul_upf"],
        "dl_gnb":result["dl_gnb"],
        "ngap_frame_observability":ngap["metrics"],
        "pfcp_frame_observability":pfcp["metrics"],
        "strict_endpoint_candidates_observed":sum(
            result[role]["strict_ipv4_teid_role_candidates"] for role in ROLES),
        "verified_ngap_asn1_transfer_nesting":False,
        "verified_pfcp_pdr_far_ie_nesting":False,
        "cryptographically_authenticated_sm_context_mapping":False,
        "cross_protocol_identity_join_proven":False,
        "truth_status":"candidate_tunnel_endpoint_only_no_UE_session_identity",
    }


def analyze(pcap:Path)->dict:
    original=prior_analyze(pcap)
    n=decode_ngap_endpoints(run_fields(
        pcap,display_filter="ngap.gTP_TEID",
        fields=("frame.time_epoch","ngap.pDUSessionID",
                "ngap.gTP_TEID","ngap.TransportLayerAddressIPv4",
                "ngap.initiatingMessage_element","ngap.successfulOutcome_element",
                "ngap.procedureCode"),
        decode_as=("-d","sctp.port==38412,ngap")))
    p=decode_pfcp_endpoints(run_fields(
        pcap,display_filter="pfcp.msg_type == 51 || pfcp.msg_type == 52",
        fields=("pfcp.msg_type","pfcp.seqno",
                "pfcp.f_teid.teid","pfcp.f_teid.ipv4_addr",
                "pfcp.outer_hdr_creation.teid","pfcp.outer_hdr_creation.ipv4",
                "ip.src","ip.dst"),
        decode_as=("-d","udp.port==8805,pfcp")))
    original["n3_role_endpoint_bridge"]=compare_endpoints(
        n,p,original["n3_teid_candidate_bridge"])
    if original["n3_role_endpoint_bridge"]["cross_protocol_identity_join_proven"]:
        raise RuntimeError("No authenticated PDU identity bridge exists")
    return original
