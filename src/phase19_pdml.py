"""Phase19: privacy-safe IE ancestry census and N3 direction diagnostic.

Raw PCAP and tshark PDML XML remain in transient host memory. Only integer
cardinalities, never IP, TEID, SUPI, SEID or PDU ID, enter signed artifacts.
"""
from __future__ import annotations
from collections import Counter
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET
from .phase18_endpoints import (
    analyze as phase18_analyze,decode_ngap_endpoints,decode_pfcp_endpoints,
)
from .phase17_teid_bridge import run_fields

NGAP_REQ_TRANSFER="ngap.PDUSessionResourceSetupRequestTransfer_element"
NGAP_RSP_TRANSFER="ngap.PDUSessionResourceSetupResponseTransfer_element"
NGAP_GTP_TUNNEL="ngap.GTPTunnel_element"
TARGETS={
    "ngap":(("ngap.gTP_TEID","ngap.TransportLayerAddressIPv4"),),
    "pfcp":(
        ("pfcp.f_teid.teid","pfcp.f_teid.ipv4_addr"),
        ("pfcp.outer_hdr_creation.teid","pfcp.outer_hdr_creation.ipv4"),
    )
}


def collect_pdml(pcap:Path,protocol:str,filter_expr:str,decode_as:str)->str:
    if protocol not in ("ngap","pfcp"):
        raise ValueError("Only NGAP and PFCP hierarchy requested")
    if not pcap.exists() or pcap.stat().st_size<24:
        raise RuntimeError("No original packet capture")
    args=["tshark","-r",str(pcap),"-d",decode_as,"-Y",filter_expr,"-T","pdml"]
    proc=subprocess.run(args,capture_output=True,text=True,timeout=100)
    if proc.returncode:
        raise RuntimeError("Real protocol PDML decoder failed: "+
                           proc.stderr[-240:].replace("\n"," "))
    return proc.stdout


def count_ancestry(xml_text:str,protocol:str)->dict:
    """Count structural ancestors with both IE fields, export no values."""
    if protocol not in TARGETS:
        raise ValueError("Unknown protocol hierarchy")
    root=ET.fromstring(xml_text)
    if root.tag!="pdml":
        raise RuntimeError("Not packet PDML")
    frames=0
    marker_counts=Counter()
    pair_subtree=Counter()
    packet_pairs=Counter()
    markers={
        "ngap":(NGAP_REQ_TRANSFER,NGAP_RSP_TRANSFER,NGAP_GTP_TUNNEL),
        "pfcp":("pfcp.ie","pfcp.create_pdr","pfcp.created_pdr",
                "pfcp.create_far","pfcp.update_far"),
    }[protocol]
    for packet in root.findall("packet"):
        frames+=1
        for proto in packet.findall("proto"):
            if proto.get("name")!=protocol:
                continue
            for node in proto.iter("field"):
                name=node.get("name","")
                if name in markers:
                    marker_counts[name]+=1
                    leaves=Counter(x.get("name","") for x in node.iter("field"))
                    for left,right in TARGETS[protocol]:
                        if leaves[left]==1 and leaves[right]==1:
                            pair_subtree[left+"|"+right]+=1
            allnames=Counter(x.get("name","") for x in proto.iter("field"))
            for left,right in TARGETS[protocol]:
                if allnames[left]>0 and allnames[right]>0:
                    packet_pairs[left+"|"+right]+=1
    return {
        "protocol_decoded_packet_trees":frames,
        "request_transfer_element_nodes":marker_counts[NGAP_REQ_TRANSFER],
        "response_transfer_element_nodes":marker_counts[NGAP_RSP_TRANSFER],
        "gtp_tunnel_element_nodes":marker_counts[NGAP_GTP_TUNNEL],
        "pfcp_ie_container_nodes":marker_counts["pfcp.ie"],
        "same_named_IE_subtree_TEID_IP_pair_occurrences":sum(pair_subtree.values()),
        "whole_packet_TEID_and_IP_coobserved":sum(packet_pairs.values()),
        "hierarchical_ie_pairing_limit":"Counts are not authenticated PDU or PDR/FAR identity mappings",
    }


def direction_diagnosis(n:dict,p:dict)->dict:
    """2x2 matrix of local numeric+IPv4 role matches, with no ID proof."""
    ns=n["candidates"];ps=p["candidates"]
    result={}
    for target in ("ul_upf","dl_gnb"):
        for source in ("ul_upf","dl_gnb"):
            shared=set(ns[source])&set(ps[target])
            result["NGAP_"+source+"_vs_PFCP_"+target]=sum(
                len(ns[source][key])==1 and len(ps[target][key])==1 for key in shared
            )
    result["crossrole_IP_TEID_candidates_without_session_proof"]=(
        result["NGAP_dl_gnb_vs_PFCP_ul_upf"]+
        result["NGAP_ul_upf_vs_PFCP_dl_gnb"])
    return result


def analyze(pcap:Path)->dict:
    obs=phase18_analyze(pcap)
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
    obs["private_ie_tree_census"]={
        "ngap":count_ancestry(collect_pdml(
            pcap,"ngap","ngap.gTP_TEID","sctp.port==38412,ngap"),"ngap"),
        "pfcp":count_ancestry(collect_pdml(
            pcap,"pfcp","pfcp.msg_type == 51 || pfcp.msg_type == 52",
            "udp.port==8805,pfcp"),"pfcp"),
    }
    obs["private_direction_role_matrix"]=direction_diagnosis(n,p)
    assert not obs["n3_role_endpoint_bridge"]["cross_protocol_identity_join_proven"]
    return obs
