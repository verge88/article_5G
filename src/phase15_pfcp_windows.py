"""Phase 15: real PFCP frames grouped into *single UE-attempt windows*.

A PFCP Session Establishment 50/51 transaction is paired by PFCP sequence
number + reverse transport endpoints ONLY within one measured capture window.
No IMSI, IP address, SEID, PFCP sequence ID or packet payload is exported.

Linux tcpdump -i any can mirror the same frame at multiple interfaces.
Duplicate observations within <=50ms are coalesced for diagnostic counts;
retransmissions after 50ms may still be considered independent. Matching
is NOT a proof of one-to-one mapping to a NAS PDU procedure.
"""
from __future__ import annotations

from collections import Counter,defaultdict
from pathlib import Path
import subprocess

from .phase14_n4_live import MESSAGE_TYPES

MATCH_TYPES=(50,51)
DEDUP_WINDOW_S=0.05


def parse_tshark_frames(lines:list[str])->list[dict]:
    result=[]
    for line in lines:
        parts=line.rstrip("\n").split("\t")
        if len(parts)!=6:
            continue
        epoch,src,dst,port_src,port_dst,msg_seq=parts
        if "|" not in msg_seq:
            continue
        msg_type,seq=msg_seq.split("|",1)
        if not epoch or not src or not dst or not msg_type.isdigit():
            continue
        try:
            t=float(epoch)
            tnum=int(msg_type)
            s=int(seq) if seq.isdigit() else None
            a=int(port_src)
            b=int(port_dst)
        except (ValueError,OverflowError):
            continue
        if not (0<=tnum<=255 and 0<=a<=65535 and 0<=b<=65535):
            continue
        result.append({
            "time":t,"type":tnum,"sequence":s,"src":src,"dst":dst,
            "srcport":a,"dstport":b,
        })
    return sorted(result,key=lambda x:x["time"])


def digest_trial_frames(frames:list[dict])->dict:
    ordered=sorted(frames,key=lambda x:x["time"])
    distinct=[]
    last_seen={}
    for p in ordered:
        key=(p["type"],p["sequence"],p["src"],p["dst"],
             p["srcport"],p["dstport"])
        last=last_seen.get(key)
        if last is not None and p["time"]-last<=DEDUP_WINDOW_S:
            continue
        last_seen[key]=p["time"]
        distinct.append(p)
    types=Counter(MESSAGE_TYPES.get(str(p["type"]),"other") for p in distinct)
    reqs=[p for p in distinct if p["type"]==50 and p["sequence"] is not None]
    resps=[p for p in distinct if p["type"]==51 and p["sequence"] is not None]
    used=set()
    matched=0
    durations=[]
    for request in reqs:
        matches=[(index,response) for index,response in enumerate(resps)
                 if index not in used
                 and response["sequence"]==request["sequence"]
                 and response["src"]==request["dst"]
                 and response["dst"]==request["src"]
                 and response["srcport"]==request["dstport"]
                 and response["dstport"]==request["srcport"]
                 and response["time"]>=request["time"]]
        if matches:
            index,response=min(matches,key=lambda x:x[1]["time"])
            used.add(index)
            matched+=1
            durations.append((response["time"]-request["time"])*1000)
    return {
        "captured_pfcp_frame_observations_raw":len(ordered),
        "captured_pfcp_messages_dedup_50ms":len(distinct),
        "pfcp_type_occurrences_dedup":dict(sorted(types.items())),
        "session_establishment_requests":len(reqs),
        "session_establishment_responses":len(resps),
        "session_establishment_matched_pairs":matched,
        "session_establishment_unmatched_requests":len(reqs)-matched,
        "session_establishment_unmatched_responses":len(resps)-matched,
        "matching_scope":"within trial only: sequence + reverse src,dst,UDP ports, response later than request",
        "pair_round_trip_min_ms":round(min(durations),3) if durations else None,
        "pair_round_trip_max_ms":round(max(durations),3) if durations else None,
        "capture_and_matching_limitations":[
            "No cryptographic peer authentication",
            "Packet capture on any interface may contain duplicates",
            "Repeated identical tuples within 50ms heuristically deduplicated",
            "PFCP sequence number is not a unique NAS or PDU identifier",
            "Unmatched PFCP might be capture loss, not a proven missing network reply",
            "No SEID, IP address, PFCP sequence or user data exported",
        ],
    }


def decode_trial_pcap(pcap:Path)->dict:
    if not pcap.exists() or pcap.stat().st_size<24:
        raise RuntimeError("No real PFCP PCAP header")
    args=[
        "tshark","-r",str(pcap),"-d","udp.port==8805,pfcp",
        "-Y","pfcp","-T","fields",
        "-E","separator=/t","-E","occurrence=f",
        "-e","frame.time_epoch","-e","ip.src","-e","ip.dst",
        "-e","udp.srcport","-e","udp.dstport",
        "-e","pfcp.msg_type","-e","pfcp.seqno",
    ]
    proc=subprocess.run(args,capture_output=True,text=True,timeout=70)
    if proc.returncode:
        raise RuntimeError("PFCP frame decoder failed: "+proc.stderr[-280:])
    lines=[]
    for ln in proc.stdout.splitlines():
        cols=ln.split("\t")
        if len(cols)==7:
            lines.append("\t".join(cols[:5])+"\t"+cols[5]+"|"+cols[6])
    return digest_trial_frames(parse_tshark_frames(lines))
