"""Stage 14 read-only PFCP observation, reversible lab N4 restriction and signature tests."""
import copy
from pathlib import Path

import pytest

from src.phase14_n4_live import (
    ALL_SERVICES, DROP_COUNTER_RE, PFCP_SVC, decode_capture,
    insert_rule, remove_rule, rule_cmd, sign_capture, run,
)
from src.phase9_receipts import create_ephemeral_key, verify_receipt


def test_firewall_may_only_change_smf_namespace_outgoing_pfcp():
    x=rule_cmd(2345,"-I")
    assert x[:6]==["sudo","-n","nsenter","-t","2345","-n"]
    assert x[-8:]==["iptables","-I","OUTPUT","1","-p","udp","--dport","8805","-j","DROP"][-8:]
    assert "--dport" in x and "8805" in x and x[-1]=="DROP"
    assert "OUTPUT" in x and "INPUT" not in x
    y=rule_cmd(2345,"-D")
    assert "-D" in y and "1" not in y
    with pytest.raises(ValueError):
        rule_cmd(2345,"-F")


def test_n4_real_packet_drop_counter_parses_packets_not_bytes():
    line=("Chain OUTPUT (policy ACCEPT 210 packets, 12000 bytes)\n"
          " pkts bytes target prot opt in out source destination\n"
          "  18 2800 DROP udp -- * * 0.0.0.0/0 0.0.0.0/0 udp dpt:8805\n")
    found=DROP_COUNTER_RE.search(line)
    assert found and int(found.group(1))==18 and int(found.group(2))==2800


def test_pfcp_signed_agent_and_pdu_phase_bound_to_key(tmp_path):
    private=tmp_path/"secret.pem"
    pub=create_ephemeral_key(private)
    observation={
        "replica":"11","phase":"n4_pfcp_drop",
        "firewall_drop_rule_installed":True,
        "phase_drop_packets":5,
        "pfcp_decoded_message_occurrences":0,
        "pfcp_type_occurrences":{},
    }
    d=sign_capture(private,"a"*32,"r11_phase1",2,observation)
    issued={"a"*32:("phase14_pfcp_host_capture","r11_phase1",2)}
    assert not verify_receipt(d,registered_keys={"phase14_pfcp_host_capture":pub},
                              pending=issued.copy(),accepted_sequences={})
    tracker={}
    assert verify_receipt(d,registered_keys={"phase14_pfcp_host_capture":pub},
                          pending=issued,accepted_sequences=tracker,
                          allowed_services=ALL_SERVICES)
    assert not verify_receipt(d,registered_keys={"phase14_pfcp_host_capture":pub},
                              pending=issued,accepted_sequences=tracker,
                              allowed_services=ALL_SERVICES)
    bad=copy.deepcopy(d)
    bad["payload"]["observation"]["phase_drop_packets"]=999
    assert not verify_receipt(bad,registered_keys={"phase14_pfcp_host_capture":pub},
                              pending={"a"*32:("phase14_pfcp_host_capture","r11_phase1",2)},
                              accepted_sequences={},allowed_services=ALL_SERVICES)
    assert PFCP_SVC=="Lab_PFCP_Captured_PacketCounts_and_SMFEgressDrop"


def test_real_lab_requires_explicit_authorization(tmp_path,monkeypatch):
    monkeypatch.delenv("ALLOW_PHASE14_DISPOSABLE_5GC",raising=False)
    with pytest.raises(RuntimeError,match="authorization"):
        run(tmp_path/"upstream_open5gs",tmp_path/"out","11")


def test_decoder_does_not_count_network_identifiers_as_sessions(tmp_path,monkeypatch):
    pcap=tmp_path/"fake.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1"+b"\x00"*24)
    class P:
        returncode=0
        stdout="1\n2\n5\n6\n50\n51\n50\n"
        stderr=""
    monkeypatch.setattr("src.phase14_n4_live.subprocess.run",lambda *args,**kw:P())
    x=decode_capture(pcap)
    assert x["pfcp_decoded_message_occurrences"]==7
    assert x["pfcp_type_occurrences"]["session_establishment_request"]==2
    assert "not sessions" in x["capture_caveat"]
