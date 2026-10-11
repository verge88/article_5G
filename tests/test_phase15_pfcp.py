"""Phase 15: preregistered per-trial PFCP pairing, half-drop and verification."""
import copy
import pytest

from src.phase15_pfcp_windows import parse_tshark_frames,digest_trial_frames
from src.phase15_live import partial_cmd, kernel_drop_count,run
from src.phase14_n4_live import sign_capture,ALL_SERVICES
from src.phase9_receipts import create_ephemeral_key,verify_receipt


def frame(t,msg,seq,src="172.22.0.1",dst="172.22.0.2",sport=8805,dport=8805):
    return f"{t}\t{src}\t{dst}\t{sport}\t{dport}\t{msg}|{seq}"


def test_real_pfcp_pair_sequence_endpoint_and_time_correlation():
    rows=[
        frame(10.0000,50,155),
        frame(10.0003,50,155),  # host capture mirror, <50ms
        frame(10.0030,51,155,"172.22.0.2","172.22.0.1"),
        frame(10.0060,51,156,"172.22.0.2","172.22.0.1"),
        frame(10.0090,50,157),
    ]
    x=digest_trial_frames(parse_tshark_frames(rows))
    assert x["captured_pfcp_frame_observations_raw"]==5
    assert x["session_establishment_requests"]==2
    assert x["session_establishment_responses"]==2
    assert x["session_establishment_matched_pairs"]==1
    assert x["session_establishment_unmatched_requests"]==1
    assert x["session_establishment_unmatched_responses"]==1
    assert x["pair_round_trip_min_ms"]==pytest.approx(3)
    assert "172." not in str(x) and "155" not in str(x)


def test_pfcp_unmatched_wrong_reverse_endpoints_and_early_response():
    rows=[
        frame(8,51,41,"172.22.0.2","172.22.0.1"),
        frame(9,50,41),
        frame(10,51,41,"172.22.0.8","172.22.0.1"),
    ]
    x=digest_trial_frames(parse_tshark_frames(rows))
    assert x["session_establishment_matched_pairs"]==0


def test_multiple_attempts_stay_in_separate_windows_and_no_personal_identifiers():
    first=digest_trial_frames(parse_tshark_frames([frame(10,50,101)]))
    second=digest_trial_frames(parse_tshark_frames([
        frame(20,51,101,"172.22.0.2","172.22.0.1")]))
    assert first["session_establishment_matched_pairs"]==0
    assert second["session_establishment_matched_pairs"]==0
    assert first["session_establishment_unmatched_requests"]==1
    assert second["session_establishment_unmatched_responses"]==1


def test_every_second_outgoing_smf_pfcp_only():
    x=partial_cmd(1077,"-I")
    assert x[:6]==["sudo","-n","nsenter","-t","1077","-n"]
    assert "OUTPUT" in x and "INPUT" not in x
    assert x[-11:]==["-p","udp","--dport","8805","-m","statistic",
                     "--mode","nth","--every","2","--packet","0","-j","DROP"][-11:]
    assert "8805" in x and "--every" in x
    with pytest.raises(ValueError):
        partial_cmd(1077,"-F")


def test_counter_for_one_actual_smf_n4_drop_rule(monkeypatch):
    text=("Chain OUTPUT (policy ACCEPT 210 packets, 12000 bytes)\n"
          " pkts bytes target prot opt in out source destination\n"
          "  9 880 DROP udp -- * * 0.0.0.0/0 0.0.0.0/0 udp dpt:8805 statistic mode nth every 2 packet 0\n")
    monkeypatch.setattr("src.phase15_live.cmd",lambda *a,**kw:text)
    assert kernel_drop_count(2345)==9


def test_sign_real_per_trial_pfcp_summary_and_replay(tmp_path):
    k=tmp_path/"pfcp-sign.pem"
    pub=create_ephemeral_key(k)
    x=digest_trial_frames(parse_tshark_frames([
        frame(1,50,44),frame(1.002,51,44,"172.22.0.2","172.22.0.1")]))
    x["pfcp_packets_dropped_by_host_lab_firewall"]=0
    receipt=sign_capture(k,"f"*32,"r11_normal_0",1,x)
    pending={"f"*32:("phase14_pfcp_host_capture","r11_normal_0",1)}
    accepted={}
    assert verify_receipt(receipt,registered_keys={"phase14_pfcp_host_capture":pub},
        pending=pending,accepted_sequences=accepted,allowed_services=ALL_SERVICES)
    assert not verify_receipt(receipt,registered_keys={"phase14_pfcp_host_capture":pub},
        pending=pending,accepted_sequences=accepted,allowed_services=ALL_SERVICES)
    forged=copy.deepcopy(receipt)
    forged["payload"]["observation"]["session_establishment_matched_pairs"]=99
    assert not verify_receipt(forged,registered_keys={"phase14_pfcp_host_capture":pub},
        pending={"f"*32:("phase14_pfcp_host_capture","r11_normal_0",1)},
        accepted_sequences={},allowed_services=ALL_SERVICES)


def test_no_fault_without_disposable_lab_opt_in(tmp_path,monkeypatch):
    monkeypatch.delenv("ALLOW_PHASE15_DISPOSABLE_LAB",raising=False)
    with pytest.raises(RuntimeError,match="authorization"):
        run(tmp_path/"upstream_open5gs",tmp_path/"out","11")
