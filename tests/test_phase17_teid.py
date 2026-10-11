"""Stage17: exact 32-bit N3 TEID numeric parsing, duplicate contexts, trust limits."""
import copy
import pytest
from src.phase17_teid_bridge import (
    parse_ngap_teid,parse_pfcp_teid,parse_ngap_lines,
    parse_pfcp_lines,compare_teid_candidates
)
from src.phase17_live import run,sign,AGENT,SERVICE
from src.phase9_receipts import create_ephemeral_key,verify_receipt


def test_ngap_4byte_hex_and_pfcp_decimal_are_distinct_formats():
    assert parse_ngap_teid("00:00:00:2a")==42
    assert parse_ngap_teid("0000002a")==42
    assert parse_ngap_teid("0x0000002a")==42
    assert parse_ngap_teid("00 00 00 2A")==42
    assert parse_ngap_teid("0x0")==None
    assert parse_ngap_teid("00000000") is None
    assert parse_ngap_teid("not-a-teid") is None
    assert parse_pfcp_teid("42")==42
    assert parse_pfcp_teid("0x2a")==42
    assert parse_pfcp_teid("0")==None
    assert parse_pfcp_teid("4294967296")==None


def ngap_one():
    return parse_ngap_lines(["10.002\t1\t00:00:00:2a\t29"])


def pfcp_ul():
    return parse_pfcp_lines(["10.100\t51\t700\t42\t\t172.22.0.2\t172.22.0.1"])


def test_observed_ul_tunnel_candidate_is_not_proven_pdu_identity():
    ngap=ngap_one()
    pfcp=pfcp_ul()
    x=compare_teid_candidates(ngap,pfcp)
    assert x["direction_gated_unique_numeric_ul_teid_candidates"]==1
    assert x["direction_gated_unique_numeric_dl_teid_candidates"]==0
    assert not x["cross_protocol_identity_join_proven"]
    assert not x["verified_transport_endpoint_and_full_ie_context"]
    assert "candidate" in x["identity_verdict"]
    assert "172.22." not in str(x) and "42" not in str(x)


def test_downlink_outer_header_requires_pfcp_modification_request():
    n=parse_ngap_lines(["10.0\t1\t00:00:00:2a\t29"])
    p=parse_pfcp_lines(["10.05\t52\t91\t\t42\t172.22.0.1\t172.22.0.2"])
    x=compare_teid_candidates(n,p)
    assert x["direction_gated_unique_numeric_dl_teid_candidates"]==1
    assert not x["cross_protocol_identity_join_proven"]
    wrong=parse_pfcp_lines(["10.05\t50\t91\t42\t42\t172.22.0.1\t172.22.0.2"])
    assert not compare_teid_candidates(n,wrong)["numeric_tunnel_candidate_observed"]


def test_colliding_numeric_tunnel_in_multiple_pfcp_transaction_contexts_abstains():
    n=ngap_one()
    p=parse_pfcp_lines([
        "10.0\t51\t700\t42\t\t172.22.0.2\t172.22.0.1",
        "10.2\t51\t701\t42\t\t172.22.0.2\t172.22.0.1"])
    result=compare_teid_candidates(n,p)
    assert result["direction_gated_ambiguous_ul_teids"]==1
    assert result["direction_gated_unique_numeric_ul_teid_candidates"]==0
    assert result["cross_protocol_identity_join_proven"] is False


def test_mirrored_single_pfcp_frame_is_one_transaction_not_false_collision():
    p=parse_pfcp_lines([
        "10.0\t51\t700\t42\t\t172.22.0.2\t172.22.0.1",
        "10.0002\t51\t700\t42\t\t172.22.0.2\t172.22.0.1"])
    result=compare_teid_candidates(ngap_one(),p)
    assert result["direction_gated_ambiguous_ul_teids"]==0
    assert result["direction_gated_unique_numeric_ul_teid_candidates"]==1


def test_ngap_conflicting_pdus_with_same_teid_must_abstain():
    n=parse_ngap_lines([
        "10.0\t1\t00:00:00:2a\t29",
        "11.0\t2\t00:00:00:2a\t29"])
    result=compare_teid_candidates(n,pfcp_ul())
    assert result["direction_gated_unique_numeric_ul_teid_candidates"]==0
    assert result["direction_gated_ambiguous_ul_teids"]==1


def test_no_ngap_pdu_context_makes_n3_candidate_unprovable():
    n=parse_ngap_lines(["10.0\t\t00:00:00:2a\t29"])
    result=compare_teid_candidates(n,pfcp_ul())
    assert result["direction_gated_unique_numeric_ul_teid_candidates"]==0
    assert result["identity_verdict"]=="insufficient_identifier_evidence"


def test_cryptographically_signed_candidate_not_trust_domain(tmp_path):
    k=tmp_path/"lab.pem"
    pub=create_ephemeral_key(k)
    evidence={"n3_teid_candidate_bridge":{
        "direction_gated_unique_numeric_ul_teid_candidates":1,
        "cross_protocol_identity_join_proven":False}}
    r=sign(k,"a"*32,"r11_normal_0",1,evidence)
    pending={"a"*32:(AGENT,"r11_normal_0",1)}
    accepted={}
    assert verify_receipt(r,registered_keys={AGENT:pub},pending=pending,
                          accepted_sequences=accepted,allowed_services=(SERVICE,))
    assert not verify_receipt(r,registered_keys={AGENT:pub},pending=pending,
                              accepted_sequences=accepted,allowed_services=(SERVICE,))
    tampered=copy.deepcopy(r)
    tampered["payload"]["observation"]["n3_teid_candidate_bridge"]["cross_protocol_identity_join_proven"]=True
    assert not verify_receipt(tampered,registered_keys={AGENT:pub},
        pending={"a"*32:(AGENT,"r11_normal_0",1)},
        accepted_sequences={},allowed_services=(SERVICE,))


def test_only_disposable_5gc_fault_injection(monkeypatch,tmp_path):
    monkeypatch.delenv("ALLOW_PHASE17_DISPOSABLE_LAB",raising=False)
    with pytest.raises(RuntimeError,match="authorization"):
        run(tmp_path/"upstream_open5gs",tmp_path/"out","11")
