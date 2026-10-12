"""Phase18 negative controls for NGAP/PFCP role+IPv4 endpoint evidence."""
import copy
import pytest
from src.phase18_endpoints import (
    decode_ngap_endpoints,decode_pfcp_endpoints,
    compare_endpoints,ipv4_only
)
from src.phase18_live import run,sign,AGENT,SERVICE
from src.phase9_receipts import create_ephemeral_key,verify_receipt


def ngap(typ="ul",ip="172.22.0.8",teid="00:00:00:2a",pdu="1"):
    initial="1" if typ=="ul" else ""
    successful="1" if typ=="dl" else ""
    return "\t".join(("10.1",pdu,teid,ip,initial,successful,"29"))


def pfcp(typ="ul",ip="172.22.0.8",teid="42",seq="700"):
    if typ=="ul":
        return "\t".join(("51",seq,teid,ip,"","","172.22.0.8","172.22.0.12"))
    return "\t".join(("52",seq,"","",teid,ip,"172.22.0.12","172.22.0.8"))


def nums(ul=1,dl=0):
    return {"direction_gated_unique_numeric_ul_teid_candidates":ul,
            "direction_gated_unique_numeric_dl_teid_candidates":dl}


def test_real_numeric_equal_and_IP_equal_with_external_role_only_candidate():
    n=decode_ngap_endpoints([ngap()])
    p=decode_pfcp_endpoints([pfcp()])
    out=compare_endpoints(n,p,nums())
    assert out["ul_upf"]["strict_ipv4_teid_role_candidates"]==1
    assert out["strict_endpoint_candidates_observed"]==1
    assert not out["cross_protocol_identity_join_proven"]
    assert not out["verified_ngap_asn1_transfer_nesting"]
    assert not out["verified_pfcp_pdr_far_ie_nesting"]
    assert "172.22." not in str(out)
    assert "42" not in str(out)


def test_same_numeric_TEID_at_wrong_IPV4_cannot_be_linked():
    n=decode_ngap_endpoints([ngap(ip="172.22.0.8")])
    p=decode_pfcp_endpoints([pfcp(ip="172.22.0.9")])
    out=compare_endpoints(n,p,nums())
    assert out["ul_upf"]["strict_ipv4_teid_role_candidates"]==0
    assert out["ul_upf"]["numeric_equal_but_ip_or_role_unverified"]==1


def test_roles_must_match_and_correct_PFCP_type():
    n=decode_ngap_endpoints([ngap(typ="dl",ip="172.22.0.3")])
    p=decode_pfcp_endpoints([pfcp(typ="ul",ip="172.22.0.3")])
    out=compare_endpoints(n,p,nums(ul=1,dl=1))
    assert out["strict_endpoint_candidates_observed"]==0
    p2=decode_pfcp_endpoints([pfcp(typ="dl",ip="172.22.0.3")])
    out2=compare_endpoints(n,p2,nums(ul=0,dl=1))
    assert out2["dl_gnb"]["strict_ipv4_teid_role_candidates"]==1


def test_multi_TEID_frame_not_guessed_by_flat_field_zip():
    n=decode_ngap_endpoints([ngap(teid="00:00:00:2a,00:00:00:2b",ip="172.22.0.8,172.22.0.9")])
    p=decode_pfcp_endpoints([pfcp(teid="42,43",ip="172.22.0.8,172.22.0.9")])
    out=compare_endpoints(n,p,nums())
    assert out["strict_endpoint_candidates_observed"]==0
    assert out["ngap_frame_observability"]["NGAP_unpaired_or_ambiguous_frames"]==1
    assert out["pfcp_frame_observability"]["PFCP_unpaired_or_ambiguous_frames"]==1


def test_missing_direction_endpoint_or_PDU_ID_abstains():
    n=decode_ngap_endpoints([
        ngap(pdu=""),ngap(ip=""),ngap(ip="239.2.3.4"),
        "\t".join(("10.1","1","00:00:00:2a","172.22.0.8","","","29"))])
    out=compare_endpoints(n,decode_pfcp_endpoints([pfcp()]),nums())
    assert out["strict_endpoint_candidates_observed"]==0
    assert out["ngap_frame_observability"]["NGAP_unpaired_or_ambiguous_frames"]==4
    assert ipv4_only("0.0.0.0") is None


def test_collision_separate_UE_contexts_with_identical_endpoint_abstains():
    n=decode_ngap_endpoints([ngap(pdu="1"),ngap(pdu="2")])
    p=decode_pfcp_endpoints([pfcp()])
    out=compare_endpoints(n,p,nums())
    assert out["strict_endpoint_candidates_observed"]==0
    assert out["ul_upf"]["same_endpoint_collision_abstentions"]==1


def test_conflicting_PFCP_transaction_same_endpoint_abstains():
    n=decode_ngap_endpoints([ngap()])
    p=decode_pfcp_endpoints([pfcp(seq="100"),pfcp(seq="101")])
    out=compare_endpoints(n,p,nums())
    assert out["strict_endpoint_candidates_observed"]==0
    assert out["ul_upf"]["same_endpoint_collision_abstentions"]==1


def test_mirrored_duplicate_packet_does_not_invent_collision():
    n=decode_ngap_endpoints([ngap(),ngap()])
    p=decode_pfcp_endpoints([pfcp(),pfcp()])
    assert compare_endpoints(n,p,nums())["strict_endpoint_candidates_observed"]==1


def test_endpoint_more_than_numeric_baseline_fails_closed():
    with pytest.raises(ValueError,match="more TEIDs"):
        compare_endpoints(decode_ngap_endpoints([ngap()]),
                          decode_pfcp_endpoints([pfcp()]),nums(0))


def test_signed_role_endpoint_cannot_be_forged(tmp_path):
    key=tmp_path/"private.pem"
    pub=create_ephemeral_key(key)
    d=sign(key,"a"*32,"r11_normal_0",1,{"n3_role_endpoint_bridge":{
        "strict_endpoint_candidates_observed":1,
        "cross_protocol_identity_join_proven":False}})
    pend={"a"*32:(AGENT,"r11_normal_0",1)}
    consumed={}
    assert verify_receipt(d,registered_keys={AGENT:pub},pending=pend,
                          accepted_sequences=consumed,allowed_services=(SERVICE,))
    assert not verify_receipt(d,registered_keys={AGENT:pub},pending=pend,
                              accepted_sequences=consumed,allowed_services=(SERVICE,))
    altered=copy.deepcopy(d)
    altered["payload"]["observation"]["n3_role_endpoint_bridge"]["cross_protocol_identity_join_proven"]=True
    assert not verify_receipt(altered,registered_keys={AGENT:pub},
        pending={"a"*32:(AGENT,"r11_normal_0",1)},
        accepted_sequences={},allowed_services=(SERVICE,))


def test_no_fault_outside_authorized_ephemeral_5gc(monkeypatch,tmp_path):
    monkeypatch.delenv("ALLOW_PHASE18_DISPOSABLE_LAB",raising=False)
    with pytest.raises(RuntimeError,match="authorization"):
        run(tmp_path/"upstream_open5gs",tmp_path/"out","11")
