"""Phase19 regression controls: genuine dual UE prerequisite and safe PDML structure."""
import copy
import pytest
from src.phase19_pdml import count_ancestry,direction_diagnosis,collect_pdml
from src.phase18_endpoints import decode_ngap_endpoints,decode_pfcp_endpoints
from src.phase19_live import run,sign,AGENT,SERVICE,dual_ue_trial
from src.phase9_receipts import create_ephemeral_key,verify_receipt


def fake_ngap_xml():
    return """<pdml><packet><proto name="ngap">
<field name="ngap.PDUSessionResourceSetupRequestTransfer_element">
  <field name="ngap.GTPTunnel_element">
    <field name="ngap.gTP_TEID" show="0000002a" value="0000002a"/>
    <field name="ngap.TransportLayerAddressIPv4" show="172.22.0.8" value="ac160008"/>
  </field>
</field></proto></packet></pdml>"""


def fake_pfcp_xml():
    return """<pdml><packet><proto name="pfcp">
<field name="pfcp.ie">
  <field name="pfcp.f_teid.teid" show="42" value="0000002a"/>
  <field name="pfcp.f_teid.ipv4_addr" show="172.22.0.8" value="ac160008"/>
</field></proto></packet></pdml>"""


def test_ngap_true_same_subtree_and_raw_identifiers_never_exported():
    c=count_ancestry(fake_ngap_xml(),"ngap")
    assert c["request_transfer_element_nodes"]==1
    assert c["response_transfer_element_nodes"]==0
    assert c["gtp_tunnel_element_nodes"]==1
    assert c["same_named_IE_subtree_TEID_IP_pair_occurrences"]==2
    assert "172.22.0.8" not in str(c)
    assert "0000002a" not in str(c)


def test_pfcp_IE_ancestry_pair_not_just_frame():
    c=count_ancestry(fake_pfcp_xml(),"pfcp")
    assert c["pfcp_ie_container_nodes"]==1
    assert c["same_named_IE_subtree_TEID_IP_pair_occurrences"]==1
    assert c["whole_packet_TEID_and_IP_coobserved"]==1


def test_flat_cooccurrence_without_shared_ie_ancestry_abstains():
    xml="""<pdml><packet><proto name="ngap">
    <field name="first"><field name="ngap.gTP_TEID" show="42"/></field>
    <field name="second"><field name="ngap.TransportLayerAddressIPv4" show="172.22.0.8"/></field>
    </proto></packet></pdml>"""
    c=count_ancestry(xml,"ngap")
    assert c["same_named_IE_subtree_TEID_IP_pair_occurrences"]==0
    assert c["whole_packet_TEID_and_IP_coobserved"]==1


def test_pdml_invalid_and_unapproved_decoder_fails_closed(tmp_path):
    with pytest.raises(Exception):
        count_ancestry("<pdml><packet>", "pfcp")
    with pytest.raises(ValueError):
        count_ancestry(fake_pfcp_xml(),"nas")
    with pytest.raises(ValueError):
        collect_pdml(tmp_path/"raw.pcap","sip","sip","udp.port==5060,sip")


def ngap_line(typ="ul",pdu="1"):
    return "\t".join(("10.1",pdu,"00:00:00:2a","172.22.0.8",
                      "1" if typ=="ul" else "",
                      "1" if typ=="dl" else "","29"))


def pfcp_line():
    return "\t".join(("51","99","42","172.22.0.8","","",
                      "172.22.0.8","172.22.0.12"))


def test_2x2_role_matrix_detects_swapped_role_without_identity_proof():
    n=decode_ngap_endpoints([ngap_line("dl")])
    p=decode_pfcp_endpoints([pfcp_line()])
    m=direction_diagnosis(n,p)
    assert m["NGAP_dl_gnb_vs_PFCP_ul_upf"]==1
    assert m["NGAP_ul_upf_vs_PFCP_ul_upf"]==0
    assert "172.22." not in str(m) and "42" not in str(m)


def test_two_real_UE_identity_context_collision_causes_abstention():
    # Both genuinely provisioned UEs may have local NAS PDU ID 1.
    # Numeric TEID+same IPv4 in different PDU contexts must not be
    # upgraded to session identity, even if same window.
    n=decode_ngap_endpoints([ngap_line("ul","1"),ngap_line("ul","2")])
    p=decode_pfcp_endpoints([pfcp_line()])
    m=direction_diagnosis(n,p)
    assert m["NGAP_ul_upf_vs_PFCP_ul_upf"]==0


def test_sign_dual_UE_evidence_nonce_and_no_forged_session_join(tmp_path):
    key=tmp_path/"agent.pem"
    pub=create_ephemeral_key(key)
    d=sign(key,"a"*32,"r11_normal_0",1,
           {"real_UE1_PDU_success":1,"real_UE2_PDU_success":1,
            "cross_protocol_identity_join_proven":False})
    pending={"a"*32:(AGENT,"r11_normal_0",1)}
    seq={}
    assert verify_receipt(d,registered_keys={AGENT:pub},
                          pending=pending,accepted_sequences=seq,
                          allowed_services=(SERVICE,))
    assert not verify_receipt(d,registered_keys={AGENT:pub},
                              pending=pending,accepted_sequences=seq,
                              allowed_services=(SERVICE,))
    forged=copy.deepcopy(d)
    forged["payload"]["observation"]["cross_protocol_identity_join_proven"]=True
    assert not verify_receipt(forged,registered_keys={AGENT:pub},
        pending={"a"*32:(AGENT,"r11_normal_0",1)},accepted_sequences={},
        allowed_services=(SERVICE,))


def test_no_live_dual_UE_without_explicit_isolation(monkeypatch,tmp_path):
    monkeypatch.delenv("ALLOW_PHASE19_DISPOSABLE_LAB",raising=False)
    with pytest.raises(RuntimeError,match="authorization"):
        run(tmp_path/"upstream_open5gs",tmp_path/"out","11")
