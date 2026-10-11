"""Phase16: safeguards against treating NGAP/PFCP/HTTP2 co-observation as identity."""
import copy
import pytest
from src.phase16_crossplane import ngap_counts,http2_nsmf_counts,seid_count,interpret_join
from src.phase16_live import sign,run,AGENT,SERVICE
from src.phase9_receipts import create_ephemeral_key,verify_receipt


def mock_pfcp(pair=1):
    return {"session_establishment_matched_pairs":pair}


def test_ngap_session_id_cardinality_but_not_exported():
    x=ngap_counts(["5\t29","5\t29","9\t32","\t10"])
    assert x["ngap_pdu_id_occurrences"]==3
    assert x["ngap_pdu_id_distinct_count"]==2
    assert "5" not in str(x.values()) or "ngap_pdu_id" in str(x)


def test_nsmf_pair_only_same_http2_connection_and_stream():
    raw=("\t".join(["10.0","100","1","/nsmf-pdusession/v1/sm-contexts","POST",""])+"\n"
         +"\t".join(["10.2","100","1","","","201"])+"\n"
         +"\t".join(["10.5","101","2","/nsmf-pdusession/v1/sm-contexts","POST",""])+"\n"
         +"\t".join(["10.8","999","2","","","200"]))
    out=http2_nsmf_counts(raw)
    assert out["nsmf_http2_unique_request_streams"]==2
    assert out["nsmf_http2_matched_responses"]==1
    assert out["nsmf_http2_unanswered_streams"]==1


def test_pfcp_seid_count_does_not_export_raw_seid():
    x=seid_count(["0","400000","0x6A","400000",""])
    assert x["pfcp_header_nonzero_seid_occurrences"]==3
    assert x["pfcp_header_distinct_nonzero_seids"]==2
    assert "400000" not in str(x)


def test_three_modalities_visible_still_never_prove_interprotocol_join():
    n2={"ngap_pdu_id_visible":True}
    sbi={"nsmf_http2_unique_request_streams":4}
    n4=mock_pfcp(1)
    x=interpret_join(n2,sbi,n4)
    assert x["naive_three_source_time_only_join_would_claim_identity"]
    assert x["causality_verdict"]=="insufficient_identity_binding"
    assert not x["cross_protocol_identity_join_proven"]
    # The underlying names are unrelated identifiers. Swapping them or
    # repeating them cannot create a real SMF mapping.
    n2["ngap_pdu_id_count"]=5
    assert not interpret_join(n2,sbi,n4)["cross_protocol_identity_join_proven"]
    with pytest.raises(ValueError,match="does not implement"):
        interpret_join(n2,sbi,n4,bridge={"not_authenticated":True})


def test_missing_ngap_prevents_naive_all_three_claim():
    x=interpret_join({"ngap_pdu_id_visible":False},
                     {"nsmf_http2_unique_request_streams":3},mock_pfcp(1))
    assert x["observed_sources_count"]==2
    assert not x["naive_three_source_time_only_join_would_claim_identity"]


def test_signed_threeplane_record_binds_trial_nonce_and_prevents_tampering(tmp_path):
    key=tmp_path/"private.pem"
    pub=create_ephemeral_key(key)
    evidence={"ngap":{"ngap_pdu_id_distinct_count":1},
              "identity":{"cross_protocol_identity_join_proven":False}}
    doc=sign(key,"1"*32,"r11_normal_0",1,evidence)
    pending={"1"*32:(AGENT,"r11_normal_0",1)}
    accepted={}
    assert verify_receipt(doc,registered_keys={AGENT:pub},
                          pending=pending,accepted_sequences=accepted,
                          allowed_services=(SERVICE,))
    assert not verify_receipt(doc,registered_keys={AGENT:pub},
                              pending=pending,accepted_sequences=accepted,
                              allowed_services=(SERVICE,))
    forged=copy.deepcopy(doc)
    forged["payload"]["observation"]["identity"]["cross_protocol_identity_join_proven"]=True
    assert not verify_receipt(forged,registered_keys={AGENT:pub},
        pending={"1"*32:(AGENT,"r11_normal_0",1)},accepted_sequences={},
        allowed_services=(SERVICE,))


def test_reject_non_disposable_lab_intervention(monkeypatch,tmp_path):
    monkeypatch.delenv("ALLOW_PHASE16_DISPOSABLE_LAB",raising=False)
    with pytest.raises(RuntimeError,match="authorization"):
        run(tmp_path/"upstream_open5gs",tmp_path/"out","11")
