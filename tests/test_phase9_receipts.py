"""Phase-9 cryptographic and scheduling regression tests (no live NF required)."""
import copy
import json
import secrets
import time
from pathlib import Path

import pytest

from src.phase9_receipts import (
    create_ephemeral_key, produce_receipt, verify_receipt, SCHEMA,
)
from src.phase9_live import arm_plan, run, negative_verification_tests


def lab_observation():
    return {
        "http_status": 200, "http_version": "2", "latency_ms": 1.0,
        "response_body_bytes": 230, "advertised_smf_profiles": 1,
        "transport_success": True, "agent_elapsed_ms": 2.0,
    }


def setup_receipt(tmp_path: Path, monkeypatch):
    key=tmp_path/"agent.pem"
    pub=create_ephemeral_key(key)
    monkeypatch.setattr("src.phase9_receipts.nrf_discovery",lambda endpoint: lab_observation())
    nonce=secrets.token_hex(16)
    signed=produce_receipt(key_path=key,agent_id="nrf_fixed",challenge=nonce,
                           trial_token="trial_000",sequence=1,endpoint="http://lab.example")
    return signed, {"nrf_fixed":pub}, {nonce:("nrf_fixed","trial_000",1)}


def test_valid_signed_laboratory_receipt_and_replay_rejection(tmp_path,monkeypatch):
    receipt,pubs,pending=setup_receipt(tmp_path,monkeypatch)
    accepted={}
    assert receipt["payload"]["schema"]==SCHEMA
    assert verify_receipt(receipt,registered_keys=pubs,pending=pending,
                          accepted_sequences=accepted)
    assert accepted["nrf_fixed"]==1
    assert not verify_receipt(receipt,registered_keys=pubs,pending=pending,
                              accepted_sequences=accepted)


def test_mutating_a_real_observation_field_breaks_signature(tmp_path,monkeypatch):
    receipt,pubs,pending=setup_receipt(tmp_path,monkeypatch)
    for field,val in (("http_status",503),("advertised_smf_profiles",0),
                      ("latency_ms",700.)):
        altered=copy.deepcopy(receipt)
        altered["payload"]["observation"][field]=val
        assert not verify_receipt(altered,registered_keys=pubs,
                                  pending=pending.copy(),accepted_sequences={})


def test_nonce_and_freshness_are_bound_to_challenge(tmp_path,monkeypatch):
    receipt,pubs,pending=setup_receipt(tmp_path,monkeypatch)
    assert not verify_receipt(receipt,registered_keys=pubs,
                              pending={},accepted_sequences={})
    assert not verify_receipt(receipt,registered_keys=pubs,
                              pending=pending.copy(),accepted_sequences={},
                              now=receipt["payload"]["measured_at_unix"]+60)
    assert not verify_receipt(receipt,registered_keys=pubs,
                              pending=pending.copy(),accepted_sequences={},
                              now=receipt["payload"]["measured_at_unix"]-10)


def test_substitution_of_key_or_issuer_rejected(tmp_path,monkeypatch):
    receipt,pubs,pending=setup_receipt(tmp_path,monkeypatch)
    wrong=copy.deepcopy(receipt)
    wrong["payload"]["agent_id"]="nrf_adaptive"
    bad_keys={"nrf_fixed":pubs["nrf_fixed"],"nrf_adaptive":pubs["nrf_fixed"]}
    assert not verify_receipt(wrong,registered_keys=bad_keys,
                              pending=pending.copy(),accepted_sequences={})
    other=create_ephemeral_key(tmp_path/"other.pem")
    assert not verify_receipt(receipt,registered_keys={"nrf_fixed":other},
                              pending=pending.copy(),accepted_sequences={})


def test_all_five_adversarial_receipt_mutations_rejected(tmp_path,monkeypatch):
    receipt,pubs,pending=setup_receipt(tmp_path,monkeypatch)
    pubs["nrf_adaptive"]=create_ephemeral_key(tmp_path/"second.pem")
    checks=negative_verification_tests(receipt,pubs,pending)
    assert len(checks)==5 and all(checks.values())


def test_equal_four_probe_budget_schedule_does_not_use_intervention_label():
    measurements=[
        {"ue_pdu_session_accepted":1},
        {"ue_pdu_session_accepted":0},
        {"ue_pdu_session_accepted":0},
    ]
    assert arm_plan(0,measurements[0],True,4)==(True,False)
    assert arm_plan(7,measurements[1],False,4)==(False,False)
    assert arm_plan(8,measurements[2],True,4)==(True,True)
    assert arm_plan(9,measurements[2],True,0)==(False,False)


def test_active_lab_requires_explicit_guard(tmp_path,monkeypatch):
    monkeypatch.delenv("ALLOW_PHASE9_DISPOSABLE_5GC",raising=False)
    with pytest.raises(RuntimeError,match="authorization guard"):
        run(tmp_path/"upstream_open5gs",tmp_path/"out")


def test_public_research_artifact_has_no_secret_material(tmp_path):
    pub=create_ephemeral_key(tmp_path/"temporary_secret.pem")
    safe=json.dumps({"public_keys":{"nrf_fixed":pub}})
    assert "PRIVATE KEY" not in safe
    assert (tmp_path/"temporary_secret.pem").stat().st_mode & 0o077 == 0
