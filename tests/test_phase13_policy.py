"""Phase 13 preregistered online source choice and signature safeguards."""
from pathlib import Path
import copy
import numpy as np
import pytest

from src.phase13_policy import (
    ARMS, BUDGET, Chooser, h, expected_information, update_posterior,
)
from src.phase13_probe import PFCP_PORT_PATTERN, sign_observation, upf_namespace_socket, SERVICES
from src.phase9_receipts import create_ephemeral_key, verify_receipt


def test_information_is_nonnegative_without_fitted_test_labels():
    for source in ("nrf","upf"):
        for prob in (.01,.1,.5,.9,.99):
            ig=expected_information(prob,source)
            assert 0<=ig<=1.
    assert expected_information(.5,"nrf")==pytest.approx(expected_information(.5,"upf"))


def test_no_future_phase_or_docker_state_in_policy_inputs():
    chooser=Chooser()
    assert chooser.decide(1,1)=={}
    first=chooser.decide(0,1)
    assert first=={"nrf_only":"nrf","upf_only":"upf","mixed":"nrf","information":"nrf"}
    chooser.observe_information("nrf",False)
    second=chooser.decide(0,1)
    assert second["mixed"]=="upf"
    assert second["information"]=="upf"


def test_equal_active_budget_two_recovered_failure_episodes():
    chooser=Chooser()
    selected={x:[] for x in ARMS}
    # First healthy PDU, four UPF failures, recovery, four SMF failures,
    # recovery. Plan sees ONLY UE success/failure.
    sequence=[1]*4+[0]*4+[1]*4+[0]*4+[1]*4
    for i,success in enumerate(sequence):
        r=chooser.decide(success,1)
        for arm,src in r.items():
            selected[arm].append((i,src))
            if arm=="information":
                # NFC claims registered in UPF failure episode; NRF absent
                # in SMF failure. State is an observation of selected request
                # and is NOT passed in as a known intervention label.
                chooser.observe_information(src,False if i<8 else True)
    assert chooser.current_episode==2
    assert all(len(selected[a])==4 for a in ARMS)
    assert all(chooser.remaining[a]==0 for a in ARMS)
    assert selected["mixed"]==[(4,"nrf"),(5,"upf"),(12,"nrf"),(13,"upf")]


def test_missing_upf_socket_is_not_equated_to_proved_absence(monkeypatch):
    class Fake:
        def __init__(self,code,stdout):
            self.returncode,self.stdout=code,stdout
    def subprocess_fake(args,**kwargs):
        if args[1]=="exec":return Fake(1,"")
        return Fake(0,"false\n")
    monkeypatch.setattr("src.phase13_probe.subprocess.run",subprocess_fake)
    x=upf_namespace_socket()
    assert x["namespace_accessible"] is False
    assert x["pfcp_udp_8805_socket_present"] is None
    assert x["docker_runtime_running_privileged_lab_only"] is False


def test_pfcp_socket_8805_recognition():
    assert PFCP_PORT_PATTERN.search(" 42: 00000000:2265 00000000:0000 07: 00000000:00000000")
    assert not PFCP_PORT_PATTERN.search(" 42: 00000000:0102 00000000:0000 07: 00000000:00000000")


def test_signed_distinct_source_cannot_be_relabelled_as_nrf(tmp_path,monkeypatch):
    k=tmp_path/"key.pem"
    identity=create_ephemeral_key(k)
    monkeypatch.setattr("src.phase13_probe.upf_namespace_socket",
                        lambda:{"namespace_accessible":False,
                                "pfcp_udp_8805_socket_present":None,
                                "docker_runtime_running_privileged_lab_only":False,
                                "probe_elapsed_ms":1.})
    doc=sign_observation(k,"phase13_test","upf","a"*32,"trial_000",1)
    pending={"a"*32:("phase13_test","trial_000",1)}
    assert not verify_receipt(doc,registered_keys={"phase13_test":identity},
                       pending=pending.copy(),accepted_sequences={})
    assert verify_receipt(doc,registered_keys={"phase13_test":identity},
        pending=pending.copy(),accepted_sequences={},
        allowed_services=tuple(SERVICES.values()))
    corrupt=copy.deepcopy(doc)
    corrupt["payload"]["service"]=SERVICES["nrf"]
    assert not verify_receipt(corrupt,registered_keys={"phase13_test":identity},
        pending=pending.copy(),accepted_sequences={},
        allowed_services=tuple(SERVICES.values()))


def test_laboratory_intervention_authorization_guard(tmp_path,monkeypatch):
    from src.phase13_live import run
    monkeypatch.delenv("ALLOW_PHASE13_LAB_ONLY",raising=False)
    with pytest.raises(RuntimeError,match="disposable 5GC"):
        run(tmp_path/"upstream_open5gs",tmp_path/"out","11")
