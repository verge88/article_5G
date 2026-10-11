"""Phase-3 scientific controls; these tests never create/kill containers."""
import pytest
from src.pdu_lab import run, SUCCESS_PAT, REG_PAT
from src.trace_audit import classify_paths


def test_pdu_log_markers():
    assert SUCCESS_PAT.search("[nas] PDU Session establishment is successful")
    assert REG_PAT.search("Registration is successful")


def test_production_lab_guard(tmp_path, monkeypatch):
    monkeypatch.delenv("ALLOW_LAB_ONLY_SMF_FAILURE", raising=False)
    with pytest.raises(RuntimeError, match="isolated-lab guard"):
        run(tmp_path / "upstream_open5gs", tmp_path / "result")


def test_capture_sanitization_omits_subscriber_paths():
    got = classify_paths([
        "/nsmf-pdusession/v1/sm-contexts",
        "/nudm-sdm/v2/imsi-001011234567895/sm-data",
        "/nnrf-disc/v1/nf-instances",
    ])
    assert got["nsmf-pdusession"] == 1
    assert got["nudm-sdm"] == 1
    assert "001011234567895" not in str(got)
