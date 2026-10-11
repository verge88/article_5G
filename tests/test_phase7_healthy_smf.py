"""Phase 7 laboratory DNN mutation and semantic correctness guards."""
import pytest
from src.phase7_healthy_smf import replace_ue_dnn, GOOD, BAD, run


def test_dnn_rewrite_only_changes_one_disposable_ue_session():
    sample = "sessions:\n  - type: 'IPv4'\n    apn: 'internet'\n    slice:\n      sst: 1\n"
    altered = replace_ue_dnn(sample, BAD)
    assert altered.count(BAD) == 1
    assert GOOD not in altered
    assert replace_ue_dnn(altered, GOOD) == sample


def test_multiple_or_missing_configured_dnn_rejected():
    with pytest.raises(ValueError):
        replace_ue_dnn(GOOD + "\n" + GOOD, BAD)
    with pytest.raises(ValueError):
        replace_ue_dnn("sessions: []\n", BAD)


def test_requires_explicit_isolated_lab_guard(tmp_path, monkeypatch):
    monkeypatch.delenv("ALLOW_LAB_UE_DNN_CHANGE", raising=False)
    with pytest.raises(RuntimeError, match="guard"):
        run(tmp_path / "upstream_open5gs", tmp_path / "output", repeats=3)
