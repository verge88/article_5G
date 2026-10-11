import os
import pytest

from src.real_fault import run


def test_fail_stop_requires_explicit_isolated_lab_flag(tmp_path, monkeypatch):
    monkeypatch.delenv("ALLOW_KILL_AUSF_IN_ISOLATED_LAB", raising=False)
    with pytest.raises(RuntimeError, match="lab-only"):
        run("http://127.0.0.1:7777", tmp_path / "observations.csv")


def test_failure_and_recovery_summary_only_after_real_probes():
    # The integration experiment is intentionally not run in unit tests:
    # it must only target an isolated Open5GS container in GitHub Actions.
    assert os.getenv("ALLOW_KILL_AUSF_IN_ISOLATED_LAB") != "yes"
