"""Scientific controls for real PDU temporal correlation in the 5G SBA."""
import pandas as pd
import pytest

from src.phase6_correlate import decode_rows, associate


def frame(epoch, tcp, stream, *, path=False, code=None):
    return {
        "epoch": epoch, "tcp": str(tcp), "http2_stream": str(stream),
        "path" : None,
        "family": "nsmf-pdusession" if path else "other",
        "has_path": path, "method": "POST" if path else "",
        "status": code,
    }


def windows():
    return pd.DataFrame([
        dict(phase="normal", trial=0, window_start_epoch=100., window_end_epoch=110.,
             ue_pdu_session_accepted=1, ue_registration_seen=1, smf_running_witness=1),
        dict(phase="smf_failstop", trial=0, window_start_epoch=112., window_end_epoch=122.,
             ue_pdu_session_accepted=0, ue_registration_seen=1, smf_running_witness=0),
        dict(phase="recovery", trial=0, window_start_epoch=124., window_end_epoch=134.,
             ue_pdu_session_accepted=1, ue_registration_seen=1, smf_running_witness=1),
    ])


def test_tshark_tab_parser_keeps_only_allowed_service_family():
    data = "102.000000\t1\t3\t/nsmf-pdusession/v1/sm-contexts\tPOST\t\n"
    data += "102.100000\t1\t3\t\t\t201\n"
    data += "109.000000\t2\t7\t/nudm-sdm/v1/imsi-sensitive/sm-data\tGET\t\n"
    result = decode_rows(data)
    assert len(result) == 3
    assert result[0]["family"] == "nsmf-pdusession"
    assert result[1]["status"] == 201
    assert result[2]["family"] == "other"
    assert "sensitive" not in str(result)


def test_dedup_and_pair_http2_stream_not_pdu_id():
    frames = [
        frame(102., 1, 3, path=True),
        frame(102.001, 1, 3, path=True),  # pcap duplicate: same logical request
        frame(102.1, 1, 3, code=201),
        frame(114., 2, 5, path=True),
        frame(126., 3, 7, path=True),
        frame(126.2, 3, 7, code=201),
        frame(140., 4, 9, path=True),  # outside all user windows
    ]
    data, audit = associate(frames, windows())
    assert data.nsmf_unique_request_streams.tolist() == [1, 1, 1]
    assert data.nsmf_paired_response_streams.tolist() == [1, 0, 1]
    assert data.nsmf_status_2xx.tolist() == [1, 0, 1]
    assert audit["nsmf_requests_outside_trials"] == 1
    assert audit["all_nsmf_unique_request_streams"] == 4


def test_overlapping_ue_trial_windows_rejected():
    bad = windows()
    bad.loc[0, "window_end_epoch"] = 112.1
    with pytest.raises(ValueError, match="overlap"):
        associate([frame(102, 1, 3, path=True)], bad)


def test_missing_real_measurement_fields_rejected():
    with pytest.raises(ValueError, match="Missing measured window"):
        associate([], pd.DataFrame({"phase":["normal"]}))
