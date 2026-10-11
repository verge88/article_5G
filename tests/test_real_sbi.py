import pytest
from src.real_sbi import parse_curl_output, MARKER


def test_parse_successful_http2_nrf_response():
    info, payload = parse_curl_output(
        '{"nfInstances":[{"nfType":"AUSF"}]}' + MARKER + "200 2 0.0201\n"
    )
    assert info["http_status"] == 200
    assert info["http_version"] == "2"
    assert info["latency_ms"] == pytest.approx(20.1)
    assert payload["nfInstances"][0]["nfType"] == "AUSF"


def test_parse_rejects_missing_metadata():
    with pytest.raises(ValueError):
        parse_curl_output("wrong response")


def test_parse_accepts_503_and_nonjson_without_claiming_success():
    info, payload = parse_curl_output("bad response" + MARKER + "503 2 0.002\n")
    assert info["http_status"] == 503 and payload == {}


def test_robustness_corruption_preserves_labels_and_source_data():
    from src.robustness import corrupt_observations
    from src.simulate import generate_frame
    original = generate_frame(23, zones=2, replicas=4, steps=90)
    changed = corrupt_observations(original, strategy="observer_capture", fraction=1, seed=2)
    assert original.y_attack.equals(changed.y_attack)
    assert original.scenario.equals(changed.scenario)
    stealth = changed.scenario == "stealth"
    assert stealth.sum() > 0
    assert changed.loc[stealth, "witness_report_disagreement"].eq(.005).all()
    assert changed.loc[stealth, "zone_witness_deviation"].eq(.003).all()
    assert original.loc[stealth, "witness_report_disagreement"].mean() > .005
