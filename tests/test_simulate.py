import numpy as np
from src.simulate import FEATURE_GROUPS, generate_frame
from src.experiment import (
    TRAIN_SEEDS, VALID_SEEDS, TEST_SEEDS, SHIFT_SEEDS,
    threshold, metrics,
)

def test_seeded_generator_reproducible():
    a = generate_frame(51, zones=2, replicas=3, steps=40)
    b = generate_frame(51, zones=2, replicas=3, steps=40)
    assert a.equals(b)
    assert len(a) == 2 * 3 * 40

def test_split_seed_disjointness_and_feature_ablation():
    groups = [set(x) for x in (TRAIN_SEEDS, VALID_SEEDS, TEST_SEEDS, SHIFT_SEEDS)]
    assert all(not (groups[i] & groups[j]) for i in range(4) for j in range(i + 1, 4))
    assert set(FEATURE_GROUPS["local"]) < set(FEATURE_GROUPS["full"])
    assert "witness_report_disagreement" not in FEATURE_GROUPS["local"]

def test_finite_features_and_correct_labels():
    df = generate_frame(19, zones=2, replicas=3, steps=50, shift=True)
    assert np.isfinite(df[FEATURE_GROUPS["full"]].to_numpy()).all()
    assert df.reported_success_rate.between(0, 1).all()
    assert df.witness_success_rate.between(0, 1).all()
    assert ((df.y_attack == 1) == df.scenario.isin(["stealth", "dos"])).all()

def test_constructed_witness_gap_not_used_as_local_feature():
    df = generate_frame(21, zones=2, replicas=4, steps=180)
    stealth = df.loc[df.scenario == "stealth", "witness_report_disagreement"]
    normal = df.loc[df.scenario == "normal", "witness_report_disagreement"]
    assert len(stealth) > 0 and len(normal) > 0
    assert stealth.mean() > normal.mean() + .04

def test_threshold_and_metrics_range():
    df = generate_frame(17, zones=2, replicas=4, steps=50)
    score = np.linspace(0, 1, len(df))
    t = threshold(df.y_attack, score)
    result = metrics(df, score, t)
    assert 0 <= t <= 1
    assert 0 <= result["fpr"] <= 1
    assert result["n"] == len(df)
