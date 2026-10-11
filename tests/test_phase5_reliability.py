"""Phase-5 controls for trust assumptions, selective alarm and leakage."""
import numpy as np
import pandas as pd
from src.phase5_reliability import inject, quorum, evaluate, select_trials


def demo():
    entries = []
    for trial, (outcome, health, amf) in enumerate([(1, 1, 1), (0, 0, 0), (1, 1, 1)]):
        for tampered in (0, 1):
            entries.append(dict(
                deployment="303", phase="normal", trial=trial, tampered=tampered,
                reported_pdu_success=1 - outcome if tampered else outcome,
                reported_healthy=health, ue_truth=outcome,
                docker_truth=health, nrf_count=health, amf_prediction=amf,
            ))
    return pd.DataFrame(entries)


def test_faults_affect_both_twins_not_only_attacks():
    df = demo()
    altered = inject(df, "ue_flip", 1., seed=100)
    assert altered.groupby("trial").ue_seen.nunique().eq(1).all()
    assert (altered.ue_seen != altered.ue_truth).all()
    assert (altered.tampered == df.tampered).all()


def test_clean_two_sources_detect_only_report_falsification():
    df = inject(demo(), "clean", 0.)
    output = quorum(df)
    assert (output[df.tampered.eq(1)] == 1).all()
    assert (output[df.tampered.eq(0)] == 0).all()


def test_single_witness_lie_causes_abstention_not_automatic_alarm():
    df = inject(demo(), "ue_flip", 1.)
    out = quorum(df, lab_oracle=False)
    assert (out == -1).all()


def test_two_corrupt_agreeing_sources_can_fool_quorum():
    df = inject(demo(), "ue_and_amf_flip", 1.)
    pred = quorum(df, lab_oracle=False)
    assert (pred[df.tampered.eq(0)] == 1).all()


def test_missing_witness_is_not_marked_as_clean():
    df = inject(demo(), "ue_missing", 1.)
    assert (quorum(df) == -1).all()


def test_abstention_recorded_in_coverage():
    df = inject(demo(), "ue_missing", 1.)
    numbers = evaluate(df, quorum(df))
    assert numbers["decision_coverage"] == 0
    assert numbers["unconditional_fpr"] == 0
    assert numbers["unconditional_recall"] == 0
    assert numbers["abstained_truthful_reports"] == 3


def test_fraction_selection_not_based_on_truthfulness_label():
    df = demo()
    choice = select_trials(df, 1/3, seed=77)
    assert choice.sum() == 2
    assert df.loc[choice, "trial"].nunique() == 1
    assert len(set(df.loc[choice, "tampered"])) == 2
