"""Reproducible held-out ablation with synthetic SMF-like network realizations."""
import argparse
import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    average_precision_score, roc_auc_score, precision_score, recall_score, f1_score,
)
from .simulate import FEATURE_GROUPS, LOCAL, generate_frame

TRAIN_SEEDS = [11, 13, 17, 19]
VALID_SEEDS = [31, 37]
TEST_SEEDS = [101, 103, 107, 109]
SHIFT_SEEDS = [211, 223, 227, 229]
TARGET_FPR = .01


def dataset(seeds, shift=False, steps=240):
    return pd.concat([generate_frame(s, steps=steps, shift=shift)
                      for s in seeds], ignore_index=True)


def threshold(y, scores):
    benign = np.asarray(scores)[np.asarray(y) == 0]
    return float(np.quantile(benign, 1 - TARGET_FPR))


def metrics(frame, score, t):
    y = frame.y_attack.to_numpy()
    pred = (score > t).astype(int)
    stealth = frame.scenario.to_numpy() == "stealth"
    dos = frame.scenario.to_numpy() == "dos"
    return dict(
        n=int(len(y)), positive_n=int(y.sum()), stealth_n=int(stealth.sum()),
        fpr=float(pred[y == 0].mean()),
        stealth_recall=float(pred[stealth].mean()),
        dos_recall=float(pred[dos].mean()),
        precision=float(precision_score(y, pred, zero_division=0)),
        recall=float(recall_score(y, pred, zero_division=0)),
        f1=float(f1_score(y, pred, zero_division=0)),
        auprc=float(average_precision_score(y, score)),
        auroc=float(roc_auc_score(y, score)),
    )


def bootstrap_gain(test, full, local, full_t, local_t, iterations=1000):
    scenario = test.scenario.to_numpy()
    seeds = test.seed.to_numpy()
    diffs = []
    for s in TEST_SEEDS:
        mask = (seeds == s) & (scenario == "stealth")
        diffs.append(float((full[mask] > full_t).mean()
                           - (local[mask] > local_t).mean()))
    rng = np.random.default_rng(2026)
    draws = rng.choice(diffs, size=(iterations, len(diffs)), replace=True).mean(axis=1)
    return dict(mean=float(np.mean(diffs)), per_seed=diffs,
                ci95=[float(x) for x in np.quantile(draws, [.025, .975])],
                method="paired seed-level percentile bootstrap",
                note="Only 4 independent test seeds; exploratory uncertainty.")


def run(out, quick=False):
    out.mkdir(parents=True, exist_ok=True)
    steps = 80 if quick else 240
    train = dataset(TRAIN_SEEDS, steps=steps)
    val = dataset(VALID_SEEDS, steps=steps)
    test = dataset(TEST_SEEDS, steps=steps)
    shifted = dataset(SHIFT_SEEDS, shift=True, steps=steps)
    records, scores, limits = [], {}, {}
    importances = []
    for ablation, features in FEATURE_GROUPS.items():
        rf = RandomForestClassifier(
            n_estimators=60 if quick else 120, max_depth=13, min_samples_leaf=12,
            class_weight="balanced_subsample", n_jobs=2, random_state=2026)
        rf.fit(train[features], train.y_attack)
        t = threshold(val.y_attack, rf.predict_proba(val[features])[:, 1])
        limits[ablation] = t
        scores[ablation] = rf.predict_proba(test[features])[:, 1]
        for env, frame, score in (
            ("in_distribution", test, scores[ablation]),
            ("shifted", shifted, rf.predict_proba(shifted[features])[:, 1]),
        ):
            records.append(dict(
                model="RF_" + ablation, environment=env, threshold=t,
                **metrics(frame, score, t)))
        if ablation == "full":
            importances = sorted(
                zip(features, map(float, rf.feature_importances_)),
                key=lambda a: a[1], reverse=True)
    iso = IsolationForest(
        n_estimators=80 if quick else 140, random_state=2026,
        contamination="auto", n_jobs=2)
    iso.fit(train.loc[train.y_attack == 0, LOCAL])
    t_unsup = threshold(val.y_attack, -iso.score_samples(val[LOCAL]))
    for env, frame in (("in_distribution", test), ("shifted", shifted)):
        records.append(dict(model="IF_local", environment=env, threshold=t_unsup,
                            **metrics(frame, -iso.score_samples(frame[LOCAL]), t_unsup)))

    pd.DataFrame(records).to_csv(out / "metrics.csv", index=False)
    pd.DataFrame(dict(seed=test.seed, scenario=test.scenario, y_attack=test.y_attack,
        score_local=scores["local"], score_full=scores["full"],
        pred_local=(scores["local"] > limits["local"]).astype(int),
        pred_full=(scores["full"] > limits["full"]).astype(int))
    ).to_csv(out / "test_predictions.csv", index=False)
    gain = bootstrap_gain(test, scores["full"], scores["local"],
                          limits["full"], limits["local"])
    meta = dict(
        source="SYNTHETIC ONLY: not a real 5G Core, 3GPP procedure or packet trace",
        training_seeds=TRAIN_SEEDS, validation_seeds=VALID_SEEDS,
        heldout_seeds=TEST_SEEDS, shifted_seeds=SHIFT_SEEDS,
        zones=4, replicas_per_zone=8, samples_per_replica=steps,
        target_validation_fpr=TARGET_FPR,
        feature_groups=FEATURE_GROUPS,
        trust_assumption="Independent witness uncompromised; local reports may be false.",
        kie_cost_assumption=dict(request_bytes=160, reply_bytes=160, interval_seconds=30,
            nominal_bytes_per_second_per_nf=320 / 30,
            note="Payload only: no protocol headers or actual network performance measured."),
        bootstrap_stealth_recall_full_minus_local=gain,
        full_feature_importances=importances)
    (out / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    lines = [
        "# Hierarchical KIE + Data Mining: SYNTHETIC experiment report",
        "",
        "**Warning: this is a simulated feature-level study, NOT a 5G SA or SBI experiment.**",
        "The simulated witness is assumed trustworthy; resulting gains may follow by construction.",
        "",
        "## Design",
        "Four zones with eight replicas each, thirty-second nominal KIE poll,",
        "contiguous normal / benign load / DoS / stealth-falsification episodes.",
        "Independent train, validation, test and harder shifted scenario seeds.",
        "Each classifier uses the same model family and validation target FPR=1%.",
        "No test samples are used to select thresholds.",
        "",
        "| Distribution | Ablation | FPR | Stealth recall | DoS recall | F1 | AUPRC |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for r in records:
        lines.append(
            "| {environment} | {model} | {fpr:.4f} | {stealth_recall:.4f} | {dos_recall:.4f} | {f1:.4f} | {auprc:.4f} |".format(**r))
    lines += [
        "",
        "## Primary comparison: full versus local",
        "Paired seed-level mean improvement of stealth recall: {:.4f}; 95% bootstrap CI: [{:.4f}, {:.4f}].".format(
            gain["mean"], *gain["ci95"]),
        "This interval is exploratory due to just four independent realizations.",
        "",
        "## Limitations",
        "No Open5GS, free5GC, SBI, HTTP/2, authorized live probes, or real PDU procedures are executed.",
        "Class labels and witness inconsistency share the generator's latent assumptions.",
        "Trust compromise of witness or leading modules is not simulated.",
        "No claims about production F1, network load, 3GPP compliance or priority over prior research.",
        "Next stage requires trace-based instrumentation on an actual 5G Core testbed.",
    ]
    (out / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return records, gain


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", type=Path, default=Path("results"))
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    records, gain = run(a.out_dir, quick=a.quick)
    print(json.dumps(dict(comparison=gain,
        full=[r for r in records if r["model"] == "RF_full"]), indent=2))
