# Experimental results: synthetic hierarchical KIE monitoring (11 October 2026)

**Evidence:** [GitHub Actions run 38133855515](https://github.com/verge88/article_5G/actions/runs/38133855515), source commit `1f1b81b35218ed86811c29b66990deb1a81511f9`, artifact `5g-kie-experiment-results` (ID 11700028721).

**Status:** GitHub Actions completed successfully; 5 unit checks passed. All figures below are reproduced from the uploaded artifact's `metrics.csv`.

## Held-out evaluation: four independent synthetic network realizations

| Feature ablation / detector | FPR | Stealth recall | DoS recall | F1 | AUPRC |
|---|---:|---:|---:|---:|---:|
| RF local | 0.0096 | 0.0182 | 1.0000 | 0.5691 | 0.6397 |
| RF local + temporal | 0.0083 | 0.0445 | 1.0000 | 0.5866 | 0.7074 |
| RF + KIE | 0.0093 | 0.7442 | 0.9983 | 0.8980 | 0.9662 |
| RF + KIE + zone | 0.0075 | 0.9682 | 1.0000 | 0.9748 | 0.9970 |
| RF full + witness/causal | 0.0087 | 1.0000 | 1.0000 | 0.9820 | 1.0000 |
| Isolation Forest local | 0.0114 | 0.0000 | 1.0000 | 0.5553 | 0.5395 |

Full-minus-local stealth recall = **+0.98185** (paired seed-level bootstrap 95% CI [0.97997, 0.98360]). This CI is exploratory: only **four independent network realizations** were resampled, although each includes many correlated time observations.

## Robustness: shifted hold-out environments

The harder shifted regime uses milder stealth compromise and noisier trusted-witness measurements. **Thresholds are kept fixed** from ordinary validation (target FPR 1%).

| Feature ablation / detector | FPR | Stealth recall | F1 | AUPRC |
|---|---:|---:|---:|---:|
| RF local | 0.0090 | 0.0156 | 0.5081 | 0.6036 |
| RF local + temporal | 0.0040 | 0.0433 | 0.5359 | 0.7319 |
| RF + KIE | 0.0609 | 0.5590 | 0.7068 | 0.8015 |
| RF + KIE + zone | 0.0154 | 0.4904 | 0.7651 | 0.8626 |
| RF full + witness/causal | **0.1759** | 0.9526 | 0.6838 | 0.9462 |
| Isolation Forest local | 0.0112 | 0.0000 | 0.4933 | 0.4669 |

**Negative finding that must be reported:** The full detector's test FPR rose to **17.59%** under distribution shift. Its apparent discrimination advantage is therefore not robust at the pre-calibrated 1% FPR operating point.

## Interpretation and limits

This is a controlled **synthetic proof-of-concept**, **not** an experiment conducted in a 5G SA network. In particular:

- Scenario generation directly creates discrepancies between falsified local NF reports and a separately simulated, assumed-trusted witness. The resulting advantage of causal features is partly built into the data-generation mechanism.
- The generated events are not 3GPP SBI HTTP/2 operations, PDU sessions, or a real instance of the SMF protocol.
- No deployed KIE protocol, signal-plane overhead, transport security, nor authenticated independent witness has been tested.
- The statistical significance of improvements is not established by four independent seeded network realizations.
- Performance numbers must not be presented as operator-network detection accuracy or as evidence that the proposed algorithm is novel relative to published methods.
- The shifted-regime FPR demonstrates the need for drift detection, selective re-calibration based on fresh benign reference data, and robustness experiments on an actual Open5GS/free5GC deployment.

## Required next experiments

1. Implement an authorized test procedure on Open5GS/free5GC and document 3GPP API compliance.
2. Collect independent NF, SCP and observer traces with source provenance.
3. Reconstruct KIE features from measured request/response paths instead of synthesizing them.
4. Introduce benign overloads and controlled partial SMF procedural faults; retain unrelated deployment splits.
5. Benchmark reproduced literature baselines and ablate trust assumptions, false witness reports and leader compromise.
6. Repeat shifted-distribution experiments with independent deployments and bootstrap at run/deployment level.

Raw metrics, predictions, metadata and Python dependencies are available in the run artifact.
