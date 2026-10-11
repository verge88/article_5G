# Synthetic study protocol

The main question is whether independent causal- and temporal-consistency
observations, combined with hierarchical active KIE monitoring, improve
detection of stealthy NF compromises compared with local signal measurements
alone under an identical target false-positive rate.

## Assumptions

There are four zones of eight simulated SMF-like replicas. Local counters may
be maliciously falsified. A second trusted witness observes a fraction of the
procedural outcomes and supplies independent observations. This witness and
the zone leaders are assumed uncompromised. These assumptions are not proved.

## Registered ablations

- local: self-reported operational metrics
- local_temporal: rolling self-reported history
- plus_kie: independently timed KIE probes
- plus_zone: zone-peer witness and KIE deviations
- full: cross-observer completion and order-consistency discrepancies

Random Forest models have identical hyperparameters. Isolation Forest trained
on benign local metrics provides an unsupervised reference. Train, validation,
test and shifted-test seeds are disjoint. Decision thresholds are fixed on
benign validation events for 1% target FPR. Test FPR is always measured.

## Attack scenarios

Normal operation; legitimate load bursts with honest reports; DoS with
visible degradation; covert selective procedure failures combined with falsely
healthy local reports. The shifted test set uses milder failures and noisier
witnesses. Episodes are contiguous, not IID record-level labels.

## Limits

The simulator operates at a feature level, not on 3GPP messages, PDU sessions
or a real HTTP/2 SBI. It cannot validate API compliance, actual network
overhead, security against witness compromise, or field-grade performance.
The paired seed-level confidence interval has only four independent test
realizations, hence is exploratory.

Before publication as a genuine 5G experiment, use Open5GS/free5GC with
authorized service procedures, independent trace instrumentation and
real measurements; reconstruct published comparison methods on common data.
