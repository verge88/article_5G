# Phase 3: real PDU Session Establishment and Nsmf traces — protocol

## Research question

Can a hierarchical KIE monitor capture **independent, real observations**
of the PDU-session control plane, correlate availability information from
NRF/SMF/AMF with a UE-observed procedure outcome, and distinguish normal
availability, controlled SMF failure, and recovery?

This is the next step after:
- a synthetic multi-zone feature-ablation study (NOT a real-5G classifier);
- live NRF discovery/KIE measurements;
- the AUSF fail-stop experiment showing temporary NRF registration staleness.

## Real deployment

- Actual Open5GS components: NRF, SCP, AUSF, UDM, UDR, PCF, BSF, NSSF,
  AMF, SMF, UPF, MongoDB, WebUI.
- Actual UERANSIM gNB and UE. The local test subscriber is provisioned with
  identical K/OPc values in the UE and Open5GS subscriber store.
- Isolated GitHub-hosted Docker network. The project intentionally does not
  connect to commercial/operator infrastructure.
- External Docker deployment source is pinned to commit
  `1f3bcf73f926b5b7526ef3c41cd2b839c2b17ac3`.
- Container image digest and our experiment's exact commit are saved with
  the results; tags are not assumed immutable.

## Trial phases (3 independent procedural attempts per phase)

1. **Normal:** SMF is running; a fresh simulated UE connects to the same gNB
   and attempts a PDU session.
2. **SMF fail-stop:** SMF container is stopped using Docker within this
   isolated environment. A fresh UE repeats the procedure. The intent is
   loss of service, **not** stealthy malicious behaviour.
3. **Recovery:** SMF restarts and three more UE attempts are observed.

Raw UE, AMF, SMF and UPF logs remain ephemeral. Only aggregated counts
and timing values are published. NRF discovery provides a fifth source of
network-visible evidence. Docker health is independent lab ground truth.

A process-level failure label is assigned by the experiment controller;
no classifier receives scenario labels as features.

## Verification gate

The run is considered a successful PDU study only if:
- at least one real normal UE attempt achieves a PDU Session Establishment
  Accept message visible in UERANSIM;
- the SMF fail-stop phase produces no successful UE PDU establishment;
- at least one PDU establishment follows recovery;
- the packet observer records actual HTTP/2 SBI paths, and identifies
  Nsmf_PDUSession when possible.

If setup or tests fail, no success may be claimed. Intermediate artifacts
and actual failure diagnostics remain visible in GitHub Actions logs.

## Packet privacy

The short-lived PCAP is created under GitHub Runner's temporary directory,
and deleted in cleanup. tshark extracts HTTP/2 :path fields, but the
project publishes **only fixed names of 5G service families** and counts
(for example, nsmf-pdusession); no subscriber identities, raw endpoints,
request bodies, credentials or bearer data are published.

## What this cannot prove

- It is not a multi-master deployment and contains only one lab SMF.
- Fail-stop and delayed NRF discovery are not cyber compromises.
- Docker process state is a privileged witness, not a standard 3GPP
  attested telemetry source.
- Three attempts per scenario are insufficient to claim statistical
  detection effectiveness, FPR, F1 or production performance.
- Actual PDU-session traffic validation is a necessary precondition,
  but no new detection novelty is established without independent
  falsification scenarios, more witness sources and comparative methods.

## Standards

The observed `Nsmf_PDUSession Create SM Context` procedure follows the
semantics of 3GPP TS 29.502; only real-decoded paths are evidence that the
specific lab invoked that service.
