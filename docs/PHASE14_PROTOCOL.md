# Phase 14 — pre-registered real PFCP/N4 link impairment with BOTH NF processes alive

Date: 2026-10-11. Scientific object: control of **actual PFCP packets**, not just UDP socket presence, under isolated genuine Open5GS+UERANSIM. No malicious attack or stealth compromise is emulated.

## Mechanism

An ephemeral GitHub-hosted runner with a disposable 5GC is used. From the host, use \`sudo nsenter -t <SMF host pid> -n iptables -I OUTPUT 1 -p udp --dport 8805 -j DROP\` to block **outgoing SMF PFCP** without stopping its container, NRF, AMF, or UPF. Verify that SMF/UPF Docker containers continue running and NRF still advertises SMF. For every intervention, check the installed rule and read its **actual dropped UDP packet counter**. Always delete the exact rule in a \`finally\` block. Only this isolated lab may be modified.

Data flow:
- 4 actual UE PDU attempts with healthy PFCP in baseline;
- 4 attempts with N4 egress drop while both NF processes are alive;
- remove the firewall rule, allow PFCP recovery, then 4 UE attempts.

Do not assume either PFCP failure or PDU failure by phase label: measure actual UERANSIM outcome and packet/iptables counters. **If N4 drop does not impair new PDU attempts, report the negative result.**

## PFCP packet evidence

A passive host-level capture on the Docker bridge collects UDP port 8805 (no payload bodies exported). Use tshark to decode \`pfcp.msg_type\` and write **sanitized counts per PFCP message type**, never any raw packets, per-user IDs, SEIDs, IP addresses or cryptographic keys. Recognized message types: Heartbeat Request 1, Heartbeat Response 2, Association Setup Request 5, Response 6, Session Establishment Request 50, Response 51, other types as other. Aggregate only the lab's own test traffic.

The timing of the 3 capture windows must be separated: baseline, N4-block and recovery. PFCP message occurrence counts are **not distinct session counts**, nor evidence of service outcome. A capture with zero packets does not prove no PFCP was sent; interface observability and packet drop *counters* are separate.

## Active signed witnesses

For each phase, obtain genuine signed Ed25519 KIE reports for: (1) HTTP/2 NRF SMF discovery, (2) UPF PFCP UDP 8805 socket presence (privileged lab namespace), and (3) passive PFCP decoded packet counts and SMF namespace firewall counter. The third is a signed **lab-capture measurement, not NF-origin attestation**. Each record is bound to a unique 128-bit challenge, phase pseudonym, monotone sequence, signing key, timestamp and explicit service type. Never publish private keys or raw packet captures.

Independent GitHub Actions job must re-verify all signatures, nonce uniqueness, freshness and replay protections, and preserve original source commit, upstream commit and container image digests.

## Comparison / hypotheses

H1: SMF and UPF remain running during N4 drop; NRF SMF presence and UPF PFCP socket presence can remain unchanged while UE PDU establishment fails. This falsifies the sufficiency of either presence indicator alone for end-to-end PDU health.

H2: A real packet count and a verified **nonzero N4 DROP counter** carry distinct information from NRF registration and a passive UPF listening socket, but neither is independently authenticated or fully pinpoints PFCP session causality.

H3: PFCP message-type counts can be extracted from genuine network frames in baseline and recovery. Missing observed packets within the drop phase is a limited negative observation, not evidence of a silent cyber compromise.

Metrics: 12 real UE procedures per runner, per-phase real PDU successes, live Docker status (audit only), NRF profile count, UPF socket present, actual PFCP packet types/counters, dropped PFCP packets, full probe cost, correctness and **abstention** under an absence of packet visibility. Three isolated compute runners share one GitHub administrative trust domain. No standard 3GPP mTLS/OAuth2 identity or trusted multi-administrator separation is evaluated.

## Safety and validity

Do not run iptables on any network outside disposable \`upstream_open5gs\`. The firewall rule is installed **inside only the SMF's network namespace**, is UDP/8805-only and must be removed in all exit paths. Capture only disposable Docker traffic; delete raw PCAP at experiment end, export sanitized counts. Do not present protocol integrity attack or cybersecurity anomaly recall. Optional comparison across exposure of endpoints does not prove data lineage or integrity without physical/trust independence.

## Key reference

3GPP TS 29.244: PFCP Heartbeat, Association, Session Establishment. NFDiscovery via TS 29.510. This experiment implements no new standard PFCP packets; it passively observes existing procedures.
