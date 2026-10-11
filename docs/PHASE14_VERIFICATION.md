# Phase 14: independent verification of unchanged Open5GS lab artifacts

Successful original GitHub Actions run: https://github.com/verge88/article_5G/actions/runs/38159871173

The independent verifier passed after all three real 5GC runner jobs succeeded. Its immutable result artifact is `phase14-independent-verified-PFCP`.

- 36 genuine UERANSIM PDU attempts: normal 12 successful, SMF UDP/8805 outgoing PFCP blocked 0 successful, recovered 12 successful.
- 253 actual UDP/8805 packets dropped by the temporary SMF network-namespace OUTPUT firewall rule (runner 11: 83; 22: 88; 33: 82).
- All three labs retained running SMF and UPF, NRF registered SMF, and UPF PFCP UDP socket throughout the phases.
- 27/27 Ed25519 receipts accepted from real NRF, UPF namespace and laboratory host PFCP capture summaries.
- 27/27 replays rejected in the separate GitHub Actions verification job.
- Passive actual PFCP packet message occurrences: normal 188, PFCP blocked 130, recovered 180. These are observations, not independently counted PFCP sessions and may contain capture duplicates.
- No raw PCAP or subscriber identifier was uploaded.

Scientific limit: This is an **authorized laboratory N4 availability fault**, not malicious NF compromise. A privileged iptables packet counter and host-level capture are not independent administrative trust domains and do not authenticate genuine 3GPP PFCP peers.

Full report: [PHASE14_RESULTS.md](PHASE14_RESULTS.md); pre-registered method: [PHASE14_PROTOCOL.md](PHASE14_PROTOCOL.md).
