# Phase 17 — preregistered N3 GTP-TEID candidate bridge, not a proven UE session identity

**Pre-measurement research protocol, 11 October 2026.** Evidence follows real NGAP/N2, SBI/Nsmf, and PFCP/N4 from three new isolated Open5GS+UERANSIM labs. The key unresolved result of stage 16 was that 18 co-observed N2/Nsmf/N4 windows contained **no authenticated common session mapping**.

## Proposed extra witness and scope
Decode `ngap.gTP_TEID` (Wireshark byte sequence), `pfcp.f_teid.teid` (N4 F-TEID) and `pfcp.outer_hdr_creation.teid` (N4 Outer Header Creation). Compare **numeric 32-bit N3 GTP-U tunnel IDs in memory only**, partitioning PFCP by actual `pfcp.msg_type`. These are existing 3GPP information elements, not novel or cryptographically authenticated identifiers.

Candidate UL N3 tunnel: an NGAP TEID observed in PDU Session Resource Setup-related messages equals the F-TEID assigned in a **PFCP Session Establishment Response, type 51**, with the relevant GTP-U addressing/routing context. Candidate DL N3 tunnel: an NGAP TEID equals a PFCP **Outer Header Creation TEID in Session Modification Request, type 52**. *Numerical TEID equality alone is insufficient*: until actual gNB/UPF endpoint addresses, direction, PDU session resource transfer IE and trusted SMF mappings are verified, even a unique numerical hit must be marked **candidate only**.

The decoder preserves TEIDs, IP addresses, message types and frame times **only in private transient memory**, publishes counts of unique candidate matches/ambiguities, per-direction counts, and never raw numbers, hashes or IP addresses. No raw PCAP in CI artifact. For ambiguous TEIDs appearing in multiple PFCP contexts or multiple NGAP contexts, decision MUST abstain. If none is decoded, abstain.

## Actual network experiment
Three disposable GitHub-hosted Open5GS+UERANSIM networks, each with 9 genuine sequential UE PDU attempts: healthy 3; both NF processes RUNNING with controlled SMF outgoing PFCP/UDP8805 full drop 3; N4 recovery 3. Same original 5GC upstream pinned commit as phases 14–16. One simultaneous N2/Nsmf/N4 capture per real trial, no subscriber credentials published. Real UE outcome measured from UERANSIM, not assigned from scenario. All drop rules removed even if error; no intrusive host network action outside disposable SMF namespace.

## Preregistered separate evidence levels
- Level 0: observed UE outcome and temporal windows.
- Level 1: per-protocol verified Nsmf HTTP2 pairs, PFCP Request/Response pairs, NGAP PDU ID presence.
- Level 2 (new): **unique TEID candidate coincidence** in plausible UL/DL message types with no key reuse within the trial. Flag as **candidate tunnel-level link**, not PDU-ID↔PFCP-SEID bridge. Numerical equality without verified transport address and PDU context is not enough for authentication.
- Level 3: protected cross-protocol UE PDU ID ↔ SM Context ↔ N3 TEID ↔ PFCP PDR/SEID mapping with unique endpoints, freshness and independent trustworthy source. **Not implemented in this phase.** Even if all fields match, `cross_protocol_identity_join_proven=false` until such an authenticated bridge exists.

## Precommitted negative controls (synthetic unit tests only)
1. Same numeric TEID in one valid 51/52 PFCP message and NGAP may yield *candidate*, never *proof*.
2. Colliding TEID across 2 separate PFCP messages / contexts ⇒ ambiguous ⇒ abstain.
3. Wrong PFCP message type, zero TEID, malformed NGAP byte sequence ⇒ abstain.
4. Independent UL/DL TEID values must not be equated as if one bidirectional tunnel.
5. Supplying an unauthenticated optional `bridge` object cannot enable proven identity.
6. Signing receipts authenticates the privileged laboratory observer, not the original NF or truth of its claimed TEIDs.

## Measurements
27 actual real UE procedures; per-phase PDU outcomes; N2/Nsmf/N4 observability; candidate UL and DL intersections; ambiguity counts; windows lacking candidates; fraction of apparent time-only joins but no TEID candidate; all signed data verified on another runner (27 original Ed25519 receipts and 27 rejected replays). Real sample is one isolated UE per window, three labs under one GitHub administrative trust domain. No malicious 5G NF compromise or attack detection recall.

## References
Wireshark [NGAP fields](https://www.wireshark.org/docs/dfref/n/ngap.html) and [PFCP fields](https://www.wireshark.org/docs/dfref/p/pfcp.html); 3GPP TS 38.413 N2 PDU Session Resource Setup, TS 29.244 N4 PFCP Created PDR / F-TEID and Outer Header Creation.

**Stopping condition:** if actual tshark cannot decode directionally meaningful N3 TEIDs, publish negative measurement and the limitation, not a fabricated verified inter-protocol join.