"""Cross-runner phase-10 audit: real HTTP/2 NRF receipts, no inferred security claims."""
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
import statistics

import pandas as pd
from .phase9_receipts import verify_receipt

REPLICAS=("11","22","33")
ARMS=("fixed","heuristic","ml")
REPEAT=4


def audit_replica(folder:Path,replica:str):
    evidence=json.loads((folder/"live_summary.json").read_text())
    if evidence["replica"] != replica or evidence["n_ue_attempts"]!=16:
        raise ValueError(f"Wrong real PDU trial provenance: {replica}")
    docs=[json.loads(line) for line in (folder/"signed_receipts.jsonl").read_text().splitlines() if line]
    pubs=json.loads((folder/"public_agent_keys.json").read_text())
    trial=pd.read_csv(folder/"live_trial_schedule.csv")
    probes=pd.read_csv(folder/"live_active_nrf_probes.csv")
    if len(trial)!=16 or len(probes)!=12 or len(docs)!=12:
        raise ValueError("Real active probe counts or receipt counts mismatch")
    if set(trial.audit_phase_not_in_policy)!={
        "normal","invalid_dnn","smf_failstop","recovery"}:
        raise ValueError("Missing expected real PDU phase")
    for phase in ("normal","recovery","invalid_dnn","smf_failstop"):
        part=trial[trial.audit_phase_not_in_policy==phase]
        if len(part)!=4:
            raise ValueError("Incomplete real PDU phase")
        count=int(part.ue_pdu_success_observed.sum())
        if count != (4 if phase in ("normal","recovery") else 0):
            raise ValueError("Unexpected genuine UE PDU outcome")
        if not all(part.actual_smf_running_docker_audit_only==int(phase!="smf_failstop")):
            raise ValueError("Controlled SMF process failed acceptance condition")
    if len({k["key_id"] for k in pubs.values()})!=3:
        raise ValueError("Each local active agent must use a distinct public key")
    issued={}
    for doc in docs:
        payload=doc["payload"]
        nonce=payload["nonce"]
        issued[nonce]=(payload["agent_id"],payload["trial_token"],payload["sequence"])
    if len(issued)!=12:
        raise ValueError("Nonce uniqueness compromised")
    accepted={}
    signature_results=[]
    for doc in docs:
        payload=doc["payload"]
        ok=verify_receipt(doc,registered_keys=pubs,pending=issued,
                         accepted_sequences=accepted,now=payload["measured_at_unix"]+1,
                         max_age_s=20)
        if not ok:
            raise RuntimeError(f"Signature / nonce / sequence invalid in replica {replica}")
        # Reuse of consumed issued nonce and seq must be rejected independently.
        replay=verify_receipt(doc,registered_keys=pubs,pending=issued,
                              accepted_sequences=accepted,now=payload["measured_at_unix"]+1)
        if replay:
            raise RuntimeError("Previously authenticated report replay was accepted")
        signature_results.append({"replica":replica,"agent":payload["agent_id"],
                                  "trial_token":payload["trial_token"],
                                  "signed_and_ordered_ok":int(ok),
                                  "replay_rejected":int(not replay)})
    if issued:
        raise RuntimeError("Unmatched signed trial challenges")
    signed_keys={(x["payload"]["agent_id"],x["payload"]["trial_token"]) for x in docs}
    expected_keys={(dict(fixed="nrf_fixed",heuristic="nrf_adaptive",ml="nrf_ml")[row.arm],
                    row.trial_token) for row in probes.itertuples()}
    if signed_keys != expected_keys:
        raise ValueError("Signed reports not in one-to-one correspondence with LIVE probes")
    rows=[]
    for arm in ARMS:
        selected=probes[probes.arm==arm]
        if len(selected)!=REPEAT or int(trial[f"probed_{arm}"].sum())!=REPEAT:
            raise RuntimeError("Live query budgets not equal")
        risk=selected[selected.audit_phase_not_in_policy=="smf_failstop"]
        healthy=selected[selected.audit_phase_not_in_policy!="smf_failstop"]
        rows.append({
            "replica":replica,"arm":arm,
            "real_pdu_trials":len(trial),
            "actual_nrf_http2_queries":len(selected),
            "real_failstop_trial_count":4,
            "real_failstop_trials_actively_checked":len(risk),
            "failstop_trial_coverage":len(risk)/4,
            "nrf_absence_during_failstop":int(risk.nrf_registry_absence.sum()),
            "registry_absence_in_other_selected_trials":int(healthy.nrf_registry_absence.sum()),
            "healthy_trials_queried":len(healthy),
            "forced_quota_fallbacks":int(trial[f"fallback_{arm}"].sum()),
            "curl_total_ms":float(selected.curl_response_ms.sum()),
            "agent_process_total_ms":float(selected.agent_process_ms.sum()),
            "http_response_body_bytes":int(selected.response_body_bytes.sum()),
            "verified_signed_reports":len(selected),
            "phase_coverage":json.dumps(selected.audit_phase_not_in_policy.value_counts().to_dict(),sort_keys=True),
        })
    return rows,signature_results, evidence


def aggregate(root:Path,out:Path):
    out.mkdir(parents=True,exist_ok=True)
    all_rows=[]
    all_sigs=[]
    model_quality=[]
    for replica in REPLICAS:
        sub=root/f"phase10-real-{replica}"
        rows,sigs,metadata=audit_replica(sub,replica)
        all_rows += rows
        all_sigs += sigs
        model=json.loads((sub/"model_training_audit.json").read_text())
        model_quality.append({
            "replica":replica,
            "validation_auc":model["validation_auc"],
            "old_original_heldout_auc":model["original_heldout_auc"],
            "frozen_threshold":model["threshold_calibrated_on_202"],
        })
    pd.DataFrame(all_rows).to_csv(out/"per_replica_metrics.csv",index=False)
    pd.DataFrame(all_sigs).to_csv(out/"signed_receipt_verification.csv",index=False)
    pd.DataFrame(model_quality).to_csv(out/"prior_model_quality.csv",index=False)
    summaries=[]
    for arm in ARMS:
        group=[x for x in all_rows if x["arm"]==arm]
        summaries.append({
            "arm":arm,
            "n_independent_runner_environments":len(group),
            "n_real_ue_attempts_across_runs":sum(x["real_pdu_trials"] for x in group),
            "n_real_lab_failstop_attempts":sum(x["real_failstop_trial_count"] for x in group),
            "actual_active_nrf_queries":sum(x["actual_nrf_http2_queries"] for x in group),
            "n_failstop_trials_actively_checked":sum(
                x["real_failstop_trials_actively_checked"] for x in group),
            "failstop_coverage":sum(x["real_failstop_trials_actively_checked"] for x in group)/12,
            "n_registry_absence_evidence_during_failstop":sum(
                x["nrf_absence_during_failstop"] for x in group),
            "healthy_trials_queried":sum(x["healthy_trials_queried"] for x in group),
            "healthy_registry_absence_observed":sum(
                x["registry_absence_in_other_selected_trials"] for x in group),
            "forced_quota_fallbacks":sum(x["forced_quota_fallbacks"] for x in group),
            "total_http_body_bytes":sum(x["http_response_body_bytes"] for x in group),
            "total_curl_http_ms":round(sum(x["curl_total_ms"] for x in group),3),
            "total_agent_process_ms":round(sum(x["agent_process_total_ms"] for x in group),3),
            "replica_failstop_coverage":dict(
                (x["replica"],x["failstop_trial_coverage"]) for x in group),
        })
    result={
        "scientific_scope":"controlled SMF FAIL-STOP coverage, not attack detection",
        "source":"48 genuine Open5GS/UERANSIM PDU attempts in three separate GH hosted ephemeral runners",
        "runs_have_separate_5gc_containers":True,
        "runs_have_independent_administrative_trust_domains":False,
        "all_agents_poll_the_same_NRF_within_each_replica":True,
        "signatures_verified":len(all_sigs),
        "replay_attempts_rejected":sum(s["replay_rejected"] for s in all_sigs),
        "arms":summaries,
        "limitations":[
            "Three runners are administratively controlled from same GitHub repository",
            "All agents within a runner use same local NRF and share underlying host trust",
            "No malicious NF compromise, no cryptographic evidence of source truth",
            "Failed UE with authorized DNN is chosen as a strong stop-specific heuristic",
            "ML was trained to predict legitimate stop, not malicious anomaly",
            "All probes are AFTER UE outcome, not early detection of outage",
            "No full HTTP/2/TLS overhead, just body sizes and measured local times",
            "Small 4-outage-per-run design without concurrent UE and with structured phases",
            "Potential interference of active probing arms querying same NRF in each run",
            "Challenge issuance ledger and key binding are generated in the same GH worker",
        ],
    }
    (out/"aggregated_summary.json").write_text(
        json.dumps(result,indent=2,ensure_ascii=False),encoding="utf-8")
    lines=[
        "# Phase 10: separate-runner real NRF active KIE budget experiment",
        "",
        "**The following results concern controlled SMF fail-stop only. They are NOT attack detection metrics.**",
        "",
        "| Active KIE scheduling policy | Real NRF requests | 12 SMF outage trials queried | Quota fallbacks | Response body bytes |",
        "|---|---:|---:|---:|---:|",
    ]
    for arm in summaries:
        lines.append(f"| {arm['arm']} | {arm['actual_active_nrf_queries']} | "
                     f"{arm['n_failstop_trials_actively_checked']} | "
                     f"{arm['forced_quota_fallbacks']} | {arm['total_http_body_bytes']} |")
    lines.extend(["",
        f"Live signed receipts independently checked: {len(all_sigs)}; "
        f"replays rejected in cross-job audit: {sum(s['replay_rejected'] for s in all_sigs)}.",
        "",
        "## Explicit trust and causal constraints",
        "- Separate GitHub runners are isolated execution environments under one account/authority.",
        "- Signature validation authenticates agent keys, not genuine NF truth or independent source domains.",
        "- Unlike classifier threshold fitting, source code comparison of phase labels is audit-only.",
        "- Query budgets are equal only when all selected live requests actually complete.",
        "- A 404 or NRF result with zero profiles is not proof of compromise.",
        "- Models learn controlled infrastructure availability using historical real PDU outcomes.",
        "- Without randomized simultaneous NF impairment there is no proof of universal model advantage.",
    ])
    (out/"REPORT.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    return result


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,default=Path("phase10_inputs"))
    p.add_argument("--out",type=Path,default=Path("results/phase10-aggregation"))
    args=p.parse_args()
    print(json.dumps(aggregate(args.root,args.out),indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()
