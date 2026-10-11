"""Phase 13 precommitted active-source choices under two failure episodes.

Each of four strategies may perform TWO actual signed KIE probes in each of
two *observed UE failure episodes*, with budget 4 over 20 PDU attempts.
No phase name, Docker ground truth, future outcome or intervention type
influences source selection.

The informational policy uses assumed Bernoulli observation accuracies
(0.9) and an explicit 0.2 re-observation penalty. These assumptions are
NOT calibrated to this laboratory and do NOT prove optimal information gain.
"""
from __future__ import annotations
from dataclasses import dataclass,field
import math

ARMS=("nrf_only","upf_only","mixed","information")
BUDGET=4
N_TRIALS=20
SERVICE_BY_SOURCE={"nrf":"Nnrf_NFDiscovery_SMF",
                   "upf":"Lab_UPF_PFCP_UDP8805_Socket"}


def h(x:float)->float:
    if x<=0 or x>=1:return 0.
    return -x*math.log2(x)-(1-x)*math.log2(1-x)


def expected_information(p_smf:float,source:str)->float:
    """A priori scenario-based idealized fault-location information (bits)."""
    if source not in ("nrf","upf"):
        raise ValueError("Unknown control-information source")
    # Outcome y=1 indicates absence of advertised SMF / UPF runtime.
    smf_prob=.9 if source=="nrf" else .1
    upf_prob=.1 if source=="nrf" else .9
    py=p_smf*smf_prob+(1-p_smf)*upf_prob
    posterior_yes=p_smf*smf_prob/py
    posterior_no=p_smf*(1-smf_prob)/(1-py)
    return h(p_smf)-(py*h(posterior_yes)+(1-py)*h(posterior_no))


def update_posterior(p_smf:float,source:str,missing:bool|None)->float:
    if missing is None:
        return p_smf
    ls=.9 if source=="nrf" else .1
    lu=.1 if source=="nrf" else .9
    if not missing:
        ls=1-ls
        lu=1-lu
    return (p_smf*ls)/(p_smf*ls+(1-p_smf)*lu)


@dataclass
class Chooser:
    remaining:dict=field(default_factory=lambda:{x:BUDGET for x in ARMS})
    current_episode:int=0
    was_failure:bool=False
    per_episode:dict=field(default_factory=lambda:{x:0 for x in ARMS})
    info_p_smf:float=.5
    info_source_counts:dict=field(default_factory=lambda:{"nrf":0,"upf":0})

    def decide(self,pdu_success:int,dnn_authorized:int)->dict:
        eligible=(pdu_success==0 and dnn_authorized==1)
        if not eligible:
            self.was_failure=False
            return {}
        if not self.was_failure:
            self.current_episode+=1
            self.per_episode={x:0 for x in ARMS}
            self.info_p_smf=.5
            self.info_source_counts={"nrf":0,"upf":0}
        self.was_failure=True
        selections={}
        for arm in ARMS:
            if self.remaining[arm]<=0 or self.per_episode[arm]>=2 or self.current_episode>2:
                continue
            source={"nrf_only":"nrf","upf_only":"upf"}.get(arm)
            if arm=="mixed":
                source="nrf" if self.per_episode[arm]==0 else "upf"
            if arm=="information":
                values={s:expected_information(self.info_p_smf,s)*
                        (.2 if self.info_source_counts[s]>0 else 1.)
                        for s in ("nrf","upf")}
                source=max(("nrf","upf"),key=lambda s:(values[s],s=="nrf"))
            selections[arm]=source
            self.per_episode[arm]+=1
            self.remaining[arm]-=1
        return selections

    def observe_information(self,source:str,absent:bool|None)->None:
        self.info_source_counts[source]+=1
        self.info_p_smf=update_posterior(self.info_p_smf,source,absent)
