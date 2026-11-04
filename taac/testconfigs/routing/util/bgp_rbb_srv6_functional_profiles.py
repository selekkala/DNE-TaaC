# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Coverage-honest profiles for deeper RBB SRv6 functional validation.

The Phase-2 test plan contains several superficially related requirements whose
preconditions are materially different:

* TC-23 is a 16K End.DT46 MySID *scale* case.
* TC-24 proves the final uSID decapsulation and inner-table lookup path.
* TC-102 requires symmetric, one-hop SRv6 services in both directions.
* TC-105 removes a controller NHG and requires an OpenR service fallback.
* TC-106 injects an unknown uSID and proves an exact local-SID miss drop.

PR #46's two-node bootstrap safely provides the complete forward-path state
needed by TC-24.  It does not provide a transactional 16K MySID programmer or
the reverse R2-head/R1-tail service required by TC-102, an OpenR-owned service
fallback for TC-105, or the raw unknown-uSID/local-SID-drop evidence pair for
TC-106.  This module therefore exports a runnable TC-24 profile and explicit
blocked assessments for the other cases. A blocked case is never silently
reduced to a weaker test.
"""

from __future__ import annotations

import enum
import types
import typing as t
from dataclasses import dataclass

from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_scenario_profiles import (
    SRV6_3_USIDS_PROFILE,
    Srv6Profile,
)
from taac.testconfigs.routing.util.bgp_rbb_state_profiles import (
    RbbAuditCoverage,
    RbbInterfaceExpectation,
    RbbMySidExpectation,
    RbbRouteExpectation,
    RbbStateAuditProfile,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology


class Srv6CaseReadiness(enum.Enum):
    """Whether the current OSS two-node primitives close a requirement."""

    RUNNABLE = "runnable"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class Srv6CaseAssessment:
    """Automation readiness for one original Phase-2 test-plan case."""

    testplan_id: str
    title: str
    readiness: Srv6CaseReadiness
    factory: str | None = None
    evidence: tuple[str, ...] = ()
    unmet_requirements: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.testplan_id.startswith("phase2:TC-"):
            raise ValueError("SRv6 functional assessment requires a Phase-2 TC ID")
        if not self.title.strip():
            raise ValueError("SRv6 functional assessment requires a title")
        if not isinstance(self.readiness, Srv6CaseReadiness):
            raise TypeError("readiness must be Srv6CaseReadiness")
        if self.readiness is Srv6CaseReadiness.RUNNABLE:
            if not self.factory or not self.evidence or self.unmet_requirements:
                raise ValueError(
                    "runnable SRv6 cases require a factory and evidence, with no "
                    "unmet requirements"
                )
        elif self.factory or self.evidence or not self.unmet_requirements:
            raise ValueError("blocked SRv6 cases must expose unmet requirements only")


SRV6_FUNCTIONAL_CASES: t.Mapping[str, Srv6CaseAssessment] = types.MappingProxyType(
    {
        "phase2:TC-23": Srv6CaseAssessment(
            testplan_id="phase2:TC-23",
            title="16K End.DT46 MySID scale",
            readiness=Srv6CaseReadiness.BLOCKED,
            unmet_requirements=(
                (
                    "the test plan requests 16,384 End.DT46 entries while the "
                    "referenced platform table is currently provisioned for 2,048"
                ),
                (
                    "PR #46 owns one decap MySID and has no bulk MySID "
                    "add/read/restore primitive with rollback after partial "
                    "programming failure"
                ),
                (
                    "a platform capacity contract and a scale-safe traffic sampling "
                    "strategy are required before this can be a release gate"
                ),
            ),
        ),
        "phase2:TC-24": Srv6CaseAssessment(
            testplan_id="phase2:TC-24",
            title="Final uSID decapsulation and inner-table lookup",
            readiness=Srv6CaseReadiness.RUNNABLE,
            factory="create_rbb_srv6_tail_decap_test_config",
            evidence=(
                "the exact final MySID entry has DECAPSULATE_AND_LOOKUP behavior",
                "the inner destination is BGPD-owned and selected in the R2 FIB",
                "the R1 TE_AGENT route carries the exact packed uSID container",
                (
                    "IXIA reports no loss while R1 core-egress and R2 edge-egress "
                    "counters increase"
                ),
            ),
        ),
        "phase2:TC-102": Srv6CaseAssessment(
            testplan_id="phase2:TC-102",
            title="Bidirectional one-hop SRv6 traffic",
            readiness=Srv6CaseReadiness.BLOCKED,
            unmet_requirements=(
                (
                    "PR #46 provisions only the R1-head to R2-tail service and one "
                    "IXIA-advertised tail prefix pool"
                ),
                "R1 has no decap MySID and R2 has no reverse SRv6 steering route",
                (
                    "the current three-uSID zig-zag emulation is not the one-hop, "
                    "single-carrier topology required by TC-102"
                ),
                (
                    "a reversible symmetric edge/BGP/bootstrap contract must be "
                    "added before bidirectional traffic can be claimed"
                ),
            ),
        ),
        "phase2:TC-105": Srv6CaseAssessment(
            testplan_id="phase2:TC-105",
            title="Controller NHG removal with OpenR fallback",
            readiness=Srv6CaseReadiness.BLOCKED,
            unmet_requirements=(
                (
                    "PR #46 restores the service prefix to BGPD after deleting "
                    "its TE_AGENT route; BGPD fallback is not the OpenR shortest-"
                    "path fallback required by TC-105"
                ),
                (
                    "the bootstrap does not provision the tested service prefix "
                    "as an OPENR-owned route or verify OPENR as its preferred FIB "
                    "owner before controller NHG removal"
                ),
                (
                    "there is no RBB transaction that removes and restores only "
                    "a test-owned controller NHG while traffic is running"
                ),
            ),
        ),
        "phase2:TC-106": Srv6CaseAssessment(
            testplan_id="phase2:TC-106",
            title="Unknown-uSID clean-drop handling",
            readiness=Srv6CaseReadiness.BLOCKED,
            unmet_requirements=(
                (
                    "TAAC has generic RAW packet support, but no RBB SRv6 packet "
                    "builder that selects a uSID proven absent from every DUT "
                    "MySID entry and injects it on the declared ingress"
                ),
                (
                    "there is no portable exact local-SID miss/drop counter "
                    "primitive; the current R2 edge-egress delta is delivery "
                    "evidence and cannot prove a local-SID drop"
                ),
                (
                    "expected IXIA loss alone cannot distinguish a clean drop from "
                    "a loop or leak; bounded capture/counter evidence across the "
                    "possible egresses is still required"
                ),
            ),
        ),
    }
)


def build_tail_decap_state_profile(
    topology: RbbTopology,
    srv6_profile: Srv6Profile = SRV6_3_USIDS_PROFILE,
) -> RbbStateAuditProfile:
    """Build TC-24's exact tail MySID and inner-route evidence profile.

    The route expectation is deliberately tied to the IXIA peer address rather
    than a CLI substring.  ``rbb_state_audit`` reads the BGPD client RIB and
    verifies that BGPD is the preferred owner in the agent FIB.  The selected
    edge's physical state is checked separately; the FBOSS route API may render
    a logical RIF name rather than that physical member as ``ifName``.
    """
    edge_interface = topology.r2.primary_ixia_interface
    if not edge_interface:
        raise ValueError("phase2:TC-24 requires an IXIA-facing R2 edge")
    return RbbStateAuditProfile(
        testplan_id="phase2:TC-24",
        playbook_name="rbb_p2_tc24_tail_decap_inner_lookup",
        title="Final uSID decapsulation and inner-table lookup",
        coverage=RbbAuditCoverage.FULL,
        target_roles=("r2",),
        routes=(
            RbbRouteExpectation(
                role="r2",
                prefix=srv6_profile.tail_prefix,
                client=C.ROUTE_OWNER_BGPD,
                next_hops=(C.IXIA_R2_EDGE_V6,),
                exact_next_hops=True,
                next_hop_count=1,
            ),
        ),
        mysids=(
            RbbMySidExpectation(
                role="r2",
                sid=srv6_profile.decap_sid,
                behavior=C.SRV6_BEHAVIOR_DECAP,
                require_resolved=False,
            ),
        ),
        interfaces_up=(RbbInterfaceExpectation("r2", edge_interface),),
    )


def runnable_srv6_functional_ids() -> tuple[str, ...]:
    """Return only requirements fully runnable with the current primitives."""
    return tuple(
        testplan_id
        for testplan_id, assessment in SRV6_FUNCTIONAL_CASES.items()
        if assessment.readiness is Srv6CaseReadiness.RUNNABLE
    )


__all__ = [
    "SRV6_FUNCTIONAL_CASES",
    "Srv6CaseAssessment",
    "Srv6CaseReadiness",
    "build_tail_decap_state_profile",
    "runnable_srv6_functional_ids",
]
