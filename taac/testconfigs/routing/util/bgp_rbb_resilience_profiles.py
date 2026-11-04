# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Declarative catalog for the two-node RBB resilience follow-up cases.

The catalog states what each original test-plan case can honestly prove on the
two-node topology.  It contains no device access and no lab-specific values.
Mutating orchestration lives in the playbook factory.
"""

from __future__ import annotations

import enum
import re
import typing as t
from dataclasses import dataclass

from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology


class RbbResilienceAction(enum.Enum):
    AGENT_WARMBOOT = "agent_warmboot"
    BGP_RESTART = "bgp_restart"
    CORE_LINK_OUTAGE = "core_link_outage"
    EDGE_LINK_OUTAGE = "edge_link_outage"


class RbbResilienceCoverage(enum.Enum):
    FULL = "full"
    ADAPTED = "adapted"
    PARTIAL = "partial"


# The public resilience suite deliberately opts into TC-30's runnable partial
# coverage. TC-22 remains excluded because the base topology does not program
# the Binding SID that case is intended to restore.
RESILIENCE_SUITE_TESTPLAN_IDS: tuple[str, ...] = (
    "phase2:TC-15",
    "phase2:TC-30",
    "phase2:TC-104",
    "phase2:TC-99",
)


@dataclass(frozen=True)
class RbbResilienceProfile:
    """One independently reported resilience scenario."""

    testplan_id: str
    playbook_name: str
    title: str
    action: RbbResilienceAction
    coverage: RbbResilienceCoverage
    target_roles: tuple[str, ...]
    requires_traffic: bool = True
    unmet_requirements: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not re.fullmatch(r"phase2:TC-[0-9]+", self.testplan_id):
            raise ValueError(f"invalid resilience test-plan ID {self.testplan_id!r}")
        if not self.playbook_name.strip() or not self.title.strip():
            raise ValueError("resilience profile requires a name and title")
        if not isinstance(self.action, RbbResilienceAction):
            raise TypeError("action must be an RbbResilienceAction")
        if not isinstance(self.coverage, RbbResilienceCoverage):
            raise TypeError("coverage must be an RbbResilienceCoverage")
        if not self.target_roles or any(
            role not in ("r1", "r2") for role in self.target_roles
        ):
            raise ValueError("target_roles must contain only r1/r2")
        if len(set(self.target_roles)) != len(self.target_roles):
            raise ValueError("target_roles must not contain duplicates")
        if self.coverage is RbbResilienceCoverage.PARTIAL:
            if not self.unmet_requirements:
                raise ValueError("partial profiles must explain their gap")
        elif self.unmet_requirements:
            raise ValueError("full/adapted profiles cannot have unmet requirements")


def build_rbb_resilience_profiles(
    topology: RbbTopology,
) -> tuple[RbbResilienceProfile, ...]:
    """Return cases in dependency-safe execution order.

    Warmboot and daemon restart reuse only control-plane primitives.  Link
    cases are listed afterwards because they additionally depend on declared
    physical wiring and reversible port-state operations.
    """
    if not topology.r1.hostname or not topology.r2.hostname:
        raise ValueError("RBB resilience requires two named DUTs")
    return (
        RbbResilienceProfile(
            testplan_id="phase2:TC-15",
            playbook_name="rbb_p2_tc15_headend_warmboot",
            title="Headend agent warmboot with SRv6 state and traffic",
            action=RbbResilienceAction.AGENT_WARMBOOT,
            coverage=RbbResilienceCoverage.FULL,
            target_roles=("r1",),
        ),
        RbbResilienceProfile(
            testplan_id="phase2:TC-30",
            playbook_name="rbb_p2_tc30_tailend_warmboot",
            title="Tailend agent warmboot with SRv6 state and traffic",
            action=RbbResilienceAction.AGENT_WARMBOOT,
            coverage=RbbResilienceCoverage.PARTIAL,
            target_roles=("r2",),
            unmet_requirements=(
                (
                    "the base SRv6 bootstrap does not provision a QoS policy, "
                    "so TC-30 cannot verify QoS restoration after the R2 warmboot"
                ),
            ),
        ),
        RbbResilienceProfile(
            testplan_id="phase2:TC-104",
            playbook_name="rbb_p2_tc104_bgpd_restart_recovery",
            title="Sequential bgpd restart and route recovery",
            action=RbbResilienceAction.BGP_RESTART,
            coverage=RbbResilienceCoverage.FULL,
            target_roles=("r1", "r2"),
        ),
        RbbResilienceProfile(
            testplan_id="phase2:TC-100",
            playbook_name="rbb_p2_tc100_core_link_failure_recovery",
            title="Core path failure, alternate-path use, and recovery",
            action=RbbResilienceAction.CORE_LINK_OUTAGE,
            coverage=RbbResilienceCoverage.PARTIAL,
            target_roles=("r1",),
            unmet_requirements=(
                (
                    "the base two-node bootstrap pins different SRv6 legs to "
                    "different core PCs, so both PCs are required; a full "
                    "TC-100 run needs failover-capable MySID and underlay NHGs"
                ),
            ),
        ),
        RbbResilienceProfile(
            testplan_id="phase2:TC-99",
            playbook_name="rbb_p2_tc99_edge_link_outage_recovery",
            title="Adapted single-edge outage and recovery",
            action=RbbResilienceAction.EDGE_LINK_OUTAGE,
            coverage=RbbResilienceCoverage.ADAPTED,
            target_roles=("r1",),
        ),
        RbbResilienceProfile(
            testplan_id="phase2:TC-22",
            playbook_name="rbb_p2_tc22_midpoint_binding_warmboot_partial",
            title="Midpoint warmboot with Binding SID state",
            action=RbbResilienceAction.AGENT_WARMBOOT,
            coverage=RbbResilienceCoverage.PARTIAL,
            target_roles=("r2",),
            unmet_requirements=(
                (
                    "PR #46 does not program a Binding SID/MySID, so TC-22 cannot "
                    "yet verify Binding SID restoration after midpoint warmboot"
                ),
            ),
        ),
    )


def select_rbb_resilience_profiles(
    profiles: t.Iterable[RbbResilienceProfile],
    testplan_ids: t.Iterable[str] | None = None,
    *,
    allow_partial: bool = False,
) -> tuple[RbbResilienceProfile, ...]:
    """Select in catalog order and fail closed on unknown/partial cases."""
    ordered = tuple(profiles)
    by_id = {profile.testplan_id: profile for profile in ordered}
    if len(by_id) != len(ordered):
        raise ValueError("duplicate resilience test-plan IDs")
    if testplan_ids is None:
        return tuple(
            profile
            for profile in ordered
            if profile.coverage is not RbbResilienceCoverage.PARTIAL
        )

    requested = tuple(testplan_ids)
    if len(set(requested)) != len(requested):
        raise ValueError("duplicate resilience test-plan IDs in selection")
    unknown = [testplan_id for testplan_id in requested if testplan_id not in by_id]
    if unknown:
        raise ValueError(f"unknown RBB resilience test-plan IDs: {unknown}")
    selected = tuple(
        profile for profile in ordered if profile.testplan_id in set(requested)
    )
    partial = [
        profile.testplan_id
        for profile in selected
        if profile.coverage is RbbResilienceCoverage.PARTIAL
    ]
    if partial and not allow_partial:
        raise ValueError(
            f"partial RBB resilience profiles require allow_partial=True: {partial}"
        )
    return selected


__all__ = [
    "RESILIENCE_SUITE_TESTPLAN_IDS",
    "RbbResilienceAction",
    "RbbResilienceCoverage",
    "RbbResilienceProfile",
    "build_rbb_resilience_profiles",
    "select_rbb_resilience_profiles",
]
