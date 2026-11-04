# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""TestConfig factory for traffic-backed RBB resilience scenarios."""

from __future__ import annotations

import typing as t

from taac.test_as_a_config.types import TestConfig

from taac.playbooks.routing.factories.qual_rbb.rbb_resilience_playbook import (
    create_rbb_resilience_playbook,
)
from taac.testconfigs.routing.factories.qual_rbb.rbb_srv6_test_config import (
    _build_rbb_test_config,
    _include_traffic,
    _resolve_topology,
)
from taac.testconfigs.routing.util.bgp_rbb_lab_wiring import build_rbb_inventories
from taac.testconfigs.routing.util.bgp_rbb_resilience_profiles import (
    build_rbb_resilience_profiles,
    select_rbb_resilience_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_scenario_profiles import (
    SRV6_3_USIDS_PROFILE,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology


def _resolve_core_pc_index(
    topology: RbbTopology,
    core_pc_index: int | None,
    core_pc_name: str | None,
) -> int:
    """Resolve a deterministic outage target without relying on CSV order."""
    if core_pc_index is not None and (
        type(core_pc_index) is not int or core_pc_index < 0
    ):
        raise ValueError("core_pc_index must be a non-negative integer")

    normalized_name = (core_pc_name or "").strip()
    if core_pc_name is not None and not normalized_name:
        raise ValueError("core_pc_name must not be empty")
    if normalized_name:
        indexes: list[int] = []
        for role in ("r1", "r2"):
            matches = [
                index
                for index, pc in enumerate(topology.node(role).core_pcs)
                if pc.name == normalized_name
            ]
            if len(matches) > 1:
                raise ValueError(
                    f"core_pc_name {normalized_name!r} identifies more than "
                    f"one core PC on {role}"
                )
            indexes.extend(matches)
        if not indexes:
            raise ValueError(
                f"core_pc_name {normalized_name!r} is not declared on either DUT"
            )
        if len(set(indexes)) != 1:
            raise ValueError(
                f"core_pc_name {normalized_name!r} is ambiguous across DUT pairs"
            )
        if core_pc_index is not None and core_pc_index != indexes[0]:
            raise ValueError("core_pc_name and core_pc_index select different PCs")
        return indexes[0]

    return 0 if core_pc_index is None else core_pc_index


def create_rbb_resilience_test_config(
    topology: RbbTopology | None = None,
    *,
    name: str = "RBB_SRV6_RESILIENCE_TEST",
    testplan_ids: t.Iterable[str] | None = None,
    include_traffic: bool | None = None,
    allow_partial: bool = False,
    recovery_timeout_seconds: int = 180,
    traffic_sample_seconds: int = 10,
    outage_hold_seconds: int = 10,
    restart_openr_after_warmboot: bool = False,
    mutate_bgp_timers: bool = False,
    core_pc_index: int | None = None,
    core_pc_name: str | None = None,
    selected_path_min_traffic_percent: float = 1.0,
    disruption_loss_threshold_pct: str | None = None,
    warmboot_hw_agent_indices: t.Iterable[int] = (0,),
) -> TestConfig:
    """Build selected resilience playbooks on the PR #46 RBB foundation.

    These test-plan cases are traffic/convergence requirements, so the factory
    refuses device-only mode instead of silently reporting incomplete coverage.
    Partial profiles are excluded by default. The public wrapper explicitly
    opts into TC-30 because its route/MySID/service/traffic recovery is runnable
    while its missing QoS evidence remains visible in the playbook label.
    TC-22 remains excluded because a Binding SID is not yet programmed by the
    base implementation.
    """
    resolved_include_traffic = _include_traffic(include_traffic)
    if not resolved_include_traffic:
        raise ValueError(
            "RBB resilience cases require live IXIA traffic; set "
            "TAAC_RBB_INCLUDE_TRAFFIC=1 or pass include_traffic=True"
        )
    topology = _resolve_topology(topology, include_traffic=True)
    selected = select_rbb_resilience_profiles(
        build_rbb_resilience_profiles(topology),
        testplan_ids,
        allow_partial=allow_partial,
    )
    if not selected:
        raise ValueError("RBB resilience profile selection is empty")
    normalized_hw_indices = tuple(warmboot_hw_agent_indices)
    resolved_core_pc_index = _resolve_core_pc_index(
        topology, core_pc_index, core_pc_name
    )

    r1, r2 = build_rbb_inventories(topology)
    return _build_rbb_test_config(
        name=name,
        profile=SRV6_3_USIDS_PROFILE,
        playbooks=[
            create_rbb_resilience_playbook(
                profile,
                topology,
                recovery_timeout_seconds=recovery_timeout_seconds,
                traffic_sample_seconds=traffic_sample_seconds,
                outage_hold_seconds=outage_hold_seconds,
                restart_openr_after_warmboot=restart_openr_after_warmboot,
                mutate_bgp_timers=mutate_bgp_timers,
                core_pc_index=resolved_core_pc_index,
                selected_path_min_traffic_percent=(
                    selected_path_min_traffic_percent
                ),
                disruption_loss_threshold_pct=disruption_loss_threshold_pct,
                warmboot_hw_agent_indices=normalized_hw_indices,
            )
            for profile in selected
        ],
        r1=r1,
        r2=r2,
        topology=topology,
        include_traffic=True,
    )


__all__ = ["create_rbb_resilience_test_config"]
