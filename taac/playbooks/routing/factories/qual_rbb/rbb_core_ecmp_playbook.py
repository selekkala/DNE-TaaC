# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Playbooks for Phase-1 Open/R path selection and core ECMP traffic."""

from __future__ import annotations

import ipaddress
import re
import typing as t

from taac.stages.stage_definitions import create_steps_stage
from taac.steps.step_definitions import (
    create_ixia_api_step,
    create_longevity_step,
    create_run_task_step,
    create_validation_step,
)
from taac.test_as_a_config.types import Playbook, Step
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_core_ecmp_profiles import (
    MIN_PATH_TRAFFIC_SHARE_PCT,
    OPENR_PREFERRED_METRIC,
    OPENR_STANDBY_METRIC,
    RbbCoreEcmpAction,
    RbbCoreEcmpProfile,
    validate_core_ecmp_topology,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology
from taac.testconfigs.routing.util.bgp_rbb_traffic_profiles import (
    FORWARD,
    TRAFFIC_DRAIN_SECONDS,
    TRAFFIC_SAMPLE_SECONDS,
    build_rbb_advertised_pools,
)

# Keep throughput/loss semantics identical to the established traffic suite.
from taac.playbooks.routing.factories.qual_rbb.rbb_traffic_foundation_playbook import (
    _packet_loss_check,
    _traffic_rate_check,
)

_METRIC_TIMEOUT_SECONDS = 30
_ROUTE_TIMEOUT_SECONDS = 60


def _sample_id(profile: RbbCoreEcmpProfile, role: str) -> str:
    return f"{profile.testplan_id}:{role}:openr-core"


def _core_rif_cidrs(role: str, path_count: int) -> list[str]:
    return [C.core_rif_cidr(role, index, 6) for index in range(path_count)]


def _remote_loopback_routes(role: str) -> list[dict[str, t.Any]]:
    if role == "r1":
        remote_v4, remote_v6 = C.R2_ROUTER_ID, C.R2_LOOPBACK_V6
    elif role == "r2":
        remote_v4, remote_v6 = C.R1_ROUTER_ID, C.R1_LOOPBACK_V6
    else:
        raise ValueError(f"unknown RBB role {role!r}")
    return [
        {
            "prefix": str(ipaddress.ip_network(f"{remote_v4}/32", strict=False)),
            "client": "OPENR",
            "require_fib": True,
        },
        {
            "prefix": str(ipaddress.ip_network(f"{remote_v6}/128", strict=False)),
            "client": "OPENR",
            "require_fib": True,
        },
    ]


def _task_step(
    profile: RbbCoreEcmpProfile,
    topology: RbbTopology,
    role: str,
    action: str,
    **params: t.Any,
) -> Step:
    hostname = topology.node(role).hostname
    return create_run_task_step(
        task_name="rbb_openr_core_path",
        params_dict={
            "action": action,
            "hostname": hostname,
            "gate": profile.testplan_id,
            "sample_id": _sample_id(profile, role),
            **params,
        },
        description=f"[{profile.testplan_id}:{role}] {action} Open/R core paths",
        start_traffic=False,
    )


def _snapshot_stage(
    profile: RbbCoreEcmpProfile, topology: RbbTopology, path_count: int
) -> t.Any:
    return create_steps_stage(
        steps=[
            _task_step(
                profile,
                topology,
                role,
                "snapshot",
                core_rif_cidrs=_core_rif_cidrs(role, path_count),
            )
            for role in ("r1", "r2")
        ],
        description=(
            f"{profile.testplan_id}: claim pristine Open/R metric state on both DUTs"
        ),
    )


def _ixia_hash_capability_stage(profile: RbbCoreEcmpProfile) -> t.Any:
    return create_steps_stage(
        steps=[
            create_run_task_step(
                task_name="rbb_ixia_capability",
                params_dict={
                    "gate": profile.testplan_id,
                    "require_variable_l4_flow_ranges": True,
                },
                description=(
                    f"[{profile.testplan_id}] require multi-flow ECMP hash inputs"
                ),
                ixia_needed=True,
                start_traffic=False,
            )
        ],
        description=(f"{profile.testplan_id}: verify IXIA ECMP-entropy capability"),
    )


def _metric_stage(
    profile: RbbCoreEcmpProfile,
    topology: RbbTopology,
    metrics: list[int],
    label: str,
) -> t.Any:
    return create_steps_stage(
        steps=[
            _task_step(
                profile,
                topology,
                role,
                "set_metrics",
                metrics=metrics,
                timeout_seconds=_METRIC_TIMEOUT_SECONDS,
                poll_interval_seconds=1,
            )
            for role in ("r1", "r2")
        ],
        description=f"{profile.testplan_id}: {label}",
    )


def _route_stage(
    profile: RbbCoreEcmpProfile,
    topology: RbbTopology,
    path_indices: list[int],
    *,
    routes_by_role: t.Mapping[str, list[dict[str, t.Any]]] | None = None,
    label: str,
) -> t.Any:
    routes_by_role = routes_by_role or {
        role: _remote_loopback_routes(role) for role in ("r1", "r2")
    }
    return create_steps_stage(
        steps=[
            _task_step(
                profile,
                topology,
                role,
                "assert_routes",
                path_indices=path_indices,
                routes=routes,
                timeout_seconds=_ROUTE_TIMEOUT_SECONDS,
                poll_interval_seconds=2,
            )
            for role, routes in routes_by_role.items()
        ],
        description=f"{profile.testplan_id}: {label}",
    )


def _restore_stage(profile: RbbCoreEcmpProfile, topology: RbbTopology) -> t.Any:
    return create_steps_stage(
        steps=[
            _task_step(
                profile,
                topology,
                role,
                "restore",
                timeout_seconds=_METRIC_TIMEOUT_SECONDS,
                poll_interval_seconds=1,
            )
            for role in ("r1", "r2")
        ],
        description=(
            f"{profile.testplan_id}: clear task-owned Open/R metric overrides"
        ),
    )


def _counter_specs(
    profile: RbbCoreEcmpProfile, topology: RbbTopology
) -> list[dict[str, t.Any]]:
    specs: list[dict[str, t.Any]] = []
    for index, (r1_pc, r2_pc) in enumerate(
        zip(topology.r1.core_pcs, topology.r2.core_pcs)
    ):
        for role, hostname, pc, direction, ixia_counter in (
            ("r1", topology.r1.hostname, r1_pc, "egress", "tx_frames"),
            ("r2", topology.r2.hostname, r2_pc, "ingress", "rx_frames"),
        ):
            specs.append(
                {
                    "hostname": hostname,
                    "gate": profile.testplan_id,
                    "sample_id": (
                        f"{profile.testplan_id}:path{index}:{role}:{direction}"
                    ),
                    "counter_interfaces": list(pc.members),
                    "counter_direction": direction,
                    "counter_kind": "packets",
                    "traffic_item": FORWARD.name,
                    "ixia_counter_field": ixia_counter,
                }
            )
    return specs


def _aggregate_counter_specs(
    profile: RbbCoreEcmpProfile, topology: RbbTopology
) -> list[dict[str, t.Any]]:
    """Correlate the complete core with IXIA before checking path shares.

    A per-path lower bound alone can be satisfied by unrelated background
    packets.  These aggregate samples prove that the measured traffic item is
    accounted for across the declared core as a whole; the per-path samples
    then prove distribution within that accounted volume.
    """
    specs: list[dict[str, t.Any]] = []
    for role, node, direction, ixia_counter in (
        ("r1", topology.r1, "egress", "tx_frames"),
        ("r2", topology.r2, "ingress", "rx_frames"),
    ):
        members = [member for pc in node.core_pcs for member in pc.members]
        specs.append(
            {
                "hostname": node.hostname,
                "gate": profile.testplan_id,
                "sample_id": f"{profile.testplan_id}:aggregate:{role}:{direction}",
                "counter_interfaces": members,
                "counter_direction": direction,
                "counter_kind": "packets",
                "traffic_item": FORWARD.name,
                "ixia_counter_field": ixia_counter,
            }
        )
    return specs


def _traffic_stage(profile: RbbCoreEcmpProfile, topology: RbbTopology) -> t.Any:
    aggregate_specs = _aggregate_counter_specs(profile, topology)
    path_specs = _counter_specs(profile, topology)
    specs = aggregate_specs + path_specs
    steps: list[Step] = [
        create_ixia_api_step(
            api_name="stop_traffic",
            args_dict={},
            description=f"[{profile.testplan_id}] stop traffic before measurement",
            start_traffic=False,
        ),
        # Initialize deferred Traffic Item selection and its statistics view.
        create_ixia_api_step(
            api_name="start_traffic",
            args_dict={},
            description=f"[{profile.testplan_id}] initialize selected traffic item",
            start_traffic=False,
        ),
        create_ixia_api_step(
            api_name="stop_traffic",
            args_dict={},
            description=f"[{profile.testplan_id}] stop initialization traffic",
            start_traffic=False,
        ),
        create_ixia_api_step(
            api_name="clear_traffic_stats",
            args_dict={},
            description=f"[{profile.testplan_id}] clear IXIA counters",
            start_traffic=False,
        ),
    ]
    steps.extend(
        create_run_task_step(
            task_name="rbb_traffic_counter_correlation",
            params_dict={"action": "snapshot", **spec},
            description=(
                f"[{profile.testplan_id}] snapshot {spec['sample_id']} counters"
            ),
            ixia_needed=True,
            start_traffic=False,
        )
        for spec in specs
    )
    steps.extend(
        [
            create_ixia_api_step(
                api_name="start_traffic",
                args_dict={},
                description=f"[{profile.testplan_id}] start {FORWARD.name}",
                start_traffic=False,
            ),
            create_longevity_step(
                duration=TRAFFIC_SAMPLE_SECONDS,
                description=(
                    f"[{profile.testplan_id}] collect {TRAFFIC_SAMPLE_SECONDS}s "
                    "multi-flow ECMP sample"
                ),
                start_traffic=False,
            ),
            create_validation_step(
                point_in_time_checks=[_traffic_rate_check([FORWARD.name])],
                description=f"[{profile.testplan_id}] verify IXIA Tx/Rx rate",
                start_traffic=False,
                fail_fast=True,
            ),
            create_ixia_api_step(
                api_name="stop_traffic",
                args_dict={},
                description=f"[{profile.testplan_id}] freeze measurement counters",
                start_traffic=False,
            ),
            create_longevity_step(
                duration=TRAFFIC_DRAIN_SECONDS,
                description=(f"[{profile.testplan_id}] allow final statistics refresh"),
                start_traffic=False,
            ),
        ]
    )
    # First prove that the complete core accounts for the IXIA traffic volume.
    # Only then use lower-bound shares to prove every constituent path carried
    # part of that same measurement window.
    steps.extend(
        create_run_task_step(
            task_name="rbb_traffic_counter_correlation",
            params_dict={"action": "assert", **spec},
            description=(
                f"[{profile.testplan_id}] correlate aggregate {spec['sample_id']}"
            ),
            ixia_needed=True,
            start_traffic=False,
        )
        for spec in aggregate_specs
    )
    steps.extend(
        create_run_task_step(
            task_name="rbb_traffic_counter_correlation",
            params_dict={
                "action": "assert_ixia_share",
                "min_ixia_share_percent": MIN_PATH_TRAFFIC_SHARE_PCT,
                **spec,
            },
            description=(
                f"[{profile.testplan_id}] require traffic on {spec['sample_id']}"
            ),
            ixia_needed=True,
            start_traffic=False,
        )
        for spec in path_specs
    )
    steps.append(
        create_validation_step(
            point_in_time_checks=[_packet_loss_check([FORWARD.name])],
            description=f"[{profile.testplan_id}] verify end-to-end packet loss",
            start_traffic=False,
            fail_fast=True,
        )
    )
    return create_steps_stage(
        steps=steps,
        description=(
            f"{profile.testplan_id}: prove every logical core path carries BGP traffic"
        ),
    )


def _cleanup_step(
    profile: RbbCoreEcmpProfile, topology: RbbTopology, *, stop_traffic: bool
) -> Step:
    operations: list[dict[str, t.Any]] = []
    if stop_traffic:
        operations.append({"type": "stop_traffic"})
    operations.extend(
        {
            "type": "restore_openr_core_path",
            "hostname": topology.node(role).hostname,
            "sample_id": _sample_id(profile, role),
            "gate": f"{profile.testplan_id}_cleanup",
        }
        for role in ("r1", "r2")
    )
    return create_run_task_step(
        task_name="rbb_best_effort_cleanup",
        params_dict={"action": "cleanup", "operations": operations},
        description=(
            f"[{profile.testplan_id}] independently stop traffic and restore metrics"
        ),
        start_traffic=False,
    )


def create_rbb_core_ecmp_playbook(
    profile: RbbCoreEcmpProfile,
    *,
    topology: RbbTopology,
) -> Playbook:
    """Build one reversible TC-02, TC-03, or TC-08 playbook."""
    path_count = validate_core_ecmp_topology(topology)
    uses_traffic = profile.action is RbbCoreEcmpAction.BGP_ECMP_TRAFFIC
    stages = []
    if uses_traffic:
        # Fail before claiming or changing Open/R path metrics when the active
        # backend would collapse TAAC's variable L4 ranges into one five-tuple.
        stages.append(_ixia_hash_capability_stage(profile))
    stages.append(_snapshot_stage(profile, topology, path_count))

    if profile.action is RbbCoreEcmpAction.OPENR_PATH_SELECTION:
        for selected in range(path_count):
            metrics = [
                OPENR_PREFERRED_METRIC if index == selected else OPENR_STANDBY_METRIC
                for index in range(path_count)
            ]
            stages.append(
                _metric_stage(
                    profile,
                    topology,
                    metrics,
                    f"make core path {selected} uniquely lowest cost",
                )
            )
            stages.append(
                _route_stage(
                    profile,
                    topology,
                    [selected],
                    label=f"verify core path {selected} is the only SPF next hop",
                )
            )
    else:
        stages.append(
            _metric_stage(
                profile,
                topology,
                [OPENR_PREFERRED_METRIC] * path_count,
                "configure equal metrics on every declared core path",
            )
        )
        stages.append(
            _route_stage(
                profile,
                topology,
                list(range(path_count)),
                label="verify Open/R installs every equal-cost next hop",
            )
        )
        if uses_traffic:
            tail_pool = next(
                pool for pool in build_rbb_advertised_pools() if pool.role == "r2"
            )
            stages.append(
                _route_stage(
                    profile,
                    topology,
                    list(range(path_count)),
                    routes_by_role={
                        "r1": [
                            {
                                "prefix": prefix,
                                "client": C.ROUTE_OWNER_BGPD,
                                "require_fib": True,
                            }
                            for prefix in tail_pool.prefixes
                        ]
                    },
                    label="verify remote BGPD prefixes resolve over core ECMP",
                )
            )
            stages.append(_traffic_stage(profile, topology))

    stages.append(_restore_stage(profile, topology))
    return Playbook(
        name=profile.playbook_name,
        description=(
            f"{profile.testplan_id} [{profile.coverage.value.upper()}]: "
            f"{profile.title}"
        ),
        prechecks=[],
        postchecks=[],
        stages=stages,
        cleanup_steps=[_cleanup_step(profile, topology, stop_traffic=uses_traffic)],
        traffic_items_to_start=[FORWARD.name] if uses_traffic else None,
        device_regexes=[f"^{re.escape(topology.r1.hostname)}$"],
    )


__all__ = ["create_rbb_core_ecmp_playbook"]
