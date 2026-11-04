# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Reusable two-node RBB SRv6 resilience playbook factory.

Every scenario follows the same evidence boundary:

1. exact BGPD/OPENR/NDP/MySID/service/interface baseline,
2. install the reversible TE_AGENT SRv6 steering route,
3. exact pre-disruption audit and lossless traffic baseline,
4. one bounded disruption/recovery action,
5. exact post-recovery audit and IXIA loss assertion, and
6. route/link/service cleanup that is safe to repeat.

Warmboot uses the shipped ``Service.AGENT`` restart primitive. In OSS mode the
FBOSS driver expands that into the warmboot-safe split-agent order. It does not
restart bgpd or OpenR and does not mutate BGP timers. OpenR restart is available
only through the explicit ``restart_openr_after_warmboot`` opt-in.
"""

from __future__ import annotations

import math
import re
import typing as t

from taac.health_check.health_check import types as hc_types
from taac.test_as_a_config import types as taac_types
from taac.test_as_a_config.types import Playbook, Step

from taac.health_checks.healthcheck_definitions import (
    create_ixia_packet_loss_check,
    create_ixia_traffic_rate_check,
)
from taac.stages.stage_definitions import create_steps_stage
from taac.steps.step_definitions import (
    create_clear_traffic_stats_step,
    create_interface_flap_step,
    create_longevity_step,
    create_run_task_step,
    create_service_convergence_step,
    create_service_interruption_step,
    create_start_traffic_step,
    create_stop_traffic_step,
    create_validation_step,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_resilience_profiles import (
    RbbResilienceAction,
    RbbResilienceProfile,
)
from taac.testconfigs.routing.util.bgp_rbb_scenario_profiles import (
    SRV6_3_USIDS_PROFILE,
    Srv6Profile,
    verify_route_owner_te_agent_spec,
)
from taac.testconfigs.routing.util.bgp_rbb_state_profiles import (
    RbbNdpExpectation,
    RbbRouteExpectation,
    build_rbb_state_audit_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology
from taac.tasks.rbb_input_validation import validated_fboss_interface_names

_AUDIT_PROFILE_IDS = (
    "phase2:TC-110",  # exact OPENR routes + ECMP
    "phase2:TC-111",  # exact NDP state per core path
    "phase2:TC-112",  # exact currently programmed MySIDs
    "phase1:TC-10",  # critical services + core interfaces
)


def _dedupe(items: t.Iterable[t.Any]) -> list[t.Any]:
    result: list[t.Any] = []
    for item in items:
        if item not in result:
            result.append(item)
    return result


def _healthy_audit_params(
    topology: RbbTopology,
    role: str,
    *,
    steering_active: bool,
    srv6_profile: Srv6Profile,
) -> dict[str, t.Any]:
    """Merge the common exact evidence into one DUT snapshot."""
    catalog = {
        profile.testplan_id: profile
        for profile in build_rbb_state_audit_profiles(topology, srv6_profile)
    }
    params: dict[str, list[t.Any]] = {
        "routes": [],
        "ndp": [],
        "mysids": [],
        "active_services": [],
        "interfaces_up": [],
    }
    for testplan_id in _AUDIT_PROFILE_IDS:
        evidence = catalog[testplan_id].to_task_params(role)
        for key, value in params.items():
            value.extend(evidence[key])

    # The traffic prefix must remain in the BGPD RIB throughout. While SRv6
    # steering is active, its TE_AGENT copy must be the preferred FIB owner.
    params["routes"].append(
        RbbRouteExpectation(
            role,
            srv6_profile.tail_prefix,
            "BGPD",
            require_fib=not (role == "r1" and steering_active),
        ).to_params()
    )
    if role == "r1" and steering_active:
        params["routes"].append(
            RbbRouteExpectation(
                "r1", srv6_profile.tail_prefix, C.ROUTE_OWNER_TE_AGENT
            ).to_params()
        )

    edge = topology.node(role).primary_ixia_interface
    if edge:
        params["interfaces_up"].append(edge)
    return {key: _dedupe(value) for key, value in params.items()}


def _audit_step(
    topology: RbbTopology,
    role: str,
    gate: str,
    *,
    steering_active: bool,
    srv6_profile: Srv6Profile,
    timeout_seconds: int = 0,
) -> Step:
    params: dict[str, t.Any] = {
        "hostname": topology.node(role).hostname,
        "gate": gate,
        **_healthy_audit_params(
            topology,
            role,
            steering_active=steering_active,
            srv6_profile=srv6_profile,
        ),
    }
    if timeout_seconds:
        params.update(
            timeout_seconds=timeout_seconds,
            poll_interval_seconds=min(5, max(1, timeout_seconds // 12)),
        )
    return create_run_task_step(
        task_name="rbb_state_audit",
        params_dict=params,
        description=f"[{gate}:{role}] exact RBB state audit",
        start_traffic=False,
    )


def _audit_stage(
    topology: RbbTopology,
    gate: str,
    *,
    steering_active: bool,
    srv6_profile: Srv6Profile,
    timeout_seconds: int = 0,
) -> t.Any:
    steps = [
        _audit_step(
            topology,
            role,
            gate,
            steering_active=steering_active,
            srv6_profile=srv6_profile,
            timeout_seconds=timeout_seconds,
        )
        for role in ("r1", "r2")
    ]
    if steering_active:
        params = {
            "hostname": topology.r1.hostname,
            **verify_route_owner_te_agent_spec(srv6_profile),
        }
        params["gate"] = gate
        steps.append(
            create_run_task_step(
                task_name="rbb_srv6_verify",
                params_dict=params,
                description=(f"[{gate}:r1] exact TE_AGENT SRv6 segment-route readback"),
                start_traffic=False,
            )
        )
    return create_steps_stage(
        steps=steps,
        description=f"{gate}: exact two-DUT state boundary",
    )


def _direct_route_step(hostname: str, action: str, profile: Srv6Profile) -> Step:
    return create_run_task_step(
        task_name="rbb_srv6_direct_route",
        params_dict={
            "hostname": hostname,
            "action": action,
            "prefix": profile.tail_prefix,
            "client": C.ROUTE_OWNER_TE_AGENT,
            "srv6_segments": [
                C.pack_usid_container(profile.locator, profile.encap_usids)
            ],
            "srv6_tunnel_id": C.SRV6_TUNNEL_ID,
        },
        description=(
            f"{action} reversible TE_AGENT SRv6 route for {profile.tail_prefix}"
        ),
        start_traffic=False,
    )


def _ixia_stats_reset_capability_step(testplan_id: str) -> Step:
    """Reject cumulative-only backends before any DUT mutation."""
    return create_run_task_step(
        task_name="rbb_ixia_capability",
        params_dict={
            "gate": testplan_id,
            "require_controller_traffic_stats_reset": True,
        },
        description=(
            f"[{testplan_id}] require isolated IXIA traffic-stat windows"
        ),
        ixia_needed=True,
        start_traffic=False,
    )


def _traffic_loss_step(
    description: str,
    *,
    expect_loss: bool = False,
    threshold_pct: str = C.PACKET_LOSS_THRESHOLD_PCT,
) -> Step:
    return create_validation_step(
        point_in_time_checks=[
            create_ixia_packet_loss_check(
                thresholds=[
                    hc_types.PacketLossThreshold(
                        names=list(C.ALL_TRAFFIC_ITEMS),
                        metric=hc_types.PacketLossMetric.PERCENTAGE,
                        str_value=threshold_pct,
                        expect_packet_loss=expect_loss,
                    )
                ]
            )
        ],
        description=description,
        start_traffic=False,
        fail_fast=True,
    )


def _edge_outage_loss_step(
    description: str,
    *,
    max_loss_pct: str | None,
) -> Step:
    """Require observable edge loss and enforce an optional maximum."""
    thresholds = [
        hc_types.PacketLossThreshold(
            names=list(C.ALL_TRAFFIC_ITEMS),
            metric=hc_types.PacketLossMetric.PERCENTAGE,
            expect_packet_loss=True,
        )
    ]
    if max_loss_pct is not None:
        thresholds.append(
            hc_types.PacketLossThreshold(
                names=list(C.ALL_TRAFFIC_ITEMS),
                metric=hc_types.PacketLossMetric.PERCENTAGE,
                str_value=max_loss_pct,
                expect_packet_loss=False,
            )
        )
    return create_validation_step(
        point_in_time_checks=[create_ixia_packet_loss_check(thresholds=thresholds)],
        description=description,
        start_traffic=False,
        fail_fast=True,
    )


def _disruption_loss_step(
    description: str,
    *,
    max_loss_pct: str | None,
) -> Step:
    """Record disruption loss and enforce a budget only when one is declared.

    The source test plan asks these convergence scenarios to measure loss and
    prove recovery, but it does not define one universal hitless SLA for agent
    warmboot, bgpd restart, and core-link failover. An unset budget therefore
    uses a non-failing 100% ceiling so IXIA still records percentage, duration,
    and frame delta in the test evidence. The isolated recovered window remains
    subject to the normal strict packet-loss threshold.
    """
    return _traffic_loss_step(
        description,
        threshold_pct=max_loss_pct if max_loss_pct is not None else "100",
    )


def _traffic_rate_step(description: str) -> Step:
    """Reject absent or zero-Tx/zero-Rx traffic before checking loss."""
    return create_validation_step(
        point_in_time_checks=[
            create_ixia_traffic_rate_check(
                thresholds=[
                    hc_types.TrafficRateThreshold(
                        names=list(C.ALL_TRAFFIC_ITEMS),
                        value=0,
                        threshold_type=hc_types.ThresholdType.ABSOLUTE,
                        metric=hc_types.TrafficRateMetric.TX_RATE,
                    )
                ]
            )
        ],
        description=description,
        start_traffic=False,
        fail_fast=True,
    )


def _service_step(
    service: taac_types.Service,
    hostname: str,
    *,
    trigger: taac_types.ServiceInterruptionTrigger,
    description: str,
) -> Step:
    return create_service_interruption_step(
        service=service,
        trigger=trigger,
        description=description,
        device_regexes=[f"^{re.escape(hostname)}$"],
        start_traffic=False,
    )


def _convergence_step(
    hostname: str,
    services: list[taac_types.Service],
    timeout_seconds: int,
    description: str,
) -> Step:
    return create_service_convergence_step(
        services=services,
        timeout=timeout_seconds,
        description=description,
        device_regexes=[f"^{re.escape(hostname)}$"],
        start_traffic=False,
    )


def _interface_step(
    hostname: str,
    interfaces: list[str],
    *,
    enable: bool,
    description: str,
) -> Step:
    validated_interfaces = validated_fboss_interface_names(
        interfaces, "resilience interfaces"
    )
    return create_interface_flap_step(
        enable=enable,
        interfaces=validated_interfaces,
        interface_flap_method=(taac_types.InterfaceFlapMethod.THRIFT_PORT_STATE_CHANGE),
        delay=0,
        device_name=hostname,
        description=description,
        start_traffic=False,
    )


def _cleanup_marker_step(marker: str, *, armed: bool) -> Step:
    action = "arm" if armed else "disarm"
    return create_run_task_step(
        task_name="rbb_best_effort_cleanup",
        params_dict={"action": action, "marker": marker},
        description=f"{action.capitalize()} guarded cleanup for {marker}",
        start_traffic=False,
    )


def _split_agent_recovery_operation(
    hostname: str,
    hw_agent_indices: tuple[int, ...],
    timeout_seconds: int,
) -> dict[str, t.Any]:
    """Describe fail-safe cleanup for an interrupted split-agent warmboot."""
    return {
        "type": "recover_split_agent",
        "hostname": hostname,
        "hw_agent_indices": list(hw_agent_indices),
        "hw_ready_timeout_seconds": timeout_seconds,
        "sw_ready_timeout_seconds": timeout_seconds,
    }


def _direct_route_cleanup_operation(
    hostname: str, profile: Srv6Profile
) -> dict[str, t.Any]:
    return {
        "type": "delete_direct_route",
        "hostname": hostname,
        "prefix": profile.tail_prefix,
        "client": C.ROUTE_OWNER_TE_AGENT,
        "srv6_segments": [C.pack_usid_container(profile.locator, profile.encap_usids)],
        "srv6_tunnel_id": C.SRV6_TUNNEL_ID,
    }


def _best_effort_cleanup_step(operations: list[dict[str, t.Any]]) -> Step:
    return create_run_task_step(
        task_name="rbb_best_effort_cleanup",
        params_dict={"action": "cleanup", "operations": operations},
        description="Best-effort RBB cleanup (attempt every independent action)",
        ixia_needed=True,
        start_traffic=False,
    )


def _bgp_session_step(
    topology: RbbTopology,
    role: str,
    gate: str,
) -> Step:
    """Verify the exact core and IXIA peers after a bgpd restart."""
    peers = (
        [C.R2_ROUTER_ID, C.IXIA_R1_EDGE_V6]
        if role == "r1"
        else [C.R1_ROUTER_ID, C.IXIA_R2_EDGE_V6]
    )
    return create_run_task_step(
        task_name="rbb_srv6_verify",
        params_dict={
            "hostname": topology.node(role).hostname,
            "gate": gate,
            "bgp_peers_established": peers,
        },
        description=f"[{gate}:{role}] exact iBGP/eBGP sessions Established",
        start_traffic=False,
    )


def _core_path_counter_stage(
    topology: RbbTopology,
    profile: RbbResilienceProfile,
    core_pc_index: int,
    traffic_sample_seconds: int,
    *,
    selected_path: bool,
    selected_path_min_traffic_percent: float,
) -> t.Any:
    """Prove traffic-scale forwarding on the selected or surviving core PC."""
    path_label = "selected" if selected_path else "surviving"
    specs: list[tuple[str, dict[str, t.Any]]] = []
    for role in ("r1", "r2"):
        counter_direction = "egress" if role == "r1" else "ingress"
        paths = [
            pc
            for index, pc in enumerate(topology.node(role).core_pcs)
            if (index == core_pc_index) is selected_path
        ]
        if len(paths) != 1 or not paths[0].members:
            raise ValueError(
                f"{profile.testplan_id} requires exactly one {path_label} core "
                f"PC on {role}"
            )
        specs.append(
            (
                role,
                {
                    "hostname": topology.node(role).hostname,
                    "gate": f"{profile.testplan_id}_{path_label}_core",
                    "sample_id": (
                        f"{profile.testplan_id}:{role}:{paths[0].name}:"
                        f"{counter_direction}"
                    ),
                    "counter_interfaces": list(paths[0].members),
                    "counter_direction": counter_direction,
                    "counter_kind": "packets",
                    "traffic_item": C.TRAFFIC_ITEM_R1_TO_R2,
                    "ixia_counter_field": "tx_frames",
                },
            )
        )

    steps: list[Step] = []
    for _, spec in specs:
        steps.append(
            create_run_task_step(
                task_name="rbb_traffic_counter_correlation",
                params_dict={"action": "snapshot", **spec},
                description=(
                    f"[{profile.testplan_id}] snapshot {path_label} core "
                    f"{spec['counter_direction']} on {spec['hostname']}"
                ),
                start_traffic=False,
            )
        )
    steps.append(
            create_longevity_step(
                duration=min(5, traffic_sample_seconds),
                description=f"Collect traffic on the {path_label} core path",
                start_traffic=False,
            )
    )
    for _, spec in specs:
        action = "assert_ixia_share" if selected_path else "assert_at_least_ixia"
        steps.append(
            create_run_task_step(
                task_name="rbb_traffic_counter_correlation",
                params_dict={
                    "action": action,
                    "tolerance_percent": 10,
                    "absolute_tolerance": 256,
                    "min_value": 1,
                    **(
                        {
                            "min_ixia_share_percent": (
                                selected_path_min_traffic_percent
                            )
                        }
                        if selected_path
                        else {}
                    ),
                    **spec,
                },
                description=(
                    f"[{profile.testplan_id}] assert {path_label} core "
                    f"{spec['counter_direction']} on {spec['hostname']}"
                ),
                start_traffic=False,
            )
        )
    return create_steps_stage(
        steps=steps,
        description=(
            f"{profile.testplan_id}: {path_label} core-path traffic evidence"
        ),
    )


def _degraded_core_audit_stage(
    topology: RbbTopology,
    profile: RbbResilienceProfile,
    srv6_profile: Srv6Profile,
    timeout_seconds: int,
    core_pc_index: int,
) -> t.Any:
    steps: list[Step] = []
    for role in ("r1", "r2"):
        node = topology.node(role)
        remaining_pcs = tuple(
            pc for index, pc in enumerate(node.core_pcs) if index != core_pc_index
        )
        remaining_paths = len(remaining_pcs)
        remote_v4 = C.R2_ROUTER_ID if role == "r1" else C.R1_ROUTER_ID
        remote_v6 = C.R2_LOOPBACK_V6 if role == "r1" else C.R1_LOOPBACK_V6
        routes = [
            RbbRouteExpectation(
                role,
                f"{remote_v4}/32",
                "OPENR",
                next_hop_count=remaining_paths,
                next_hop_interface_count=remaining_paths,
                next_hop_scope="link_local",
            ).to_params(),
            RbbRouteExpectation(
                role,
                f"{remote_v6}/128",
                "OPENR",
                next_hop_count=remaining_paths,
                next_hop_interface_count=remaining_paths,
                next_hop_scope="link_local",
            ).to_params(),
            RbbRouteExpectation(
                role,
                srv6_profile.tail_prefix,
                "BGPD",
                require_fib=role != "r1",
            ).to_params(),
        ]
        if role == "r1":
            routes.append(
                RbbRouteExpectation(
                    role, srv6_profile.tail_prefix, C.ROUTE_OWNER_TE_AGENT
                ).to_params()
            )
        steps.append(
            create_run_task_step(
                task_name="rbb_state_audit",
                params_dict={
                    "hostname": node.hostname,
                    "gate": f"{profile.testplan_id}_degraded_core",
                    "routes": routes,
                    "ndp": [
                        RbbNdpExpectation(role, pc.members[0]).to_params()
                        for pc in remaining_pcs
                    ],
                    "interfaces_up": [
                        member for pc in remaining_pcs for member in pc.members
                    ],
                    "timeout_seconds": timeout_seconds,
                    "poll_interval_seconds": 2,
                },
                description=(
                    f"[{profile.testplan_id}:{role}] verify {remaining_paths} "
                    "remaining OpenR path(s)"
                ),
                start_traffic=False,
            )
        )
    return create_steps_stage(
        steps=steps,
        description=(f"{profile.testplan_id}: bounded alternate-core-path convergence"),
    )


def _disruption_stages(
    profile: RbbResilienceProfile,
    topology: RbbTopology,
    srv6_profile: Srv6Profile,
    *,
    recovery_timeout_seconds: int,
    outage_hold_seconds: int,
    restart_openr_after_warmboot: bool,
    core_pc_index: int,
    selected_path_min_traffic_percent: float,
    disruption_loss_threshold_pct: str | None,
    warmboot_hw_agent_indices: tuple[int, ...],
    traffic_sample_seconds: int,
) -> tuple[list[t.Any], list[dict[str, t.Any]]]:
    """Return scenario stages plus guarded mutation-cleanup operations."""
    stages: list[t.Any] = []
    cleanup: list[dict[str, t.Any]] = []

    if profile.action is RbbResilienceAction.AGENT_WARMBOOT:
        hostname = topology.node(profile.target_roles[0]).hostname
        agent_marker = f"{profile.testplan_id}:warmboot:{hostname}"
        # This must be the first mutation cleanup. A failed split restart may
        # leave one or both agent layers stopped, in which case route cleanup
        # cannot even contact the DUT until the dependency-safe recovery runs.
        cleanup.append(
            {
                **_split_agent_recovery_operation(
                    hostname,
                    warmboot_hw_agent_indices,
                    recovery_timeout_seconds,
                ),
                "marker": agent_marker,
            }
        )
        steps = [
            _cleanup_marker_step(agent_marker, armed=True),
            create_clear_traffic_stats_step(start_traffic=False),
            _service_step(
                taac_types.Service.AGENT,
                hostname,
                trigger=taac_types.ServiceInterruptionTrigger.SYSTEMCTL_RESTART,
                description=(
                    f"{profile.testplan_id}: warmboot FBOSS agent on {hostname}"
                ),
            ),
            _convergence_step(
                hostname,
                [
                    taac_types.Service.AGENT,
                    taac_types.Service.BGP,
                    taac_types.Service.OPENR,
                ],
                recovery_timeout_seconds,
                f"{profile.testplan_id}: bounded agent/control-plane recovery",
            ),
        ]
        if restart_openr_after_warmboot:
            openr_marker = f"{profile.testplan_id}:openr-restart:{hostname}"
            steps.extend(
                [
                    _cleanup_marker_step(openr_marker, armed=True),
                    _service_step(
                        taac_types.Service.OPENR,
                        hostname,
                        trigger=(
                            taac_types.ServiceInterruptionTrigger.SYSTEMCTL_RESTART
                        ),
                        description=(
                            f"{profile.testplan_id}: explicitly requested OpenR restart"
                        ),
                    ),
                    _convergence_step(
                        hostname,
                        [taac_types.Service.OPENR],
                        recovery_timeout_seconds,
                        f"{profile.testplan_id}: bounded OpenR recovery",
                    ),
                ]
            )
            cleanup.append(
                {
                    "type": "start_service",
                    "marker": openr_marker,
                    "hostname": hostname,
                    "service": "OPENR",
                }
            )
        stages.append(
            create_steps_stage(
                steps=steps,
                description=f"{profile.testplan_id}: warmboot and bounded recovery",
            )
        )
        return stages, cleanup

    if profile.action is RbbResilienceAction.BGP_RESTART:
        steps: list[Step] = []
        for role_index, role in enumerate(profile.target_roles):
            hostname = topology.node(role).hostname
            marker = f"{profile.testplan_id}:bgp-restart:{hostname}"
            steps.append(_cleanup_marker_step(marker, armed=True))
            if role_index == 0:
                # Isolate the complete sequential-restart event. This reset is
                # intentionally after cleanup is armed and immediately before
                # the first disruptive operation.
                steps.append(create_clear_traffic_stats_step(start_traffic=False))
            steps.extend(
                [
                    _service_step(
                        taac_types.Service.BGP,
                        hostname,
                        trigger=(
                            taac_types.ServiceInterruptionTrigger.SYSTEMCTL_RESTART
                        ),
                        description=(
                            f"{profile.testplan_id}: restart bgpd on {hostname}"
                        ),
                    ),
                    _convergence_step(
                        hostname,
                        [taac_types.Service.BGP],
                        recovery_timeout_seconds,
                        f"{profile.testplan_id}: bounded BGP recovery on {hostname}",
                    ),
                    _bgp_session_step(
                        topology,
                        role,
                        f"{profile.testplan_id}_bgp_recovery",
                    ),
                ]
            )
            cleanup.append(
                {
                    "type": "start_service",
                    "marker": marker,
                    "hostname": hostname,
                    "service": "BGP",
                }
            )
        stages.append(
            create_steps_stage(
                steps=steps,
                description=f"{profile.testplan_id}: sequential bgpd restart/recovery",
            )
        )
        return stages, cleanup

    role = profile.target_roles[0]
    node = topology.node(role)
    if profile.action is RbbResilienceAction.CORE_LINK_OUTAGE:
        if any(len(topology.node(item).core_pcs) < 2 for item in ("r1", "r2")):
            raise ValueError(
                f"{profile.testplan_id} requires at least two independent core "
                "PCs on both DUTs"
            )
        if any(
            not 0 <= core_pc_index < len(topology.node(item).core_pcs)
            for item in ("r1", "r2")
        ):
            raise ValueError(
                f"core_pc_index {core_pc_index} does not exist on both DUTs"
            )
        selected = node.core_pcs[core_pc_index]
        interfaces = list(selected.members)
        if not interfaces:
            raise ValueError(f"selected core PC {selected.name} has no members")
        marker = f"{profile.testplan_id}:core-outage:{node.hostname}:{selected.name}"
        restore = _interface_step(
            node.hostname,
            interfaces,
            enable=True,
            description=f"Restore {selected.name} members on {node.hostname}",
        )
        cleanup.append(
            {
                "type": "enable_interfaces",
                "marker": marker,
                "hostname": node.hostname,
                "interfaces": interfaces,
            }
        )
        stages.extend(
            [
                # Fail before arming cleanup or mutating the DUT if the
                # requested outage target is not carrying the IXIA flow. This
                # prevents a false pass caused by disabling an unused PC.
                _core_path_counter_stage(
                    topology,
                    profile,
                    core_pc_index,
                    traffic_sample_seconds,
                    selected_path=True,
                    selected_path_min_traffic_percent=(
                        selected_path_min_traffic_percent
                    ),
                ),
                create_steps_stage(
                    steps=[
                        _cleanup_marker_step(marker, armed=True),
                        create_clear_traffic_stats_step(start_traffic=False),
                        _interface_step(
                            node.hostname,
                            interfaces,
                            enable=False,
                            description=(
                                f"{profile.testplan_id}: disable all {selected.name} "
                                f"members on {node.hostname}"
                            ),
                        ),
                    ],
                    description=f"{profile.testplan_id}: fail one core path",
                ),
                _degraded_core_audit_stage(
                    topology,
                    profile,
                    srv6_profile,
                    recovery_timeout_seconds,
                    core_pc_index,
                ),
                _core_path_counter_stage(
                    topology,
                    profile,
                    core_pc_index,
                    traffic_sample_seconds,
                    selected_path=False,
                    selected_path_min_traffic_percent=(
                        selected_path_min_traffic_percent
                    ),
                ),
                create_steps_stage(
                    steps=[restore],
                    description=f"{profile.testplan_id}: restore failed core path",
                ),
            ]
        )
        return stages, cleanup

    if profile.action is RbbResilienceAction.EDGE_LINK_OUTAGE:
        interface = node.primary_ixia_interface
        if not interface:
            raise ValueError(f"{profile.testplan_id} requires a selected IXIA edge")
        marker = f"{profile.testplan_id}:edge-outage:{node.hostname}:{interface}"
        restore = _interface_step(
            node.hostname,
            [interface],
            enable=True,
            description=f"Restore IXIA edge {interface} on {node.hostname}",
        )
        cleanup.append(
            {
                "type": "enable_interfaces",
                "marker": marker,
                "hostname": node.hostname,
                "interfaces": [interface],
            }
        )
        stages.extend(
            [
                create_steps_stage(
                    steps=[
                        _cleanup_marker_step(marker, armed=True),
                        create_clear_traffic_stats_step(start_traffic=False),
                        _interface_step(
                            node.hostname,
                            [interface],
                            enable=False,
                            description=(
                                f"{profile.testplan_id}: disable IXIA edge "
                                f"{interface} on {node.hostname}"
                            ),
                        ),
                        create_longevity_step(
                            duration=outage_hold_seconds,
                            description=(
                                "Hold the single-edge outage measurement window"
                            ),
                            start_traffic=False,
                        ),
                        _edge_outage_loss_step(
                            (
                                f"{profile.testplan_id}: outage produces "
                                "measurable loss"
                            ),
                            max_loss_pct=disruption_loss_threshold_pct,
                        ),
                    ],
                    description=f"{profile.testplan_id}: adapted edge outage",
                ),
                create_steps_stage(
                    steps=[restore],
                    description=f"{profile.testplan_id}: restore IXIA edge",
                ),
            ]
        )
        return stages, cleanup

    raise ValueError(f"unsupported resilience action {profile.action}")


def create_rbb_resilience_playbook(
    profile: RbbResilienceProfile,
    topology: RbbTopology,
    *,
    srv6_profile: Srv6Profile = SRV6_3_USIDS_PROFILE,
    recovery_timeout_seconds: int = 180,
    traffic_sample_seconds: int = 10,
    outage_hold_seconds: int = 10,
    restart_openr_after_warmboot: bool = False,
    mutate_bgp_timers: bool = False,
    core_pc_index: int = 0,
    selected_path_min_traffic_percent: float = 1.0,
    disruption_loss_threshold_pct: str | None = None,
    warmboot_hw_agent_indices: t.Iterable[int] = (0,),
) -> Playbook:
    """Build one traffic-backed, reversible resilience playbook.

    ``mutate_bgp_timers`` deliberately fails closed. There is no OSS task that
    snapshots, mutates, verifies, and restores this image's bgpd JSON timers;
    silently issuing shell edits would violate the cleanup contract. A future
    timer overlay must first provide that reversible primitive.

    ``warmboot_hw_agent_indices`` defaults to ``(0,)`` for the single-NPU
    two-node C8501 topology. Multi-NPU adopters must declare every split HW
    agent index so fail-safe cleanup restores all agent layers in order.
    """
    if recovery_timeout_seconds <= 0:
        raise ValueError("recovery_timeout_seconds must be positive")
    if traffic_sample_seconds <= 0 or outage_hold_seconds <= 0:
        raise ValueError("traffic/outage windows must be positive")
    if (
        isinstance(selected_path_min_traffic_percent, bool)
        or not isinstance(selected_path_min_traffic_percent, (int, float))
        or not math.isfinite(float(selected_path_min_traffic_percent))
        or not 0 < selected_path_min_traffic_percent <= 100
    ):
        raise ValueError(
            "selected_path_min_traffic_percent must be finite and in (0, 100]"
        )
    if disruption_loss_threshold_pct is not None:
        try:
            loss_threshold = float(disruption_loss_threshold_pct)
        except (TypeError, ValueError) as error:
            raise ValueError("disruption_loss_threshold_pct must be numeric") from error
        if not 0 <= loss_threshold <= 100:
            raise ValueError("disruption_loss_threshold_pct must be in 0..100")
    normalized_hw_indices = tuple(warmboot_hw_agent_indices)
    if (
        not normalized_hw_indices
        or any(type(index) is not int or index < 0 for index in normalized_hw_indices)
        or len(set(normalized_hw_indices)) != len(normalized_hw_indices)
    ):
        raise ValueError(
            "warmboot_hw_agent_indices must contain unique non-negative integers"
        )
    normalized_hw_indices = tuple(sorted(normalized_hw_indices))
    if mutate_bgp_timers:
        raise ValueError(
            "BGP timer mutation is not enabled: add a reversible OSS timer "
            "overlay before opting in"
        )
    if (
        restart_openr_after_warmboot
        and profile.action is not RbbResilienceAction.AGENT_WARMBOOT
    ):
        raise ValueError("OpenR restart opt-in applies only to warmboot scenarios")

    coverage = profile.coverage.value.upper()
    r1_hostname = topology.r1.hostname
    stages = [
        _audit_stage(
            topology,
            f"{profile.testplan_id}_baseline",
            steering_active=False,
            srv6_profile=srv6_profile,
        ),
        create_steps_stage(
            steps=[_ixia_stats_reset_capability_step(profile.testplan_id)],
            description=(
                f"{profile.testplan_id}: verify IXIA measurement capability"
            ),
        ),
        create_steps_stage(
            steps=[_direct_route_step(r1_hostname, "install", srv6_profile)],
            description=f"{profile.testplan_id}: enable SRv6 steering",
        ),
        _audit_stage(
            topology,
            f"{profile.testplan_id}_pre",
            steering_active=True,
            srv6_profile=srv6_profile,
            timeout_seconds=recovery_timeout_seconds,
        ),
        create_steps_stage(
            steps=[
                create_start_traffic_step(),
                create_clear_traffic_stats_step(start_traffic=False),
                create_longevity_step(
                    duration=traffic_sample_seconds,
                    description="Collect pre-disruption IXIA baseline",
                    start_traffic=False,
                ),
                _traffic_rate_step(
                    f"{profile.testplan_id}: pre-disruption Tx/Rx are positive"
                ),
                _traffic_loss_step(
                    f"{profile.testplan_id}: pre-disruption traffic is lossless"
                ),
                # Packet-loss health checks stop traffic before reading the
                # final counters. Restart explicitly and prove liveness again
                # so the disruption never runs against a stopped generator.
                create_start_traffic_step(),
                create_clear_traffic_stats_step(start_traffic=False),
                create_longevity_step(
                    duration=min(5, traffic_sample_seconds),
                    description="Warm up the disruption measurement window",
                    start_traffic=False,
                ),
                _traffic_rate_step(
                    f"{profile.testplan_id}: Tx/Rx are positive before disruption"
                ),
            ],
            description=f"{profile.testplan_id}: establish IXIA baseline",
        ),
    ]
    disruption, mutation_cleanup = _disruption_stages(
        profile,
        topology,
        srv6_profile,
        recovery_timeout_seconds=recovery_timeout_seconds,
        outage_hold_seconds=outage_hold_seconds,
        restart_openr_after_warmboot=restart_openr_after_warmboot,
        core_pc_index=core_pc_index,
        selected_path_min_traffic_percent=float(
            selected_path_min_traffic_percent
        ),
        disruption_loss_threshold_pct=disruption_loss_threshold_pct,
        warmboot_hw_agent_indices=normalized_hw_indices,
        traffic_sample_seconds=traffic_sample_seconds,
    )
    stages.extend(disruption)
    if profile.action is not RbbResilienceAction.EDGE_LINK_OUTAGE:
        # Preserve the original counter window across the disruption. This is
        # deliberately before the post-recovery clear so a hit during agent,
        # bgpd, or core-path convergence cannot be hidden by later recovery.
        stages.append(
            create_steps_stage(
                steps=[
                    _disruption_loss_step(
                        (
                            f"{profile.testplan_id}: disruption-window loss "
                            + (
                                "budget"
                                if disruption_loss_threshold_pct is not None
                                else "measurement (no configured SLA)"
                            )
                        ),
                        max_loss_pct=disruption_loss_threshold_pct,
                    )
                ],
                description=(
                    f"{profile.testplan_id}: measure traffic across disruption"
                ),
            )
        )
    stages.append(
        _audit_stage(
            topology,
            f"{profile.testplan_id}_post",
            steering_active=True,
            srv6_profile=srv6_profile,
            timeout_seconds=recovery_timeout_seconds,
        )
    )
    mutation_markers = list(
        dict.fromkeys(
            str(operation["marker"])
            for operation in mutation_cleanup
            if operation.get("marker")
        )
    )
    if mutation_markers:
        stages.append(
            create_steps_stage(
                steps=[
                    _cleanup_marker_step(marker, armed=False)
                    for marker in mutation_markers
                ],
                description=(
                    f"{profile.testplan_id}: confirm recovery and disarm cleanup"
                ),
            )
        )
    stages.extend(
        [
            create_steps_stage(
                steps=[
                    # The disruption-window loss check stops traffic. Start a
                    # new, isolated window before proving recovered forwarding.
                    create_start_traffic_step(),
                    create_clear_traffic_stats_step(start_traffic=False),
                    create_longevity_step(
                        duration=traffic_sample_seconds,
                        description="Collect recovered IXIA traffic window",
                        start_traffic=False,
                    ),
                    _traffic_rate_step(
                        f"{profile.testplan_id}: recovered Tx/Rx are positive"
                    ),
                    _traffic_loss_step(
                        f"{profile.testplan_id}: recovered traffic is lossless"
                    ),
                ],
                description=f"{profile.testplan_id}: verify traffic recovery",
            ),
            create_steps_stage(
                steps=[
                    _direct_route_step(r1_hostname, "delete", srv6_profile),
                    create_stop_traffic_step(),
                ],
                description=f"{profile.testplan_id}: restore BGPD ownership",
            ),
            _audit_stage(
                topology,
                f"{profile.testplan_id}_cleanup",
                steering_active=False,
                srv6_profile=srv6_profile,
                timeout_seconds=recovery_timeout_seconds,
            ),
        ]
    )

    # One registered task owns the entire cleanup plan because TAAC stops a
    # cleanup-step list after its first exception. Guarded service/interface
    # restorations run only when their disruption marker remains armed. Route
    # deletion has its own per-playbook ownership marker, and traffic stop is
    # attempted even if any earlier operation fails.
    cleanup_steps = [
        _best_effort_cleanup_step(
            [
                *mutation_cleanup,
                _direct_route_cleanup_operation(r1_hostname, srv6_profile),
                {"type": "stop_traffic"},
            ]
        )
    ]
    return Playbook(
        name=profile.playbook_name,
        description=f"{profile.testplan_id} [{coverage}]: {profile.title}",
        stages=stages,
        cleanup_steps=cleanup_steps,
        device_regexes=[f"^{re.escape(r1_hostname)}$"],
    )


__all__ = ["create_rbb_resilience_playbook"]
