# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Playbook factory for Phase-1 bidirectional RBB traffic foundations."""

from __future__ import annotations

import re
import typing as t

from taac.health_check.health_check import types as hc_types
from taac.test_as_a_config.types import Playbook, Step

from taac.health_checks.healthcheck_definitions import (
    create_ixia_packet_loss_check,
    create_ixia_traffic_rate_check,
)
from taac.stages.stage_definitions import create_steps_stage
from taac.steps.step_definitions import (
    create_ixia_api_step,
    create_longevity_step,
    create_run_task_step,
    create_validation_step,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology
from taac.testconfigs.routing.util.bgp_rbb_traffic_profiles import (
    ALL_TRAFFIC_ITEMS,
    COUNTER_ABSOLUTE_TOLERANCE,
    COUNTER_TOLERANCE_PERCENT,
    EDGE_BANDWIDTH_GBPS,
    TRAFFIC_DRAIN_SECONDS,
    TRAFFIC_RATE_TOLERANCE_PERCENT,
    TRAFFIC_SAMPLE_SECONDS,
    RbbTrafficDirection,
    RbbTrafficFoundationProfile,
)


def _route_audit_steps(
    profile: RbbTrafficFoundationProfile,
    hostnames: t.Mapping[str, str],
) -> list[Step]:
    steps: list[Step] = []
    for role in ("r1", "r2"):
        routes = [route.to_params() for route in profile.routes if route.role == role]
        if not routes:
            continue
        steps.append(
            create_run_task_step(
                task_name="rbb_state_audit",
                params_dict={
                    "hostname": hostnames[role],
                    "gate": profile.testplan_id,
                    "routes": routes,
                    "ndp": [],
                    "mysids": [],
                    "active_services": [],
                    "interfaces_up": [],
                },
                description=(
                    f"[{profile.testplan_id}:{role}] exact BGPD RIB/FIB audit"
                ),
                # Route convergence is a prerequisite; a read-only audit must
                # not implicitly start every configured IXIA traffic item.
                start_traffic=False,
            )
        )
    return steps


def _ixia_received_route_steps(
    profile: RbbTrafficFoundationProfile,
    topology: RbbTopology,
    hostnames: t.Mapping[str, str],
) -> list[Step]:
    steps: list[Step] = []
    for expectation in profile.ixia_received_routes:
        interface = topology.node(expectation.role).primary_ixia_interface
        if not interface:
            raise ValueError(
                f"{profile.testplan_id}: {expectation.role} has no IXIA interface"
            )
        port_identifier = f"{hostnames[expectation.role]}:{interface}"
        steps.append(
            create_run_task_step(
                task_name="rbb_ixia_bgp_learned_routes",
                params_dict={
                    "gate": profile.testplan_id,
                    "port_identifier": port_identifier,
                    "expected_prefixes": list(expectation.prefixes),
                    "timeout_seconds": 60,
                    "poll_interval_seconds": 2,
                },
                description=(
                    f"[{profile.testplan_id}:{expectation.role}] verify opposite "
                    "IXIA BGP received-route view"
                ),
                ixia_needed=True,
                start_traffic=False,
            )
        )
    return steps


def _stop_all_traffic_step(description: str) -> Step:
    return create_ixia_api_step(
        api_name="stop_traffic",
        args_dict={},
        description=description,
        start_traffic=False,
    )


def _core_members(topology: RbbTopology, role: str) -> list[str]:
    """Return every declared core member once, preserving topology order."""
    members: list[str] = []
    seen: set[str] = set()
    for port_channel in topology.node(role).core_pcs:
        for member in port_channel.members:
            normalized = member.casefold()
            if normalized not in seen:
                members.append(member)
                seen.add(normalized)
    if not members:
        raise ValueError(f"{role} has no declared core port-channel members")
    return members


def _counter_steps(
    profile: RbbTrafficFoundationProfile,
    topology: RbbTopology,
    hostnames: t.Mapping[str, str],
    action: str,
) -> list[Step]:
    steps: list[Step] = []
    for direction in profile.directions:
        source_edge = topology.node(direction.source_role).primary_ixia_interface
        destination_edge = topology.node(
            direction.destination_role
        ).primary_ixia_interface
        if not source_edge or not destination_edge:
            raise ValueError(
                f"{profile.testplan_id}: both traffic endpoints require an "
                "IXIA edge interface"
            )
        evidence = (
            (
                direction.source_role,
                "edge",
                [source_edge],
                "ingress",
                "tx",
            ),
            (
                direction.source_role,
                "core",
                _core_members(topology, direction.source_role),
                "egress",
                "tx",
            ),
            (
                direction.destination_role,
                "core",
                _core_members(topology, direction.destination_role),
                "ingress",
                "rx",
            ),
            (
                direction.destination_role,
                "edge",
                [destination_edge],
                "egress",
                "rx",
            ),
        )
        for role, location, interfaces, counter_direction, ixia_direction in evidence:
            for counter_kind, suffix in (("packets", "frames"), ("bytes", "bytes")):
                task_action = action
                sample_id = (
                    f"{direction.name}:{role}:{location}:"
                    f"{counter_direction}:{counter_kind}"
                )
                params: dict[str, t.Any] = {
                    "hostname": hostnames[role],
                    "gate": profile.testplan_id,
                    "action": task_action,
                    "sample_id": sample_id,
                    "counter_interfaces": interfaces,
                    "counter_direction": counter_direction,
                    "counter_kind": counter_kind,
                }
                if counter_kind == "packets":
                    params.update(
                        {
                            "traffic_item": direction.name,
                            "ixia_counter_field": f"{ixia_direction}_{suffix}",
                        }
                    )
                    if action == "assert":
                        params.update(
                            {
                                "tolerance_percent": COUNTER_TOLERANCE_PERCENT,
                                "absolute_tolerance": COUNTER_ABSOLUTE_TOLERANCE,
                                "min_value": 1,
                            }
                        )
                elif action == "assert":
                    # RESTPy Traffic Item Statistics does not expose byte
                    # columns on every IxNetwork release. Keep byte counters
                    # as required DUT path-activity evidence, while packet
                    # counters provide portable exact IXIA/DUT correlation.
                    task_action = "assert_min_delta"
                    params["action"] = task_action
                    params["min_delta"] = 1
                steps.append(
                    create_run_task_step(
                        task_name="rbb_traffic_counter_correlation",
                        params_dict=params,
                        description=(
                            f"[{profile.testplan_id}] {action} {role} {location} "
                            f"{counter_direction} {counter_kind} across "
                            f"{len(interfaces)} interface(s) for {direction.name}"
                        ),
                        ixia_needed=counter_kind == "packets",
                        start_traffic=False,
                    )
                )
    return steps


def _traffic_rate_check(names: list[str]) -> t.Any:
    # Treat the configured line-rate percentage as the expected throughput,
    # not merely a liveness floor. Both Tx and Rx are checked by default.
    return create_ixia_traffic_rate_check(
        thresholds=[
            hc_types.TrafficRateThreshold(
                names=names,
                value=C.TRAFFIC_LINE_RATE_PCT,
                threshold_type=hc_types.ThresholdType.PERCENT,
                metric=hc_types.TrafficRateMetric.TX_RATE,
            )
        ],
        base_bandwidth_gbps=EDGE_BANDWIDTH_GBPS,
        rate_tolerance_percent=TRAFFIC_RATE_TOLERANCE_PERCENT,
    )


def _packet_loss_check(names: list[str]) -> t.Any:
    skipped = sorted(set(ALL_TRAFFIC_ITEMS) - set(names))
    return create_ixia_packet_loss_check(
        thresholds=[
            hc_types.PacketLossThreshold(
                names=names,
                metric=hc_types.PacketLossMetric.PERCENTAGE,
                str_value=C.PACKET_LOSS_THRESHOLD_PCT,
                expect_packet_loss=False,
            )
        ],
        skip_traffic_items=skipped,
        sleep_time=TRAFFIC_DRAIN_SECONDS,
        check_id="rbb_" + "_".join(name.lower() for name in names) + "_loss",
    )


def _traffic_stage(
    profile: RbbTrafficFoundationProfile,
    topology: RbbTopology,
    hostnames: t.Mapping[str, str],
) -> t.Any:
    names = [direction.name for direction in profile.directions]
    steps: list[Step] = [
        _stop_all_traffic_step(
            f"[{profile.testplan_id}] stop all traffic before isolated measurement"
        )
    ]
    if profile.correlate_counters:
        # RESTPy defers selected Traffic Item generation/apply until the first
        # start in a playbook. That start also creates the Traffic Item
        # statistics view required by the cumulative IXIA baseline snapshots.
        # Start once to prime it, then stop and clear so this preparation
        # traffic is excluded from both the IXIA and DUT measurement windows.
        steps.append(
            create_ixia_api_step(
                api_name="start_traffic",
                args_dict={},
                description=(
                    f"[{profile.testplan_id}] initialize selected traffic and "
                    "statistics view"
                ),
                start_traffic=False,
            )
        )
        steps.append(
            _stop_all_traffic_step(
                f"[{profile.testplan_id}] stop traffic after statistics-view "
                "initialization"
            )
        )
    steps.append(
        create_ixia_api_step(
            api_name="clear_traffic_stats",
            # Keep this on the AbstractTrafficGenerator signature so both
            # RESTPy and OTG can run traffic-only profile selections.
            args_dict={},
            description=f"[{profile.testplan_id}] clear IXIA counters",
            start_traffic=False,
        )
    )
    if profile.correlate_counters:
        steps.extend(_counter_steps(profile, topology, hostnames, "snapshot"))
    steps.extend(
        [
            create_ixia_api_step(
                # The priming start above completed deferred selection,
                # generation, apply, and statistics-view initialization. Start
                # the same selected items again for the measured window.
                api_name="start_traffic",
                args_dict={},
                description=(f"[{profile.testplan_id}] start only: {', '.join(names)}"),
                start_traffic=False,
            ),
            create_longevity_step(
                duration=TRAFFIC_SAMPLE_SECONDS,
                description=(
                    f"[{profile.testplan_id}] collect {TRAFFIC_SAMPLE_SECONDS}s "
                    "traffic sample"
                ),
                start_traffic=False,
            ),
            create_validation_step(
                point_in_time_checks=[_traffic_rate_check(names)],
                description=(
                    f"[{profile.testplan_id}] IXIA Tx/Rx throughput matches "
                    f"configured {C.TRAFFIC_LINE_RATE_PCT}% line rate"
                ),
                start_traffic=False,
                fail_fast=True,
            ),
        ]
    )
    if profile.correlate_counters:
        # Freeze both IXIA and DUT cumulative counters before comparing them.
        # Reading the DUT while traffic is still running gives it a later
        # measurement endpoint than the most recent IXIA statistics sample,
        # which can create a false mismatch at high packet rates.
        steps.extend(
            [
                _stop_all_traffic_step(
                    f"[{profile.testplan_id}] stop traffic before final "
                    "counter snapshots"
                ),
                create_longevity_step(
                    duration=TRAFFIC_DRAIN_SECONDS,
                    description=(
                        f"[{profile.testplan_id}] allow "
                        f"{TRAFFIC_DRAIN_SECONDS}s for final counter refresh"
                    ),
                    start_traffic=False,
                ),
            ]
        )
        steps.extend(_counter_steps(profile, topology, hostnames, "assert"))
    steps.append(
        create_validation_step(
            point_in_time_checks=[_packet_loss_check(names)],
            description=(
                f"[{profile.testplan_id}] IXIA packet loss is within "
                f"{C.PACKET_LOSS_THRESHOLD_PCT}%"
            ),
            start_traffic=False,
            fail_fast=True,
        )
    )
    if not profile.correlate_counters:
        steps.append(
            _stop_all_traffic_step(
                f"[{profile.testplan_id}] stop traffic after measurement"
            )
        )
    return create_steps_stage(
        steps=steps,
        description=f"{profile.testplan_id}: {profile.title}",
    )


def create_rbb_traffic_foundation_playbook(
    profile: RbbTrafficFoundationProfile,
    *,
    topology: RbbTopology,
    r1_hostname: str = C.R1_HOSTNAME,
    r2_hostname: str = C.R2_HOSTNAME,
) -> Playbook:
    """Build one independently reported Phase-1 routing or traffic case."""
    hostnames = {"r1": r1_hostname, "r2": r2_hostname}
    stages = []
    route_steps = _route_audit_steps(profile, hostnames)
    route_steps.extend(_ixia_received_route_steps(profile, topology, hostnames))
    if route_steps:
        stages.append(
            create_steps_stage(
                steps=route_steps,
                description=(
                    f"{profile.testplan_id}: exact prefix, BGPD RIB, and "
                    "preferred FIB owner"
                ),
            )
        )
    if profile.directions:
        stages.append(_traffic_stage(profile, topology, hostnames))
    return Playbook(
        name=profile.playbook_name,
        description=f"{profile.testplan_id} [FULL]: {profile.title}",
        prechecks=[],
        postchecks=[],
        stages=stages,
        cleanup_steps=(
            [_stop_all_traffic_step(f"[{profile.testplan_id}] cleanup traffic")]
            if profile.directions
            else []
        ),
        traffic_items_to_start=(
            [direction.name for direction in profile.directions]
            if profile.directions
            else None
        ),
        # Every step explicitly selects its DUT. Anchor the playbook once so
        # TAAC does not duplicate it across both endpoints.
        device_regexes=[f"^{re.escape(r1_hostname)}$"],
    )


__all__ = ["create_rbb_traffic_foundation_playbook"]
