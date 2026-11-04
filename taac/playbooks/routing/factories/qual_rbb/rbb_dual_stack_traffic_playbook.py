# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Playbook factory for Phase-1 RBB IPv4 and concurrent dual-stack traffic."""

from __future__ import annotations

import re
import typing as t

from taac.health_check.health_check import types as hc_types
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
from taac.test_as_a_config.types import Playbook, Step
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_dual_stack_profiles import (
    ALL_DUAL_STACK_TRAFFIC_ITEMS,
    RbbDualStackProfile,
)
from taac.testconfigs.routing.util.bgp_rbb_traffic_profiles import (
    EDGE_BANDWIDTH_GBPS,
    TRAFFIC_DRAIN_SECONDS,
    TRAFFIC_RATE_TOLERANCE_PERCENT,
    TRAFFIC_SAMPLE_SECONDS,
)

_ROUTE_CONVERGENCE_TIMEOUT_SECONDS = 60
_ROUTE_CONVERGENCE_POLL_SECONDS = 2


def _stop_traffic(description: str) -> Step:
    return create_ixia_api_step(
        api_name="stop_traffic",
        args_dict={},
        description=description,
        start_traffic=False,
    )


def _route_steps(
    profile: RbbDualStackProfile, hostnames: t.Mapping[str, str]
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
                    "timeout_seconds": _ROUTE_CONVERGENCE_TIMEOUT_SECONDS,
                    "poll_interval_seconds": _ROUTE_CONVERGENCE_POLL_SECONDS,
                },
                description=(
                    f"[{profile.testplan_id}:{role}] exact dual-stack BGPD "
                    "RIB/FIB audit"
                ),
                start_traffic=False,
            )
        )
    return steps


def _rate_check(names: list[str]) -> t.Any:
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


def _loss_check(names: list[str]) -> t.Any:
    return create_ixia_packet_loss_check(
        thresholds=[
            hc_types.PacketLossThreshold(
                names=names,
                metric=hc_types.PacketLossMetric.PERCENTAGE,
                str_value=C.PACKET_LOSS_THRESHOLD_PCT,
                expect_packet_loss=False,
            )
        ],
        skip_traffic_items=sorted(set(ALL_DUAL_STACK_TRAFFIC_ITEMS) - set(names)),
        sleep_time=TRAFFIC_DRAIN_SECONDS,
        check_id="rbb_" + "_".join(name.lower() for name in names) + "_loss",
    )


def _traffic_stage(profile: RbbDualStackProfile) -> t.Any:
    names = [direction.name for direction in profile.directions]
    return create_steps_stage(
        steps=[
            _stop_traffic(
                f"[{profile.testplan_id}] stop all traffic before isolated sample"
            ),
            create_ixia_api_step(
                api_name="clear_traffic_stats",
                args_dict={},
                description=f"[{profile.testplan_id}] clear IXIA counters",
                start_traffic=False,
            ),
            create_ixia_api_step(
                api_name="start_traffic",
                args_dict={},
                description=(
                    f"[{profile.testplan_id}] start concurrently: {', '.join(names)}"
                ),
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
                point_in_time_checks=[_rate_check(names)],
                description=(
                    f"[{profile.testplan_id}] every selected IPv4/IPv6 item "
                    f"matches {C.TRAFFIC_LINE_RATE_PCT}% line rate"
                ),
                start_traffic=False,
                fail_fast=True,
            ),
            create_validation_step(
                point_in_time_checks=[_loss_check(names)],
                description=(
                    f"[{profile.testplan_id}] every selected IPv4/IPv6 item is "
                    f"within {C.PACKET_LOSS_THRESHOLD_PCT}% loss"
                ),
                start_traffic=False,
                fail_fast=True,
            ),
            _stop_traffic(f"[{profile.testplan_id}] stop traffic after measurement"),
        ],
        description=f"{profile.testplan_id}: {profile.title}",
    )


def create_rbb_dual_stack_traffic_playbook(
    profile: RbbDualStackProfile,
    *,
    r1_hostname: str = C.R1_HOSTNAME,
    r2_hostname: str = C.R2_HOSTNAME,
) -> Playbook:
    """Build one independently selectable IPv4/dual-stack requirement."""
    hostnames = {"r1": r1_hostname, "r2": r2_hostname}
    route_steps = _route_steps(profile, hostnames)
    description = f"{profile.testplan_id} [{profile.coverage}]: {profile.title}"
    if profile.limitation:
        description += f"; limitation: {profile.limitation}"
    return Playbook(
        name=profile.playbook_name,
        description=description,
        prechecks=[],
        postchecks=[],
        stages=[
            create_steps_stage(
                steps=route_steps,
                description=(
                    f"{profile.testplan_id}: exact IPv4/IPv6 convergence and "
                    "BGPD ownership"
                ),
            ),
            _traffic_stage(profile),
        ],
        cleanup_steps=[
            _stop_traffic(f"[{profile.testplan_id}] best-effort traffic cleanup")
        ],
        traffic_items_to_start=[direction.name for direction in profile.directions],
        device_regexes=[f"^{re.escape(r1_hostname)}$"],
    )


__all__ = ["create_rbb_dual_stack_traffic_playbook"]
