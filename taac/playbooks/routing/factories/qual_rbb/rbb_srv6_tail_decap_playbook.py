# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Phase-2 TC-24 final-uSID decapsulation playbook factory.

This focused case composes four independent observations rather than treating
an edge-port counter as proof of decapsulation by itself:

1. R2 owns the exact final MySID with ``DECAPSULATE_AND_LOOKUP`` behavior.
2. R2's inner destination route is BGPD-owned, preferred in the FIB, and
   resolves to the IXIA peer.
3. R1's selected TE_AGENT route carries the exact packed uSID container.
4. During lossless IXIA traffic, both the R1 SRv6 core-egress counter and R2
   post-decap edge-egress counter increase.

The route mutation is the existing PR #46 transactional task.  Cleanup deletes
only the route installed by this playbook and always stops IXIA traffic.
"""

from __future__ import annotations

import ipaddress
import re

from taac.health_check.health_check import types as hc_types
from taac.test_as_a_config.types import Playbook, Step

from taac.health_checks.healthcheck_definitions import (
    create_ixia_packet_loss_check,
    create_ixia_traffic_rate_check,
)
from taac.stages.stage_definitions import create_steps_stage
from taac.steps.step_definitions import (
    create_clear_traffic_stats_step,
    create_longevity_step,
    create_run_task_step,
    create_start_traffic_step,
    create_stop_traffic_step,
    create_validation_step,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_scenario_profiles import (
    SRV6_3_USIDS_PROFILE,
    Srv6Profile,
    srv6_decap_counter_spec,
    srv6_encap_counter_spec,
    verify_route_owner_bgpd_spec,
    verify_route_owner_te_agent_spec,
)
from taac.testconfigs.routing.util.bgp_rbb_srv6_functional_profiles import (
    build_tail_decap_state_profile,
)
from taac.testconfigs.routing.util.bgp_rbb_state_profiles import (
    RbbStateAuditProfile,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import (
    RbbTopology,
    validate_rbb_topology,
)

_TRAFFIC_WARMUP_SECONDS = 5


def _state_audit_step(
    profile: RbbStateAuditProfile, hostname: str, role: str = "r2"
) -> Step:
    params = profile.to_task_params(role)
    return create_run_task_step(
        task_name="rbb_state_audit",
        params_dict={
            "hostname": hostname,
            "gate": profile.testplan_id,
            **params,
        },
        description=(
            f"[{profile.testplan_id}] exact final-MySID and inner-FIB audit on "
            f"{hostname}"
        ),
        start_traffic=False,
    )


def _verify_step_no_implicit_start(hostname: str, spec: dict[str, object]) -> Step:
    """Run a TC-24 state assertion without changing IXIA traffic state."""
    return create_run_task_step(
        task_name="rbb_srv6_verify",
        params_dict={"hostname": hostname, **spec},
        description=f"[{spec.get('gate', 'verify')}] {hostname}: {spec['show_cmd']}",
        start_traffic=False,
    )


def _direct_route_step_no_implicit_start(
    hostname: str, action: str, profile: Srv6Profile
) -> Step:
    """Install/delete TC-24's route without silently starting IXIA traffic."""
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
        description=f"S{'21' if action == 'install' else '27'} {action} "
        f"TE_AGENT direct route for {profile.tail_prefix} on {hostname}",
        start_traffic=False,
    )


def _best_effort_cleanup_step(hostname: str, profile: Srv6Profile) -> Step:
    """Withdraw this run's route and stop traffic even if withdrawal fails."""
    return create_run_task_step(
        task_name="rbb_best_effort_cleanup",
        params_dict={
            "action": "cleanup",
            "operations": [
                {
                    "type": "delete_direct_route",
                    "hostname": hostname,
                    "prefix": profile.tail_prefix,
                    "client": C.ROUTE_OWNER_TE_AGENT,
                    "srv6_segments": [
                        C.pack_usid_container(profile.locator, profile.encap_usids)
                    ],
                    "srv6_tunnel_id": C.SRV6_TUNNEL_ID,
                },
                {"type": "stop_traffic"},
            ],
        },
        description="TC-24 best-effort route and IXIA cleanup",
        ixia_needed=True,
        start_traffic=False,
    )


def _counter_step_no_implicit_start(
    hostname: str, action: str, spec: dict[str, object]
) -> Step:
    """Snapshot/assert a path counter without changing IXIA traffic state."""
    params = {"hostname": hostname, "action": action, **spec}
    return create_run_task_step(
        task_name="rbb_srv6_counter_delta",
        params_dict=params,
        description=(
            f"[{spec.get('gate', 'counter')}] {action} "
            f"{spec.get('direction', 'srv6')} path counter on {hostname}"
        ),
        ixia_needed=True,
        start_traffic=False,
    )


def _traffic_liveness_step() -> Step:
    """Reject an idle generator or receiver before evaluating packet loss."""
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
        description="TC-24 IXIA Tx/Rx rates are both positive",
        start_traffic=False,
        fail_fast=True,
    )


def _traffic_loss_step() -> Step:
    """Assert loss without allowing the step pre-hook to restart traffic."""
    return create_validation_step(
        point_in_time_checks=[
            create_ixia_packet_loss_check(
                thresholds=[
                    hc_types.PacketLossThreshold(
                        names=list(C.ALL_TRAFFIC_ITEMS),
                        metric=hc_types.PacketLossMetric.PERCENTAGE,
                        str_value=C.PACKET_LOSS_THRESHOLD_PCT,
                        expect_packet_loss=False,
                    )
                ]
            )
        ],
        description="TC-24 final-uSID decap and inner lookup: IXIA no-loss",
        start_traffic=False,
        fail_fast=True,
    )


def create_rbb_srv6_tail_decap_playbook(
    *,
    topology: RbbTopology,
    profile: Srv6Profile = SRV6_3_USIDS_PROFILE,
    r1_hostname: str | None = None,
    r2_hostname: str | None = None,
    name: str = "rbb_p2_tc24_tail_decap_inner_lookup",
) -> Playbook:
    """Create the complete traffic-backed TC-24 playbook.

    TC-24 cannot run in device-only mode: the final proof requires an inner
    packet to leave R2 after the exact final MySID is selected.  The enclosing
    TestConfig therefore always attaches PR #46's IXIA topology and traffic
    item.
    """
    validate_rbb_topology(topology, require_ixia=True)
    r1_hostname = r1_hostname or topology.r1.hostname
    r2_hostname = r2_hostname or topology.r2.hostname
    final_wire_usid = ipaddress.ip_address(profile.encap_usids[-1])
    decap_sid = ipaddress.ip_address(str(profile.decap_sid).split("/", 1)[0])
    if final_wire_usid != decap_sid:
        raise ValueError(
            "phase2:TC-24 requires the final on-wire uSID to equal the R2 "
            f"decap MySID: final={final_wire_usid}, decap={decap_sid}"
        )
    tail_state = build_tail_decap_state_profile(topology, profile)

    install = _direct_route_step_no_implicit_start(r1_hostname, "install", profile)
    delete = _direct_route_step_no_implicit_start(r1_hostname, "delete", profile)

    stages = [
        create_steps_stage(
            steps=[_state_audit_step(tail_state, r2_hostname)],
            description=(
                "TC-24 prerequisite: exact final MySID and inner destination FIB"
            ),
        ),
        create_steps_stage(
            steps=[install],
            description="TC-24 install SRv6 steering route on R1",
        ),
        create_steps_stage(
            steps=[
                _verify_step_no_implicit_start(
                    r1_hostname, verify_route_owner_te_agent_spec(profile)
                )
            ],
            description="TC-24 verify exact packed uSID container on R1",
        ),
        create_steps_stage(
            steps=[
                # Earlier setup/audit steps may use TAAC's generic traffic
                # pre-hook. Close that window before taking the DUT baselines
                # so TC-24 owns one deterministic measurement interval.
                create_stop_traffic_step(),
                _counter_step_no_implicit_start(
                    r1_hostname,
                    "snapshot",
                    srv6_encap_counter_spec("r1", topology),
                ),
                _counter_step_no_implicit_start(
                    r2_hostname,
                    "snapshot",
                    srv6_decap_counter_spec("r2", topology),
                ),
                create_clear_traffic_stats_step(start_traffic=False),
                create_start_traffic_step(),
                create_longevity_step(
                    duration=_TRAFFIC_WARMUP_SECONDS,
                    description="TC-24 warm up IXIA Tx/Rx rate sample",
                    start_traffic=False,
                ),
                _traffic_liveness_step(),
                _traffic_loss_step(),
                _counter_step_no_implicit_start(
                    r1_hostname,
                    "assert",
                    srv6_encap_counter_spec("r1", topology),
                ),
                _counter_step_no_implicit_start(
                    r2_hostname,
                    "assert",
                    srv6_decap_counter_spec("r2", topology),
                ),
                create_stop_traffic_step(),
            ],
            description=("TC-24 lossless SRv6 traffic with pre/post-decap path deltas"),
        ),
        create_steps_stage(
            steps=[delete],
            description="TC-24 withdraw temporary SRv6 steering route",
        ),
        create_steps_stage(
            steps=[
                _verify_step_no_implicit_start(
                    r1_hostname, verify_route_owner_bgpd_spec(profile)
                )
            ],
            description="TC-24 verify BGPD ownership restored",
        ),
    ]

    return Playbook(
        name=name,
        description=("phase2:TC-24 [FULL]: final uSID decap and inner-table lookup"),
        stages=stages,
        prechecks=[],
        postchecks=[],
        cleanup_steps=[_best_effort_cleanup_step(r1_hostname, profile)],
        device_regexes=[f"^{re.escape(r1_hostname)}$"],
    )


__all__ = ["create_rbb_srv6_tail_decap_playbook"]
