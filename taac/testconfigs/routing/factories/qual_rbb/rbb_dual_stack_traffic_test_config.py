# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""TestConfig factory for opt-in RBB IPv4 and dual-stack traffic cases."""

from __future__ import annotations

import typing as t

from ixia.ixia import types as ixia_types
from taac.test_as_a_config import types as taac_types
from taac.test_as_a_config.types import (
    BasicPortConfig,
    BasicTrafficItemConfig,
    BgpConfig,
    DeviceGroupConfig,
    Endpoint,
    IpAddressesConfig,
    RouteScale,
    RouteScaleSpec,
    TestConfig,
    TrafficEndpoint,
)

from taac.abstractions.physical_inventory.physical_inventory import (
    PhysicalInventory,
)
from taac.playbooks.routing.factories.qual_rbb.rbb_dual_stack_traffic_playbook import (
    create_rbb_dual_stack_traffic_playbook,
)
from taac.task_definitions import create_run_task
from taac.testconfigs.routing.factories.qual_rbb.rbb_srv6_test_config import (
    _direct_ixia_connections,
    _dut_bootstrap_setup_tasks,
    _dut_bootstrap_teardown_tasks,
    _resolve_topology,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_dual_stack_profiles import (
    RbbDualStackDirection,
    RbbDualStackSettings,
    RbbIpPool,
    V4_FORWARD,
    V4_REVERSE,
    V6_FORWARD,
    V6_REVERSE,
    build_rbb_dual_stack_profiles,
    build_rbb_dual_stack_settings,
    select_rbb_dual_stack_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_lab_wiring import (
    build_rbb_inventories,
    rbb_oss_mock_device_data,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology


def _edge_bgp_config(local_as: int, pool: RbbIpPool) -> BgpConfig:
    if not 1 <= local_as <= 0xFFFFFFFF:
        raise ValueError("IXIA edge AS must be in 1..4294967295")
    route = RouteScale(
        prefix_name=pool.name,
        starting_prefixes=pool.starting_prefix,
        prefix_length=pool.prefix_length,
        prefix_step=pool.prefix_step,
        multiplier=1,
        prefix_count=pool.prefix_count,
        ip_address_family=(
            ixia_types.IpAddressFamily.IPV4
            if pool.family == 4
            else ixia_types.IpAddressFamily.IPV6
        ),
    )
    scale = RouteScaleSpec(network_group_index=0, multiplier=1)
    if pool.family == 4:
        scale = RouteScaleSpec(
            network_group_index=0, multiplier=1, v4_route_scale=route
        )
        capabilities = [ixia_types.BgpCapability.IpV4Unicast]
    else:
        scale = RouteScaleSpec(
            network_group_index=0, multiplier=1, v6_route_scale=route
        )
        capabilities = [ixia_types.BgpCapability.IpV6Unicast]
    return BgpConfig(
        local_as_4_bytes=local_as,
        enable_4_byte_local_as=True,
        bgp_capabilities=capabilities,
        bgp_peer_type=ixia_types.BgpPeerType.EBGP,
        enable_graceful_restart=True,
        graceful_restart_timer=120,
        advertise_end_of_rib=True,
        route_scales=[scale],
    )


def _device_group(
    settings: RbbDualStackSettings,
    role: str,
    family: int,
    local_as: int,
) -> DeviceGroupConfig:
    addresses = IpAddressesConfig(
        starting_ip=settings.edge_peer[(role, family)],
        gateway_starting_ip=settings.edge_gateway[(role, family)],
        mask=settings.edge_prefix_length[family],
    )
    bgp = _edge_bgp_config(local_as, settings.pool(role, family))
    if family == 4:
        return DeviceGroupConfig(
            device_group_index=1,
            multiplier=1,
            v4_addresses_config=addresses,
            v4_bgp_config=bgp,
            device_group_name=f"RBB_{role.upper()}_IPV4",
        )
    return DeviceGroupConfig(
        device_group_index=0,
        multiplier=1,
        v6_addresses_config=addresses,
        v6_bgp_config=bgp,
        device_group_name=f"RBB_{role.upper()}_IPV6",
    )


def _ixia_port_configs(
    r1: PhysicalInventory,
    r2: PhysicalInventory,
    topology: RbbTopology,
    settings: RbbDualStackSettings,
) -> list[BasicPortConfig]:
    result: list[BasicPortConfig] = []
    for role, inventory, local_as in (
        ("r1", r1, C.IXIA_R1_EDGE_AS),
        ("r2", r2, C.IXIA_R2_EDGE_AS),
    ):
        interface = topology.node(role).primary_ixia_interface
        if not interface:
            raise ValueError(f"dual-stack traffic requires a {role} IXIA edge")
        result.append(
            BasicPortConfig(
                endpoint=f"{inventory.device_name}:{interface}",
                # Keep the established IPv6 group at DG0.  IPv4 uses a
                # separate DG1 and therefore a separate emulated eBGP peer.
                device_group_configs=[
                    _device_group(settings, role, 6, local_as),
                    _device_group(settings, role, 4, local_as),
                ],
            )
        )
    return result


def _traffic_item(
    direction: RbbDualStackDirection,
    inventories: t.Mapping[str, PhysicalInventory],
    topology: RbbTopology,
) -> BasicTrafficItemConfig:
    source_interface = topology.node(direction.source_role).primary_ixia_interface
    destination_interface = topology.node(
        direction.destination_role
    ).primary_ixia_interface
    if not source_interface or not destination_interface:
        raise ValueError(f"{direction.name} requires both IXIA interfaces")
    device_group_index = 1 if direction.family == 4 else 0
    return BasicTrafficItemConfig(
        name=direction.name,
        src_endpoints=[
            TrafficEndpoint(
                name=(
                    f"{inventories[direction.source_role].device_name}:"
                    f"{source_interface}"
                ),
                device_group_index=device_group_index,
            )
        ],
        dest_endpoints=[
            TrafficEndpoint(
                name=(
                    f"{inventories[direction.destination_role].device_name}:"
                    f"{destination_interface}"
                ),
                device_group_index=device_group_index,
                network_group_index=0,
            )
        ],
        traffic_type=(
            ixia_types.TrafficType.IPV4
            if direction.family == 4
            else ixia_types.TrafficType.IPV6
        ),
        line_rate=C.TRAFFIC_LINE_RATE_PCT,
        line_rate_type=ixia_types.RateType.PERCENT_LINE_RATE,
        frame_size_settings=ixia_types.FrameSize(
            type=ixia_types.FrameSizeType.FIXED,
            fixed_size=C.TRAFFIC_FRAME_SIZE,
        ),
        bidirectional=False,
        merge_destinations=True,
        src_dest_mesh=ixia_types.SrcDestMeshType.MANY_TO_MANY,
        route_mesh=ixia_types.RouteMeshType.ROUTE_FULL_MESH,
        tracking_types=[ixia_types.TrafficStatsTrackingType.TRAFFIC_ITEM],
        # Leave skip_default_l4_protocol unset so TAAC supplies variable TCP
        # source/destination ranges. Besides realistic traffic diversity, this
        # gives the DUT many stable inputs for any recursive core ECMP hash.
    )


def _dual_stack_edge_setup_tasks(
    r1: PhysicalInventory,
    r2: PhysicalInventory,
    topology: RbbTopology,
    settings: RbbDualStackSettings,
) -> list[taac_types.Task]:
    if not C.EDGE_EBGP_ENABLED:
        return []
    common = {
        "enable_ipv6_afi": True,
    }
    return [
        create_run_task(
            task_name="rbb_edge_ebgp",
            params_dict={
                "hostname": r1.device_name,
                "action": "apply",
                "edge_peer_addr": settings.edge_peer[("r1", 6)],
                "edge_remote_as": C.IXIA_R1_EDGE_AS,
                "edge_local_addr": settings.edge_gateway[("r1", 6)],
                "edge_rif_cidr": (
                    f"{settings.edge_gateway[('r1', 6)]}/"
                    f"{settings.edge_prefix_length[6]}"
                ),
                "edge_peer_addr4": settings.edge_peer[("r1", 4)],
                "edge_local_addr4": settings.edge_gateway[("r1", 4)],
                "edge_rif_cidr4": (
                    f"{settings.edge_gateway[('r1', 4)]}/"
                    f"{settings.edge_prefix_length[4]}"
                ),
                "edge_port_name": topology.r1.primary_ixia_interface,
                "ibgp_peer_addr": C.R2_ROUTER_ID,
                "ibgp_next_hop_self": True,
                **common,
                **(
                    {"ibgp_srv6_nexthop": C.R1_IBGP_NEXT_HOP_V6}
                    if C.R1_IBGP_NEXT_HOP_V6
                    else {}
                ),
            },
        ),
        create_run_task(
            task_name="rbb_edge_ebgp",
            params_dict={
                "hostname": r2.device_name,
                "action": "apply",
                "edge_peer_addr": settings.edge_peer[("r2", 6)],
                "edge_remote_as": C.IXIA_R2_EDGE_AS,
                "edge_local_addr": settings.edge_gateway[("r2", 6)],
                "edge_rif_cidr": (
                    f"{settings.edge_gateway[('r2', 6)]}/"
                    f"{settings.edge_prefix_length[6]}"
                ),
                "edge_peer_addr4": settings.edge_peer[("r2", 4)],
                "edge_local_addr4": settings.edge_gateway[("r2", 4)],
                "edge_rif_cidr4": (
                    f"{settings.edge_gateway[('r2', 4)]}/"
                    f"{settings.edge_prefix_length[4]}"
                ),
                "edge_port_name": topology.r2.primary_ixia_interface,
                "ibgp_peer_addr": C.R1_ROUTER_ID,
                "ibgp_srv6_nexthop": C.SRV6_DECAP_SID,
                "ibgp_next_hop_self": True,
                "withdraw_network6_prefix": C.TAIL_DEST_PREFIX,
                **common,
            },
        ),
    ]


def _dual_stack_edge_teardown_tasks(
    r1: PhysicalInventory, r2: PhysicalInventory
) -> list[taac_types.Task]:
    if not C.EDGE_EBGP_ENABLED:
        return []
    return [
        create_run_task(
            task_name="rbb_edge_ebgp",
            params_dict={"hostname": inventory.device_name, "action": "restore"},
        )
        for inventory in (r1, r2)
    ]


def create_rbb_dual_stack_traffic_test_config(
    topology: RbbTopology | None = None,
    *,
    name: str = "RBB_DUAL_STACK_TRAFFIC_TEST",
    testplan_ids: t.Iterable[str] | None = None,
) -> TestConfig:
    """Build Phase-1 TC-11/12 and partial TC-15 without changing v6 suites."""
    if not 1 <= C.TRAFFIC_LINE_RATE_PCT <= 100:
        raise ValueError("TAAC_RBB_TRAFFIC_LINE_RATE must be in 1..100")
    if C.TRAFFIC_FRAME_SIZE < 64:
        raise ValueError("TAAC_RBB_TRAFFIC_FRAME_SIZE must be at least 64 bytes")
    topology = _resolve_topology(topology, include_traffic=True)
    settings = build_rbb_dual_stack_settings()
    selected = select_rbb_dual_stack_profiles(
        build_rbb_dual_stack_profiles(settings), testplan_ids
    )
    if not selected:
        raise ValueError("RBB dual-stack profile selection is empty")
    if any(profile.testplan_id == "phase1:TC-15" for profile in selected):
        # TC-15 runs v4 and v6 simultaneously in each direction.  Each source
        # port therefore transmits two independently rated traffic items.
        if 2 * C.TRAFFIC_LINE_RATE_PCT > 100:
            raise ValueError(
                "phase1:TC-15 requires 2 * TAAC_RBB_TRAFFIC_LINE_RATE <= 100 "
                "on each IXIA source port"
            )

    r1, r2 = build_rbb_inventories(topology)
    inventories = {"r1": r1, "r2": r2}
    chassis = topology.ixia_chassis or C.IXIA_CHASSIS
    all_directions = (V4_FORWARD, V4_REVERSE, V6_FORWARD, V6_REVERSE)
    return TestConfig(
        name=name,
        basset_pool="",
        skip_ixia_protocol_verification=False,
        skip_advertised_prefixes_check=C.SKIP_ADVERTISED_PREFIXES_CHECK,
        skip_default_oss_setup_tasks=True,
        endpoints=[
            Endpoint(
                name=inventory.device_name,
                dut=True,
                ixia_needed=True,
                ixia_ports=[interface for interface, _ in inventory.ixia_ports],
                direct_ixia_connections=_direct_ixia_connections(
                    inventory, topology.node(role), chassis
                ),
            )
            for role, inventory in (("r1", r1), ("r2", r2))
        ],
        host_os_type_map={
            r1.device_name: taac_types.DeviceOsType.FBOSS,
            r2.device_name: taac_types.DeviceOsType.FBOSS,
        },
        oss_mock_device_data=rbb_oss_mock_device_data((r1, r2)),
        startup_checks=[],
        setup_tasks=(
            _dut_bootstrap_setup_tasks(r1, r2, topology, include_traffic=True)
            + _dual_stack_edge_setup_tasks(r1, r2, topology, settings)
        ),
        teardown_tasks=(
            _dual_stack_edge_teardown_tasks(r1, r2)
            + _dut_bootstrap_teardown_tasks(r1, r2)
        ),
        basic_port_configs=_ixia_port_configs(r1, r2, topology, settings),
        basic_traffic_item_configs=[
            _traffic_item(direction, inventories, topology)
            for direction in all_directions
        ],
        playbooks=[
            create_rbb_dual_stack_traffic_playbook(
                profile,
                r1_hostname=r1.device_name,
                r2_hostname=r2.device_name,
            )
            for profile in selected
        ],
    )


__all__ = ["create_rbb_dual_stack_traffic_test_config"]
