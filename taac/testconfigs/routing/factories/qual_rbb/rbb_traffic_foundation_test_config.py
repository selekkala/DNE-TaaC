# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""TestConfig factory for bidirectional RBB BGP and IPv6 traffic cases."""

from __future__ import annotations

import ipaddress
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
from taac.playbooks.routing.factories.qual_rbb.rbb_traffic_foundation_playbook import (
    create_rbb_traffic_foundation_playbook,
)
from taac.testconfigs.routing.factories.qual_rbb.rbb_srv6_test_config import (
    _direct_ixia_connections,
    _dut_bootstrap_setup_tasks,
    _dut_bootstrap_teardown_tasks,
    _edge_ebgp_setup_tasks,
    _edge_ebgp_teardown_tasks,
    _resolve_topology,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_lab_wiring import (
    build_rbb_inventories,
    rbb_oss_mock_device_data,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology
from taac.testconfigs.routing.util.bgp_rbb_traffic_profiles import (
    FORWARD,
    REVERSE,
    RbbAdvertisedPool,
    RbbTrafficDirection,
    build_rbb_advertised_pools,
    build_rbb_traffic_foundation_profiles,
    select_rbb_traffic_foundation_profiles,
)


def _validate_edge_address(peer: str, gateway: str, role: str) -> None:
    peer_if = ipaddress.ip_interface(f"{peer}/{C.IXIA_EDGE_PREFIX_MASK}")
    gateway_if = ipaddress.ip_interface(f"{gateway}/{C.IXIA_EDGE_PREFIX_MASK}")
    if peer_if.version != 6 or gateway_if.version != 6:
        raise ValueError(f"{role} IXIA edge addresses must be IPv6")
    if peer_if.network != gateway_if.network or peer_if.ip == gateway_if.ip:
        raise ValueError(
            f"{role} IXIA peer and DUT gateway must be distinct addresses "
            "in one subnet"
        )


def _edge_bgp_config(local_as: int, pool: RbbAdvertisedPool) -> BgpConfig:
    if not 1 <= local_as <= 0xFFFFFFFF:
        raise ValueError("IXIA edge AS must be in 1..4294967295")
    return BgpConfig(
        local_as_4_bytes=local_as,
        enable_4_byte_local_as=True,
        bgp_capabilities=[ixia_types.BgpCapability.IpV6Unicast],
        bgp_peer_type=ixia_types.BgpPeerType.EBGP,
        enable_graceful_restart=True,
        graceful_restart_timer=120,
        advertise_end_of_rib=True,
        route_scales=[
            RouteScaleSpec(
                network_group_index=0,
                multiplier=1,
                v6_route_scale=RouteScale(
                    prefix_name=pool.name,
                    starting_prefixes=pool.starting_prefix,
                    prefix_length=pool.prefix_length,
                    prefix_step=pool.prefix_step,
                    multiplier=1,
                    prefix_count=pool.prefix_count,
                    ip_address_family=ixia_types.IpAddressFamily.IPV6,
                ),
            )
        ],
    )


def _edge_port_config(
    inventory: PhysicalInventory,
    interface: str,
    peer: str,
    gateway: str,
    local_as: int,
    pool: RbbAdvertisedPool,
) -> BasicPortConfig:
    return BasicPortConfig(
        endpoint=f"{inventory.device_name}:{interface}",
        device_group_configs=[
            DeviceGroupConfig(
                device_group_index=0,
                multiplier=1,
                v6_addresses_config=IpAddressesConfig(
                    starting_ip=peer,
                    gateway_starting_ip=gateway,
                    mask=C.IXIA_EDGE_PREFIX_MASK,
                ),
                v6_bgp_config=_edge_bgp_config(local_as, pool),
            )
        ],
    )


def _ixia_port_configs(
    r1: PhysicalInventory,
    r2: PhysicalInventory,
    topology: RbbTopology,
    pools: tuple[RbbAdvertisedPool, ...],
) -> list[BasicPortConfig]:
    by_role = {pool.role: pool for pool in pools}
    r1_interface = topology.r1.primary_ixia_interface
    r2_interface = topology.r2.primary_ixia_interface
    if not r1_interface or not r2_interface:
        raise ValueError("bidirectional RBB traffic requires one IXIA edge per DUT")
    _validate_edge_address(C.IXIA_R1_EDGE_V6, C.IXIA_R1_EDGE_GW_V6, "R1")
    _validate_edge_address(C.IXIA_R2_EDGE_V6, C.IXIA_R2_EDGE_GW_V6, "R2")
    return [
        _edge_port_config(
            r1,
            r1_interface,
            C.IXIA_R1_EDGE_V6,
            C.IXIA_R1_EDGE_GW_V6,
            C.IXIA_R1_EDGE_AS,
            by_role["r1"],
        ),
        _edge_port_config(
            r2,
            r2_interface,
            C.IXIA_R2_EDGE_V6,
            C.IXIA_R2_EDGE_GW_V6,
            C.IXIA_R2_EDGE_AS,
            by_role["r2"],
        ),
    ]


def _traffic_item(
    direction: RbbTrafficDirection,
    inventories: t.Mapping[str, PhysicalInventory],
    topology: RbbTopology,
) -> BasicTrafficItemConfig:
    source_interface = topology.node(direction.source_role).primary_ixia_interface
    destination_interface = topology.node(
        direction.destination_role
    ).primary_ixia_interface
    if not source_interface or not destination_interface:
        raise ValueError(f"{direction.name} requires both selected IXIA interfaces")
    frame = ixia_types.FrameSize(
        type=ixia_types.FrameSizeType.FIXED,
        fixed_size=C.TRAFFIC_FRAME_SIZE,
    )
    return BasicTrafficItemConfig(
        name=direction.name,
        src_endpoints=[
            TrafficEndpoint(
                name=(
                    f"{inventories[direction.source_role].device_name}:"
                    f"{source_interface}"
                ),
                device_group_index=0,
            )
        ],
        dest_endpoints=[
            TrafficEndpoint(
                name=(
                    f"{inventories[direction.destination_role].device_name}:"
                    f"{destination_interface}"
                ),
                device_group_index=0,
                network_group_index=0,
            )
        ],
        traffic_type=ixia_types.TrafficType.IPV6,
        line_rate=C.TRAFFIC_LINE_RATE_PCT,
        line_rate_type=ixia_types.RateType.PERCENT_LINE_RATE,
        frame_size_settings=frame,
        bidirectional=False,
        merge_destinations=True,
        src_dest_mesh=ixia_types.SrcDestMeshType.MANY_TO_MANY,
        tracking_types=[ixia_types.TrafficStatsTrackingType.TRAFFIC_ITEM],
    )


def create_rbb_traffic_foundation_test_config(
    topology: RbbTopology | None = None,
    *,
    name: str = "RBB_TRAFFIC_FOUNDATION_TEST",
    testplan_ids: t.Iterable[str] | None = None,
) -> TestConfig:
    """Build all or selected TC-05/06/07/13/14/17 playbooks.

    This is intentionally an IXIA-only family: choosing the factory is the
    explicit opt-in to reserve and configure the two declared IXIA ports.
    DUT bootstrap and edge eBGP mutation remain separately controlled by the
    existing ``TAAC_RBB_SETUP_DUTS`` and ``TAAC_RBB_EDGE_EBGP`` switches.
    """
    if not 1 <= C.TRAFFIC_LINE_RATE_PCT <= 100:
        raise ValueError("TAAC_RBB_TRAFFIC_LINE_RATE must be in 1..100")
    if C.TRAFFIC_FRAME_SIZE < 64:
        raise ValueError("TAAC_RBB_TRAFFIC_FRAME_SIZE must be at least 64 bytes")
    topology = _resolve_topology(topology, include_traffic=True)
    pools = build_rbb_advertised_pools()
    selected = select_rbb_traffic_foundation_profiles(
        build_rbb_traffic_foundation_profiles(topology, pools),
        testplan_ids=testplan_ids,
    )
    if not selected:
        raise ValueError("RBB traffic foundation profile selection is empty")

    r1, r2 = build_rbb_inventories(topology)
    inventories = {"r1": r1, "r2": r2}
    chassis = topology.ixia_chassis or C.IXIA_CHASSIS
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
            + _edge_ebgp_setup_tasks(r1, r2, topology, include_traffic=True)
        ),
        teardown_tasks=(
            _edge_ebgp_teardown_tasks(r1, r2, include_traffic=True)
            + _dut_bootstrap_teardown_tasks(r1, r2)
        ),
        basic_port_configs=_ixia_port_configs(r1, r2, topology, pools),
        basic_traffic_item_configs=[
            _traffic_item(direction, inventories, topology)
            for direction in (FORWARD, REVERSE)
        ],
        playbooks=[
            create_rbb_traffic_foundation_playbook(
                profile,
                topology=topology,
                r1_hostname=r1.device_name,
                r2_hostname=r2.device_name,
            )
            for profile in selected
        ],
    )


__all__ = ["create_rbb_traffic_foundation_test_config"]
