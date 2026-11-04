# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""TestConfig factory for Phase-1 Open/R and BGP core ECMP cases."""

from __future__ import annotations

import typing as t

from taac.test_as_a_config import types as taac_types
from taac.test_as_a_config.types import Endpoint, TestConfig

from taac.playbooks.routing.factories.qual_rbb.rbb_core_ecmp_playbook import (
    create_rbb_core_ecmp_playbook,
)
from taac.testconfigs.routing.factories.qual_rbb.rbb_srv6_test_config import (
    _direct_ixia_connections,
    _dut_bootstrap_setup_tasks,
    _dut_bootstrap_teardown_tasks,
    _edge_ebgp_setup_tasks,
    _edge_ebgp_teardown_tasks,
    _resolve_topology,
)
from taac.testconfigs.routing.factories.qual_rbb.rbb_traffic_foundation_test_config import (
    _ixia_port_configs,
    _traffic_item,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_core_ecmp_profiles import (
    build_rbb_core_ecmp_profiles,
    select_rbb_core_ecmp_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_lab_wiring import (
    build_rbb_inventories,
    rbb_oss_mock_device_data,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology
from taac.testconfigs.routing.util.bgp_rbb_traffic_profiles import (
    FORWARD,
    build_rbb_advertised_pools,
)


def create_rbb_core_ecmp_test_config(
    topology: RbbTopology | None = None,
    *,
    name: str = "RBB_CORE_ECMP_TEST",
    testplan_ids: t.Iterable[str] | None = None,
) -> TestConfig:
    """Build TC-02/03/08 with live IXIA support for TC-08 evidence.

    The suite reserves IXIA even when a caller selects only TC-02 or TC-03.
    This keeps one deterministic TestConfig contract and prevents a later
    TC-08 selection from silently switching topology/setup behavior.
    """
    if not 1 <= C.TRAFFIC_LINE_RATE_PCT <= 100:
        raise ValueError("TAAC_RBB_TRAFFIC_LINE_RATE must be in 1..100")
    if C.TRAFFIC_FRAME_SIZE < 64:
        raise ValueError("TAAC_RBB_TRAFFIC_FRAME_SIZE must be at least 64 bytes")
    topology = _resolve_topology(topology, include_traffic=True)
    selected = select_rbb_core_ecmp_profiles(
        build_rbb_core_ecmp_profiles(topology), testplan_ids=testplan_ids
    )
    if not selected:
        raise ValueError("RBB core ECMP profile selection is empty")

    pools = build_rbb_advertised_pools()
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
        # BasicTrafficItemConfig lowering keeps the default variable TCP
        # source/destination port ranges. Those distinct five-tuples are the
        # hash diversity TC-08 needs to exercise every eligible ECMP path.
        basic_traffic_item_configs=[_traffic_item(FORWARD, inventories, topology)],
        playbooks=[
            create_rbb_core_ecmp_playbook(profile, topology=topology)
            for profile in selected
        ],
    )


__all__ = ["create_rbb_core_ecmp_test_config"]
