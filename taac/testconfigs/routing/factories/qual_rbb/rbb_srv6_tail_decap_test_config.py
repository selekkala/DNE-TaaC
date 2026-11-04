# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""TestConfig factory for Phase-2 TC-24 tail decapsulation validation."""

from __future__ import annotations

from taac.test_as_a_config.types import TestConfig

from taac.playbooks.routing.factories.qual_rbb.rbb_srv6_tail_decap_playbook import (
    create_rbb_srv6_tail_decap_playbook,
)
from taac.testconfigs.routing.factories.qual_rbb.rbb_srv6_test_config import (
    _build_rbb_test_config,
    _resolve_topology,
)
from taac.testconfigs.routing.util.bgp_rbb_lab_wiring import build_rbb_inventories
from taac.testconfigs.routing.util.bgp_rbb_scenario_profiles import (
    SRV6_3_USIDS_PROFILE,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology


def create_rbb_srv6_tail_decap_test_config(
    topology: RbbTopology | None = None,
    *,
    name: str = "RBB_P2_TC24_TAIL_DECAP_TEST",
) -> TestConfig:
    """Create TC-24 using the existing forward IXIA/SRv6 bootstrap contract."""
    topology = _resolve_topology(topology, include_traffic=True)
    r1, r2 = build_rbb_inventories(topology)
    return _build_rbb_test_config(
        name=name,
        profile=SRV6_3_USIDS_PROFILE,
        playbooks=[
            create_rbb_srv6_tail_decap_playbook(
                topology=topology,
                profile=SRV6_3_USIDS_PROFILE,
                r1_hostname=r1.device_name,
                r2_hostname=r2.device_name,
            )
        ],
        r1=r1,
        r2=r2,
        topology=topology,
        include_traffic=True,
    )


__all__ = ["create_rbb_srv6_tail_decap_test_config"]
