# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""TestConfig factory for the Phase-2 named SRv6 NHG lifecycle."""

from __future__ import annotations

import typing as t

from taac.test_as_a_config.types import TestConfig

from taac.playbooks.routing.factories.qual_rbb.rbb_named_nhg_playbook import (
    create_rbb_named_nhg_playbook,
)
from taac.testconfigs.routing.factories.qual_rbb.rbb_srv6_test_config import (
    _build_rbb_test_config,
    _resolve_topology,
)
from taac.testconfigs.routing.util.bgp_rbb_lab_wiring import build_rbb_inventories
from taac.testconfigs.routing.util.bgp_rbb_named_nhg_profiles import (
    build_rbb_named_nhg_profiles,
    select_rbb_named_nhg_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_scenario_profiles import (
    SRV6_3_USIDS_PROFILE,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology


def create_rbb_named_nhg_test_config(
    topology: RbbTopology | None = None,
    *,
    name: str = "RBB_NAMED_NHG_LIFECYCLE_TEST",
    testplan_ids: t.Iterable[str] | None = None,
) -> TestConfig:
    """Build the device-only TC-02/06/07 named-NHG lifecycle suite.

    The suite reuses the two-DUT topology and optional transactional bootstrap,
    but never reserves IXIA. Each playbook owns and removes its TE_AGENT route
    and named NHG. TC-06/TC-07 remain independently selectable and self-cleaning.
    """
    topology = _resolve_topology(topology, include_traffic=False)
    selected = select_rbb_named_nhg_profiles(
        build_rbb_named_nhg_profiles(topology, SRV6_3_USIDS_PROFILE),
        testplan_ids=testplan_ids,
    )
    if not selected:
        raise ValueError("named-NHG lifecycle profile selection is empty")

    r1, r2 = build_rbb_inventories(topology)
    return _build_rbb_test_config(
        name=name,
        profile=SRV6_3_USIDS_PROFILE,
        playbooks=[
            create_rbb_named_nhg_playbook(profile, r1_hostname=r1.device_name)
            for profile in selected
        ],
        r1=r1,
        r2=r2,
        topology=topology,
        include_traffic=False,
    )


__all__ = ["create_rbb_named_nhg_test_config"]
