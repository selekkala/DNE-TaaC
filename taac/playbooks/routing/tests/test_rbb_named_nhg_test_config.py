# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Integration tests for the device-only named SRv6 NHG TestConfig."""

import runpy
import unittest
from pathlib import Path
from unittest import mock

from taac.testconfigs.routing.factories.qual_rbb.rbb_named_nhg_test_config import (
    create_rbb_named_nhg_test_config,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import (
    CorePortChannel,
    IxiaEdge,
    NodeTopology,
    RbbTopology,
)


def _topology() -> RbbTopology:
    return RbbTopology(
        r1=NodeTopology(
            role="r1",
            hostname="nhg-r1.example",
            core_pcs=(CorePortChannel("port-channel1", ("eth1/1",)),),
            ixia_edges=(IxiaEdge("eth1/5", "1/1"),),
        ),
        r2=NodeTopology(
            role="r2",
            hostname="nhg-r2.example",
            core_pcs=(CorePortChannel("port-channel1", ("eth1/1",)),),
            ixia_edges=(IxiaEdge("eth1/5", "1/2"),),
        ),
        ixia_chassis="ixia.example",
    )


class RbbNamedNhgTestConfigTest(unittest.TestCase):
    def test_default_config_exposes_three_independent_playbooks(self) -> None:
        config = create_rbb_named_nhg_test_config(_topology())

        self.assertEqual(
            [playbook.name for playbook in config.playbooks],
            [
                "rbb_p2_tc02_program_named_srv6_nhg",
                "rbb_p2_tc06_named_nhg_forward_reference",
                "rbb_p2_tc07_resolve_named_nhg_forward_reference",
            ],
        )

    def test_device_only_config_does_not_reserve_or_configure_ixia(self) -> None:
        config = create_rbb_named_nhg_test_config(_topology())

        self.assertTrue(config.skip_ixia_protocol_verification)
        self.assertIsNone(config.basic_port_configs)
        self.assertIsNone(config.basic_traffic_item_configs)
        self.assertEqual(len(config.endpoints), 2)
        for endpoint in config.endpoints:
            self.assertFalse(endpoint.ixia_needed)
            self.assertIsNone(endpoint.ixia_ports)
            self.assertIsNone(endpoint.direct_ixia_connections)

    def test_explicit_selection_keeps_catalog_order(self) -> None:
        config = create_rbb_named_nhg_test_config(
            _topology(), testplan_ids=["phase2:TC-07", "phase2:TC-02"]
        )

        self.assertEqual(
            [playbook.name for playbook in config.playbooks],
            [
                "rbb_p2_tc02_program_named_srv6_nhg",
                "rbb_p2_tc07_resolve_named_nhg_forward_reference",
            ],
        )

    def test_empty_selection_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "selection is empty"):
            create_rbb_named_nhg_test_config(_topology(), testplan_ids=[])

    def test_example_wrapper_exports_factory_result(self) -> None:
        wrapper = (
            Path(__file__).resolve().parents[4] / "examples" / "rbb_named_nhg_config.py"
        )
        sentinel = object()
        target = (
            "taac.testconfigs.routing.factories.qual_rbb."
            "rbb_named_nhg_test_config.create_rbb_named_nhg_test_config"
        )
        with mock.patch(target, return_value=sentinel):
            result = runpy.run_path(str(wrapper))
        self.assertIs(result["test_config"], sentinel)


if __name__ == "__main__":
    unittest.main()
