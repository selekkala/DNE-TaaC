# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Integration tests for the bidirectional RBB traffic TestConfig factory."""

import runpy
import unittest
from pathlib import Path
from unittest import mock

from taac.testconfigs.routing.factories.qual_rbb.rbb_traffic_foundation_test_config import (
    _edge_bgp_config,
    create_rbb_traffic_foundation_test_config,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_topology import (
    CorePortChannel,
    IxiaEdge,
    NodeTopology,
    RbbTopology,
)
from taac.testconfigs.routing.util.bgp_rbb_traffic_profiles import (
    TRAFFIC_ITEM_R1_TO_R2,
    TRAFFIC_ITEM_R2_TO_R1,
    RbbAdvertisedPool,
)


def _topology() -> RbbTopology:
    return RbbTopology(
        r1=NodeTopology(
            role="r1",
            hostname="traffic-r1.example",
            core_pcs=(
                CorePortChannel("port-channel1", ("eth1/1",)),
                CorePortChannel("port-channel2", ("eth1/2",)),
            ),
            ixia_edges=(IxiaEdge("eth1/5", "1/1"),),
        ),
        r2=NodeTopology(
            role="r2",
            hostname="traffic-r2.example",
            core_pcs=(
                CorePortChannel("port-channel1", ("eth1/1",)),
                CorePortChannel("port-channel2", ("eth1/2",)),
            ),
            ixia_edges=(IxiaEdge("eth1/6", "1/2"),),
        ),
        ixia_chassis="ixia.example",
    )


class RbbTrafficFoundationTestConfigTest(unittest.TestCase):
    def test_multi_prefix_pool_renders_the_same_exact_ipv6_step(self) -> None:
        pool = RbbAdvertisedPool("r2", "THREE_PREFIXES", "2001:db8:200::", 64, 3)

        rendered = _edge_bgp_config(65200, pool).route_scales[0].v6_route_scale

        self.assertEqual(rendered.prefix_count, 3)
        self.assertEqual(rendered.prefix_step, "0:0:0:1::")
        self.assertEqual(
            pool.prefixes,
            (
                "2001:db8:200::/64",
                "2001:db8:200:1::/64",
                "2001:db8:200:2::/64",
            ),
        )

    def test_default_factory_builds_six_independent_playbooks(self) -> None:
        config = create_rbb_traffic_foundation_test_config(_topology())

        self.assertEqual(
            [playbook.name for playbook in config.playbooks],
            [
                "rbb_p1_tc05_head_prefix_propagation",
                "rbb_p1_tc06_tail_prefix_propagation",
                "rbb_p1_tc07_exact_bidirectional_rib_fib",
                "rbb_p1_tc13_forward_ipv6_traffic",
                "rbb_p1_tc14_reverse_ipv6_traffic",
                "rbb_p1_tc17_ixia_dut_counter_correlation",
            ],
        )
        self.assertFalse(config.skip_ixia_protocol_verification)
        self.assertTrue(all(endpoint.ixia_needed for endpoint in config.endpoints))
        self.assertTrue(
            all(endpoint.direct_ixia_connections for endpoint in config.endpoints)
        )

    def test_ixia_config_has_two_bgp_pools_and_isolated_directions(self) -> None:
        config = create_rbb_traffic_foundation_test_config(_topology())

        ports = config.basic_port_configs or []
        self.assertEqual(
            [port.endpoint for port in ports],
            ["traffic-r1.example:eth1/5", "traffic-r2.example:eth1/6"],
        )
        self.assertEqual(len(ports), 2)
        route_scales = [
            port.device_group_configs[0].v6_bgp_config.route_scales[0] for port in ports
        ]
        self.assertEqual([scale.network_group_index for scale in route_scales], [0, 0])
        self.assertTrue(
            all(scale.v6_route_scale.prefix_count >= 1 for scale in route_scales)
        )
        self.assertEqual(
            [scale.v6_route_scale.prefix_step for scale in route_scales],
            ["0:0:0:1::", "0:0:0:1::"],
        )

        traffic = config.basic_traffic_item_configs or []
        self.assertEqual(
            [item.name for item in traffic],
            [TRAFFIC_ITEM_R1_TO_R2, TRAFFIC_ITEM_R2_TO_R1],
        )
        self.assertTrue(all(not item.bidirectional for item in traffic))
        self.assertTrue(
            all(item.line_rate == C.TRAFFIC_LINE_RATE_PCT for item in traffic)
        )
        self.assertEqual(
            [item.src_endpoints[0].name for item in traffic],
            ["traffic-r1.example:eth1/5", "traffic-r2.example:eth1/6"],
        )
        self.assertEqual(
            [item.dest_endpoints[0].name for item in traffic],
            ["traffic-r2.example:eth1/6", "traffic-r1.example:eth1/5"],
        )

    def test_subset_selection_retains_catalog_order(self) -> None:
        config = create_rbb_traffic_foundation_test_config(
            _topology(),
            testplan_ids=["phase1:TC-17", "phase1:TC-05"],
        )

        self.assertEqual(
            [playbook.name for playbook in config.playbooks],
            [
                "rbb_p1_tc05_head_prefix_propagation",
                "rbb_p1_tc17_ixia_dut_counter_correlation",
            ],
        )

    def test_example_wrapper_exports_factory_result_without_registration(self) -> None:
        wrapper = (
            Path(__file__).resolve().parents[4]
            / "examples"
            / "rbb_traffic_foundation_config.py"
        )
        sentinel = object()
        target = (
            "taac.testconfigs.routing.factories.qual_rbb."
            "rbb_traffic_foundation_test_config."
            "create_rbb_traffic_foundation_test_config"
        )
        with mock.patch(target, return_value=sentinel):
            result = runpy.run_path(str(wrapper))

        self.assertIs(result["test_config"], sentinel)


if __name__ == "__main__":
    unittest.main()
