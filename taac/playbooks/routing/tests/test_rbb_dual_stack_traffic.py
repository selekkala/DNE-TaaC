# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Tests for Phase-1 RBB IPv4 and concurrent dual-stack automation."""

import ipaddress
import json
import os
import runpy
import types
import unittest
from pathlib import Path
from unittest import mock

from ixia.ixia import types as ixia_types
from taac.ixia.ixnetwork_restpy_constants import ALLOWED_IPV4_ADVERTISEMENTS
from taac.test_as_a_config.types import StepName

from taac.playbooks.routing.factories.qual_rbb.rbb_dual_stack_traffic_playbook import (
    create_rbb_dual_stack_traffic_playbook,
)
from taac.testconfigs.routing.factories.qual_rbb.rbb_dual_stack_traffic_test_config import (
    create_rbb_dual_stack_traffic_test_config,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_dual_stack_profiles import (
    ALL_DUAL_STACK_TRAFFIC_ITEMS,
    RbbDualStackSettings,
    RbbIpPool,
    build_rbb_dual_stack_profiles,
    build_rbb_dual_stack_settings,
    select_rbb_dual_stack_profiles,
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
            "r1",
            "dual-r1.example",
            (
                CorePortChannel("port-channel1", ("eth1/1",)),
                CorePortChannel("port-channel2", ("eth1/2",)),
            ),
            (IxiaEdge("eth1/5", "1/1"),),
        ),
        r2=NodeTopology(
            "r2",
            "dual-r2.example",
            (
                CorePortChannel("port-channel1", ("eth1/1",)),
                CorePortChannel("port-channel2", ("eth1/2",)),
            ),
            (IxiaEdge("eth1/6", "1/2"),),
        ),
        ixia_chassis="ixia.example",
    )


def _settings() -> RbbDualStackSettings:
    return RbbDualStackSettings(
        pools=(
            RbbIpPool("r1", "HEAD6", "2001:db8:100::", 64, 2, 6),
            RbbIpPool("r2", "TAIL6", "2001:db8:200::", 64, 2, 6),
            RbbIpPool("r1", "HEAD4", "198.51.100.128", 32, 2, 4),
            RbbIpPool("r2", "TAIL4", "198.51.100.192", 32, 2, 4),
        ),
        edge_peer=types.MappingProxyType(
            {
                ("r1", 4): "203.0.113.2",
                ("r2", 4): "203.0.113.6",
                ("r1", 6): "2001:db8:1::2",
                ("r2", 6): "2001:db8:2::2",
            }
        ),
        edge_gateway=types.MappingProxyType(
            {
                ("r1", 4): "203.0.113.1",
                ("r2", 4): "203.0.113.5",
                ("r1", 6): "2001:db8:1::1",
                ("r2", 6): "2001:db8:2::1",
            }
        ),
        edge_prefix_length=types.MappingProxyType({4: 30, 6: 64}),
    )


def _steps(playbook):
    return [step for stage in playbook.stages or [] for step in stage.steps or []]


def _run_tasks(playbook):
    result = []
    for step in _steps(playbook):
        if step.name != StepName.RUN_TASK_STEP:
            continue
        task = json.loads(step.input_json)["task"]
        result.append((task["task_name"], json.loads(task["params"]["json_params"])))
    return result


def _ixia_calls(playbook):
    result = []
    for step in _steps(playbook):
        if step.name != StepName.INVOKE_IXIA_API_STEP:
            continue
        params = json.loads(step.step_params.json_params)
        result.append(params["api_name"])
    return result


class RbbDualStackProfileTest(unittest.TestCase):
    _DEFAULT_POOL_ENVIRONMENT = {
        "TAAC_RBB_IXIA_HEAD_PREFIX": "2001:db8:feed::",
        "TAAC_RBB_IXIA_HEAD_PREFIX_LEN": "64",
        "TAAC_RBB_IXIA_HEAD_PREFIX_COUNT": "1",
        "TAAC_RBB_IXIA_TAIL_PREFIX": "2001:db8:beef::",
        "TAAC_RBB_IXIA_TAIL_PREFIX_LEN": "64",
        "TAAC_RBB_IXIA_TAIL_PREFIX_COUNT": "1",
        "TAAC_RBB_IXIA_R1_EDGE_V4": "10.100.75.2",
        "TAAC_RBB_IXIA_R1_EDGE_GW_V4": "10.100.75.1",
        "TAAC_RBB_IXIA_R2_EDGE_V4": "10.100.75.6",
        "TAAC_RBB_IXIA_R2_EDGE_GW_V4": "10.100.75.5",
        "TAAC_RBB_IXIA_EDGE_PREFIX_MASK_V4": "30",
        "TAAC_RBB_IXIA_HEAD_PREFIX_V4": "10.100.75.128",
        "TAAC_RBB_IXIA_HEAD_PREFIX_LEN_V4": "32",
        "TAAC_RBB_IXIA_HEAD_PREFIX_COUNT_V4": "1",
        "TAAC_RBB_IXIA_TAIL_PREFIX_V4": "10.100.75.192",
        "TAAC_RBB_IXIA_TAIL_PREFIX_LEN_V4": "32",
        "TAAC_RBB_IXIA_TAIL_PREFIX_COUNT_V4": "1",
    }

    def test_builder_defaults_fit_restpy_ipv4_advertisement_allowlist(self) -> None:
        with mock.patch.dict(os.environ, self._DEFAULT_POOL_ENVIRONMENT, clear=True):
            with mock.patch.object(C, "SKIP_ADVERTISED_PREFIXES_CHECK", False):
                settings = build_rbb_dual_stack_settings()

        for pool in (item for item in settings.pools if item.family == 4):
            first = ipaddress.IPv4Address(pool.starting_prefix)
            self.assertTrue(
                any(
                    first in allowed and pool.last_address in allowed
                    for allowed in ALLOWED_IPV4_ADVERTISEMENTS
                )
            )

    def test_builder_requires_explicit_opt_out_for_nonallowlisted_ipv4_pool(
        self,
    ) -> None:
        environment = dict(self._DEFAULT_POOL_ENVIRONMENT)
        environment["TAAC_RBB_IXIA_HEAD_PREFIX_V4"] = "203.0.113.128"
        with mock.patch.dict(os.environ, environment, clear=True):
            with mock.patch.object(C, "SKIP_ADVERTISED_PREFIXES_CHECK", False):
                with self.assertRaisesRegex(ValueError, "advertisement allowlist"):
                    build_rbb_dual_stack_settings()
            with mock.patch.object(C, "SKIP_ADVERTISED_PREFIXES_CHECK", True):
                settings = build_rbb_dual_stack_settings()

        self.assertEqual(settings.pool("r1", 4).starting_prefix, "203.0.113.128")

    def test_catalog_order_and_coverage_are_explicit(self) -> None:
        profiles = build_rbb_dual_stack_profiles(_settings())

        self.assertEqual(
            [profile.testplan_id for profile in profiles],
            ["phase1:TC-11", "phase1:TC-12", "phase1:TC-15"],
        )
        self.assertEqual(
            [profile.coverage for profile in profiles], ["FULL", "FULL", "PARTIAL"]
        )
        self.assertIn("latency", profiles[2].limitation)
        self.assertEqual(
            [direction.name for direction in profiles[2].directions],
            list(ALL_DUAL_STACK_TRAFFIC_ITEMS),
        )

    def test_forward_and_reverse_ipv4_require_origin_and_remote_bgpd_routes(
        self,
    ) -> None:
        tc11, tc12, _ = build_rbb_dual_stack_profiles(_settings())

        self.assertEqual({route.role for route in tc11.routes}, {"r1", "r2"})
        self.assertTrue(
            all(route.prefix.startswith("198.51.100.19") for route in tc11.routes)
        )
        origin11 = [route for route in tc11.routes if route.role == "r2"]
        self.assertTrue(all(route.next_hops == ("203.0.113.6",) for route in origin11))
        origin12 = [route for route in tc12.routes if route.role == "r1"]
        self.assertTrue(all(route.next_hops == ("203.0.113.2",) for route in origin12))
        self.assertTrue(
            all(
                route.client == C.ROUTE_OWNER_BGPD
                for route in tc11.routes + tc12.routes
            )
        )

    def test_selection_is_stable_and_rejects_unknown_or_duplicates(self) -> None:
        profiles = build_rbb_dual_stack_profiles(_settings())
        selected = select_rbb_dual_stack_profiles(
            profiles, ["phase1:TC-15", "phase1:TC-11"]
        )
        self.assertEqual(
            [profile.testplan_id for profile in selected],
            ["phase1:TC-11", "phase1:TC-15"],
        )
        with self.assertRaisesRegex(ValueError, "unknown"):
            select_rbb_dual_stack_profiles(profiles, ["phase1:TC-999"])
        with self.assertRaisesRegex(ValueError, "duplicates"):
            select_rbb_dual_stack_profiles(profiles, ["phase1:TC-11", "phase1:TC-11"])

    def test_pool_validation_rejects_overlap_and_wrong_network_boundary(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid IPv4 pool"):
            RbbIpPool("r1", "BAD", "198.51.100.1", 24, 1, 4)
        settings = _settings()
        with self.assertRaisesRegex(ValueError, "overlap"):
            RbbDualStackSettings(
                pools=settings.pools[:-1]
                + (RbbIpPool("r2", "OVERLAP", "198.51.100.128", 32, 1, 4),),
                edge_peer=settings.edge_peer,
                edge_gateway=settings.edge_gateway,
                edge_prefix_length=settings.edge_prefix_length,
            )

    def test_pool_validation_rejects_edge_subnet_overlap(self) -> None:
        settings = _settings()
        with self.assertRaisesRegex(ValueError, "overlaps the r1 IXIA edge subnet"):
            RbbDualStackSettings(
                pools=(
                    settings.pools[0],
                    settings.pools[1],
                    RbbIpPool("r1", "BAD_EDGE", "203.0.113.2", 32, 1, 4),
                    settings.pools[3],
                ),
                edge_peer=settings.edge_peer,
                edge_gateway=settings.edge_gateway,
                edge_prefix_length=settings.edge_prefix_length,
            )


class RbbDualStackPlaybookTest(unittest.TestCase):
    def _playbook(self, index):
        return create_rbb_dual_stack_traffic_playbook(
            build_rbb_dual_stack_profiles(_settings())[index],
            r1_hostname="dual-r1.example",
            r2_hostname="dual-r2.example",
        )

    def test_tc11_and_tc12_isolate_one_ipv4_direction(self) -> None:
        tc11 = self._playbook(0)
        tc12 = self._playbook(1)

        self.assertEqual(tc11.traffic_items_to_start, ["RBB_R1_TO_R2_IPV4"])
        self.assertEqual(tc12.traffic_items_to_start, ["RBB_R2_TO_R1_IPV4"])
        self.assertEqual(
            _ixia_calls(tc11),
            ["stop_traffic", "clear_traffic_stats", "start_traffic", "stop_traffic"],
        )
        self.assertEqual(
            [name for name, _ in _run_tasks(tc11)],
            ["rbb_state_audit", "rbb_state_audit"],
        )
        for _, params in _run_tasks(tc11):
            self.assertEqual(params["timeout_seconds"], 60)
            self.assertEqual(params["poll_interval_seconds"], 2)

    def test_tc15_starts_all_four_items_together_and_declares_partial_reason(
        self,
    ) -> None:
        playbook = self._playbook(2)

        self.assertEqual(
            playbook.traffic_items_to_start, list(ALL_DUAL_STACK_TRAFFIC_ITEMS)
        )
        self.assertIn("[PARTIAL]", playbook.description)
        self.assertIn("latency", playbook.description)
        self.assertEqual(_ixia_calls(playbook).count("start_traffic"), 1)
        routes = [
            route
            for name, params in _run_tasks(playbook)
            if name == "rbb_state_audit"
            for route in params["routes"]
        ]
        self.assertTrue(any(":" in route["prefix"] for route in routes))
        self.assertTrue(any("." in route["prefix"] for route in routes))


class RbbDualStackTestConfigTest(unittest.TestCase):
    def test_factory_renders_two_device_groups_and_four_route_pool_items(self) -> None:
        config = create_rbb_dual_stack_traffic_test_config(_topology())

        self.assertEqual(len(config.playbooks or []), 3)
        ports = config.basic_port_configs or []
        self.assertEqual(len(ports), 2)
        self.assertTrue(
            all(
                [group.device_group_index for group in port.device_group_configs]
                == [0, 1]
                for port in ports
            )
        )
        self.assertTrue(
            all(port.device_group_configs[0].v6_bgp_config for port in ports)
        )
        self.assertTrue(
            all(port.device_group_configs[1].v4_bgp_config for port in ports)
        )
        items = config.basic_traffic_item_configs or []
        self.assertEqual(
            [item.name for item in items], list(ALL_DUAL_STACK_TRAFFIC_ITEMS)
        )
        self.assertEqual(
            [item.src_endpoints[0].device_group_index for item in items],
            [1, 1, 0, 0],
        )
        self.assertTrue(
            all(item.dest_endpoints[0].network_group_index == 0 for item in items)
        )
        self.assertTrue(
            all(item.skip_default_l4_protocol is not True for item in items)
        )
        self.assertEqual(
            [item.traffic_type for item in items],
            [
                ixia_types.TrafficType.IPV4,
                ixia_types.TrafficType.IPV4,
                ixia_types.TrafficType.IPV6,
                ixia_types.TrafficType.IPV6,
            ],
        )
        self.assertTrue(
            all(
                item.route_mesh == ixia_types.RouteMeshType.ROUTE_FULL_MESH
                for item in items
            )
        )

    def test_tc15_rejects_aggregate_source_load_above_port_capacity(self) -> None:
        with mock.patch.object(C, "TRAFFIC_LINE_RATE_PCT", 51):
            with self.assertRaisesRegex(ValueError, r"2 \* TAAC_RBB_TRAFFIC_LINE_RATE"):
                create_rbb_dual_stack_traffic_test_config(
                    _topology(), testplan_ids=["phase1:TC-15"]
                )

    def test_tc11_can_run_at_more_than_half_line_rate_when_selected_alone(self) -> None:
        with mock.patch.object(C, "TRAFFIC_LINE_RATE_PCT", 75):
            config = create_rbb_dual_stack_traffic_test_config(
                _topology(), testplan_ids=["phase1:TC-11"]
            )
        self.assertEqual(len(config.playbooks or []), 1)

    def test_edge_overlay_contains_one_atomic_v4_and_v6_request_per_dut(self) -> None:
        with mock.patch.object(C, "EDGE_EBGP_ENABLED", True):
            config = create_rbb_dual_stack_traffic_test_config(_topology())
        params = [
            json.loads(task.params.json_params)
            for task in config.setup_tasks or []
            if task.task_name == "rbb_edge_ebgp"
        ]
        self.assertEqual(len(params), 2)
        self.assertTrue(all("edge_peer_addr" in item for item in params))
        self.assertTrue(all("edge_peer_addr4" in item for item in params))
        self.assertTrue(all("edge_rif_cidr4" in item for item in params))
        self.assertTrue(all(item["ibgp_next_hop_self"] for item in params))

    def test_example_wrapper_exports_factory_result(self) -> None:
        wrapper = (
            Path(__file__).resolve().parents[4]
            / "examples"
            / "rbb_dual_stack_traffic_config.py"
        )
        sentinel = object()
        target = (
            "taac.testconfigs.routing.factories.qual_rbb."
            "rbb_dual_stack_traffic_test_config."
            "create_rbb_dual_stack_traffic_test_config"
        )
        with mock.patch(target, return_value=sentinel):
            result = runpy.run_path(str(wrapper))
        self.assertIs(result["test_config"], sentinel)


if __name__ == "__main__":
    unittest.main()
