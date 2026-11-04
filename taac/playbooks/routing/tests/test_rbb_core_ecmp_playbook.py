# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Structure tests for reversible Open/R and BGP core ECMP playbooks."""

import json
import unittest

from taac.test_as_a_config import types as taac_types
from taac.playbooks.routing.factories.qual_rbb.rbb_core_ecmp_playbook import (
    create_rbb_core_ecmp_playbook,
)
from taac.testconfigs.routing.util.bgp_rbb_core_ecmp_profiles import (
    OPENR_PREFERRED_METRIC,
    OPENR_STANDBY_METRIC,
    build_rbb_core_ecmp_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import (
    CorePortChannel,
    IxiaEdge,
    NodeTopology,
    RbbTopology,
)
from taac.testconfigs.routing.util.bgp_rbb_traffic_profiles import FORWARD


def _topology():
    return RbbTopology(
        r1=NodeTopology(
            "r1",
            "core-r1.example",
            (
                CorePortChannel("port-channel1", ("eth1/1/1", "eth1/1/2")),
                CorePortChannel("port-channel2", ("eth1/2/1",)),
            ),
            (IxiaEdge("eth1/10", "1/1"),),
        ),
        r2=NodeTopology(
            "r2",
            "core-r2.example",
            (
                CorePortChannel("peer-a", ("eth1/1/1", "eth1/1/2")),
                CorePortChannel("peer-b", ("eth1/2/1",)),
            ),
            (IxiaEdge("eth1/10", "1/2"),),
        ),
        ixia_chassis="ixia.example",
    )


def _profile(testplan_id):
    return next(
        profile
        for profile in build_rbb_core_ecmp_profiles(_topology())
        if profile.testplan_id == testplan_id
    )


def _task_payload(step):
    task = json.loads(step.input_json or "{}")["task"]
    return task["task_name"], json.loads(task["params"]["json_params"])


def _run_tasks(playbook, task_name=None):
    result = []
    for stage in playbook.stages:
        for step in stage.steps:
            if step.name != taac_types.StepName.RUN_TASK_STEP:
                continue
            name, params = _task_payload(step)
            if task_name is None or name == task_name:
                result.append((name, params))
    return result


def _traffic_counter_event_order(playbook):
    events = []
    for stage in playbook.stages:
        for step in stage.steps:
            if step.name == taac_types.StepName.INVOKE_IXIA_API_STEP:
                params = json.loads(step.step_params.json_params)
                events.append(f"ixia:{params['api_name']}")
            elif step.name == taac_types.StepName.RUN_TASK_STEP:
                name, params = _task_payload(step)
                if name == "rbb_traffic_counter_correlation":
                    events.append(f"counter:{params['action']}")
    return events


class RbbCoreEcmpPlaybookTest(unittest.TestCase):
    def test_tc02_selects_each_core_path_in_both_directions(self) -> None:
        playbook = create_rbb_core_ecmp_playbook(
            _profile("phase1:TC-02"), topology=_topology()
        )
        tasks = [params for _, params in _run_tasks(playbook, "rbb_openr_core_path")]
        metric_writes = [
            params for params in tasks if params["action"] == "set_metrics"
        ]
        route_checks = [
            params for params in tasks if params["action"] == "assert_routes"
        ]

        self.assertEqual(
            [params["metrics"] for params in metric_writes],
            [
                [OPENR_PREFERRED_METRIC, OPENR_STANDBY_METRIC],
                [OPENR_PREFERRED_METRIC, OPENR_STANDBY_METRIC],
                [OPENR_STANDBY_METRIC, OPENR_PREFERRED_METRIC],
                [OPENR_STANDBY_METRIC, OPENR_PREFERRED_METRIC],
            ],
        )
        self.assertEqual(
            [params["path_indices"] for params in route_checks],
            [[0], [0], [1], [1]],
        )
        self.assertTrue(all(len(params["routes"]) == 2 for params in route_checks))
        self.assertIsNone(playbook.traffic_items_to_start)

    def test_tc03_programs_and_verifies_all_equal_cost_paths(self) -> None:
        playbook = create_rbb_core_ecmp_playbook(
            _profile("phase1:TC-03"), topology=_topology()
        )
        tasks = [params for _, params in _run_tasks(playbook, "rbb_openr_core_path")]
        metric_writes = [
            params for params in tasks if params["action"] == "set_metrics"
        ]
        route_checks = [
            params for params in tasks if params["action"] == "assert_routes"
        ]

        self.assertEqual(len(metric_writes), 2)
        self.assertTrue(
            all(
                params["metrics"] == [OPENR_PREFERRED_METRIC] * 2
                for params in metric_writes
            )
        )
        self.assertEqual(len(route_checks), 2)
        self.assertTrue(
            all(params["path_indices"] == [0, 1] for params in route_checks)
        )

    def test_tc08_proves_bgpd_resolution_and_each_path_traffic_share(self) -> None:
        topology = _topology()
        playbook = create_rbb_core_ecmp_playbook(
            _profile("phase1:TC-08"), topology=topology
        )
        first_name, first_params = _task_payload(playbook.stages[0].steps[0])
        self.assertEqual(first_name, "rbb_ixia_capability")
        self.assertTrue(first_params["require_variable_l4_flow_ranges"])
        openr_tasks = [
            params for _, params in _run_tasks(playbook, "rbb_openr_core_path")
        ]
        bgp_route_checks = [
            params
            for params in openr_tasks
            if params["action"] == "assert_routes"
            and any(route["client"] == "BGPD" for route in params["routes"])
        ]
        self.assertEqual(len(bgp_route_checks), 1)
        self.assertEqual(bgp_route_checks[0]["hostname"], "core-r1.example")
        self.assertEqual(bgp_route_checks[0]["path_indices"], [0, 1])

        counters = [
            params
            for _, params in _run_tasks(playbook, "rbb_traffic_counter_correlation")
        ]
        self.assertEqual(
            [params["action"] for params in counters],
            ["snapshot"] * 6 + ["assert"] * 2 + ["assert_ixia_share"] * 4,
        )
        aggregate_members = [
            ["eth1/1/1", "eth1/1/2", "eth1/2/1"],
            ["eth1/1/1", "eth1/1/2", "eth1/2/1"],
        ]
        expected_members = [
            ["eth1/1/1", "eth1/1/2"],
            ["eth1/1/1", "eth1/1/2"],
            ["eth1/2/1"],
            ["eth1/2/1"],
        ]
        self.assertEqual(
            [params["counter_interfaces"] for params in counters[:6]],
            aggregate_members + expected_members,
        )
        self.assertTrue(
            all(params["traffic_item"] == FORWARD.name for params in counters)
        )
        self.assertEqual(
            [params["ixia_counter_field"] for params in counters[:6]],
            [
                "tx_frames",
                "rx_frames",
                "tx_frames",
                "rx_frames",
                "tx_frames",
                "rx_frames",
            ],
        )
        # Aggregate correlation must complete before any independent path-share
        # lower bound can be accepted as evidence.
        self.assertEqual(
            [params["action"] for params in counters[6:8]], ["assert", "assert"]
        )
        self.assertEqual(
            _traffic_counter_event_order(playbook),
            [
                "ixia:stop_traffic",
                "ixia:start_traffic",
                "ixia:stop_traffic",
                "ixia:clear_traffic_stats",
                *(["counter:snapshot"] * 6),
                "ixia:start_traffic",
                "ixia:stop_traffic",
                *(["counter:assert"] * 2),
                *(["counter:assert_ixia_share"] * 4),
            ],
        )
        self.assertEqual(playbook.traffic_items_to_start, [FORWARD.name])

    def test_cleanup_is_best_effort_and_restores_both_duts(self) -> None:
        for testplan_id, has_traffic in (
            ("phase1:TC-02", False),
            ("phase1:TC-03", False),
            ("phase1:TC-08", True),
        ):
            with self.subTest(testplan_id=testplan_id):
                playbook = create_rbb_core_ecmp_playbook(
                    _profile(testplan_id), topology=_topology()
                )
                name, params = _task_payload(playbook.cleanup_steps[0])
                self.assertEqual(name, "rbb_best_effort_cleanup")
                operations = params["operations"]
                restores = [
                    operation
                    for operation in operations
                    if operation["type"] == "restore_openr_core_path"
                ]
                self.assertEqual(
                    [operation["hostname"] for operation in restores],
                    ["core-r1.example", "core-r2.example"],
                )
                self.assertEqual(
                    any(
                        operation["type"] == "stop_traffic" for operation in operations
                    ),
                    has_traffic,
                )


if __name__ == "__main__":
    unittest.main()
