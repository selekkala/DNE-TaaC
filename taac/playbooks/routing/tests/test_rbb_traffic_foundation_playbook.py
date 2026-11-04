# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Unit tests for RBB traffic-foundation playbook lowering."""

import json
import unittest

from taac.test_as_a_config.types import StepName

from taac.playbooks.routing.factories.qual_rbb.rbb_traffic_foundation_playbook import (
    create_rbb_traffic_foundation_playbook,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_topology import (
    CorePortChannel,
    IxiaEdge,
    NodeTopology,
    RbbTopology,
)
from taac.testconfigs.routing.util.bgp_rbb_traffic_profiles import (
    RbbAdvertisedPool,
    build_rbb_traffic_foundation_profiles,
)


def _topology(*, multi_member: bool = False) -> RbbTopology:
    r1_core = (
        (
            CorePortChannel("port-channel1", ("eth1/1", "eth1/2")),
            CorePortChannel("port-channel2", ("eth1/3",)),
        )
        if multi_member
        else (CorePortChannel("port-channel1", ("eth1/1",)),)
    )
    r2_core = (
        (
            CorePortChannel("port-channel1", ("eth1/1", "eth1/2")),
            CorePortChannel("port-channel2", ("eth1/3",)),
        )
        if multi_member
        else (CorePortChannel("port-channel1", ("eth1/1",)),)
    )
    return RbbTopology(
        r1=NodeTopology(
            role="r1",
            hostname="traffic-r1.example",
            core_pcs=r1_core,
            ixia_edges=(IxiaEdge("eth1/5", "1/1"),),
        ),
        r2=NodeTopology(
            role="r2",
            hostname="traffic-r2.example",
            core_pcs=r2_core,
            ixia_edges=(IxiaEdge("eth1/5", "1/2"),),
        ),
        ixia_chassis="ixia.example",
    )


def _profiles(topology=None):
    pools = (
        RbbAdvertisedPool("r1", "HEAD", "2001:db8:100::", 64, 2),
        RbbAdvertisedPool("r2", "TAIL", "2001:db8:200::", 64, 2),
    )
    return build_rbb_traffic_foundation_profiles(topology or _topology(), pools)


def _steps(playbook):
    return [step for stage in playbook.stages or [] for step in stage.steps or []]


def _run_tasks(playbook):
    tasks = []
    for step in _steps(playbook):
        if step.name != StepName.RUN_TASK_STEP:
            continue
        raw = json.loads(step.input_json)["task"]
        tasks.append((raw["task_name"], json.loads(raw["params"]["json_params"])))
    return tasks


def _ixia_api_calls(playbook):
    calls = []
    for step in _steps(playbook):
        if step.name != StepName.INVOKE_IXIA_API_STEP:
            continue
        params = json.loads(step.step_params.json_params)
        calls.append((params["api_name"], json.loads(params["args_json"])))
    return calls


class RbbTrafficFoundationPlaybookTest(unittest.TestCase):
    def _playbook(self, index, topology=None):
        topology = topology or _topology()
        return create_rbb_traffic_foundation_playbook(
            _profiles(topology)[index],
            topology=topology,
            r1_hostname="traffic-r1.example",
            r2_hostname="traffic-r2.example",
        )

    def test_one_stable_playbook_per_original_test_id(self) -> None:
        playbooks = [self._playbook(index) for index in range(6)]

        self.assertEqual(
            [playbook.name for playbook in playbooks],
            [profile.playbook_name for profile in _profiles()],
        )
        self.assertEqual(
            [playbook.description.split()[0] for playbook in playbooks],
            [profile.testplan_id for profile in _profiles()],
        )
        self.assertTrue(
            all(
                playbook.device_regexes == [r"^traffic\-r1\.example$"]
                for playbook in playbooks
            )
        )

    def test_tc05_checks_dut_and_opposite_ixia_received_routes(self) -> None:
        tasks = _run_tasks(self._playbook(0))

        self.assertEqual(
            [name for name, _ in tasks],
            [
                "rbb_state_audit",
                "rbb_state_audit",
                "rbb_ixia_bgp_learned_routes",
            ],
        )
        self.assertEqual(tasks[0][1]["hostname"], "traffic-r1.example")
        self.assertEqual(
            [route["prefix"] for route in tasks[0][1]["routes"]],
            ["2001:db8:100::/64", "2001:db8:100:1::/64"],
        )
        self.assertEqual(
            tasks[0][1]["routes"][0]["next_hops"],
            [C.IXIA_R1_EDGE_V6],
        )
        self.assertEqual(tasks[1][1]["hostname"], "traffic-r2.example")
        self.assertEqual(
            [route["prefix"] for route in tasks[1][1]["routes"]],
            ["2001:db8:100::/64", "2001:db8:100:1::/64"],
        )
        self.assertEqual(tasks[2][1]["port_identifier"], "traffic-r2.example:eth1/5")
        self.assertEqual(
            tasks[2][1]["expected_prefixes"],
            ["2001:db8:100::/64", "2001:db8:100:1::/64"],
        )

    def test_tc06_checks_origin_remote_and_opposite_ixia_received_routes(self) -> None:
        tasks = _run_tasks(self._playbook(1))

        self.assertEqual(
            [name for name, _ in tasks],
            [
                "rbb_state_audit",
                "rbb_state_audit",
                "rbb_ixia_bgp_learned_routes",
            ],
        )
        self.assertEqual(tasks[0][1]["hostname"], "traffic-r1.example")
        self.assertEqual(
            [route["prefix"] for route in tasks[0][1]["routes"]],
            ["2001:db8:200::/64", "2001:db8:200:1::/64"],
        )
        self.assertEqual(tasks[1][1]["hostname"], "traffic-r2.example")
        self.assertEqual(
            tasks[1][1]["routes"][0]["next_hops"],
            [C.IXIA_R2_EDGE_V6],
        )
        self.assertEqual(tasks[2][1]["port_identifier"], "traffic-r1.example:eth1/5")
        self.assertEqual(
            tasks[2][1]["expected_prefixes"],
            ["2001:db8:200::/64", "2001:db8:200:1::/64"],
        )

    def test_tc13_starts_only_forward_item(self) -> None:
        playbook = self._playbook(3)
        calls = _ixia_api_calls(playbook)

        start = [args for api, args in calls if api == "start_traffic"]
        self.assertEqual(start, [{}])
        self.assertEqual(playbook.traffic_items_to_start, ["RBB_R1_TO_R2_IPV6"])
        self.assertEqual(calls[0][0], "stop_traffic")
        self.assertEqual(calls[-1][0], "stop_traffic")
        self.assertEqual(len(playbook.cleanup_steps or []), 1)
        self.assertFalse(
            any(
                name == "rbb_traffic_counter_correlation"
                for name, _ in _run_tasks(playbook)
            )
        )

    def test_tc14_starts_only_reverse_item(self) -> None:
        playbook = self._playbook(4)
        start = [
            args
            for api, args in _ixia_api_calls(playbook)
            if api == "start_traffic"
        ]
        self.assertEqual(start, [{}])
        self.assertEqual(playbook.traffic_items_to_start, ["RBB_R2_TO_R1_IPV6"])

    def test_tc17_correlates_packets_and_requires_byte_activity(self) -> None:
        topology = _topology(multi_member=True)
        tasks = [
            params
            for name, params in _run_tasks(self._playbook(5, topology))
            if name == "rbb_traffic_counter_correlation"
        ]

        self.assertEqual(len(tasks), 32)
        self.assertEqual([task["action"] for task in tasks[:16]], ["snapshot"] * 16)
        packet_asserts = [
            task for task in tasks[16:] if task["action"] == "assert"
        ]
        byte_asserts = [
            task for task in tasks[16:] if task["action"] == "assert_min_delta"
        ]
        self.assertEqual(len(packet_asserts), 8)
        self.assertEqual(len(byte_asserts), 8)
        self.assertEqual(
            {task["ixia_counter_field"] for task in packet_asserts},
            {"tx_frames", "rx_frames"},
        )
        self.assertTrue(
            all("tolerance_percent" in task for task in packet_asserts)
        )
        self.assertTrue(all(task["min_delta"] == 1 for task in byte_asserts))
        self.assertTrue(
            all("ixia_counter_field" not in task for task in byte_asserts)
        )
        self.assertTrue(
            all(
                "counter_cmd" not in task and "counter_regex" not in task
                for task in tasks
            )
        )

        forward_r1_core = next(
            task
            for task in tasks[:16]
            if task["sample_id"]
            == "RBB_R1_TO_R2_IPV6:r1:core:egress:packets"
        )
        self.assertEqual(
            forward_r1_core["counter_interfaces"],
            ["eth1/1", "eth1/2", "eth1/3"],
        )
        reverse_r2_core = next(
            task
            for task in tasks[:16]
            if task["sample_id"]
            == "RBB_R2_TO_R1_IPV6:r2:core:egress:packets"
        )
        self.assertEqual(
            reverse_r2_core["counter_interfaces"],
            ["eth1/1", "eth1/2", "eth1/3"],
        )

    def test_tc17_uses_structured_edge_and_core_counter_targets(self) -> None:
        snapshots = [
            params
            for name, params in _run_tasks(self._playbook(5))
            if name == "rbb_traffic_counter_correlation"
            and params["action"] == "snapshot"
        ]

        self.assertEqual(len(snapshots), 16)
        self.assertEqual(
            {
                (task["counter_direction"], task["counter_kind"])
                for task in snapshots
            },
            {
                ("ingress", "packets"),
                ("ingress", "bytes"),
                ("egress", "packets"),
                ("egress", "bytes"),
            },
        )
        self.assertTrue(
            all(
                task["counter_interfaces"] == ["eth1/5"]
                for task in snapshots
                if ":edge:" in task["sample_id"]
            )
        )
        self.assertTrue(
            all(
                task["counter_interfaces"] == ["eth1/1"]
                for task in snapshots
                if ":core:" in task["sample_id"]
            )
        )

    def test_tc17_initializes_view_then_clears_snapshots_and_starts(self) -> None:
        steps = _steps(self._playbook(5))
        clear_index = next(
            index
            for index, step in enumerate(steps)
            if step.name == StepName.INVOKE_IXIA_API_STEP
            and json.loads(step.step_params.json_params)["api_name"]
            == "clear_traffic_stats"
        )
        start_indices = [
            index
            for index, step in enumerate(steps)
            if step.name == StepName.INVOKE_IXIA_API_STEP
            and json.loads(step.step_params.json_params)["api_name"]
            == "start_traffic"
        ]
        stop_indices = [
            index
            for index, step in enumerate(steps)
            if step.name == StepName.INVOKE_IXIA_API_STEP
            and json.loads(step.step_params.json_params)["api_name"]
            == "stop_traffic"
        ]
        snapshot_indices = []
        for index, step in enumerate(steps):
            if step.name != StepName.RUN_TASK_STEP:
                continue
            raw = json.loads(step.input_json)["task"]
            params = json.loads(raw["params"]["json_params"])
            if (
                raw["task_name"] == "rbb_traffic_counter_correlation"
                and params["action"] == "snapshot"
            ):
                snapshot_indices.append(index)

        self.assertEqual(len(snapshot_indices), 16)
        self.assertEqual(len(start_indices), 2)
        prepare_start, measurement_start = start_indices
        preparation_stop = next(
            index for index in stop_indices if index > prepare_start
        )
        self.assertTrue(stop_indices[0] < prepare_start)
        self.assertTrue(prepare_start < preparation_stop < clear_index)
        self.assertTrue(clear_index < min(snapshot_indices))
        self.assertTrue(max(snapshot_indices) < measurement_start)

    def test_tc17_stops_traffic_before_final_counter_reads(self) -> None:
        steps = _steps(self._playbook(5))
        start_indices = [
            index
            for index, step in enumerate(steps)
            if step.name == StepName.INVOKE_IXIA_API_STEP
            and json.loads(step.step_params.json_params)["api_name"]
            == "start_traffic"
        ]
        stop_indices = [
            index
            for index, step in enumerate(steps)
            if step.name == StepName.INVOKE_IXIA_API_STEP
            and json.loads(step.step_params.json_params)["api_name"]
            == "stop_traffic"
        ]
        assert_indices = []
        for index, step in enumerate(steps):
            if step.name != StepName.RUN_TASK_STEP:
                continue
            raw = json.loads(step.input_json)["task"]
            params = json.loads(raw["params"]["json_params"])
            if (
                raw["task_name"] == "rbb_traffic_counter_correlation"
                and params["action"] in {"assert", "assert_min_delta"}
            ):
                assert_indices.append(index)

        self.assertEqual(len(start_indices), 2)
        measurement_start = start_indices[-1]
        measurement_stop = next(
            index for index in stop_indices if index > measurement_start
        )
        self.assertEqual(len(assert_indices), 16)
        self.assertTrue(measurement_stop < min(assert_indices))

    def test_traffic_steps_never_implicitly_start_all_items(self) -> None:
        playbook = self._playbook(5)
        for step in _steps(playbook):
            if step.step_params is None or not step.step_params.json_params:
                continue
            params = json.loads(step.step_params.json_params)
            self.assertTrue(params.get("skip_start_traffic", False))


if __name__ == "__main__":
    unittest.main()
