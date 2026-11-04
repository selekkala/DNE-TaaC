# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Structure and safety tests for RBB resilience playbooks."""

import json
import unittest

from taac.health_check.health_check import types as hc_types
from taac.test_as_a_config import types as taac_types

from taac.playbooks.routing.factories.qual_rbb.rbb_resilience_playbook import (
    create_rbb_resilience_playbook,
)
from taac.testconfigs.routing.util.bgp_rbb_resilience_profiles import (
    build_rbb_resilience_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import (
    CorePortChannel,
    IxiaEdge,
    NodeTopology,
    RbbTopology,
)


def _topology(*, core_paths: int = 2, members_per_pc: int = 1) -> RbbTopology:
    pcs = tuple(
        CorePortChannel(
            f"port-channel{index}",
            (
                (f"eth1/{index}",)
                if members_per_pc == 1
                else tuple(
                    f"eth1/{index}/{member}"
                    for member in range(1, members_per_pc + 1)
                )
            ),
        )
        for index in range(1, core_paths + 1)
    )
    return RbbTopology(
        r1=NodeTopology(
            role="r1",
            hostname="res-r1.example",
            core_pcs=pcs,
            ixia_edges=(IxiaEdge("eth1/3", "1/1"),),
        ),
        r2=NodeTopology(
            role="r2",
            hostname="res-r2.example",
            core_pcs=pcs,
            ixia_edges=(IxiaEdge("eth1/3", "1/2"),),
        ),
        ixia_chassis="ixia.example",
    )


def _profile(testplan_id: str, topology: RbbTopology | None = None):
    return next(
        item
        for item in build_rbb_resilience_profiles(topology or _topology())
        if item.testplan_id == testplan_id
    )


def _stage_steps(playbook):
    return [step for stage in playbook.stages for step in stage.steps]


def _task_payload(step):
    run_task = json.loads(step.input_json or "{}")["task"]
    return run_task["task_name"], json.loads(run_task["params"]["json_params"])


def _validation_threshold(step):
    validation = json.loads(step.input_json or "{}")
    check = validation["point_in_time_checks"][0]
    return check["name"], json.loads(check["input_json"])["thresholds"][0]


class RbbResiliencePlaybookTest(unittest.TestCase):
    def test_warmboot_uses_native_agent_only_by_default(self) -> None:
        playbook = create_rbb_resilience_playbook(_profile("phase2:TC-15"), _topology())
        interruptions = [
            step
            for step in _stage_steps(playbook)
            if step.name == taac_types.StepName.SERVICE_INTERRUPTION_STEP
        ]

        self.assertEqual(len(interruptions), 1)
        self.assertEqual(
            json.loads(interruptions[0].input_json or "{}")["name"],
            taac_types.Service.AGENT,
        )
        self.assertNotIn("restart bgpd", interruptions[0].description.lower())
        self.assertNotIn("openr restart", interruptions[0].description.lower())

    def test_openr_restart_requires_explicit_warmboot_opt_in(self) -> None:
        playbook = create_rbb_resilience_playbook(
            _profile("phase2:TC-15"),
            _topology(),
            restart_openr_after_warmboot=True,
        )
        services = [
            json.loads(step.input_json or "{}")["name"]
            for step in _stage_steps(playbook)
            if step.name == taac_types.StepName.SERVICE_INTERRUPTION_STEP
        ]

        self.assertEqual(services, [taac_types.Service.AGENT, taac_types.Service.OPENR])

    def test_warmboot_cleanup_recovers_split_agents_first(self) -> None:
        playbook = create_rbb_resilience_playbook(
            _profile("phase2:TC-15"),
            _topology(),
            warmboot_hw_agent_indices=(1, 0),
        )
        task_name, params = _task_payload(playbook.cleanup_steps[0])

        self.assertEqual(task_name, "rbb_best_effort_cleanup")
        self.assertEqual(params["action"], "cleanup")
        recovery = params["operations"][0]
        self.assertEqual(recovery["type"], "recover_split_agent")
        self.assertEqual(recovery["hostname"], "res-r1.example")
        self.assertEqual(recovery["hw_agent_indices"], [0, 1])
        self.assertEqual(recovery["hw_ready_timeout_seconds"], 180)
        self.assertIn("marker", recovery)

    def test_warmboot_cleanup_indices_fail_closed(self) -> None:
        for indices in ((), (0, 0), (True,)):
            with (
                self.subTest(indices=indices),
                self.assertRaisesRegex(ValueError, "warmboot_hw_agent_indices"),
            ):
                create_rbb_resilience_playbook(
                    _profile("phase2:TC-15"),
                    _topology(),
                    warmboot_hw_agent_indices=indices,
                )

    def test_bgp_timer_mutation_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "reversible OSS timer overlay"):
            create_rbb_resilience_playbook(
                _profile("phase2:TC-15"),
                _topology(),
                mutate_bgp_timers=True,
            )

    def test_core_failure_requires_two_independent_paths(self) -> None:
        topology = _topology(core_paths=1)
        with self.assertRaisesRegex(ValueError, "at least two independent core"):
            create_rbb_resilience_playbook(
                _profile("phase2:TC-100", topology), topology
            )

    def test_link_disruption_rejects_malformed_interface_before_mutation(self) -> None:
        topology = _topology()
        topology = RbbTopology(
            r1=NodeTopology(
                role="r1",
                hostname=topology.r1.hostname,
                core_pcs=(
                    CorePortChannel("port-channel1", ("eth1/1; reboot",)),
                    topology.r1.core_pcs[1],
                ),
                ixia_edges=topology.r1.ixia_edges,
            ),
            r2=topology.r2,
            ixia_chassis=topology.ixia_chassis,
        )
        with self.assertRaisesRegex(ValueError, "invalid interface name"):
            create_rbb_resilience_playbook(
                _profile("phase2:TC-100", topology), topology
            )

    def test_core_failure_audits_remaining_path_ndp_and_interface(self) -> None:
        playbook = create_rbb_resilience_playbook(
            _profile("phase2:TC-100"), _topology(), core_pc_index=0
        )
        degraded = []
        for step in _stage_steps(playbook):
            if step.name != taac_types.StepName.RUN_TASK_STEP:
                continue
            name, params = _task_payload(step)
            if name == "rbb_state_audit" and params["gate"].endswith("_degraded_core"):
                degraded.append(params)

        self.assertEqual(len(degraded), 2)
        for params in degraded:
            openr_routes = [
                route for route in params["routes"] if route["client"] == "OPENR"
            ]
            self.assertEqual(len(openr_routes), 2)
            self.assertTrue(all(route["next_hop_count"] == 1 for route in openr_routes))
            self.assertEqual(params["interfaces_up"], ["eth1/2"])
            self.assertEqual(
                [entry["interface"] for entry in params["ndp"]], ["eth1/2"]
            )

    def test_core_failure_proves_selected_and_surviving_path_traffic(self) -> None:
        topology = _topology(members_per_pc=2)
        playbook = create_rbb_resilience_playbook(
            _profile("phase2:TC-100", topology), topology, core_pc_index=0
        )
        tasks_by_gate = {}
        for gate in ("phase2:TC-100_selected_core", "phase2:TC-100_surviving_core"):
            tasks_by_gate[gate] = [
                params
                for step in _stage_steps(playbook)
                if step.name == taac_types.StepName.RUN_TASK_STEP
                for name, params in [_task_payload(step)]
                if name == "rbb_traffic_counter_correlation"
                and params["gate"] == gate
            ]

        selected = tasks_by_gate["phase2:TC-100_selected_core"]
        surviving = tasks_by_gate["phase2:TC-100_surviving_core"]
        self.assertEqual(len(selected), 4)
        self.assertEqual(len(surviving), 4)
        for tasks, expected_interfaces, expected_action in (
            (selected, ["eth1/1/1", "eth1/1/2"], "assert_ixia_share"),
            (surviving, ["eth1/2/1", "eth1/2/2"], "assert_at_least_ixia"),
        ):
            self.assertEqual(
                [item["action"] for item in tasks],
                ["snapshot"] * 2 + [expected_action] * 2,
            )
            self.assertTrue(
                all(
                    item["counter_interfaces"] == expected_interfaces
                    for item in tasks
                )
            )
            self.assertEqual(
                {
                    item["hostname"]: item["counter_direction"]
                    for item in tasks[:2]
                },
                {"res-r1.example": "egress", "res-r2.example": "ingress"},
            )
            self.assertTrue(all(item["counter_kind"] == "packets" for item in tasks))
            self.assertTrue(
                all(
                    "counter_cmd" not in item and "counter_regex" not in item
                    for item in tasks
                )
            )
            for item in tasks:
                self.assertEqual(item["traffic_item"], "RBB_R1_TO_R2_SRV6")
                self.assertEqual(item["ixia_counter_field"], "tx_frames")
        self.assertTrue(
            all(item["min_ixia_share_percent"] == 1.0 for item in selected[2:])
        )

    def test_core_failure_rejects_invalid_selected_path_share(self) -> None:
        for value in (0, -1, 101, float("inf"), True, "1"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    ValueError, "selected_path_min_traffic_percent"
                ):
                    create_rbb_resilience_playbook(
                        _profile("phase2:TC-100"),
                        _topology(),
                        selected_path_min_traffic_percent=value,
                    )

    def test_core_failure_activity_gate_precedes_cleanup_arm_and_shutdown(self) -> None:
        playbook = create_rbb_resilience_playbook(
            _profile("phase2:TC-100"), _topology(), core_pc_index=1
        )
        descriptions = [stage.description for stage in playbook.stages]
        activity_index = next(
            index
            for index, value in enumerate(descriptions)
            if "selected core-path traffic evidence" in value
        )
        outage_index = next(
            index
            for index, value in enumerate(descriptions)
            if "fail one core path" in value
        )
        self.assertLess(activity_index, outage_index)

        outage_steps = playbook.stages[outage_index].steps
        arm_name, arm_params = _task_payload(outage_steps[0])
        self.assertEqual(arm_name, "rbb_best_effort_cleanup")
        self.assertEqual(arm_params["action"], "arm")
        self.assertEqual(outage_steps[1].description, "Clear traffic statistics")
        self.assertEqual(
            json.loads(outage_steps[2].step_params.json_params)["interfaces"],
            ["eth1/2"],
        )

    def test_core_failure_selected_path_uses_requested_members(self) -> None:
        topology = _topology(members_per_pc=2)
        playbook = create_rbb_resilience_playbook(
            _profile("phase2:TC-100", topology), topology, core_pc_index=1
        )
        tasks = [
            params
            for step in _stage_steps(playbook)
            if step.name == taac_types.StepName.RUN_TASK_STEP
            for name, params in [_task_payload(step)]
            if name == "rbb_traffic_counter_correlation"
            and params["gate"] == "phase2:TC-100_selected_core"
        ]
        self.assertEqual(len(tasks), 4)
        self.assertTrue(
            all(
                item["counter_interfaces"] == ["eth1/2/1", "eth1/2/2"]
                for item in tasks
            )
        )

    def test_core_failure_has_idempotent_link_restore_cleanup(self) -> None:
        playbook = create_rbb_resilience_playbook(
            _profile("phase2:TC-100"), _topology()
        )
        task_name, params = _task_payload(playbook.cleanup_steps[0])
        self.assertEqual(task_name, "rbb_best_effort_cleanup")
        interface_cleanup = params["operations"][0]
        self.assertEqual(interface_cleanup["type"], "enable_interfaces")
        self.assertEqual(interface_cleanup["interfaces"], ["eth1/1"])
        self.assertIn("marker", interface_cleanup)

    def test_every_disruption_is_armed_before_it_can_mutate_state(self) -> None:
        restart_trigger = taac_types.ServiceInterruptionTrigger.SYSTEMCTL_RESTART
        for testplan_id in (
            "phase2:TC-15",
            "phase2:TC-30",
            "phase2:TC-104",
            "phase2:TC-100",
            "phase2:TC-99",
        ):
            with self.subTest(testplan_id=testplan_id):
                playbook = create_rbb_resilience_playbook(
                    _profile(testplan_id), _topology()
                )
                _, cleanup = _task_payload(playbook.cleanup_steps[0])
                guarded_markers = {
                    operation["marker"]
                    for operation in cleanup["operations"]
                    if "marker" in operation
                }
                mutations = []
                for stage in playbook.stages:
                    for index, step in enumerate(stage.steps):
                        if step.name == taac_types.StepName.SERVICE_INTERRUPTION_STEP:
                            trigger = json.loads(step.input_json or "{}")["trigger"]
                            if trigger == restart_trigger:
                                mutations.append((stage.steps, index))
                        elif step.name == taac_types.StepName.INTERFACE_FLAP_STEP:
                            if not json.loads(step.step_params.json_params)["enable"]:
                                mutations.append((stage.steps, index))

                self.assertTrue(mutations)
                for steps, index in mutations:
                    self.assertGreater(index, 0)
                    preceding_arms = []
                    for candidate in steps[:index]:
                        if candidate.name != taac_types.StepName.RUN_TASK_STEP:
                            continue
                        name, params = _task_payload(candidate)
                        if name == "rbb_best_effort_cleanup" and params.get(
                            "action"
                        ) == "arm":
                            preceding_arms.append(params["marker"])
                    self.assertTrue(set(preceding_arms) & guarded_markers)

    def test_event_counter_window_is_reset_immediately_before_mutation(self) -> None:
        restart_trigger = taac_types.ServiceInterruptionTrigger.SYSTEMCTL_RESTART
        for testplan_id in (
            "phase2:TC-15",
            "phase2:TC-30",
            "phase2:TC-104",
            "phase2:TC-100",
            "phase2:TC-99",
        ):
            with self.subTest(testplan_id=testplan_id):
                playbook = create_rbb_resilience_playbook(
                    _profile(testplan_id), _topology()
                )
                first_mutation = None
                for stage in playbook.stages:
                    for index, step in enumerate(stage.steps):
                        if step.name == taac_types.StepName.SERVICE_INTERRUPTION_STEP:
                            trigger = json.loads(step.input_json or "{}")["trigger"]
                            if trigger == restart_trigger:
                                first_mutation = (stage.steps, index)
                                break
                        if step.name == taac_types.StepName.INTERFACE_FLAP_STEP:
                            if not json.loads(step.step_params.json_params)["enable"]:
                                first_mutation = (stage.steps, index)
                                break
                    if first_mutation:
                        break

                self.assertIsNotNone(first_mutation)
                steps, index = first_mutation
                self.assertGreater(index, 0)
                self.assertEqual(
                    steps[index - 1].description, "Clear traffic statistics"
                )

    def test_ixia_reset_capability_is_checked_before_route_mutation(self) -> None:
        playbook = create_rbb_resilience_playbook(
            _profile("phase2:TC-15"), _topology()
        )
        capability_index = next(
            index
            for index, stage in enumerate(playbook.stages)
            if "verify IXIA measurement capability" in stage.description
        )
        route_index = next(
            index
            for index, stage in enumerate(playbook.stages)
            if "enable SRv6 steering" in stage.description
        )
        self.assertLess(capability_index, route_index)
        name, params = _task_payload(playbook.stages[capability_index].steps[0])
        self.assertEqual(name, "rbb_ixia_capability")
        self.assertTrue(params["require_controller_traffic_stats_reset"])

    def test_cleanup_markers_stay_armed_until_post_audit_succeeds(self) -> None:
        for testplan_id in (
            "phase2:TC-15",
            "phase2:TC-30",
            "phase2:TC-104",
            "phase2:TC-100",
            "phase2:TC-99",
        ):
            with self.subTest(testplan_id=testplan_id):
                playbook = create_rbb_resilience_playbook(
                    _profile(testplan_id), _topology()
                )
                descriptions = [stage.description for stage in playbook.stages]
                post_index = next(
                    index
                    for index, value in enumerate(descriptions)
                    if value.startswith(f"{testplan_id}_post")
                )
                disarm_index = next(
                    index
                    for index, value in enumerate(descriptions)
                    if "confirm recovery and disarm cleanup" in value
                )
                self.assertGreater(disarm_index, post_index)
                self.assertFalse(
                    any(
                        params.get("action") == "disarm"
                        for stage in playbook.stages[: post_index + 1]
                        for step in stage.steps
                        if step.name == taac_types.StepName.RUN_TASK_STEP
                        for name, params in [_task_payload(step)]
                        if name == "rbb_best_effort_cleanup"
                    )
                )

    def test_disruption_loss_is_checked_before_recovered_window(self) -> None:
        for testplan_id in (
            "phase2:TC-15",
            "phase2:TC-30",
            "phase2:TC-104",
            "phase2:TC-100",
        ):
            with self.subTest(testplan_id=testplan_id):
                playbook = create_rbb_resilience_playbook(
                    _profile(testplan_id), _topology()
                )
                descriptions = [stage.description for stage in playbook.stages]
                disruption_index = next(
                    index
                    for index, value in enumerate(descriptions)
                    if "measure traffic across disruption" in value
                )
                recovered_index = next(
                    index
                    for index, value in enumerate(descriptions)
                    if "verify traffic recovery" in value
                )
                self.assertLess(disruption_index, recovered_index)

    def test_post_recovery_reads_back_exact_srv6_segment_route(self) -> None:
        playbook = create_rbb_resilience_playbook(_profile("phase2:TC-15"), _topology())
        post_tasks = []
        for stage in playbook.stages:
            if not stage.description.startswith("phase2:TC-15_post"):
                continue
            post_tasks.extend(_task_payload(step) for step in stage.steps)

        verify = [params for name, params in post_tasks if name == "rbb_srv6_verify"]
        self.assertEqual(len(verify), 1)
        self.assertEqual(verify[0]["gate"], "phase2:TC-15_post")
        self.assertIn("TE_AGENT", verify[0]["expect_contains"])

    def test_bgpd_restart_verifies_core_and_edge_sessions(self) -> None:
        playbook = create_rbb_resilience_playbook(
            _profile("phase2:TC-104"), _topology()
        )
        peers = []
        for step in _stage_steps(playbook):
            if step.name != taac_types.StepName.RUN_TASK_STEP:
                continue
            name, params = _task_payload(step)
            if (
                name == "rbb_srv6_verify"
                and params.get("gate") == "phase2:TC-104_bgp_recovery"
            ):
                peers.append((params["hostname"], params["bgp_peers_established"]))

        self.assertEqual(len(peers), 2)
        self.assertEqual(
            [hostname for hostname, _ in peers],
            ["res-r1.example", "res-r2.example"],
        )
        self.assertTrue(all(len(expected) == 2 for _, expected in peers))

    def test_rate_gate_rejects_zero_tx_and_rx(self) -> None:
        playbook = create_rbb_resilience_playbook(_profile("phase2:TC-15"), _topology())
        rate_step = next(
            step
            for step in _stage_steps(playbook)
            if "Tx/Rx are positive before disruption" in step.description
        )
        check_name, threshold = _validation_threshold(rate_step)

        self.assertEqual(check_name, hc_types.CheckName.IXIA_TRAFFIC_RATE_CHECK)
        self.assertEqual(threshold["value"], 0)
        self.assertEqual(threshold["threshold_type"], hc_types.ThresholdType.ABSOLUTE)
        # With no rate_metrics override, the health check applies its strict
        # ``rate > threshold`` rule to both TX and RX.  A 0 Gbps observation
        # therefore fails this 0 Gbps floor instead of masking absent traffic.
        self.assertIsNone(
            json.loads(rate_step.input_json or "{}")["point_in_time_checks"][0].get(
                "check_params"
            )
        )

    def test_loss_threshold_semantics_match_each_disruption(self) -> None:
        measurement = create_rbb_resilience_playbook(
            _profile("phase2:TC-104"), _topology()
        )
        measurement_step = next(
            step
            for step in _stage_steps(measurement)
            if "disruption-window loss measurement" in step.description
        )
        _, measurement_threshold = _validation_threshold(measurement_step)
        self.assertEqual(measurement_threshold["str_value"], "100")
        self.assertFalse(measurement_threshold["expect_packet_loss"])

        no_loss = create_rbb_resilience_playbook(
            _profile("phase2:TC-15"),
            _topology(),
            disruption_loss_threshold_pct="0.25",
        )
        no_loss_step = next(
            step
            for step in _stage_steps(no_loss)
            if "disruption-window loss budget" in step.description
        )
        _, no_loss_threshold = _validation_threshold(no_loss_step)
        self.assertFalse(no_loss_threshold["expect_packet_loss"])
        self.assertEqual(no_loss_threshold["str_value"], "0.25")
        self.assertEqual(
            no_loss_threshold["metric"], hc_types.PacketLossMetric.PERCENTAGE
        )
        self.assertEqual(
            no_loss_threshold["comparison"], hc_types.ComparisonType.LESS_THAN_EQUAL_TO
        )

        expected_loss = create_rbb_resilience_playbook(
            _profile("phase2:TC-99"),
            _topology(),
            disruption_loss_threshold_pct="40",
        )
        expected_loss_step = next(
            step
            for step in _stage_steps(expected_loss)
            if "outage produces measurable loss" in step.description
        )
        _, expected_loss_threshold = _validation_threshold(expected_loss_step)
        self.assertTrue(expected_loss_threshold["expect_packet_loss"])
        self.assertEqual(
            expected_loss_threshold["metric"], hc_types.PacketLossMetric.PERCENTAGE
        )
        validation = json.loads(expected_loss_step.input_json or "{}")
        thresholds = json.loads(
            validation["point_in_time_checks"][0]["input_json"]
        )["thresholds"]
        self.assertEqual(len(thresholds), 2)
        self.assertTrue(thresholds[0]["expect_packet_loss"])
        self.assertFalse(thresholds[1]["expect_packet_loss"])
        self.assertEqual(thresholds[1]["str_value"], "40")
        self.assertFalse(
            any(
                "disruption-window loss budget" in step.description
                for step in _stage_steps(expected_loss)
            )
        )

    def test_packet_loss_checks_are_followed_by_explicit_traffic_restart(self) -> None:
        playbook = create_rbb_resilience_playbook(_profile("phase2:TC-15"), _topology())
        baseline = next(
            stage
            for stage in playbook.stages
            if "establish IXIA baseline" in stage.description
        )
        baseline_descriptions = [step.description for step in baseline.steps]
        loss_index = next(
            index
            for index, value in enumerate(baseline_descriptions)
            if "pre-disruption traffic is lossless" in value
        )
        restart_index = next(
            index
            for index in range(loss_index + 1, len(baseline.steps))
            if baseline.steps[index].name == taac_types.StepName.INVOKE_IXIA_API_STEP
            and "start" in baseline.steps[index].description.lower()
        )
        rate_index = next(
            index
            for index, value in enumerate(baseline_descriptions)
            if "positive before disruption" in value
        )
        self.assertLess(loss_index, restart_index)
        self.assertLess(restart_index, rate_index)

        recovered = next(
            stage
            for stage in playbook.stages
            if "verify traffic recovery" in stage.description
        )
        self.assertIn("start", recovered.steps[0].description.lower())
        self.assertTrue(
            any(
                "recovered Tx/Rx are positive" in step.description
                for step in recovered.steps
            )
        )

    def test_registered_tasks_never_start_traffic_implicitly(self) -> None:
        for testplan_id in (
            "phase2:TC-15",
            "phase2:TC-30",
            "phase2:TC-104",
            "phase2:TC-100",
            "phase2:TC-99",
        ):
            with self.subTest(testplan_id=testplan_id):
                playbook = create_rbb_resilience_playbook(
                    _profile(testplan_id), _topology()
                )
                task_steps = [
                    step
                    for step in [*_stage_steps(playbook), *playbook.cleanup_steps]
                    if step.name == taac_types.StepName.RUN_TASK_STEP
                ]
                self.assertTrue(task_steps)
                self.assertTrue(
                    all(
                        json.loads(step.step_params.json_params)["skip_start_traffic"]
                        for step in task_steps
                    )
                )

    def test_tc99_restarts_traffic_only_after_edge_is_restored(self) -> None:
        playbook = create_rbb_resilience_playbook(_profile("phase2:TC-99"), _topology())
        descriptions = [stage.description for stage in playbook.stages]
        restore = next(
            index
            for index, value in enumerate(descriptions)
            if "restore IXIA edge" in value
        )
        recovered = next(
            index
            for index, value in enumerate(descriptions)
            if "verify traffic recovery" in value
        )
        self.assertLess(restore, recovered)
        self.assertIn("start", playbook.stages[recovered].steps[0].description.lower())

    def test_tc99_is_only_outage_and_restoration(self) -> None:
        playbook = create_rbb_resilience_playbook(_profile("phase2:TC-99"), _topology())
        text = " ".join(
            [playbook.description]
            + [stage.description for stage in playbook.stages]
            + [step.description for step in _stage_steps(playbook)]
        ).lower()

        self.assertIn("adapted edge outage", text)
        self.assertIn("outage produces measurable loss", text)
        self.assertIn("restore ixia edge", text)
        self.assertNotIn("failover", text)

    def test_route_cleanup_precedes_traffic_stop(self) -> None:
        playbook = create_rbb_resilience_playbook(_profile("phase2:TC-15"), _topology())
        self.assertEqual(len(playbook.cleanup_steps), 1)
        name, params = _task_payload(playbook.cleanup_steps[0])

        self.assertEqual(name, "rbb_best_effort_cleanup")
        self.assertEqual(
            [operation["type"] for operation in params["operations"][-2:]],
            ["delete_direct_route", "stop_traffic"],
        )


if __name__ == "__main__":
    unittest.main()
