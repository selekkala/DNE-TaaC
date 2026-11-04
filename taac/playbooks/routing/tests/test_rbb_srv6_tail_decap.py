# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Tests for Phase-2 TC-24 and the adjacent coverage assessments."""

import json
import unittest
from dataclasses import replace

from taac.health_check.health_check import types as hc_types
from taac.test_as_a_config.types import StepName

from taac.playbooks.routing.factories.qual_rbb.rbb_srv6_tail_decap_playbook import (
    create_rbb_srv6_tail_decap_playbook,
)
from taac.testconfigs.routing.factories.qual_rbb.rbb_srv6_tail_decap_test_config import (
    create_rbb_srv6_tail_decap_test_config,
)
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_scenario_profiles import (
    SRV6_3_USIDS_PROFILE,
)
from taac.testconfigs.routing.util.bgp_rbb_srv6_functional_profiles import (
    SRV6_FUNCTIONAL_CASES,
    Srv6CaseReadiness,
    build_tail_decap_state_profile,
    runnable_srv6_functional_ids,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import (
    CorePortChannel,
    IxiaEdge,
    NodeTopology,
    RbbTopology,
)


def _topology(*, with_r2_edge: bool = True) -> RbbTopology:
    return RbbTopology(
        r1=NodeTopology(
            role="r1",
            hostname="tc24-r1.example",
            core_pcs=(
                CorePortChannel("port-channel1", ("eth1/1",)),
                CorePortChannel("port-channel2", ("eth1/2",)),
            ),
            ixia_edges=(IxiaEdge("eth1/5", "1/1"),),
        ),
        r2=NodeTopology(
            role="r2",
            hostname="tc24-r2.example",
            core_pcs=(
                CorePortChannel("port-channel1", ("eth1/1",)),
                CorePortChannel("port-channel2", ("eth1/2",)),
            ),
            ixia_edges=((IxiaEdge("eth1/6", "1/2"),) if with_r2_edge else ()),
        ),
        ixia_chassis="ixia.example",
    )


def _steps(playbook):
    return [step for stage in playbook.stages or [] for step in (stage.steps or [])]


def _run_tasks(playbook):
    tasks = []
    for step in _steps(playbook):
        if step.name != StepName.RUN_TASK_STEP:
            continue
        task = json.loads(step.input_json)["task"]
        tasks.append((task["task_name"], json.loads(task["params"]["json_params"])))
    return tasks


def _step_params(step):
    if step.step_params is None or not step.step_params.json_params:
        return {}
    return json.loads(step.step_params.json_params)


def _traffic_stage(playbook):
    return next(
        stage
        for stage in playbook.stages or []
        if "lossless SRv6 traffic" in (stage.description or "")
    )


class RbbSrv6FunctionalCoverageTest(unittest.TestCase):
    def test_only_tc24_is_currently_runnable(self) -> None:
        self.assertEqual(
            set(SRV6_FUNCTIONAL_CASES),
            {
                "phase2:TC-23",
                "phase2:TC-24",
                "phase2:TC-102",
                "phase2:TC-105",
                "phase2:TC-106",
            },
        )
        self.assertEqual(runnable_srv6_functional_ids(), ("phase2:TC-24",))
        self.assertIs(
            SRV6_FUNCTIONAL_CASES["phase2:TC-24"].readiness,
            Srv6CaseReadiness.RUNNABLE,
        )

    def test_scale_and_bidirectional_cases_fail_closed(self) -> None:
        scale = SRV6_FUNCTIONAL_CASES["phase2:TC-23"]
        bidirectional = SRV6_FUNCTIONAL_CASES["phase2:TC-102"]
        self.assertIs(scale.readiness, Srv6CaseReadiness.BLOCKED)
        self.assertIs(bidirectional.readiness, Srv6CaseReadiness.BLOCKED)
        self.assertIsNone(scale.factory)
        self.assertIsNone(bidirectional.factory)
        self.assertTrue(any("16,384" in item for item in scale.unmet_requirements))
        self.assertTrue(
            any(
                "R1 has no decap MySID" in item
                for item in bidirectional.unmet_requirements
            )
        )

    def test_tc105_requires_real_openr_service_fallback(self) -> None:
        fallback = SRV6_FUNCTIONAL_CASES["phase2:TC-105"]
        self.assertIs(fallback.readiness, Srv6CaseReadiness.BLOCKED)
        self.assertIsNone(fallback.factory)
        self.assertTrue(
            any(
                "BGPD fallback is not" in item and "OpenR" in item and "TC-105" in item
                for item in fallback.unmet_requirements
            )
        )
        self.assertTrue(
            any(
                "OPENR-owned route" in item and "preferred FIB owner" in item
                for item in fallback.unmet_requirements
            )
        )

    def test_tc106_requires_unknown_usid_injection_and_exact_drop_evidence(
        self,
    ) -> None:
        unknown_sid = SRV6_FUNCTIONAL_CASES["phase2:TC-106"]
        self.assertIs(unknown_sid.readiness, Srv6CaseReadiness.BLOCKED)
        self.assertIsNone(unknown_sid.factory)
        self.assertTrue(
            any(
                "generic RAW" in item and "proven absent" in item
                for item in unknown_sid.unmet_requirements
            )
        )
        self.assertTrue(
            any(
                "exact local-SID miss/drop counter" in item
                for item in unknown_sid.unmet_requirements
            )
        )
        self.assertTrue(
            any("loop or leak" in item for item in unknown_sid.unmet_requirements)
        )

    def test_tc24_profile_is_exact_tail_state(self) -> None:
        profile = build_tail_decap_state_profile(_topology())
        self.assertEqual(profile.testplan_id, "phase2:TC-24")
        self.assertEqual(profile.target_roles, ("r2",))
        params = profile.to_task_params("r2")
        self.assertEqual(
            params["mysids"],
            [
                {
                    "sid": C.SRV6_DECAP_SID,
                    "behavior": C.SRV6_BEHAVIOR_DECAP,
                    "require_resolved": False,
                }
            ],
        )
        self.assertEqual(params["routes"][0]["prefix"], C.TAIL_DEST_PREFIX)
        self.assertEqual(params["routes"][0]["client"], C.ROUTE_OWNER_BGPD)
        self.assertEqual(params["routes"][0]["next_hops"], [C.IXIA_R2_EDGE_V6])
        self.assertTrue(params["routes"][0]["exact_next_hops"])
        self.assertEqual(params["interfaces_up"], ["eth1/6"])

    def test_tc24_requires_tail_ixia_edge(self) -> None:
        with self.assertRaisesRegex(ValueError, "IXIA-facing R2 edge"):
            build_tail_decap_state_profile(_topology(with_r2_edge=False))


class RbbSrv6TailDecapPlaybookTest(unittest.TestCase):
    def test_playbook_composes_exact_state_route_and_traffic_evidence(self) -> None:
        playbook = create_rbb_srv6_tail_decap_playbook(topology=_topology())
        self.assertEqual(playbook.name, "rbb_p2_tc24_tail_decap_inner_lookup")
        self.assertIn("phase2:TC-24 [FULL]", playbook.description)
        self.assertEqual(playbook.device_regexes, [r"^tc24\-r1\.example$"])

        tasks = _run_tasks(playbook)
        names = [name for name, _ in tasks]
        self.assertEqual(names.count("rbb_state_audit"), 1)
        self.assertEqual(names.count("rbb_srv6_direct_route"), 2)
        self.assertEqual(names.count("rbb_srv6_counter_delta"), 4)
        self.assertEqual(names.count("rbb_srv6_verify"), 2)

        audit = next(params for name, params in tasks if name == "rbb_state_audit")
        self.assertEqual(audit["gate"], "phase2:TC-24")
        self.assertEqual(audit["hostname"], "tc24-r2.example")
        self.assertEqual(audit["mysids"][0]["behavior"], C.SRV6_BEHAVIOR_DECAP)
        self.assertEqual(audit["routes"][0]["next_hops"], [C.IXIA_R2_EDGE_V6])

    def test_tc24_installs_exact_forward_segment_container_then_restores(self) -> None:
        playbook = create_rbb_srv6_tail_decap_playbook(topology=_topology())
        direct = [
            params
            for name, params in _run_tasks(playbook)
            if name == "rbb_srv6_direct_route"
        ]
        self.assertEqual([params["action"] for params in direct], ["install", "delete"])
        self.assertEqual(direct[0]["prefix"], C.TAIL_DEST_PREFIX)
        self.assertEqual(
            direct[0]["srv6_segments"],
            ["2001:db8:6:27d6:27cc:7fff::"],
        )
        self.assertEqual(direct[0]["srv6_tunnel_id"], C.SRV6_TUNNEL_ID)

    def test_tc24_rejects_a_final_usid_that_is_not_the_decap_mysid(self) -> None:
        mismatched = replace(
            SRV6_3_USIDS_PROFILE,
            decap_sid="2001:db8:6:7000::",
        )
        with self.assertRaisesRegex(ValueError, "final on-wire uSID"):
            create_rbb_srv6_tail_decap_playbook(
                topology=_topology(), profile=mismatched
            )

    def test_traffic_counter_order_is_snapshot_then_assert(self) -> None:
        playbook = create_rbb_srv6_tail_decap_playbook(topology=_topology())
        counters = [
            params
            for name, params in _run_tasks(playbook)
            if name == "rbb_srv6_counter_delta"
        ]
        self.assertEqual(
            [(item["direction"], item["action"]) for item in counters],
            [
                ("encap", "snapshot"),
                ("decap", "snapshot"),
                ("encap", "assert"),
                ("decap", "assert"),
            ],
        )
        descriptions = [step.description or "" for step in _steps(playbook)]
        self.assertIn("Clear traffic statistics", descriptions)
        self.assertIn("Call Ixia API: start_traffic", descriptions)
        self.assertIn("Call Ixia API: stop_traffic", descriptions)
        self.assertTrue(
            any("IXIA no-loss" in description for description in descriptions)
        )

    def test_traffic_measurement_window_has_strict_order_and_no_hidden_starts(
        self,
    ) -> None:
        playbook = create_rbb_srv6_tail_decap_playbook(topology=_topology())
        steps = list(_traffic_stage(playbook).steps or [])
        self.assertEqual(
            [step.description for step in steps],
            [
                "Call Ixia API: stop_traffic",
                (
                    "[S25_srv6_encap_delta] snapshot encap path counter on "
                    "tc24-r1.example"
                ),
                (
                    "[S25_srv6_decap_delta] snapshot decap path counter on "
                    "tc24-r2.example"
                ),
                "Clear traffic statistics",
                "Call Ixia API: start_traffic",
                "TC-24 warm up IXIA Tx/Rx rate sample",
                "TC-24 IXIA Tx/Rx rates are both positive",
                "TC-24 final-uSID decap and inner lookup: IXIA no-loss",
                (
                    "[S25_srv6_encap_delta] assert encap path counter on "
                    "tc24-r1.example"
                ),
                (
                    "[S25_srv6_decap_delta] assert decap path counter on "
                    "tc24-r2.example"
                ),
                "Call Ixia API: stop_traffic",
            ],
        )

        # The only traffic-state mutations in the measurement window are the
        # three explicit IXIA API steps above. Snapshots, warm-up, validation,
        # and assertions must never invoke the generic traffic-start pre-hook.
        for index in (1, 2, 3, 5, 6, 7, 8, 9):
            self.assertTrue(
                _step_params(steps[index]).get("skip_start_traffic"),
                f"step {index} can implicitly start traffic",
            )
        self.assertEqual(_step_params(steps[5])["duration"], 5)

    def test_positive_tx_and_rx_gate_precedes_packet_loss_gate(self) -> None:
        playbook = create_rbb_srv6_tail_decap_playbook(topology=_topology())
        steps = list(_traffic_stage(playbook).steps or [])
        rate_step = steps[6]
        loss_step = steps[7]
        self.assertEqual(rate_step.name, StepName.VALIDATION_STEP)
        self.assertEqual(loss_step.name, StepName.VALIDATION_STEP)

        rate_check = json.loads(rate_step.input_json)["point_in_time_checks"][0]
        self.assertEqual(
            rate_check["name"], hc_types.CheckName.IXIA_TRAFFIC_RATE_CHECK.value
        )
        # With no check_params.rate_metrics override, the IXIA rate health
        # check evaluates both Tx and Rx. A strict absolute floor of zero
        # rejects missing statistics and either direction at zero rate.
        self.assertNotIn("check_params", rate_check)
        threshold = json.loads(rate_check["input_json"])["thresholds"][0]
        self.assertEqual(threshold["names"], list(C.ALL_TRAFFIC_ITEMS))
        self.assertEqual(threshold["value"], 0)
        self.assertEqual(
            threshold["threshold_type"], hc_types.ThresholdType.ABSOLUTE.value
        )

        loss_check = json.loads(loss_step.input_json)["point_in_time_checks"][0]
        self.assertEqual(
            loss_check["name"], hc_types.CheckName.IXIA_PACKET_LOSS_CHECK.value
        )
        self.assertTrue(_step_params(rate_step)["skip_start_traffic"])
        self.assertTrue(_step_params(loss_step)["skip_start_traffic"])

    def test_only_explicit_ixia_api_steps_can_change_traffic_state(self) -> None:
        playbook = create_rbb_srv6_tail_decap_playbook(topology=_topology())
        task_steps = [
            step
            for step in [*_steps(playbook), *(playbook.cleanup_steps or [])]
            if step.name == StepName.RUN_TASK_STEP
        ]
        self.assertTrue(task_steps)
        for step in task_steps:
            self.assertTrue(
                _step_params(step).get("skip_start_traffic"),
                f"{step.description!r} can implicitly start IXIA traffic",
            )

    def test_cleanup_attempts_route_delete_then_traffic_stop_in_one_task(self) -> None:
        playbook = create_rbb_srv6_tail_decap_playbook(topology=_topology())
        cleanup = playbook.cleanup_steps or []
        self.assertEqual(len(cleanup), 1)
        task = json.loads(cleanup[0].input_json)["task"]
        params = json.loads(task["params"]["json_params"])
        self.assertEqual(task["task_name"], "rbb_best_effort_cleanup")
        self.assertEqual(params["action"], "cleanup")
        self.assertEqual(
            [operation["type"] for operation in params["operations"]],
            ["delete_direct_route", "stop_traffic"],
        )

    def test_test_config_reuses_pr46_ixia_contract(self) -> None:
        config = create_rbb_srv6_tail_decap_test_config(_topology())
        self.assertEqual(config.name, "RBB_P2_TC24_TAIL_DECAP_TEST")
        self.assertEqual(len(config.endpoints or []), 2)
        self.assertTrue(
            all(endpoint.ixia_needed for endpoint in config.endpoints or [])
        )
        self.assertEqual(
            [item.name for item in config.basic_traffic_item_configs or []],
            [C.TRAFFIC_ITEM_R1_TO_R2],
        )
        self.assertEqual(
            [playbook.name for playbook in config.playbooks or []],
            ["rbb_p2_tc24_tail_decap_inner_lookup"],
        )


if __name__ == "__main__":
    unittest.main()
