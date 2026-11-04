# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Structure tests for named SRv6 NHG lifecycle playbooks."""

import json
import unittest

from taac.playbooks.routing.factories.qual_rbb.rbb_named_nhg_playbook import (
    create_rbb_named_nhg_playbook,
)
from taac.test_as_a_config import types as taac_types
from taac.testconfigs.routing.util.bgp_rbb_named_nhg_profiles import (
    build_rbb_named_nhg_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import (
    CorePortChannel,
    NodeTopology,
    RbbTopology,
)


def _topology() -> RbbTopology:
    return RbbTopology(
        r1=NodeTopology("r1", "r1.example", (CorePortChannel("pc1", ("eth1/1",)),)),
        r2=NodeTopology("r2", "r2.example", (CorePortChannel("peer1", ("eth1/1",)),)),
    )


def _payload(step):
    task = json.loads(step.input_json or "{}")["task"]
    return task["task_name"], json.loads(task["params"]["json_params"])


def _stage_tasks(playbook):
    result = []
    for stage in playbook.stages:
        for step in stage.steps:
            if step.name == taac_types.StepName.RUN_TASK_STEP:
                result.append(_payload(step))
    return result


class RbbNamedNhgPlaybookTest(unittest.TestCase):
    def setUp(self) -> None:
        self.profiles = build_rbb_named_nhg_profiles(_topology())

    def test_tc02_programs_group_then_verifies_resolved_fib(self) -> None:
        playbook = create_rbb_named_nhg_playbook(
            self.profiles[0], r1_hostname="r1.example"
        )
        tasks = _stage_tasks(playbook)

        self.assertTrue(all(name == "rbb_srv6_named_nhg" for name, _ in tasks))
        self.assertEqual(
            [params["action"] for _, params in tasks],
            [
                "precheck",
                "program_nhg",
                "verify_nhg",
                "program_route",
                "verify_nhg",
                "verify_programmed",
            ],
        )
        verify = [params for _, params in tasks if params["action"] == "verify_nhg"]
        self.assertNotIn("expected_programmed", verify[0])
        self.assertTrue(verify[1]["expected_programmed"])
        self.assertIn("members", tasks[1][1])
        self.assertNotIn("members", tasks[3][1])
        self.assertIn("[PARTIAL]", playbook.description)
        self.assertIn("traffic", playbook.description)

    def test_tc06_requires_exact_rib_only_forward_reference(self) -> None:
        playbook = create_rbb_named_nhg_playbook(
            self.profiles[1], r1_hostname="r1.example"
        )
        tasks = _stage_tasks(playbook)

        self.assertEqual(
            [params["action"] for _, params in tasks],
            ["precheck", "install_forward_ref", "verify_rib_only"],
        )
        self.assertIn("SKIP", playbook.description)
        self.assertTrue(all("members" not in params for _, params in tasks))

    def test_tc07_recreates_forward_reference_before_adding_group(self) -> None:
        playbook = create_rbb_named_nhg_playbook(
            self.profiles[2], r1_hostname="r1.example"
        )
        tasks = _stage_tasks(playbook)

        self.assertEqual(
            [params["action"] for _, params in tasks],
            [
                "precheck",
                "install_forward_ref",
                "verify_rib_only",
                "program_nhg",
                "verify_nhg",
                "verify_programmed",
            ],
        )
        self.assertTrue(tasks[4][1]["expected_programmed"])
        self.assertIn("members", tasks[3][1])
        self.assertIn("members", tasks[4][1])
        self.assertIn("SKIP", playbook.description)

    def test_every_playbook_is_device_only_and_has_owned_cleanup(self) -> None:
        for profile in self.profiles:
            with self.subTest(profile=profile.testplan_id):
                playbook = create_rbb_named_nhg_playbook(
                    profile, r1_hostname="r1.example"
                )
                self.assertIsNone(playbook.traffic_items_to_start)
                self.assertEqual(playbook.device_regexes, ["^r1\\.example$"])
                self.assertEqual(len(playbook.cleanup_steps), 1)
                name, params = _payload(playbook.cleanup_steps[0])
                self.assertEqual(name, "rbb_srv6_named_nhg")
                self.assertEqual(params["action"], "cleanup")
                self.assertEqual(params["hostname"], "r1.example")
                self.assertIn("members", params)

    def test_rejects_empty_hostname(self) -> None:
        with self.assertRaisesRegex(ValueError, "R1 hostname"):
            create_rbb_named_nhg_playbook(self.profiles[0], r1_hostname="")


if __name__ == "__main__":
    unittest.main()
