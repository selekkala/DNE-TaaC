# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Integration tests for the standalone resilience TestConfig factory."""

import json
import os
import runpy
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from taac.testconfigs.routing.factories.qual_rbb.rbb_resilience_test_config import (
    create_rbb_resilience_test_config,
)
from taac.testconfigs.routing.util.bgp_rbb_resilience_profiles import (
    RESILIENCE_SUITE_TESTPLAN_IDS,
    build_rbb_resilience_profiles,
    select_rbb_resilience_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import (
    CorePortChannel,
    IxiaEdge,
    NodeTopology,
    RbbTopology,
)


def _topology() -> RbbTopology:
    pcs = (
        CorePortChannel("port-channel1", ("eth1/1",)),
        CorePortChannel("port-channel2", ("eth1/2",)),
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


class RbbResilienceTestConfigTest(unittest.TestCase):
    def test_device_only_mode_is_rejected_as_incomplete(self) -> None:
        with self.assertRaisesRegex(ValueError, "require live IXIA traffic"):
            create_rbb_resilience_test_config(_topology(), include_traffic=False)

    def test_default_live_selection_matches_nonpartial_catalog(self) -> None:
        topology = _topology()
        expected = select_rbb_resilience_profiles(
            build_rbb_resilience_profiles(topology)
        )
        config = create_rbb_resilience_test_config(topology, include_traffic=True)

        self.assertEqual(
            [playbook.name for playbook in config.playbooks],
            [profile.playbook_name for profile in expected],
        )
        self.assertFalse(config.skip_ixia_protocol_verification)
        self.assertTrue(all(endpoint.ixia_needed for endpoint in config.endpoints))
        self.assertTrue(config.basic_port_configs)
        self.assertTrue(config.basic_traffic_item_configs)

    def test_partial_binding_sid_warmboot_requires_explicit_opt_in(self) -> None:
        with self.assertRaisesRegex(ValueError, "allow_partial"):
            create_rbb_resilience_test_config(
                _topology(),
                include_traffic=True,
                testplan_ids=["phase2:TC-22"],
            )
        config = create_rbb_resilience_test_config(
            _topology(),
            include_traffic=True,
            testplan_ids=["phase2:TC-22"],
            allow_partial=True,
        )

        self.assertEqual(len(config.playbooks), 1)
        self.assertIn("[PARTIAL]", config.playbooks[0].description)

    def test_public_suite_runs_tc30_partial_but_not_tc22(self) -> None:
        config = create_rbb_resilience_test_config(
            _topology(),
            include_traffic=True,
            testplan_ids=RESILIENCE_SUITE_TESTPLAN_IDS,
            allow_partial=True,
        )

        descriptions = [playbook.description for playbook in config.playbooks]
        self.assertEqual(len(descriptions), 4)
        self.assertTrue(any("phase2:TC-30 [PARTIAL]" in item for item in descriptions))
        self.assertFalse(any("phase2:TC-100" in item for item in descriptions))
        self.assertFalse(any("phase2:TC-22" in item for item in descriptions))

    def test_core_pc_name_selects_second_declared_path(self) -> None:
        config = create_rbb_resilience_test_config(
            _topology(),
            include_traffic=True,
            testplan_ids=["phase2:TC-100"],
            allow_partial=True,
            core_pc_name="port-channel2",
        )
        cleanup = config.playbooks[0].cleanup_steps[0]
        task = json.loads(cleanup.input_json or "{}")["task"]
        params = json.loads(task["params"]["json_params"])

        self.assertEqual(params["operations"][0]["interfaces"], ["eth1/2"])

    def test_core_pc_name_may_be_local_to_one_dut(self) -> None:
        topology = _topology()
        topology = replace(
            topology,
            r2=replace(
                topology.r2,
                core_pcs=(
                    CorePortChannel("peer-core-a", ("eth1/1",)),
                    CorePortChannel("peer-core-b", ("eth1/2",)),
                ),
            ),
        )
        config = create_rbb_resilience_test_config(
            topology,
            include_traffic=True,
            testplan_ids=["phase2:TC-100"],
            allow_partial=True,
            core_pc_name="port-channel2",
        )

        self.assertEqual(len(config.playbooks), 1)

    def test_core_pc_name_and_index_must_select_the_same_path(self) -> None:
        with self.assertRaisesRegex(ValueError, "select different PCs"):
            create_rbb_resilience_test_config(
                _topology(),
                include_traffic=True,
                testplan_ids=["phase2:TC-100"],
                allow_partial=True,
                core_pc_name="port-channel2",
                core_pc_index=0,
            )

    def test_core_pc_selection_rejects_unknown_name_and_bad_index(self) -> None:
        with self.assertRaisesRegex(ValueError, "not declared on either DUT"):
            create_rbb_resilience_test_config(
                _topology(),
                include_traffic=True,
                testplan_ids=["phase2:TC-100"],
                allow_partial=True,
                core_pc_name="missing",
            )
        for index in (-1, True):
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(ValueError, "non-negative integer"),
            ):
                create_rbb_resilience_test_config(
                    _topology(),
                    include_traffic=True,
                    testplan_ids=["phase2:TC-100"],
                    allow_partial=True,
                    core_pc_index=index,
                )

    def test_example_wrapper_exports_factory_result_without_registration(self) -> None:
        wrapper = (
            Path(__file__).resolve().parents[4]
            / "examples"
            / "rbb_srv6_resilience_config.py"
        )
        sentinel = object()
        target = (
            "taac.testconfigs.routing.factories.qual_rbb."
            "rbb_resilience_test_config.create_rbb_resilience_test_config"
        )
        runtime_names = {
            "TAAC_RBB_RESILIENCE_CORE_PC_NAME": "",
            "TAAC_RBB_RESILIENCE_CORE_PC_INDEX": "",
            "TAAC_RBB_RESILIENCE_MAX_LOSS_PCT": "",
            "TAAC_RBB_RESILIENCE_MIN_SELECTED_PATH_SHARE_PCT": "",
        }
        with (
            mock.patch.dict(os.environ, runtime_names),
            mock.patch(target, return_value=sentinel) as factory,
        ):
            result = runpy.run_path(str(wrapper))

        self.assertIs(result["test_config"], sentinel)
        factory.assert_called_once_with(
            testplan_ids=RESILIENCE_SUITE_TESTPLAN_IDS,
            allow_partial=True,
        )

    def test_example_wrapper_forwards_explicit_runtime_options(self) -> None:
        wrapper = (
            Path(__file__).resolve().parents[4]
            / "examples"
            / "rbb_srv6_resilience_config.py"
        )
        target = (
            "taac.testconfigs.routing.factories.qual_rbb."
            "rbb_resilience_test_config.create_rbb_resilience_test_config"
        )
        runtime = {
            "TAAC_RBB_RESILIENCE_CORE_PC_NAME": "port-channel2",
            "TAAC_RBB_RESILIENCE_CORE_PC_INDEX": "1",
            "TAAC_RBB_RESILIENCE_MAX_LOSS_PCT": "35",
            "TAAC_RBB_RESILIENCE_MIN_SELECTED_PATH_SHARE_PCT": "2.5",
        }
        with (
            mock.patch.dict(os.environ, runtime),
            mock.patch(target, return_value=object()) as factory,
        ):
            runpy.run_path(str(wrapper))

        factory.assert_called_once_with(
            testplan_ids=RESILIENCE_SUITE_TESTPLAN_IDS,
            allow_partial=True,
            core_pc_name="port-channel2",
            core_pc_index=1,
            disruption_loss_threshold_pct="35",
            selected_path_min_traffic_percent=2.5,
        )


if __name__ == "__main__":
    unittest.main()
