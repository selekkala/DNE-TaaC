# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Coverage-contract tests for the RBB resilience catalog."""

import unittest

from taac.testconfigs.routing.util.bgp_rbb_resilience_profiles import (
    RESILIENCE_SUITE_TESTPLAN_IDS,
    RbbResilienceCoverage,
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
    return RbbTopology(
        r1=NodeTopology(
            role="r1",
            hostname="res-r1.example",
            core_pcs=(
                CorePortChannel("port-channel1", ("eth1/1",)),
                CorePortChannel("port-channel2", ("eth1/2",)),
            ),
            ixia_edges=(IxiaEdge("eth1/3", "1/1"),),
        ),
        r2=NodeTopology(
            role="r2",
            hostname="res-r2.example",
            core_pcs=(
                CorePortChannel("port-channel1", ("eth1/1",)),
                CorePortChannel("port-channel2", ("eth1/2",)),
            ),
            ixia_edges=(IxiaEdge("eth1/3", "1/2"),),
        ),
        ixia_chassis="ixia.example",
    )


class RbbResilienceProfilesTest(unittest.TestCase):
    def test_default_selection_excludes_partial_cases(self) -> None:
        selected = select_rbb_resilience_profiles(
            build_rbb_resilience_profiles(_topology())
        )

        self.assertEqual(
            [profile.testplan_id for profile in selected],
            [
                "phase2:TC-15",
                "phase2:TC-104",
                "phase2:TC-99",
            ],
        )
        self.assertTrue(
            all(
                profile.coverage is not RbbResilienceCoverage.PARTIAL
                for profile in selected
            )
        )

    def test_public_suite_explicitly_opts_into_tc30_partial(self) -> None:
        selected = select_rbb_resilience_profiles(
            build_rbb_resilience_profiles(_topology()),
            RESILIENCE_SUITE_TESTPLAN_IDS,
            allow_partial=True,
        )

        self.assertEqual(
            [profile.testplan_id for profile in selected],
            list(RESILIENCE_SUITE_TESTPLAN_IDS),
        )
        tc30 = next(item for item in selected if item.testplan_id == "phase2:TC-30")
        self.assertIs(tc30.coverage, RbbResilienceCoverage.PARTIAL)
        self.assertIn("QoS", " ".join(tc30.unmet_requirements))
        self.assertEqual(
            [
                item.testplan_id
                for item in selected
                if item.coverage is RbbResilienceCoverage.PARTIAL
            ],
            ["phase2:TC-30"],
        )

    def test_tc100_is_partial_and_excluded_from_public_suite(self) -> None:
        profiles = build_rbb_resilience_profiles(_topology())
        tc100 = next(
            item for item in profiles if item.testplan_id == "phase2:TC-100"
        )

        self.assertIs(tc100.coverage, RbbResilienceCoverage.PARTIAL)
        self.assertNotIn(tc100.testplan_id, RESILIENCE_SUITE_TESTPLAN_IDS)
        self.assertIn("failover-capable", " ".join(tc100.unmet_requirements))
        with self.assertRaisesRegex(ValueError, "allow_partial"):
            select_rbb_resilience_profiles(profiles, [tc100.testplan_id])
        self.assertEqual(
            select_rbb_resilience_profiles(
                profiles, [tc100.testplan_id], allow_partial=True
            ),
            (tc100,),
        )

    def test_tc99_is_adapted_outage_not_failover(self) -> None:
        profile = next(
            item
            for item in build_rbb_resilience_profiles(_topology())
            if item.testplan_id == "phase2:TC-99"
        )

        self.assertIs(profile.coverage, RbbResilienceCoverage.ADAPTED)
        self.assertIn("single-edge outage", profile.title.lower())
        self.assertNotIn("failover", profile.title.lower())

    def test_tc22_binding_sid_case_is_partial_and_default_excluded(self) -> None:
        profiles = build_rbb_resilience_profiles(_topology())
        tc22 = next(item for item in profiles if item.testplan_id == "phase2:TC-22")

        self.assertIs(tc22.coverage, RbbResilienceCoverage.PARTIAL)
        self.assertIn("Binding SID", " ".join(tc22.unmet_requirements))
        with self.assertRaisesRegex(ValueError, "allow_partial"):
            select_rbb_resilience_profiles(profiles, ["phase2:TC-22"])
        self.assertEqual(
            select_rbb_resilience_profiles(
                profiles, ["phase2:TC-22"], allow_partial=True
            ),
            (tc22,),
        )

    def test_unknown_and_duplicate_selection_fail_closed(self) -> None:
        profiles = build_rbb_resilience_profiles(_topology())
        with self.assertRaisesRegex(ValueError, "unknown"):
            select_rbb_resilience_profiles(profiles, ["phase2:TC-999"])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            select_rbb_resilience_profiles(profiles, ["phase2:TC-15", "phase2:TC-15"])


if __name__ == "__main__":
    unittest.main()
