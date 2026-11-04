# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Unit tests for declarative named-NHG lifecycle profiles."""

import ipaddress
import unittest
from dataclasses import replace
from unittest.mock import patch

from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_named_nhg_profiles import (
    NAMED_NHG_SUITE_TESTPLAN_IDS,
    RbbNamedNhgAction,
    RbbNamedNhgCoverage,
    RbbNamedNhgMember,
    build_rbb_named_nhg_profiles,
    select_rbb_named_nhg_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_scenario_profiles import (
    SRV6_3_USIDS_PROFILE,
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


class RbbNamedNhgProfilesTest(unittest.TestCase):
    def test_catalog_is_partial_and_dependency_ordered(self) -> None:
        profiles = build_rbb_named_nhg_profiles(_topology())

        self.assertEqual(
            tuple(profile.testplan_id for profile in profiles),
            NAMED_NHG_SUITE_TESTPLAN_IDS,
        )
        self.assertTrue(
            all(profile.coverage is RbbNamedNhgCoverage.PARTIAL for profile in profiles)
        )
        self.assertTrue(all(profile.unmet_requirements for profile in profiles))
        self.assertEqual(
            tuple(profile.action for profile in profiles),
            (
                RbbNamedNhgAction.PROGRAM_AND_VERIFY,
                RbbNamedNhgAction.FORWARD_REFERENCE,
                RbbNamedNhgAction.RESOLVE_FORWARD_REFERENCE,
            ),
        )
        self.assertFalse(profiles[0].requires_forward_reference_support)
        self.assertTrue(profiles[1].requires_forward_reference_support)
        self.assertTrue(profiles[2].requires_forward_reference_support)

    def test_members_derive_from_declared_core_plan_and_existing_srv6_plan(
        self,
    ) -> None:
        profile = build_rbb_named_nhg_profiles(_topology())[0]
        member = profile.members[0]

        self.assertEqual(
            member.address,
            str(ipaddress.ip_interface(C.core_rif_cidr("r2", 0, 6)).ip),
        )
        self.assertIsNone(member.interface)
        self.assertEqual(member.weight, 1)
        self.assertEqual(member.tunnel_id, C.SRV6_TUNNEL_ID)
        self.assertEqual(
            member.srv6_segments,
            (
                C.pack_usid_container(
                    SRV6_3_USIDS_PROFILE.locator,
                    SRV6_3_USIDS_PROFILE.encap_usids,
                ),
            ),
        )
        self.assertEqual(
            member.to_params(),
            {
                "address": member.address,
                "weight": 1,
                "srv6_segments": list(member.srv6_segments),
                "tunnel_id": C.SRV6_TUNNEL_ID,
            },
        )

    def test_forward_reference_cases_share_name_and_route_but_tc02_is_isolated(
        self,
    ) -> None:
        tc02, tc06, tc07 = build_rbb_named_nhg_profiles(_topology())

        self.assertNotEqual(tc02.group_name, tc06.group_name)
        self.assertEqual(tc06.group_name, tc07.group_name)
        self.assertEqual(
            {profile.route_prefix for profile in (tc02, tc06, tc07)},
            {C.NAMED_NHG_TEST_PREFIX},
        )
        self.assertNotEqual(tc02.route_prefix, C.TAIL_DEST_PREFIX)
        self.assertTrue(
            all(len(profile.group_name) <= 31 for profile in (tc02, tc06, tc07))
        )

    def test_selector_reorders_to_catalog_and_rejects_bad_requests(self) -> None:
        profiles = build_rbb_named_nhg_profiles(_topology())

        selected = select_rbb_named_nhg_profiles(
            profiles, ["phase2:TC-07", "phase2:TC-02"]
        )
        self.assertEqual(
            [profile.testplan_id for profile in selected],
            ["phase2:TC-02", "phase2:TC-07"],
        )
        with self.assertRaisesRegex(ValueError, "duplicate"):
            select_rbb_named_nhg_profiles(profiles, ["phase2:TC-02", "phase2:TC-02"])
        with self.assertRaisesRegex(ValueError, "unknown"):
            select_rbb_named_nhg_profiles(profiles, ["phase2:TC-99"])

    def test_profile_validation_rejects_nonportable_or_unsafe_inputs(self) -> None:
        profile = build_rbb_named_nhg_profiles(_topology())[0]
        with self.assertRaisesRegex(ValueError, "1..31"):
            replace(profile, group_name="x" * 32)
        with self.assertRaisesRegex(ValueError, "IPv6"):
            replace(profile, route_prefix="192.0.2.0/24")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            replace(profile, members=(profile.members[0], profile.members[0]))
        with self.assertRaisesRegex(ValueError, "interface"):
            RbbNamedNhgMember(
                address="fe80::1",
                weight=1,
                srv6_segments=("2001:db8::1",),
                tunnel_id="srv6_tunnel",
            )

    def test_builder_rejects_service_prefix_overlap_and_unscoped_link_local(
        self,
    ) -> None:
        with patch.object(
            C, "NAMED_NHG_TEST_PREFIX", SRV6_3_USIDS_PROFILE.tail_prefix
        ), self.assertRaisesRegex(ValueError, "active tail service prefix"):
            build_rbb_named_nhg_profiles(_topology())

        with patch.object(
            C, "core_rif_cidr", return_value="fe80::2/64"
        ), self.assertRaisesRegex(ValueError, "FBOSS RIF name"):
            build_rbb_named_nhg_profiles(_topology())


if __name__ == "__main__":
    unittest.main()
