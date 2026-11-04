# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Unit tests for declarative RBB traffic-foundation profiles."""

import unittest

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
    select_rbb_traffic_foundation_profiles,
)
from taac.testconfigs.routing.util.bgp_rbb_limits import (
    MAX_RBB_ADVERTISED_PREFIX_COUNT,
)


def _pools() -> tuple[RbbAdvertisedPool, ...]:
    return (
        RbbAdvertisedPool("r1", "HEAD", "2001:db8:100::", 64, 2),
        RbbAdvertisedPool("r2", "TAIL", "2001:db8:200::", 64, 3),
    )


def _topology() -> RbbTopology:
    return RbbTopology(
        r1=NodeTopology(
            "r1",
            "r1.example",
            (
                CorePortChannel("port-channel1", ("eth1/1",)),
                CorePortChannel("port-channel2", ("eth1/2",)),
            ),
            (IxiaEdge("eth1/5", "1/1"),),
        ),
        r2=NodeTopology(
            "r2",
            "r2.example",
            (
                CorePortChannel("port-channel1", ("eth1/1",)),
                CorePortChannel("port-channel2", ("eth1/2",)),
            ),
            (IxiaEdge("eth1/5", "1/2"),),
        ),
        ixia_chassis="ixia.example",
    )


class RbbTrafficProfilesTest(unittest.TestCase):
    def test_catalog_is_in_dependency_order(self) -> None:
        profiles = build_rbb_traffic_foundation_profiles(_topology(), _pools())
        self.assertEqual(
            [profile.testplan_id for profile in profiles],
            [
                "phase1:TC-05",
                "phase1:TC-06",
                "phase1:TC-07",
                "phase1:TC-13",
                "phase1:TC-14",
                "phase1:TC-17",
            ],
        )
        self.assertEqual(len({profile.playbook_name for profile in profiles}), 6)

    def test_tc05_is_head_pool_on_origin_and_remote_duts(self) -> None:
        profile = build_rbb_traffic_foundation_profiles(_topology(), _pools())[0]

        self.assertIn("Head-edge", profile.title)
        self.assertEqual(
            [route.role for route in profile.routes], ["r1", "r1", "r2", "r2"]
        )
        self.assertEqual(
            [route.prefix for route in profile.routes],
            [
                "2001:db8:100::/64",
                "2001:db8:100:1::/64",
                "2001:db8:100::/64",
                "2001:db8:100:1::/64",
            ],
        )
        self.assertTrue(
            all(route.next_hops == (C.IXIA_R1_EDGE_V6,) for route in profile.routes[:2])
        )

    def test_tc06_is_tail_pool_on_origin_and_remote_duts(self) -> None:
        profile = build_rbb_traffic_foundation_profiles(_topology(), _pools())[1]

        self.assertIn("Tail-edge", profile.title)
        self.assertEqual(
            [route.role for route in profile.routes], ["r2"] * 3 + ["r1"] * 3
        )
        self.assertEqual(
            [route.prefix for route in profile.routes],
            [
                "2001:db8:200::/64",
                "2001:db8:200:1::/64",
                "2001:db8:200:2::/64",
                "2001:db8:200::/64",
                "2001:db8:200:1::/64",
                "2001:db8:200:2::/64",
            ],
        )
        self.assertTrue(
            all(route.next_hops == (C.IXIA_R2_EDGE_V6,) for route in profile.routes[:3])
        )

    def test_tc07_audits_every_prefix_from_both_pools(self) -> None:
        profile = build_rbb_traffic_foundation_profiles(_topology(), _pools())[2]

        self.assertEqual(len(profile.routes), 10)
        self.assertTrue(all(route.client == "BGPD" for route in profile.routes))
        self.assertTrue(all(route.require_fib for route in profile.routes))
        origin = [route for route in profile.routes if route.next_hops]
        remote = [route for route in profile.routes if not route.next_hops]
        self.assertEqual(len(origin), 5)
        self.assertEqual(len(remote), 5)
        self.assertTrue(all(route.next_hop_count == 1 for route in origin))
        # TC-07 validates prefix, BGPD ownership, and FIB installation.  It
        # must not infer recursive ECMP width from the number of declared core
        # links because routing policy can legitimately prefer one path.
        self.assertTrue(all(route.next_hop_count is None for route in remote))
        self.assertTrue(
            all(route.next_hop_interface_count is None for route in remote)
        )
        self.assertTrue(all(route.next_hop_scope is None for route in remote))
        self.assertEqual(
            {route.prefix for route in profile.routes},
            set(_pools()[0].prefixes + _pools()[1].prefixes),
        )

    def test_forward_reverse_and_correlation_cases_are_explicit(self) -> None:
        profiles = build_rbb_traffic_foundation_profiles(_topology(), _pools())
        tc13, tc14, tc17 = profiles[3:]

        self.assertEqual(
            [(item.source_role, item.destination_role) for item in tc13.directions],
            [("r1", "r2")],
        )
        self.assertEqual(
            [(item.source_role, item.destination_role) for item in tc14.directions],
            [("r2", "r1")],
        )
        self.assertEqual(len(tc17.directions), 2)
        self.assertTrue(tc17.correlate_counters)

    def test_selection_retains_catalog_order_and_rejects_unknown(self) -> None:
        profiles = build_rbb_traffic_foundation_profiles(_topology(), _pools())
        selected = select_rbb_traffic_foundation_profiles(
            profiles, ["phase1:TC-17", "phase1:TC-05"]
        )
        self.assertEqual(
            [profile.testplan_id for profile in selected],
            ["phase1:TC-05", "phase1:TC-17"],
        )
        with self.assertRaisesRegex(ValueError, "unknown"):
            select_rbb_traffic_foundation_profiles(profiles, ["phase1:TC-999"])

    def test_pool_requires_network_boundary(self) -> None:
        with self.assertRaises(ValueError):
            RbbAdvertisedPool("r1", "BAD", "2001:db8:100::1", 64, 1)

    def test_pool_rejects_prefix_count_above_shared_limit(self) -> None:
        with self.assertRaisesRegex(ValueError, "must not exceed"):
            RbbAdvertisedPool(
                "r1",
                "TOO_LARGE",
                "2001:db8:100::",
                64,
                MAX_RBB_ADVERTISED_PREFIX_COUNT + 1,
            )


if __name__ == "__main__":
    unittest.main()
