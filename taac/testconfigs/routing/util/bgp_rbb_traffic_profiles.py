# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Declarative profiles for the two-node RBB traffic foundation.

This module maps the original Phase-1 requirements to small, independently
reported playbooks.  It intentionally describes only facts: the two IXIA BGP
route pools, the direction(s) a case exercises, and the exact BGPD RIB/FIB
entries that must exist before traffic starts.  IXIA rendering lives in the
TestConfig factory and orchestration lives in the playbook factory.

All addresses are runtime inputs.  Defaults use RFC 3849 documentation space;
operators bind a lab through ``TAAC_RBB_*`` environment variables and the
normal ``device_info.csv`` / ``circuit_info.csv`` inventory files.
"""

from __future__ import annotations

import ipaddress
import os
import re
import types
import typing as t
from dataclasses import dataclass

from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_limits import (
    MAX_RBB_ADVERTISED_PREFIX_COUNT,
)
from taac.testconfigs.routing.util.bgp_rbb_state_profiles import (
    RbbRouteExpectation,
)
from taac.testconfigs.routing.util.bgp_rbb_topology import RbbTopology

_ROLES = frozenset(("r1", "r2"))

TRAFFIC_ITEM_R1_TO_R2 = "RBB_R1_TO_R2_IPV6"
TRAFFIC_ITEM_R2_TO_R1 = "RBB_R2_TO_R1_IPV6"
ALL_TRAFFIC_ITEMS: tuple[str, ...] = (
    TRAFFIC_ITEM_R1_TO_R2,
    TRAFFIC_ITEM_R2_TO_R1,
)


def _positive_int(env_name: str, default: int) -> int:
    value = int(os.environ.get(env_name, str(default)))
    if value < 1:
        raise ValueError(f"{env_name} must be positive")
    return value


def _bounded_float(
    env_name: str, default: float, *, minimum: float, maximum: float
) -> float:
    value = float(os.environ.get(env_name, str(default)))
    if not minimum <= value <= maximum:
        raise ValueError(f"{env_name} must be between {minimum:g} and {maximum:g}")
    return value


@dataclass(frozen=True)
class RbbAdvertisedPool:
    """One IPv6 prefix pool advertised by an IXIA edge BGP peer."""

    role: str
    name: str
    starting_prefix: str
    prefix_length: int
    prefix_count: int

    def __post_init__(self) -> None:
        role = self.role.lower().strip()
        if role not in _ROLES:
            raise ValueError(f"RBB pool role must be r1 or r2: {self.role!r}")
        object.__setattr__(self, "role", role)
        if not self.name.strip():
            raise ValueError("RBB advertised pool requires a name")
        if not 1 <= self.prefix_length <= 128:
            raise ValueError("RBB advertised pool prefix_length must be in 1..128")
        network = ipaddress.ip_network(
            f"{self.starting_prefix}/{self.prefix_length}", strict=True
        )
        if network.version != 6:
            raise ValueError("RBB advertised pools must be IPv6")
        if self.prefix_count < 1:
            raise ValueError("RBB advertised pool prefix_count must be positive")
        if self.prefix_count > MAX_RBB_ADVERTISED_PREFIX_COUNT:
            raise ValueError(
                "RBB advertised pool prefix_count must not exceed "
                f"{MAX_RBB_ADVERTISED_PREFIX_COUNT}"
            )
        last = int(network.network_address) + (
            (self.prefix_count - 1) * network.num_addresses
        )
        if last > (1 << 128) - 1:
            raise ValueError(f"RBB advertised pool {self.name!r} exceeds IPv6 space")
        object.__setattr__(self, "starting_prefix", str(network.network_address))

    @property
    def first_prefix(self) -> str:
        return f"{self.starting_prefix}/{self.prefix_length}"

    @property
    def prefixes(self) -> tuple[str, ...]:
        """Every exact prefix represented by the IXIA route range."""
        first = ipaddress.ip_network(self.first_prefix, strict=True)
        return tuple(
            str(
                ipaddress.ip_network(
                    (
                        int(first.network_address) + index * first.num_addresses,
                        first.prefixlen,
                    )
                )
            )
            for index in range(self.prefix_count)
        )

    @property
    def last_address(self) -> ipaddress.IPv6Address:
        first = ipaddress.ip_network(self.first_prefix, strict=True)
        return ipaddress.IPv6Address(
            int(first.network_address) + self.prefix_count * first.num_addresses - 1
        )

    @property
    def prefix_step(self) -> str:
        """IXIA increment that advances by exactly one advertised prefix."""
        return str(ipaddress.IPv6Address(1 << (128 - self.prefix_length)))


@dataclass(frozen=True)
class RbbTrafficDirection:
    """One independently named, unidirectional IPv6 traffic item."""

    name: str
    source_role: str
    destination_role: str

    def __post_init__(self) -> None:
        source = self.source_role.lower().strip()
        destination = self.destination_role.lower().strip()
        if source not in _ROLES or destination not in _ROLES:
            raise ValueError("RBB traffic roles must be r1 or r2")
        if source == destination:
            raise ValueError("RBB traffic source and destination must differ")
        if not self.name.strip():
            raise ValueError("RBB traffic direction requires a name")
        object.__setattr__(self, "source_role", source)
        object.__setattr__(self, "destination_role", destination)


FORWARD = RbbTrafficDirection(TRAFFIC_ITEM_R1_TO_R2, "r1", "r2")
REVERSE = RbbTrafficDirection(TRAFFIC_ITEM_R2_TO_R1, "r2", "r1")


@dataclass(frozen=True)
class RbbIxiaLearnedRouteExpectation:
    """Exact pool expected in one IXIA edge peer's received-route view."""

    role: str
    prefixes: tuple[str, ...]

    def __post_init__(self) -> None:
        role = self.role.lower().strip()
        if role not in _ROLES:
            raise ValueError("IXIA learned-route role must be r1 or r2")
        normalized = tuple(
            str(ipaddress.ip_network(prefix, strict=True)) for prefix in self.prefixes
        )
        if not normalized or any(
            ipaddress.ip_network(prefix).version != 6 for prefix in normalized
        ):
            raise ValueError("IXIA learned-route expectations require IPv6 prefixes")
        object.__setattr__(self, "role", role)
        object.__setattr__(self, "prefixes", normalized)


@dataclass(frozen=True)
class RbbTrafficFoundationProfile:
    """One fully automated Phase-1 requirement."""

    testplan_id: str
    playbook_name: str
    title: str
    routes: tuple[RbbRouteExpectation, ...] = ()
    ixia_received_routes: tuple[RbbIxiaLearnedRouteExpectation, ...] = ()
    directions: tuple[RbbTrafficDirection, ...] = ()
    correlate_counters: bool = False

    def __post_init__(self) -> None:
        if not re.fullmatch(r"phase1:TC-[0-9]+", self.testplan_id):
            raise ValueError(f"invalid Phase-1 testplan ID {self.testplan_id!r}")
        if not self.playbook_name.strip() or not self.title.strip():
            raise ValueError("RBB traffic profile requires a playbook name and title")
        if not self.routes and not self.ixia_received_routes and not self.directions:
            raise ValueError(
                f"{self.testplan_id} has no route, IXIA, or traffic assertion"
            )
        direction_names = [direction.name for direction in self.directions]
        if len(direction_names) != len(set(direction_names)):
            raise ValueError(f"{self.testplan_id} repeats a traffic direction")
        if self.correlate_counters and not self.directions:
            raise ValueError("counter correlation requires at least one direction")


TESTPLAN_ID_TO_PLAYBOOK: t.Mapping[str, str] = types.MappingProxyType(
    {
        "phase1:TC-05": "rbb_p1_tc05_head_prefix_propagation",
        "phase1:TC-06": "rbb_p1_tc06_tail_prefix_propagation",
        "phase1:TC-07": "rbb_p1_tc07_exact_bidirectional_rib_fib",
        "phase1:TC-13": "rbb_p1_tc13_forward_ipv6_traffic",
        "phase1:TC-14": "rbb_p1_tc14_reverse_ipv6_traffic",
        "phase1:TC-17": "rbb_p1_tc17_ixia_dut_counter_correlation",
    }
)


def build_rbb_advertised_pools() -> tuple[RbbAdvertisedPool, ...]:
    """Build and validate the two runtime-configured IXIA route pools."""
    pools = (
        RbbAdvertisedPool(
            role="r1",
            name="RBB_HEAD_REMOTE_V6",
            starting_prefix=os.environ.get(
                "TAAC_RBB_IXIA_HEAD_PREFIX", "2001:db8:feed::"
            ),
            prefix_length=_positive_int("TAAC_RBB_IXIA_HEAD_PREFIX_LEN", 64),
            prefix_count=_positive_int("TAAC_RBB_IXIA_HEAD_PREFIX_COUNT", 1),
        ),
        RbbAdvertisedPool(
            role="r2",
            name=C.IXIA_TAIL_PREFIX_POOL_NAME,
            starting_prefix=C.IXIA_TAIL_ADVERTISED_PREFIX,
            prefix_length=C.IXIA_TAIL_ADVERTISED_PREFIX_LEN,
            prefix_count=C.IXIA_TAIL_ADVERTISED_PREFIX_COUNT,
        ),
    )
    if pools[0].name == pools[1].name:
        raise ValueError("RBB head and tail advertised pool names must differ")
    ranges = tuple(
        (
            ipaddress.ip_network(pool.first_prefix).network_address,
            pool.last_address,
        )
        for pool in pools
    )
    if ranges[0][0] <= ranges[1][1] and ranges[1][0] <= ranges[0][1]:
        raise ValueError("RBB head and tail advertised pools must not overlap")
    return pools


def _remote_routes(
    role: str,
    pool: RbbAdvertisedPool,
    *,
    resolved_path_count: int | None = None,
) -> tuple[RbbRouteExpectation, ...]:
    if role == pool.role:
        raise ValueError("remote route expectation must target the opposite DUT")
    return tuple(
        RbbRouteExpectation(
            role=role,
            prefix=prefix,
            client=C.ROUTE_OWNER_BGPD,
            require_fib=True,
            # The exact recursive address is a runtime BGP policy choice.  This
            # assertion is still exact for prefix, RIB client, and preferred FIB
            # owner; no unrelated route can satisfy it.
            exact_next_hops=False,
            next_hop_count=resolved_path_count,
            next_hop_interface_count=resolved_path_count,
            next_hop_scope=("link_local" if resolved_path_count is not None else None),
        )
        for prefix in pool.prefixes
    )


def _origin_routes(
    role: str,
    pool: RbbAdvertisedPool,
    next_hop: str,
) -> tuple[RbbRouteExpectation, ...]:
    """Build exact RIB/FIB expectations on the DUT adjacent to IXIA."""
    if role != pool.role:
        raise ValueError("origin route expectation must target the adjacent DUT")
    return tuple(
        RbbRouteExpectation(
            role=role,
            prefix=prefix,
            client=C.ROUTE_OWNER_BGPD,
            require_fib=True,
            next_hops=(next_hop,),
            exact_next_hops=True,
            next_hop_count=1,
        )
        for prefix in pool.prefixes
    )


def build_rbb_traffic_foundation_profiles(
    topology: RbbTopology,
    pools: tuple[RbbAdvertisedPool, ...] | None = None,
) -> tuple[RbbTrafficFoundationProfile, ...]:
    """Return cases in dependency order: routing before data-plane evidence."""
    pools = pools or build_rbb_advertised_pools()
    by_role = {pool.role: pool for pool in pools}
    if set(by_role) != _ROLES:
        raise ValueError("RBB traffic foundation requires one pool on each role")
    head_origin_on_r1 = _origin_routes("r1", by_role["r1"], C.IXIA_R1_EDGE_V6)
    tail_origin_on_r2 = _origin_routes("r2", by_role["r2"], C.IXIA_R2_EDGE_V6)
    tail_on_r1 = _remote_routes("r1", by_role["r2"])
    head_on_r2 = _remote_routes("r2", by_role["r1"])
    head_received_on_r2 = RbbIxiaLearnedRouteExpectation("r2", by_role["r1"].prefixes)
    tail_received_on_r1 = RbbIxiaLearnedRouteExpectation("r1", by_role["r2"].prefixes)
    return (
        RbbTrafficFoundationProfile(
            testplan_id="phase1:TC-05",
            playbook_name=TESTPLAN_ID_TO_PLAYBOOK["phase1:TC-05"],
            title="Head-edge prefix installation on R1 and propagation to R2",
            routes=head_origin_on_r1 + head_on_r2,
            ixia_received_routes=(head_received_on_r2,),
        ),
        RbbTrafficFoundationProfile(
            testplan_id="phase1:TC-06",
            playbook_name=TESTPLAN_ID_TO_PLAYBOOK["phase1:TC-06"],
            title="Tail-edge prefix installation on R2 and propagation to R1",
            routes=tail_origin_on_r2 + tail_on_r1,
            ixia_received_routes=(tail_received_on_r1,),
        ),
        RbbTrafficFoundationProfile(
            testplan_id="phase1:TC-07",
            playbook_name=TESTPLAN_ID_TO_PLAYBOOK["phase1:TC-07"],
            title="Exact bidirectional BGPD RIB and preferred FIB ownership",
            # TC-07 covers every member of both advertised route ranges, not
            # merely the first prefix in each pool. Each pool is checked on
            # both its origin DUT and the remote DUT.
            routes=(
                head_origin_on_r1
                + tail_on_r1
                + tail_origin_on_r2
                + head_on_r2
            ),
            ixia_received_routes=(head_received_on_r2, tail_received_on_r1),
        ),
        RbbTrafficFoundationProfile(
            testplan_id="phase1:TC-13",
            playbook_name=TESTPLAN_ID_TO_PLAYBOOK["phase1:TC-13"],
            title="Forward IPv6 throughput and loss",
            routes=tail_on_r1,
            directions=(FORWARD,),
        ),
        RbbTrafficFoundationProfile(
            testplan_id="phase1:TC-14",
            playbook_name=TESTPLAN_ID_TO_PLAYBOOK["phase1:TC-14"],
            title="Reverse IPv6 throughput and loss",
            routes=head_on_r2,
            directions=(REVERSE,),
        ),
        RbbTrafficFoundationProfile(
            testplan_id="phase1:TC-17",
            playbook_name=TESTPLAN_ID_TO_PLAYBOOK["phase1:TC-17"],
            title="IXIA frame and DUT edge-counter correlation",
            routes=tail_on_r1 + head_on_r2,
            directions=(FORWARD, REVERSE),
            correlate_counters=True,
        ),
    )


def select_rbb_traffic_foundation_profiles(
    profiles: t.Iterable[RbbTrafficFoundationProfile],
    testplan_ids: t.Iterable[str] | None = None,
) -> tuple[RbbTrafficFoundationProfile, ...]:
    """Select known cases while retaining their dependency-safe catalog order."""
    catalog = tuple(profiles)
    if len({profile.testplan_id for profile in catalog}) != len(catalog):
        raise ValueError("RBB traffic foundation testplan IDs must be unique")
    if testplan_ids is None:
        return catalog
    requested = tuple(testplan_ids)
    if len(requested) != len(set(requested)):
        raise ValueError("RBB traffic testplan selection contains duplicates")
    known = {profile.testplan_id for profile in catalog}
    unknown = sorted(set(requested) - known)
    if unknown:
        raise ValueError(f"unknown RBB traffic testplan IDs: {unknown}")
    selected = set(requested)
    return tuple(profile for profile in catalog if profile.testplan_id in selected)


TRAFFIC_SAMPLE_SECONDS = _positive_int("TAAC_RBB_TRAFFIC_SAMPLE_SECONDS", 10)
TRAFFIC_DRAIN_SECONDS = _positive_int("TAAC_RBB_TRAFFIC_DRAIN_SECONDS", 5)
COUNTER_TOLERANCE_PERCENT = _bounded_float(
    "TAAC_RBB_COUNTER_TOLERANCE_PCT", 5.0, minimum=0.0, maximum=100.0
)
COUNTER_ABSOLUTE_TOLERANCE = _positive_int("TAAC_RBB_COUNTER_ABSOLUTE_TOLERANCE", 256)
EDGE_BANDWIDTH_GBPS = _positive_int("TAAC_RBB_EDGE_BANDWIDTH_GBPS", 400)
TRAFFIC_RATE_TOLERANCE_PERCENT = _positive_int("TAAC_RBB_TRAFFIC_RATE_TOLERANCE_PCT", 5)
if TRAFFIC_RATE_TOLERANCE_PERCENT > 100:
    raise ValueError("TAAC_RBB_TRAFFIC_RATE_TOLERANCE_PCT must not exceed 100")


__all__ = [
    "ALL_TRAFFIC_ITEMS",
    "COUNTER_ABSOLUTE_TOLERANCE",
    "COUNTER_TOLERANCE_PERCENT",
    "EDGE_BANDWIDTH_GBPS",
    "FORWARD",
    "REVERSE",
    "TESTPLAN_ID_TO_PLAYBOOK",
    "TRAFFIC_DRAIN_SECONDS",
    "TRAFFIC_ITEM_R1_TO_R2",
    "TRAFFIC_ITEM_R2_TO_R1",
    "TRAFFIC_RATE_TOLERANCE_PERCENT",
    "TRAFFIC_SAMPLE_SECONDS",
    "RbbAdvertisedPool",
    "RbbIxiaLearnedRouteExpectation",
    "RbbTrafficDirection",
    "RbbTrafficFoundationProfile",
    "build_rbb_advertised_pools",
    "build_rbb_traffic_foundation_profiles",
    "select_rbb_traffic_foundation_profiles",
]
