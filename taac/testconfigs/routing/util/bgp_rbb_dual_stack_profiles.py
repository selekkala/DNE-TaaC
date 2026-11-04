# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Declarative Phase-1 IPv4 and dual-stack RBB traffic profiles.

The existing traffic-foundation suite intentionally remains IPv6-only.  This
module adds an opt-in dual-stack suite, so adopters that do not configure an
IPv4 IXIA edge keep exactly the behavior they had before this follow-up.
"""

from __future__ import annotations

import ipaddress
import os
import re
import types
import typing as t
from dataclasses import dataclass

from taac.ixia.ixnetwork_restpy_constants import ALLOWED_IPV4_ADVERTISEMENTS
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_limits import (
    MAX_RBB_ADVERTISED_PREFIX_COUNT,
)
from taac.testconfigs.routing.util.bgp_rbb_state_profiles import (
    RbbRouteExpectation,
)
from taac.testconfigs.routing.util.bgp_rbb_traffic_profiles import (
    build_rbb_advertised_pools,
)

_ROLES = frozenset(("r1", "r2"))

TRAFFIC_ITEM_R1_TO_R2_IPV4 = "RBB_R1_TO_R2_IPV4"
TRAFFIC_ITEM_R2_TO_R1_IPV4 = "RBB_R2_TO_R1_IPV4"
TRAFFIC_ITEM_R1_TO_R2_IPV6 = "RBB_R1_TO_R2_IPV6"
TRAFFIC_ITEM_R2_TO_R1_IPV6 = "RBB_R2_TO_R1_IPV6"
ALL_DUAL_STACK_TRAFFIC_ITEMS: tuple[str, ...] = (
    TRAFFIC_ITEM_R1_TO_R2_IPV4,
    TRAFFIC_ITEM_R2_TO_R1_IPV4,
    TRAFFIC_ITEM_R1_TO_R2_IPV6,
    TRAFFIC_ITEM_R2_TO_R1_IPV6,
)


def _positive_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < 1:
        raise ValueError(f"{name} must be positive")
    return value


@dataclass(frozen=True)
class RbbIpPool:
    """One contiguous IXIA-advertised IPv4 or IPv6 prefix range."""

    role: str
    name: str
    starting_prefix: str
    prefix_length: int
    prefix_count: int
    family: int

    def __post_init__(self) -> None:
        role = self.role.lower().strip()
        if role not in _ROLES:
            raise ValueError("RBB pool role must be r1 or r2")
        if self.family not in (4, 6):
            raise ValueError("RBB pool family must be 4 or 6")
        if not self.name.strip():
            raise ValueError("RBB pool requires a name")
        maximum_length = 32 if self.family == 4 else 128
        if not 1 <= self.prefix_length <= maximum_length:
            raise ValueError(
                f"IPv{self.family} prefix_length must be in 1..{maximum_length}"
            )
        try:
            network = ipaddress.ip_network(
                f"{self.starting_prefix}/{self.prefix_length}", strict=True
            )
        except ValueError as exc:
            raise ValueError(
                f"invalid IPv{self.family} pool {self.starting_prefix!r}/"
                f"{self.prefix_length}"
            ) from exc
        if network.version != self.family:
            raise ValueError(f"RBB pool must use IPv{self.family}")
        if not 1 <= self.prefix_count <= MAX_RBB_ADVERTISED_PREFIX_COUNT:
            raise ValueError(
                "RBB pool prefix_count must be positive and not exceed "
                f"{MAX_RBB_ADVERTISED_PREFIX_COUNT}"
            )
        last = int(network.network_address) + (
            (self.prefix_count - 1) * network.num_addresses
        )
        if last > (1 << maximum_length) - 1:
            raise ValueError(f"RBB IPv{self.family} pool exceeds address space")
        object.__setattr__(self, "role", role)
        object.__setattr__(self, "starting_prefix", str(network.network_address))

    @property
    def first_prefix(self) -> str:
        return f"{self.starting_prefix}/{self.prefix_length}"

    @property
    def prefixes(self) -> tuple[str, ...]:
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
    def prefix_step(self) -> str:
        width = 32 if self.family == 4 else 128
        return str(ipaddress.ip_address(1 << (width - self.prefix_length)))

    @property
    def last_address(
        self,
    ) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        first = ipaddress.ip_network(self.first_prefix, strict=True)
        return ipaddress.ip_address(
            int(first.network_address) + self.prefix_count * first.num_addresses - 1
        )


@dataclass(frozen=True)
class RbbDualStackSettings:
    pools: tuple[RbbIpPool, ...]
    edge_peer: t.Mapping[tuple[str, int], str]
    edge_gateway: t.Mapping[tuple[str, int], str]
    edge_prefix_length: t.Mapping[int, int]

    def __post_init__(self) -> None:
        expected = {(role, family) for role in _ROLES for family in (4, 6)}
        pool_keys = {(pool.role, pool.family) for pool in self.pools}
        if pool_keys != expected or len(self.pools) != len(expected):
            raise ValueError("dual-stack settings require one v4 and v6 pool per role")
        if set(self.edge_peer) != expected or set(self.edge_gateway) != expected:
            raise ValueError("dual-stack settings require every edge peer and gateway")
        if set(self.edge_prefix_length) != {4, 6}:
            raise ValueError("dual-stack settings require v4 and v6 edge masks")
        ranges: dict[int, list[tuple[int, int, str]]] = {4: [], 6: []}
        for pool in self.pools:
            network = ipaddress.ip_network(pool.first_prefix)
            ranges[pool.family].append(
                (int(network.network_address), int(pool.last_address), pool.name)
            )
        for family, family_ranges in ranges.items():
            for index, (start, end, name) in enumerate(family_ranges):
                for other_start, other_end, other_name in family_ranges[index + 1 :]:
                    if start <= other_end and other_start <= end:
                        raise ValueError(
                            f"IPv{family} pools {name!r} and {other_name!r} overlap"
                        )
        edge_networks: dict[
            int, list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]]
        ] = {
            4: [],
            6: [],
        }
        for key in expected:
            peer = ipaddress.ip_address(self.edge_peer[key])
            gateway = ipaddress.ip_address(self.edge_gateway[key])
            family = key[1]
            if peer.version != family or gateway.version != family:
                raise ValueError(f"{key[0]} edge addresses must use IPv{family}")
            mask = self.edge_prefix_length[family]
            peer_if = ipaddress.ip_interface(f"{peer}/{mask}")
            gateway_if = ipaddress.ip_interface(f"{gateway}/{mask}")
            if peer_if.network != gateway_if.network or peer == gateway:
                raise ValueError(
                    f"{key[0]} IPv{family} peer and gateway must be distinct "
                    "addresses in one subnet"
                )
            edge_networks[family].append((key[0], peer_if.network))
        for family, family_ranges in ranges.items():
            for start, end, name in family_ranges:
                for role, edge_network in edge_networks[family]:
                    if (
                        start <= int(edge_network.broadcast_address)
                        and int(edge_network.network_address) <= end
                    ):
                        raise ValueError(
                            f"IPv{family} pool {name!r} overlaps the {role} "
                            "IXIA edge subnet"
                        )

    def pool(self, role: str, family: int) -> RbbIpPool:
        return next(
            pool
            for pool in self.pools
            if pool.role == role.lower() and pool.family == family
        )


@dataclass(frozen=True)
class RbbDualStackDirection:
    name: str
    source_role: str
    destination_role: str
    family: int

    def __post_init__(self) -> None:
        source = self.source_role.lower().strip()
        destination = self.destination_role.lower().strip()
        if source not in _ROLES or destination not in _ROLES or source == destination:
            raise ValueError("dual-stack direction requires two different RBB roles")
        if self.family not in (4, 6):
            raise ValueError("traffic family must be 4 or 6")
        if not self.name.strip():
            raise ValueError("traffic direction requires a name")
        object.__setattr__(self, "source_role", source)
        object.__setattr__(self, "destination_role", destination)


V4_FORWARD = RbbDualStackDirection(TRAFFIC_ITEM_R1_TO_R2_IPV4, "r1", "r2", 4)
V4_REVERSE = RbbDualStackDirection(TRAFFIC_ITEM_R2_TO_R1_IPV4, "r2", "r1", 4)
V6_FORWARD = RbbDualStackDirection(TRAFFIC_ITEM_R1_TO_R2_IPV6, "r1", "r2", 6)
V6_REVERSE = RbbDualStackDirection(TRAFFIC_ITEM_R2_TO_R1_IPV6, "r2", "r1", 6)


@dataclass(frozen=True)
class RbbDualStackProfile:
    testplan_id: str
    playbook_name: str
    title: str
    routes: tuple[RbbRouteExpectation, ...]
    directions: tuple[RbbDualStackDirection, ...]
    coverage: str = "FULL"
    limitation: str | None = None

    def __post_init__(self) -> None:
        if not re.fullmatch(r"phase1:TC-[0-9]+", self.testplan_id):
            raise ValueError(f"invalid Phase-1 testplan ID {self.testplan_id!r}")
        if not self.playbook_name.strip() or not self.title.strip():
            raise ValueError("dual-stack profile requires a name and title")
        if not self.routes or not self.directions:
            raise ValueError("dual-stack profiles require routes and traffic")
        if len({direction.name for direction in self.directions}) != len(
            self.directions
        ):
            raise ValueError("dual-stack profile repeats a traffic direction")
        coverage = self.coverage.upper().strip()
        if coverage not in ("FULL", "PARTIAL"):
            raise ValueError("coverage must be FULL or PARTIAL")
        if coverage == "PARTIAL" and not self.limitation:
            raise ValueError("partial coverage requires a limitation")
        object.__setattr__(self, "coverage", coverage)


TESTPLAN_ID_TO_PLAYBOOK: t.Mapping[str, str] = types.MappingProxyType(
    {
        "phase1:TC-11": "rbb_p1_tc11_forward_ipv4_traffic",
        "phase1:TC-12": "rbb_p1_tc12_reverse_ipv4_traffic",
        "phase1:TC-15": "rbb_p1_tc15_concurrent_dual_stack_traffic",
    }
)


def build_rbb_dual_stack_settings() -> RbbDualStackSettings:
    """Read and validate the opt-in dual-stack IXIA contract."""
    v6_pools = build_rbb_advertised_pools()
    pools = tuple(
        RbbIpPool(
            pool.role,
            pool.name,
            pool.starting_prefix,
            pool.prefix_length,
            pool.prefix_count,
            6,
        )
        for pool in v6_pools
    ) + (
        RbbIpPool(
            "r1",
            "RBB_HEAD_REMOTE_V4",
            os.environ.get("TAAC_RBB_IXIA_HEAD_PREFIX_V4", "10.100.75.128"),
            _positive_int("TAAC_RBB_IXIA_HEAD_PREFIX_LEN_V4", 32),
            _positive_int("TAAC_RBB_IXIA_HEAD_PREFIX_COUNT_V4", 1),
            4,
        ),
        RbbIpPool(
            "r2",
            "RBB_TAIL_REMOTE_V4",
            os.environ.get("TAAC_RBB_IXIA_TAIL_PREFIX_V4", "10.100.75.192"),
            _positive_int("TAAC_RBB_IXIA_TAIL_PREFIX_LEN_V4", 32),
            _positive_int("TAAC_RBB_IXIA_TAIL_PREFIX_COUNT_V4", 1),
            4,
        ),
    )
    mask4 = _positive_int("TAAC_RBB_IXIA_EDGE_PREFIX_MASK_V4", 30)
    if mask4 > 32:
        raise ValueError("TAAC_RBB_IXIA_EDGE_PREFIX_MASK_V4 must be in 1..32")
    settings = RbbDualStackSettings(
        pools=pools,
        edge_peer=types.MappingProxyType(
            {
                ("r1", 4): os.environ.get("TAAC_RBB_IXIA_R1_EDGE_V4", "10.100.75.2"),
                ("r2", 4): os.environ.get("TAAC_RBB_IXIA_R2_EDGE_V4", "10.100.75.6"),
                ("r1", 6): C.IXIA_R1_EDGE_V6,
                ("r2", 6): C.IXIA_R2_EDGE_V6,
            }
        ),
        edge_gateway=types.MappingProxyType(
            {
                ("r1", 4): os.environ.get("TAAC_RBB_IXIA_R1_EDGE_GW_V4", "10.100.75.1"),
                ("r2", 4): os.environ.get("TAAC_RBB_IXIA_R2_EDGE_GW_V4", "10.100.75.5"),
                ("r1", 6): C.IXIA_R1_EDGE_GW_V6,
                ("r2", 6): C.IXIA_R2_EDGE_GW_V6,
            }
        ),
        edge_prefix_length=types.MappingProxyType(
            {4: mask4, 6: C.IXIA_EDGE_PREFIX_MASK}
        ),
    )
    if not C.SKIP_ADVERTISED_PREFIXES_CHECK:
        for pool in settings.pools:
            if pool.family != 4:
                continue
            first = ipaddress.IPv4Address(pool.starting_prefix)
            if not any(
                first in allowed and pool.last_address in allowed
                for allowed in ALLOWED_IPV4_ADVERTISEMENTS
            ):
                raise ValueError(
                    f"IPv4 pool {pool.name!r} is outside TAAC's IXIA "
                    "advertisement allowlist; use an allowlisted range or "
                    "explicitly set TAAC_RBB_SKIP_ADVERTISED_PREFIXES_CHECK=1 "
                    "for an owned isolated-lab prefix"
                )
    return settings


def _pool_routes(
    settings: RbbDualStackSettings, origin_role: str, family: int
) -> tuple[RbbRouteExpectation, ...]:
    pool = settings.pool(origin_role, family)
    remote_role = "r2" if origin_role == "r1" else "r1"
    origin = tuple(
        RbbRouteExpectation(
            role=origin_role,
            prefix=prefix,
            client=C.ROUTE_OWNER_BGPD,
            require_fib=True,
            next_hops=(settings.edge_peer[(origin_role, family)],),
            exact_next_hops=True,
            next_hop_count=1,
        )
        for prefix in pool.prefixes
    )
    remote = tuple(
        RbbRouteExpectation(
            role=remote_role,
            prefix=prefix,
            client=C.ROUTE_OWNER_BGPD,
            require_fib=True,
            exact_next_hops=False,
        )
        for prefix in pool.prefixes
    )
    return origin + remote


def build_rbb_dual_stack_profiles(
    settings: RbbDualStackSettings | None = None,
) -> tuple[RbbDualStackProfile, ...]:
    settings = settings or build_rbb_dual_stack_settings()
    forward_v4_routes = _pool_routes(settings, "r2", 4)
    reverse_v4_routes = _pool_routes(settings, "r1", 4)
    all_routes = tuple(
        route
        for family in (4, 6)
        for role in ("r1", "r2")
        for route in _pool_routes(settings, role, family)
    )
    return (
        RbbDualStackProfile(
            testplan_id="phase1:TC-11",
            playbook_name=TESTPLAN_ID_TO_PLAYBOOK["phase1:TC-11"],
            title="Forward IPv4 throughput and loss",
            routes=forward_v4_routes,
            directions=(V4_FORWARD,),
        ),
        RbbDualStackProfile(
            testplan_id="phase1:TC-12",
            playbook_name=TESTPLAN_ID_TO_PLAYBOOK["phase1:TC-12"],
            title="Reverse IPv4 throughput and loss",
            routes=reverse_v4_routes,
            directions=(V4_REVERSE,),
        ),
        RbbDualStackProfile(
            testplan_id="phase1:TC-15",
            playbook_name=TESTPLAN_ID_TO_PLAYBOOK["phase1:TC-15"],
            title="Concurrent bidirectional IPv4 and IPv6 traffic",
            routes=all_routes,
            directions=(V4_FORWARD, V4_REVERSE, V6_FORWARD, V6_REVERSE),
            coverage="PARTIAL",
            limitation=(
                "throughput, convergence, and loss are portable across TAAC IXIA "
                "backends; the source plan's latency target has no backend-neutral "
                "threshold/API yet"
            ),
        ),
    )


def select_rbb_dual_stack_profiles(
    profiles: t.Iterable[RbbDualStackProfile],
    testplan_ids: t.Iterable[str] | None = None,
) -> tuple[RbbDualStackProfile, ...]:
    catalog = tuple(profiles)
    if len({profile.testplan_id for profile in catalog}) != len(catalog):
        raise ValueError("dual-stack profile testplan IDs must be unique")
    if testplan_ids is None:
        return catalog
    requested = tuple(testplan_ids)
    if len(requested) != len(set(requested)):
        raise ValueError("dual-stack profile selection contains duplicates")
    known = {profile.testplan_id for profile in catalog}
    unknown = sorted(set(requested) - known)
    if unknown:
        raise ValueError(f"unknown dual-stack testplan IDs: {unknown}")
    selected = set(requested)
    return tuple(profile for profile in catalog if profile.testplan_id in selected)


__all__ = [
    "ALL_DUAL_STACK_TRAFFIC_ITEMS",
    "RbbDualStackDirection",
    "RbbDualStackProfile",
    "RbbDualStackSettings",
    "RbbIpPool",
    "TESTPLAN_ID_TO_PLAYBOOK",
    "V4_FORWARD",
    "V4_REVERSE",
    "V6_FORWARD",
    "V6_REVERSE",
    "build_rbb_dual_stack_profiles",
    "build_rbb_dual_stack_settings",
    "select_rbb_dual_stack_profiles",
]
