# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Focused OSS tests for the structured named SRv6 NHG task."""

import asyncio
import ipaddress
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from taac.constants import TestCaseFailure
from taac.tasks.rbb_srv6_named_nhg_task import RbbSrv6NamedNhgTask
from taac.tasks.registry import TASK_NAME_TO_CLASS

_DRIVER_PATH = "taac.tasks.rbb_srv6_named_nhg_task.async_get_device_driver"
_HOST = "rbb-r1"
_GROUP = "taac-rbb-p2-test"
_PREFIX = "2001:db8:100::/64"
_MEMBERS = [
    {
        "address": "2001:db8:12::2",
        "weight": 1,
        "srv6_segments": ["fdad:ffff:27d6:7fff::"],
        "tunnel_id": "srv6_tunnel",
    }
]


def _params(action, *, include_members=False, **overrides):
    params = {
        "hostname": _HOST,
        "action": action,
        "group_name": _GROUP,
        "route_prefix": _PREFIX,
        "client": "TE_AGENT",
    }
    if include_members:
        params["members"] = list(_MEMBERS)
    params.update(overrides)
    return params


def _driver(agent):
    driver = MagicMock()
    driver.async_agent_client = MagicMock()
    driver.async_agent_client.__aenter__ = AsyncMock(return_value=agent)
    driver.async_agent_client.__aexit__ = AsyncMock(return_value=False)
    return driver


def _dest(prefix=_PREFIX):
    network = ipaddress.ip_network(prefix)
    return SimpleNamespace(
        ip=SimpleNamespace(addr=network.network_address.packed),
        prefixLength=network.prefixlen,
    )


def _route(group_name=_GROUP):
    return SimpleNamespace(
        dest=_dest(),
        namedRouteDestination=SimpleNamespace(nextHopGroup=group_name),
        # FBOSS resolves named-group members in this readback and deliberately
        # omits adminDistance; RouteDetails.nextHopMulti is authoritative for
        # the original per-client attributes.
        nextHops=[SimpleNamespace(address="resolved-named-member")],
        nextHopAddrs=[],
        adminDistance=None,
    )


def _te_client_id():
    from neteng.fboss.ctrl.types import ClientID

    return int(getattr(ClientID.TE_AGENT, "value", ClientID.TE_AGENT))


def _route_detail(
    *,
    route=None,
    client_id=None,
    group_name=_GROUP,
    admin_distance=2,
    preferred=True,
    next_hops=None,
    client_next_hops=None,
):
    route = route or _route(group_name)
    return SimpleNamespace(
        dest=route.dest,
        namedRouteDestination=SimpleNamespace(nextHopGroup=group_name),
        nextHopMulti=[
            SimpleNamespace(
                clientId=_te_client_id() if client_id is None else client_id,
                namedRouteDestination=SimpleNamespace(nextHopGroup=group_name),
                adminDistance=admin_distance,
                isPreferred=preferred,
                nextHops=[] if client_next_hops is None else client_next_hops,
                nextHopAddrs=[],
            )
        ],
        nextHops=[] if next_hops is None else next_hops,
        adminDistance=admin_distance if preferred else None,
    )


def _group(*, programmed=False, tunnel_id="srv6_tunnel"):
    from neteng.fboss.common.types import TunnelType

    return SimpleNamespace(
        name=_GROUP,
        isProgrammed=programmed,
        nexthops=[
            SimpleNamespace(
                address=SimpleNamespace(
                    addr=ipaddress.ip_address("2001:db8:12::2").packed,
                    ifName=None,
                ),
                weight=1,
                srv6SegmentList=[
                    SimpleNamespace(
                        addr=ipaddress.ip_address("fdad:ffff:27d6:7fff::").packed
                    )
                ],
                tunnelType=TunnelType.SRV6_ENCAP,
                tunnelId=tunnel_id,
            )
        ],
    )


class RbbSrv6NamedNhgTaskTest(unittest.IsolatedAsyncioTestCase):
    def test_registered_in_oss_task_registry(self) -> None:
        self.assertIs(TASK_NAME_TO_CLASS["rbb_srv6_named_nhg"], RbbSrv6NamedNhgTask)

    def test_client_readback_uses_route_details_for_admin_distance(self) -> None:
        route = _route()
        RbbSrv6NamedNhgTask._assert_named_route(
            _HOST,
            route,
            ipaddress.ip_network(_PREFIX),
            _GROUP,
            "TE_AGENT",
        )
        with self.assertRaisesRegex(TestCaseFailure, "admin distance"):
            RbbSrv6NamedNhgTask._assert_client_candidate(
                _HOST,
                [_route_detail(admin_distance=10)],
                ipaddress.ip_network(_PREFIX),
                _GROUP,
                "TE_AGENT",
                _te_client_id(),
                2,
            )

    def test_rib_only_rejects_resolved_per_client_next_hops(self) -> None:
        with self.assertRaisesRegex(TestCaseFailure, "resolved next hops"):
            RbbSrv6NamedNhgTask._assert_rib_only(
                _HOST,
                [_route_detail(client_next_hops=[SimpleNamespace()])],
                ipaddress.ip_network(_PREFIX),
                _GROUP,
                "TE_AGENT",
                _te_client_id(),
                2,
                None,
            )

    def test_rib_only_allows_an_unrelated_resolved_route_for_same_prefix(
        self,
    ) -> None:
        RbbSrv6NamedNhgTask._assert_rib_only(
            _HOST,
            [_route_detail(preferred=True)],
            ipaddress.ip_network(_PREFIX),
            _GROUP,
            "TE_AGENT",
            _te_client_id(),
            2,
            SimpleNamespace(
                dest=_dest(),
                namedRouteDestination=None,
                nextHops=[SimpleNamespace(address="bgpd-resolved")],
            ),
        )

    async def test_validation_finishes_before_device_contact(self) -> None:
        task = RbbSrv6NamedNhgTask(hostname=_HOST, logger=MagicMock())
        invalid = (
            _params("precheck", expected_programmed="false"),
            _params("precheck", unexpected=True),
            _params("precheck", client="BGPD"),
            _params("precheck", admin_distance="OPENR"),
            _params(
                "program_nhg",
                include_members=True,
                route_prefix="192.0.2.0/24",
            ),
            _params(
                "program_nhg",
                members=[
                    {
                        "address": "fe80::2",
                        "weight": 1,
                        "srv6_segments": ["fdad:ffff:7fff::"],
                        "tunnel_id": "srv6_tunnel",
                    }
                ],
            ),
        )
        with patch(_DRIVER_PATH, new_callable=AsyncMock) as get_driver:
            for params in invalid:
                with self.subTest(params=params), self.assertRaises(ValueError):
                    await task.run(params)
        get_driver.assert_not_awaited()

    async def test_program_route_and_verify_programmed_use_shared_members(
        self,
    ) -> None:
        state = {"group": None, "route": None, "client_id": None}
        agent = MagicMock()

        async def get_groups(_names):
            return [state["group"]] if state["group"] is not None else []

        async def add_groups(groups):
            supplied = groups[0]
            state["group"] = SimpleNamespace(
                name=supplied.name,
                nexthops=list(supplied.nexthops),
                isProgrammed=False,
            )

        async def get_routes(_client_id):
            return [state["route"]] if state["route"] is not None else []

        async def add_routes(client_id, routes):
            state["client_id"] = client_id
            state["route"] = routes[0]

        async def get_details():
            if state["route"] is None:
                return []
            member = state["group"].nexthops[0]
            resolved_member = SimpleNamespace(
                address=SimpleNamespace(
                    addr=member.address.addr,
                    ifName="fboss2011",
                ),
                weight=member.weight,
                srv6SegmentList=list(member.srv6SegmentList),
                tunnelType=member.tunnelType,
                tunnelId=member.tunnelId,
            )
            return [
                SimpleNamespace(
                    dest=state["route"].dest,
                    namedRouteDestination=state["route"].namedRouteDestination,
                    nextHopMulti=[
                        SimpleNamespace(
                            clientId=state["client_id"],
                            namedRouteDestination=state["route"].namedRouteDestination,
                            adminDistance=2,
                            isPreferred=True,
                        )
                    ],
                    nextHops=[resolved_member],
                    adminDistance=None,
                )
            ]

        async def get_fib():
            if state["route"] is None or not state["group"].isProgrammed:
                return []
            member = state["group"].nexthops[0]
            return [
                SimpleNamespace(
                    dest=state["route"].dest,
                    # Current FBOSS resolved-route readback retains the exact
                    # NHEs but not the original named destination.
                    namedRouteDestination=None,
                    nextHops=[
                        SimpleNamespace(
                            address=SimpleNamespace(
                                addr=member.address.addr,
                                ifName="fboss2011",
                            ),
                            weight=member.weight,
                            srv6SegmentList=list(member.srv6SegmentList),
                            tunnelType=member.tunnelType,
                            tunnelId=member.tunnelId,
                        )
                    ],
                )
            ]

        agent.getNamedNextHopGroups = AsyncMock(side_effect=get_groups)
        agent.addNamedNextHopGroups = AsyncMock(side_effect=add_groups)
        agent.addOrUpdateNamedNextHopGroups = AsyncMock()
        agent.getRouteTableByClient = AsyncMock(side_effect=get_routes)
        agent.addUnicastRoutes = AsyncMock(side_effect=add_routes)
        agent.getRouteTableDetails = AsyncMock(side_effect=get_details)
        agent.getRouteTable = AsyncMock(side_effect=get_fib)
        driver = _driver(agent)
        shared = {}

        with patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=driver):
            await RbbSrv6NamedNhgTask(
                hostname=_HOST, logger=MagicMock(), shared_data=shared
            ).run(_params("program_nhg", include_members=True))
            # The playbook intentionally does not repeat members here.
            await RbbSrv6NamedNhgTask(
                hostname=_HOST, logger=MagicMock(), shared_data=shared
            ).run(_params("program_route"))
            state["group"].isProgrammed = True
            await RbbSrv6NamedNhgTask(
                hostname=_HOST, logger=MagicMock(), shared_data=shared
            ).run(_params("verify_programmed"))

        agent.addNamedNextHopGroups.assert_awaited_once()
        agent.addOrUpdateNamedNextHopGroups.assert_not_awaited()
        agent.addUnicastRoutes.assert_awaited_once()

    async def test_program_nhg_refuses_unowned_name_collision(self) -> None:
        agent = MagicMock()
        agent.getNamedNextHopGroups = AsyncMock(return_value=[_group()])
        agent.addNamedNextHopGroups = AsyncMock()
        task = RbbSrv6NamedNhgTask(hostname=_HOST, logger=MagicMock(), shared_data={})
        with patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=_driver(agent)):
            with self.assertRaisesRegex(TestCaseFailure, "refusing to replace"):
                await task.run(_params("program_nhg", include_members=True))
        agent.addNamedNextHopGroups.assert_not_awaited()

    async def test_exact_group_readback_rejects_tunnel_mismatch(self) -> None:
        agent = MagicMock()
        agent.getNamedNextHopGroups = AsyncMock(
            return_value=[_group(tunnel_id="wrong_tunnel")]
        )
        task = RbbSrv6NamedNhgTask(hostname=_HOST, logger=MagicMock())
        with patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=_driver(agent)):
            with self.assertRaisesRegex(TestCaseFailure, "member mismatch"):
                await task.run(_params("verify_nhg", include_members=True))

    async def test_deprecated_add_is_only_used_when_preferred_rpc_absent(
        self,
    ) -> None:
        state = {"group": None}
        agent = MagicMock()
        agent.addNamedNextHopGroups = None

        async def get_groups(_names):
            return [state["group"]] if state["group"] is not None else []

        async def add_fallback(groups):
            supplied = groups[0]
            state["group"] = SimpleNamespace(
                name=supplied.name,
                nexthops=list(supplied.nexthops),
                isProgrammed=False,
            )

        agent.getNamedNextHopGroups = AsyncMock(side_effect=get_groups)
        agent.addOrUpdateNamedNextHopGroups = AsyncMock(side_effect=add_fallback)
        with patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=_driver(agent)):
            await RbbSrv6NamedNhgTask(
                hostname=_HOST, logger=MagicMock(), shared_data={}
            ).run(_params("program_nhg", include_members=True))
        agent.addOrUpdateNamedNextHopGroups.assert_awaited_once()

    async def test_preferred_add_failure_is_not_retried_via_deprecated_rpc(
        self,
    ) -> None:
        shared = {}
        agent = MagicMock()
        agent.getNamedNextHopGroups = AsyncMock(return_value=[])
        agent.addNamedNextHopGroups = AsyncMock(
            side_effect=RuntimeError("ambiguous transport failure")
        )
        agent.addOrUpdateNamedNextHopGroups = AsyncMock()
        task = RbbSrv6NamedNhgTask(
            hostname=_HOST, logger=MagicMock(), shared_data=shared
        )
        with patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=_driver(agent)):
            with self.assertRaisesRegex(RuntimeError, "ambiguous"):
                await task.run(_params("program_nhg", include_members=True))
        agent.addOrUpdateNamedNextHopGroups.assert_not_awaited()
        self.assertTrue(task._data[task._group_key(_HOST, _GROUP)])

    async def test_current_missing_group_rejection_skips_after_no_residue(
        self,
    ) -> None:
        from neteng.fboss.fboss.types import FbossBaseError

        agent = MagicMock()
        agent.getNamedNextHopGroups = AsyncMock(return_value=[])
        agent.getRouteTableByClient = AsyncMock(return_value=[])
        agent.getRouteTableDetails = AsyncMock(return_value=[])
        agent.addUnicastRoutes = AsyncMock(
            side_effect=FbossBaseError(
                message=f"Named next-hop group '{_GROUP}' does not exist"
            )
        )
        task = RbbSrv6NamedNhgTask(hostname=_HOST, logger=MagicMock(), shared_data={})
        with patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=_driver(agent)):
            with self.assertRaisesRegex(unittest.SkipTest, "atomically rejects"):
                await task.run(_params("install_forward_ref"))
        network = ipaddress.ip_network(_PREFIX)
        self.assertFalse(task._data[task._route_key(_HOST, network, "TE_AGENT")])

    async def test_unrelated_fboss_error_is_not_reported_as_skip(self) -> None:
        from neteng.fboss.fboss.types import FbossBaseError

        agent = MagicMock()
        agent.getNamedNextHopGroups = AsyncMock(return_value=[])
        agent.getRouteTableByClient = AsyncMock(return_value=[])
        agent.addUnicastRoutes = AsyncMock(
            side_effect=FbossBaseError(message="unrelated validation failure")
        )
        task = RbbSrv6NamedNhgTask(hostname=_HOST, logger=MagicMock(), shared_data={})
        with patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=_driver(agent)):
            with self.assertRaises(FbossBaseError):
                await task.run(_params("install_forward_ref"))
        network = ipaddress.ip_network(_PREFIX)
        self.assertTrue(task._data[task._route_key(_HOST, network, "TE_AGENT")])

    async def test_rejected_forward_reference_with_residue_fails_not_skips(
        self,
    ) -> None:
        from neteng.fboss.fboss.types import FbossBaseError

        state = {"route": None, "reads": 0}
        agent = MagicMock()
        agent.getNamedNextHopGroups = AsyncMock(return_value=[])

        async def get_routes(_client_id):
            state["reads"] += 1
            return [] if state["reads"] == 1 else [state["route"]]

        async def reject(_client_id, routes):
            state["route"] = routes[0]
            raise FbossBaseError(
                message=f"Named next-hop group '{_GROUP}' does not exist"
            )

        agent.getRouteTableByClient = AsyncMock(side_effect=get_routes)
        agent.addUnicastRoutes = AsyncMock(side_effect=reject)
        task = RbbSrv6NamedNhgTask(hostname=_HOST, logger=MagicMock(), shared_data={})
        with patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=_driver(agent)):
            with self.assertRaisesRegex(TestCaseFailure, "left.*in the RIB"):
                await task.run(_params("install_forward_ref"))

    async def test_forward_reference_can_be_preferred_rib_but_unresolved(
        self,
    ) -> None:
        state = {"route": None, "te_client": None}
        agent = MagicMock()
        agent.getNamedNextHopGroups = AsyncMock(return_value=[])

        async def get_routes(_client_id):
            return [state["route"]] if state["route"] is not None else []

        async def add_route(client_id, routes):
            state["te_client"] = client_id
            state["route"] = routes[0]

        async def details():
            if state["route"] is None:
                return []
            return [
                SimpleNamespace(
                    dest=state["route"].dest,
                    namedRouteDestination=state["route"].namedRouteDestination,
                    nextHopMulti=[
                        SimpleNamespace(
                            clientId=state["te_client"],
                            namedRouteDestination=state["route"].namedRouteDestination,
                            adminDistance=2,
                            isPreferred=True,
                            nextHops=[],
                            nextHopAddrs=[],
                        ),
                    ],
                    nextHops=[],
                    adminDistance=2,
                )
            ]

        agent.getRouteTableByClient = AsyncMock(side_effect=get_routes)
        agent.addUnicastRoutes = AsyncMock(side_effect=add_route)
        agent.getRouteTableDetails = AsyncMock(side_effect=details)
        agent.getRouteTable = AsyncMock(return_value=[])
        driver = _driver(agent)
        shared = {}
        with patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=driver):
            await RbbSrv6NamedNhgTask(
                hostname=_HOST, logger=MagicMock(), shared_data=shared
            ).run(_params("install_forward_ref"))
            await RbbSrv6NamedNhgTask(
                hostname=_HOST, logger=MagicMock(), shared_data=shared
            ).run(_params("verify_rib_only"))

    async def test_forward_reference_transitions_to_fib_and_cleans_up(self) -> None:
        state = {"route": None, "group": None, "client_id": None}
        order = []
        agent = MagicMock()

        async def get_groups(_names):
            return [state["group"]] if state["group"] is not None else []

        async def get_client_routes(_client_id):
            return [state["route"]] if state["route"] is not None else []

        async def add_route(client_id, routes):
            order.append("add-route")
            state["client_id"] = client_id
            state["route"] = routes[0]

        async def add_group(groups):
            order.append("add-group")
            supplied = groups[0]
            state["group"] = SimpleNamespace(
                name=supplied.name,
                nexthops=list(supplied.nexthops),
                isProgrammed=state["route"] is not None,
            )

        def resolved_member():
            member = state["group"].nexthops[0]
            return SimpleNamespace(
                address=SimpleNamespace(
                    addr=member.address.addr,
                    ifName="fboss2011",
                ),
                weight=member.weight,
                srv6SegmentList=list(member.srv6SegmentList),
                tunnelType=member.tunnelType,
                tunnelId=member.tunnelId,
            )

        async def get_details():
            if state["route"] is None:
                return []
            programmed = state["group"] is not None
            return [
                SimpleNamespace(
                    dest=state["route"].dest,
                    namedRouteDestination=state["route"].namedRouteDestination,
                    nextHopMulti=[
                        SimpleNamespace(
                            clientId=state["client_id"],
                            namedRouteDestination=state["route"].namedRouteDestination,
                            adminDistance=2,
                            isPreferred=True,
                            nextHops=(
                                list(state["group"].nexthops) if programmed else []
                            ),
                            nextHopAddrs=[],
                        )
                    ],
                    nextHops=[resolved_member()] if programmed else [],
                    adminDistance=2,
                )
            ]

        async def get_fib():
            if state["route"] is None or state["group"] is None:
                return []
            return [
                SimpleNamespace(
                    dest=state["route"].dest,
                    namedRouteDestination=None,
                    nextHops=[resolved_member()],
                )
            ]

        async def delete_route(_client_id, _prefixes):
            order.append("delete-route")
            state["route"] = None
            state["group"].isProgrammed = False

        async def delete_group(_names):
            order.append("delete-group")
            state["group"] = None

        agent.getNamedNextHopGroups = AsyncMock(side_effect=get_groups)
        agent.getRouteTableByClient = AsyncMock(side_effect=get_client_routes)
        agent.getRouteTableDetails = AsyncMock(side_effect=get_details)
        agent.getRouteTable = AsyncMock(side_effect=get_fib)
        agent.addUnicastRoutes = AsyncMock(side_effect=add_route)
        agent.addNamedNextHopGroups = AsyncMock(side_effect=add_group)
        agent.addOrUpdateNamedNextHopGroups = AsyncMock()
        agent.deleteUnicastRoutes = AsyncMock(side_effect=delete_route)
        agent.deleteNamedNextHopGroups = AsyncMock(side_effect=delete_group)
        shared = {}

        async def run(action, *, include_members=False):
            await RbbSrv6NamedNhgTask(
                hostname=_HOST,
                logger=MagicMock(),
                shared_data=shared,
            ).run(_params(action, include_members=include_members))

        with patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=_driver(agent)):
            await run("precheck")
            await run("install_forward_ref")
            await run("verify_rib_only")
            await run("program_nhg", include_members=True)
            await run("verify_programmed")
            await run("cleanup", include_members=True)

        self.assertEqual(
            order,
            ["add-route", "add-group", "delete-route", "delete-group"],
        )
        self.assertIsNone(state["route"])
        self.assertIsNone(state["group"])
        agent.addOrUpdateNamedNextHopGroups.assert_not_awaited()

    async def test_cleanup_deletes_owned_route_before_owned_group(self) -> None:
        order = []
        state = {"route": _route(), "group": _group(programmed=True)}
        agent = MagicMock()
        agent.getRouteTableByClient = AsyncMock(
            side_effect=lambda _client: (
                [state["route"]] if state["route"] is not None else []
            )
        )
        agent.getNamedNextHopGroups = AsyncMock(
            side_effect=lambda _names: (
                [state["group"]] if state["group"] is not None else []
            )
        )
        agent.getRouteTableDetails = AsyncMock(
            return_value=[_route_detail(route=state["route"])]
        )

        async def delete_route(_client, _prefixes):
            order.append("route")
            state["route"] = None

        async def delete_group(_names):
            order.append("group")
            state["group"] = None

        agent.deleteUnicastRoutes = AsyncMock(side_effect=delete_route)
        agent.deleteNamedNextHopGroups = AsyncMock(side_effect=delete_group)
        task = RbbSrv6NamedNhgTask(hostname=_HOST, logger=MagicMock(), shared_data={})
        network = ipaddress.ip_network(_PREFIX)
        task._data[task._route_key(_HOST, network, "TE_AGENT")] = True
        task._data[task._group_key(_HOST, _GROUP)] = True

        with patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=_driver(agent)):
            await task.run(_params("cleanup", include_members=True))
        self.assertEqual(order, ["route", "group"])

    async def test_cleanup_attempts_group_after_route_failure(self) -> None:
        order = []
        agent = MagicMock()
        agent.getRouteTableByClient = AsyncMock(return_value=[_route()])
        group_reads = {"count": 0}

        async def get_group(_names):
            group_reads["count"] += 1
            return [_group()] if group_reads["count"] == 1 else []

        async def fail_route(_client, _prefixes):
            order.append("route")
            raise RuntimeError("route delete failed")

        async def delete_group(_names):
            order.append("group")

        agent.getNamedNextHopGroups = AsyncMock(side_effect=get_group)
        agent.getRouteTableDetails = AsyncMock(return_value=[_route_detail()])
        agent.deleteUnicastRoutes = AsyncMock(side_effect=fail_route)
        agent.deleteNamedNextHopGroups = AsyncMock(side_effect=delete_group)
        task = RbbSrv6NamedNhgTask(hostname=_HOST, logger=MagicMock(), shared_data={})
        network = ipaddress.ip_network(_PREFIX)
        task._data[task._route_key(_HOST, network, "TE_AGENT")] = True
        task._data[task._group_key(_HOST, _GROUP)] = True

        with patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=_driver(agent)):
            with self.assertRaisesRegex(TestCaseFailure, "route cleanup"):
                await task.run(_params("cleanup", include_members=True))
        self.assertEqual(order, ["route", "group"])

    async def test_cleanup_preserves_cancellation_after_group_attempt(self) -> None:
        order = []
        agent = MagicMock()
        agent.getRouteTableByClient = AsyncMock(return_value=[_route()])
        group_reads = {"count": 0}

        async def get_group(_names):
            group_reads["count"] += 1
            return [_group()] if group_reads["count"] == 1 else []

        async def cancel_route(_client, _prefixes):
            order.append("route")
            raise asyncio.CancelledError()

        async def delete_group(_names):
            order.append("group")

        agent.getNamedNextHopGroups = AsyncMock(side_effect=get_group)
        agent.getRouteTableDetails = AsyncMock(return_value=[_route_detail()])
        agent.deleteUnicastRoutes = AsyncMock(side_effect=cancel_route)
        agent.deleteNamedNextHopGroups = AsyncMock(side_effect=delete_group)
        task = RbbSrv6NamedNhgTask(hostname=_HOST, logger=MagicMock(), shared_data={})
        network = ipaddress.ip_network(_PREFIX)
        task._data[task._route_key(_HOST, network, "TE_AGENT")] = True
        task._data[task._group_key(_HOST, _GROUP)] = True

        with patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=_driver(agent)):
            with self.assertRaises(asyncio.CancelledError):
                await task.run(_params("cleanup", include_members=True))
        self.assertEqual(order, ["route", "group"])


if __name__ == "__main__":
    unittest.main()
