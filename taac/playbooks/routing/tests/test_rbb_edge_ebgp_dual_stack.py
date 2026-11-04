# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Focused tests for the optional IPv4 RBB edge companion."""

import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from taac.constants import TestCaseFailure
from taac.tasks.rbb_edge_ebgp_task import RbbEdgeEbgpTask
from taac.testconfigs.routing.util import bgp_rbb_constants as C
from taac.testconfigs.routing.util.bgp_rbb_edge_config import (
    EDGE_EBGP_PEER_GROUP,
    EDGE_EBGP_V4_PEER_GROUP,
    add_edge_ebgp_peer,
    enable_ipv6_afi_on_ibgp,
)

_EDGE_MOD = "taac.tasks.rbb_edge_ebgp_task"
_EDGE_PATH = f"{_EDGE_MOD}.async_get_device_driver"


def _ibgp_bgp_json() -> dict:
    return {
        "local_as_4_byte": 65001,
        "router_id": "192.0.2.1",
        "networks4": [{"prefix": "192.0.2.1/32"}],
        "networks6": [],
        "peer_groups": [
            {
                "name": "CORE-IBGP-V4",
                "remote_as_4_byte": 65001,
                "next_hop_self": False,
                "disable_ipv4_afi": False,
                "disable_ipv6_afi": True,
            }
        ],
        "peers": [
            {
                "peer_addr": "192.0.2.2",
                "peer_group_name": "CORE-IBGP-V4",
                "local_addr": "192.0.2.1",
                "next_hop6": "::",
                "remote_as_4_byte": 65001,
            }
        ],
    }


def _edge_agent_json(
    interface_addresses: list[str],
    *,
    vlan_addresses: list[str] | None = None,
    state: int = 2,
) -> dict:
    return {
        "sw": {
            "interfaces": [
                {
                    "intfID": 2001,
                    "vlanID": 2001,
                    "ipAddresses": interface_addresses,
                }
            ],
            "vlans": [
                {
                    "id": 2001,
                    "ipAddresses": (
                        vlan_addresses if vlan_addresses is not None else []
                    ),
                }
            ],
            "vlanPorts": [{"vlanID": 2001, "logicalPort": 1}],
            "ports": [
                {
                    "name": "eth1/1/1",
                    "logicalID": 1,
                    "state": state,
                    "ingressVlan": 2001,
                    "portType": 0,
                    "routable": True,
                }
            ],
        }
    }


def _dual_stack_params() -> dict:
    return {
        "hostname": "rbb-r1",
        "action": "apply",
        "edge_peer_addr": "2001:db8:a:3::2",
        "edge_remote_as": 64512,
        "edge_local_addr": "2001:db8:a:3::1",
        "enable_ipv6_afi": True,
        "ibgp_peer_addr": "192.0.2.2",
        "ibgp_srv6_nexthop": "2001:db8::1",
        "ibgp_next_hop_self": True,
        "edge_rif_cidr": "2001:db8:a:3::1/64",
        "edge_peer_addr4": "203.0.113.2",
        "edge_local_addr4": "203.0.113.1",
        "edge_rif_cidr4": "203.0.113.1/30",
        "edge_port_name": "eth1/1/1",
    }


def _configured_dual_stack_bgp_json() -> dict:
    cfg = _ibgp_bgp_json()
    enable_ipv6_afi_on_ibgp(
        cfg,
        ibgp_next_hop6="2001:db8::1",
        ibgp_peer_addr="192.0.2.2",
        ibgp_next_hop_self=True,
        enable_ipv4_afi=True,
    )
    add_edge_ebgp_peer(
        cfg,
        peer_addr="2001:db8:a:3::2",
        remote_as=64512,
        local_addr="2001:db8:a:3::1",
        description="IXIA edge eBGP peer 2001:db8:a:3::2 (AS 64512)",
    )
    add_edge_ebgp_peer(
        cfg,
        peer_addr="203.0.113.2",
        remote_as=64512,
        local_addr="203.0.113.1",
        peer_group_name=EDGE_EBGP_V4_PEER_GROUP,
        description="IXIA IPv4 edge eBGP peer 203.0.113.2 (AS 64512)",
    )
    return cfg


class RbbEdgeEbgpIpv4HelperTest(unittest.TestCase):
    def test_dual_stack_enables_ipv4_on_selected_core_group(self) -> None:
        cfg = _ibgp_bgp_json()
        cfg["peer_groups"][0]["disable_ipv4_afi"] = True

        enable_ipv6_afi_on_ibgp(
            cfg,
            ibgp_next_hop6="2001:db8::1",
            ibgp_peer_addr="192.0.2.2",
            enable_ipv4_afi=True,
        )

        self.assertFalse(cfg["peer_groups"][0]["disable_ipv4_afi"])
        self.assertFalse(cfg["peer_groups"][0]["disable_ipv6_afi"])

    def test_ipv4_peer_uses_dedicated_owned_group(self) -> None:
        cfg = _ibgp_bgp_json()
        add_edge_ebgp_peer(
            cfg,
            peer_addr="203.0.113.2",
            remote_as=64513,
            local_addr="203.0.113.1",
            peer_group_name=EDGE_EBGP_V4_PEER_GROUP,
        )

        group = next(
            group
            for group in cfg["peer_groups"]
            if group["name"] == EDGE_EBGP_V4_PEER_GROUP
        )
        peer = next(peer for peer in cfg["peers"] if peer["peer_addr"] == "203.0.113.2")
        self.assertFalse(group["disable_ipv4_afi"])
        self.assertTrue(group["disable_ipv6_afi"])
        self.assertEqual(peer["local_addr"], "203.0.113.1")
        self.assertEqual(peer["next_hop4"], "203.0.113.1")
        self.assertEqual(peer["next_hop6"], "::")


class RbbEdgeEbgpDualStackTaskTest(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _driver() -> MagicMock:
        driver = MagicMock()
        driver.async_write_file_on_device = AsyncMock()
        driver.async_restart_service = AsyncMock()
        driver.async_agent_config_reload = AsyncMock()
        driver.async_wait_for_agent_state_configured = AsyncMock()
        driver.async_check_if_file_exists = AsyncMock(return_value=True)
        driver.async_read_file = AsyncMock(return_value="restored-content")

        def command_result(command: str) -> str:
            if command == "id -u":
                return "0\n"
            if command.startswith("systemctl show "):
                return "LoadState=loaded\nActiveState=active\n"
            return ""

        driver.async_run_cmd_on_shell = AsyncMock(side_effect=command_result)
        return driver

    async def test_apply_writes_complete_dual_stack_documents_once(self) -> None:
        task = RbbEdgeEbgpTask(hostname="rbb-r1", logger=MagicMock())
        driver = self._driver()
        events: list[str] = []
        initial_bgp = _ibgp_bgp_json()
        # A valid pre-existing v6-only core must be upgraded explicitly; the
        # IPv4 IXIA peers are otherwise established but cannot propagate.
        initial_bgp["peer_groups"][0]["disable_ipv4_afi"] = True
        documents = iter(
            (
                json.dumps(initial_bgp),
                json.dumps(_edge_agent_json([], state=0)),
            )
        )

        def read_document(*_args: object, **_kwargs: object) -> str:
            events.append("read")
            return next(documents)

        def take_snapshot(*_args: object, **_kwargs: object) -> bool:
            events.append("snapshot")
            return True

        def write_document(*_args: object, **_kwargs: object) -> None:
            events.append("write")

        with (
            patch(_EDGE_PATH, new_callable=AsyncMock, return_value=driver),
            patch(
                f"{_EDGE_MOD}.async_read_file_or_none",
                new_callable=AsyncMock,
                side_effect=read_document,
            ),
            patch(
                f"{_EDGE_MOD}.async_guard_snapshot_set",
                new_callable=AsyncMock,
            ),
            patch(
                f"{_EDGE_MOD}.async_backup_before_overwrite",
                new_callable=AsyncMock,
                side_effect=take_snapshot,
            ) as snapshot,
            patch(
                f"{_EDGE_MOD}.async_write_json_file",
                new_callable=AsyncMock,
                side_effect=write_document,
            ) as write_json,
            patch(
                f"{_EDGE_MOD}.async_apply_backup_metadata",
                new_callable=AsyncMock,
            ),
        ):
            await task.run(_dual_stack_params())

        # Both complete transforms happen before these two full-file snapshots.
        # Each document is then written exactly once.
        self.assertEqual(snapshot.await_count, 2)
        self.assertEqual(write_json.await_count, 2)
        self.assertEqual(events[:2], ["read", "read"])
        self.assertNotIn("write", events[: events.index("snapshot")])
        written = [call.args[2] for call in write_json.await_args_list]
        bgp_cfg = next(value for value in written if "peers" in value)
        agent_cfg = next(value for value in written if "sw" in value)
        peer_groups = {group["name"]: group for group in bgp_cfg["peer_groups"]}
        peers = {peer["peer_addr"]: peer for peer in bgp_cfg["peers"]}
        self.assertIn(EDGE_EBGP_PEER_GROUP, peer_groups)
        self.assertIn(EDGE_EBGP_V4_PEER_GROUP, peer_groups)
        self.assertEqual(peers["203.0.113.2"]["local_addr"], "203.0.113.1")
        self.assertFalse(peer_groups[EDGE_EBGP_V4_PEER_GROUP]["disable_ipv4_afi"])
        self.assertFalse(peer_groups["CORE-IBGP-V4"]["disable_ipv4_afi"])
        # This is deliberately host-independent: the same selected iBGP group
        # can be enabled for next-hop-self by either R1 or R2.
        self.assertTrue(bgp_cfg["peer_groups"][0]["next_hop_self"])
        self.assertEqual(
            agent_cfg["sw"]["interfaces"][0]["ipAddresses"],
            ["2001:db8:a:3::1/64", "203.0.113.1/30"],
        )
        self.assertEqual(agent_cfg["sw"]["ports"][0]["state"], 2)

    async def test_bgp_write_failure_restores_both_complete_documents(self) -> None:
        task = RbbEdgeEbgpTask(hostname="rbb-r1", logger=MagicMock())
        driver = self._driver()
        with (
            patch(_EDGE_PATH, new_callable=AsyncMock, return_value=driver),
            patch(
                f"{_EDGE_MOD}.async_read_file_or_none",
                new_callable=AsyncMock,
                side_effect=[
                    json.dumps(_ibgp_bgp_json()),
                    json.dumps(_edge_agent_json([], state=0)),
                ],
            ),
            patch(
                f"{_EDGE_MOD}.async_guard_snapshot_set",
                new_callable=AsyncMock,
            ),
            patch(
                f"{_EDGE_MOD}.async_backup_before_overwrite",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch(
                f"{_EDGE_MOD}.async_write_json_file",
                new_callable=AsyncMock,
                side_effect=[None, RuntimeError("injected BGP write failure")],
            ),
            patch(
                f"{_EDGE_MOD}.async_apply_backup_metadata",
                new_callable=AsyncMock,
            ),
            patch(
                f"{_EDGE_MOD}.async_restore_backup",
                new_callable=AsyncMock,
                return_value=True,
            ) as restore_backup,
            patch(
                f"{_EDGE_MOD}.async_discard_backup",
                new_callable=AsyncMock,
            ) as discard_backup,
            patch("taac.utils.json_thrift_utils.json_to_thrift"),
            self.assertRaisesRegex(TestCaseFailure, "was rolled back"),
        ):
            await task.run(_dual_stack_params())

        self.assertEqual(
            [call.args[1] for call in restore_backup.await_args_list],
            [C.BGP_CONFIG_PATH, C.AGENT_CONFIG_PATH],
        )
        self.assertEqual(
            [call.args[1] for call in discard_backup.await_args_list],
            [C.BGP_CONFIG_PATH, C.AGENT_CONFIG_PATH],
        )
        # One live apply reload plus one restore reload.
        self.assertEqual(driver.async_agent_config_reload.await_count, 2)
        driver.async_wait_for_agent_state_configured.assert_awaited()
        driver.async_restart_service.assert_awaited()

    async def test_fully_configured_dual_stack_overlay_is_idempotent(self) -> None:
        task = RbbEdgeEbgpTask(hostname="rbb-r1", logger=MagicMock())
        driver = self._driver()
        with (
            patch(_EDGE_PATH, new_callable=AsyncMock, return_value=driver),
            patch(
                f"{_EDGE_MOD}.async_read_file_or_none",
                new_callable=AsyncMock,
                side_effect=[
                    json.dumps(_configured_dual_stack_bgp_json()),
                    json.dumps(
                        _edge_agent_json(["2001:db8:a:3::1/64", "203.0.113.1/30"])
                    ),
                ],
            ),
            patch(
                f"{_EDGE_MOD}.async_guard_snapshot_set",
                new_callable=AsyncMock,
            ) as guard_snapshot,
            patch(
                f"{_EDGE_MOD}.async_backup_before_overwrite",
                new_callable=AsyncMock,
            ) as backup,
            patch(
                f"{_EDGE_MOD}.async_write_json_file",
                new_callable=AsyncMock,
            ) as write_json,
        ):
            await task.run(_dual_stack_params())

        guard_snapshot.assert_awaited_once()
        backup.assert_not_awaited()
        write_json.assert_not_awaited()
        driver.async_agent_config_reload.assert_not_awaited()
        driver.async_restart_service.assert_not_awaited()

    async def test_partial_ipv4_parameters_fail_before_file_access(self) -> None:
        task = RbbEdgeEbgpTask(hostname="rbb-r1", logger=MagicMock())
        driver = self._driver()
        with patch(_EDGE_PATH, new_callable=AsyncMock, return_value=driver):
            with self.assertRaisesRegex(ValueError, "IPv4 companion requires"):
                await task.run(
                    {
                        "hostname": "rbb-r1",
                        "edge_peer_addr": "2001:db8:a:3::2",
                        "edge_remote_as": 64512,
                        "edge_local_addr": "2001:db8:a:3::1",
                        "edge_peer_addr4": "203.0.113.2",
                    }
                )
        driver.async_read_file.assert_not_awaited()

    async def test_ipv4_companion_requires_primary_rif(self) -> None:
        task = RbbEdgeEbgpTask(hostname="rbb-r1", logger=MagicMock())
        driver = self._driver()
        with patch(_EDGE_PATH, new_callable=AsyncMock, return_value=driver):
            with self.assertRaisesRegex(ValueError, "applied atomically"):
                await task.run(
                    {
                        "hostname": "rbb-r1",
                        "edge_peer_addr": "2001:db8:a:3::2",
                        "edge_remote_as": 64512,
                        "edge_local_addr": "2001:db8:a:3::1",
                        "edge_peer_addr4": "203.0.113.2",
                        "edge_local_addr4": "203.0.113.1",
                        "edge_rif_cidr4": "203.0.113.1/30",
                    }
                )
        driver.async_read_file.assert_not_awaited()

    async def test_ipv4_peer_and_rif_must_share_one_subnet(self) -> None:
        task = RbbEdgeEbgpTask(hostname="rbb-r1", logger=MagicMock())
        driver = self._driver()
        with patch(_EDGE_PATH, new_callable=AsyncMock, return_value=driver):
            with self.assertRaisesRegex(ValueError, "share a subnet"):
                await task.run(
                    {
                        "hostname": "rbb-r1",
                        "edge_peer_addr": "2001:db8:a:3::2",
                        "edge_remote_as": 64512,
                        "edge_local_addr": "2001:db8:a:3::1",
                        "edge_rif_cidr": "2001:db8:a:3::1/64",
                        "edge_peer_addr4": "203.0.113.6",
                        "edge_local_addr4": "203.0.113.1",
                        "edge_rif_cidr4": "203.0.113.1/30",
                    }
                )
        driver.async_read_file.assert_not_awaited()

    async def test_empty_svi_gets_both_rif_families_in_one_transform(self) -> None:
        task = RbbEdgeEbgpTask(hostname="rbb-r1", logger=MagicMock())
        with patch(
            f"{_EDGE_MOD}.async_read_file_or_none",
            new_callable=AsyncMock,
            return_value=json.dumps(_edge_agent_json([])),
        ):
            cfg, changed = await task._prepare_edge_rif(
                self._driver(),
                "rbb-r1",
                "2001:db8:a:3::1/64",
                "eth1/1/1",
                None,
                "203.0.113.1/30",
            )
        self.assertTrue(changed)
        self.assertEqual(
            cfg["sw"]["interfaces"][0]["ipAddresses"],
            ["2001:db8:a:3::1/64", "203.0.113.1/30"],
        )

    async def test_exact_dual_stack_preconfiguration_is_idempotent(self) -> None:
        task = RbbEdgeEbgpTask(hostname="rbb-r1", logger=MagicMock())
        addresses = ["203.0.113.1/30", "2001:db8:a:3::1/64"]
        with patch(
            f"{_EDGE_MOD}.async_read_file_or_none",
            new_callable=AsyncMock,
            return_value=json.dumps(_edge_agent_json(addresses)),
        ):
            cfg, changed = await task._prepare_edge_rif(
                self._driver(),
                "rbb-r1",
                "2001:db8:a:3::1/64",
                "eth1/1/1",
                None,
                "203.0.113.1/30",
            )
        self.assertFalse(changed)
        self.assertEqual(cfg["sw"]["interfaces"][0]["ipAddresses"], addresses)

    async def test_exact_single_family_preconfiguration_adds_only_missing_rif(
        self,
    ) -> None:
        task = RbbEdgeEbgpTask(hostname="rbb-r1", logger=MagicMock())
        with patch(
            f"{_EDGE_MOD}.async_read_file_or_none",
            new_callable=AsyncMock,
            return_value=json.dumps(_edge_agent_json(["2001:db8:a:3::1/64"])),
        ):
            cfg, changed = await task._prepare_edge_rif(
                self._driver(),
                "rbb-r1",
                "2001:db8:a:3::1/64",
                "eth1/1/1",
                None,
                "203.0.113.1/30",
            )
        self.assertTrue(changed)
        self.assertEqual(
            cfg["sw"]["interfaces"][0]["ipAddresses"],
            ["2001:db8:a:3::1/64", "203.0.113.1/30"],
        )

    async def test_unrelated_split_or_duplicate_dual_stack_addresses_fail_closed(
        self,
    ) -> None:
        task = RbbEdgeEbgpTask(hostname="rbb-r1", logger=MagicMock())
        cases = (
            (["2001:db8:a:3::1/64", "198.51.100.1/30"], []),
            (["2001:db8:a:3::1/64"], ["203.0.113.1/30"]),
            (
                ["2001:db8:a:3::1/64", "203.0.113.1/30"],
                ["203.0.113.1/30"],
            ),
            (
                ["2001:db8:a:3::1/64", "2001:db8:a:3::1/64"],
                [],
            ),
        )
        for interface_addresses, vlan_addresses in cases:
            with (
                self.subTest(
                    interface_addresses=interface_addresses,
                    vlan_addresses=vlan_addresses,
                ),
                patch(
                    f"{_EDGE_MOD}.async_read_file_or_none",
                    new_callable=AsyncMock,
                    return_value=json.dumps(
                        _edge_agent_json(
                            interface_addresses,
                            vlan_addresses=vlan_addresses,
                        )
                    ),
                ),
                self.assertRaisesRegex(
                    TestCaseFailure,
                    "unrelated or split|duplicate IP addresses",
                ),
            ):
                await task._prepare_edge_rif(
                    self._driver(),
                    "rbb-r1",
                    "2001:db8:a:3::1/64",
                    "eth1/1/1",
                    None,
                    "203.0.113.1/30",
                )


if __name__ == "__main__":
    unittest.main()
