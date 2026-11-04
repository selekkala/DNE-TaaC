# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Unit tests for RBB IXIA learned-route and DUT-counter evidence tasks."""

import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from taac.constants import TestCaseFailure
from taac.ixia.otg_traffic_gen import OtgTrafficGen
from taac.tasks.rbb_ixia_bgp_learned_routes_task import (
    RbbIxiaBgpLearnedRoutesTask,
    _table_prefixes,
)
from taac.tasks.rbb_traffic_counter_correlation_task import (
    RbbTrafficCounterCorrelationTask,
)


class RbbTrafficCounterCorrelationTaskTest(unittest.IsolatedAsyncioTestCase):
    def test_traffic_evidence_tasks_are_registered(self) -> None:
        from taac.tasks.registry import TASK_NAME_TO_CLASS

        self.assertIs(
            TASK_NAME_TO_CLASS["rbb_ixia_bgp_learned_routes"],
            RbbIxiaBgpLearnedRoutesTask,
        )
        self.assertIs(
            TASK_NAME_TO_CLASS["rbb_traffic_counter_correlation"],
            RbbTrafficCounterCorrelationTask,
        )

    def _task(self, driver, stats, *, baseline_stats=None):
        ixia = MagicMock()
        if baseline_stats is None:
            ixia.get_latest_stats.return_value = stats
        else:
            ixia.get_latest_stats.side_effect = [baseline_stats, stats]
        task = RbbTrafficCounterCorrelationTask(
            hostname="r1.example",
            ixia=ixia,
            logger=MagicMock(),
            shared_data={},
        )
        return task, ixia

    @staticmethod
    def _row(
        interface,
        bytes_in=0,
        unicast_in=0,
        multicast_in=0,
        broadcast_in=0,
        bytes_out=0,
        unicast_out=0,
        multicast_out=0,
        broadcast_out=0,
    ):
        return (
            f"{interface} {bytes_in} {unicast_in} {multicast_in} "
            f"{broadcast_in} {bytes_out} {unicast_out} {multicast_out} "
            f"{broadcast_out}"
        )

    async def test_correlates_packet_delta_with_ixia_frames(self) -> None:
        driver = MagicMock()
        driver.async_run_cmd_on_shell = AsyncMock(
            side_effect=[
                self._row("eth1/1", unicast_in=10, multicast_in=2, broadcast_in=3),
                self._row(
                    "eth1/1", unicast_in=1010, multicast_in=2, broadcast_in=3
                ),
            ]
        )
        task, ixia = self._task(
            driver,
            [{"identifier": "FLOW", "tx_frames": 6000}],
            baseline_stats=[{"identifier": "FLOW", "tx_frames": 5000}],
        )
        base = {
            "hostname": "r1.example",
            "gate": "phase1:TC-17",
            "sample_id": "forward:ingress:packets",
            "counter_interfaces": ["eth1/1"],
            "counter_direction": "ingress",
            "counter_kind": "packets",
            "traffic_item": "FLOW",
            "ixia_counter_field": "tx_frames",
        }
        with (
            patch(
                "taac.tasks.rbb_traffic_counter_correlation_task."
                "async_get_device_driver",
                AsyncMock(return_value=driver),
            ),
            patch(
                "taac.tasks.rbb_traffic_counter_correlation_task.time.time",
                return_value=1234.5,
            ),
        ):
            await task.run({**base, "action": "snapshot"})
            await task.run(
                {
                    **base,
                    "action": "assert",
                    "traffic_item": "FLOW",
                    "ixia_counter_field": "tx_frames",
                    "tolerance_percent": 5,
                    "absolute_tolerance": 1,
                    "min_value": 1,
                }
            )

        self.assertEqual(
            ixia.get_latest_stats.call_args_list,
            [
                unittest.mock.call(since_time=1234.5),
                unittest.mock.call(since_time=1234.5),
            ],
        )
        self.assertEqual(
            [call.args[0] for call in driver.async_run_cmd_on_shell.await_args_list],
            ["fboss2 show interface eth1/1 counters"] * 2,
        )

    async def test_correlates_byte_delta_with_ixia_bytes(self) -> None:
        driver = MagicMock()
        driver.async_run_cmd_on_shell = AsyncMock(
            side_effect=[
                self._row("eth1/5", bytes_out=10000),
                self._row("eth1/5", bytes_out=522000),
            ]
        )
        task, _ = self._task(
            driver,
            [{"identifier": "FLOW", "rx_bytes": 576000}],
            baseline_stats=[{"identifier": "FLOW", "rx_bytes": 64000}],
        )
        base = {
            "hostname": "r2.example",
            "sample_id": "forward:egress:bytes",
            "counter_interfaces": ["eth1/5"],
            "counter_direction": "egress",
            "counter_kind": "bytes",
            "traffic_item": "FLOW",
            "ixia_counter_field": "rx_bytes",
        }
        with patch(
            "taac.tasks.rbb_traffic_counter_correlation_task.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run({**base, "action": "snapshot"})
            await task.run(
                {
                    **base,
                    "action": "assert",
                    "traffic_item": "FLOW",
                    "ixia_counter_field": "rx_bytes",
                    "tolerance_percent": 1,
                    "absolute_tolerance": 1,
                    "min_value": 1,
                }
            )

    async def test_sums_every_declared_core_member(self) -> None:
        driver = MagicMock()
        driver.async_run_cmd_on_shell = AsyncMock(
            side_effect=[
                self._row("eth1/1", unicast_out=100),
                self._row("eth1/2", unicast_out=200),
                self._row("eth1/1", unicast_out=500),
                self._row("eth1/2", unicast_out=800),
            ]
        )
        task, _ = self._task(
            driver,
            [{"identifier": "FLOW", "tx_frames": 4000}],
            baseline_stats=[{"identifier": "FLOW", "tx_frames": 3000}],
        )
        base = {
            "hostname": "r1.example",
            "sample_id": "forward:r1:core:egress:packets",
            "counter_interfaces": ["eth1/1", "eth1/2"],
            "counter_direction": "egress",
            "counter_kind": "packets",
            "traffic_item": "FLOW",
            "ixia_counter_field": "tx_frames",
        }
        with patch(
            "taac.tasks.rbb_traffic_counter_correlation_task."
            "async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run({**base, "action": "snapshot"})
            await task.run(
                {
                    **base,
                    "action": "assert",
                    "traffic_item": "FLOW",
                    "ixia_counter_field": "tx_frames",
                    "tolerance_percent": 0,
                    "absolute_tolerance": 0,
                }
            )

    async def test_minimum_delta_sums_members_without_ixia(self) -> None:
        driver = MagicMock()
        driver.async_run_cmd_on_shell = AsyncMock(
            side_effect=[
                self._row("eth1/1", unicast_out=100),
                self._row("eth1/2", unicast_out=200),
                self._row("eth1/1", unicast_out=100),
                self._row("eth1/2", unicast_out=201),
            ]
        )
        task, ixia = self._task(driver, [])
        base = {
            "hostname": "r1.example",
            "sample_id": "surviving-core",
            "counter_interfaces": ["eth1/1", "eth1/2"],
            "counter_direction": "egress",
            "counter_kind": "packets",
        }
        with patch(
            "taac.tasks.rbb_traffic_counter_correlation_task."
            "async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run({**base, "action": "snapshot"})
            await task.run(
                {
                    **base,
                    "action": "assert_min_delta",
                    "min_delta": 1,
                }
            )

        ixia.get_latest_stats.assert_not_called()

    async def test_at_least_ixia_allows_multiple_path_traversals(self) -> None:
        driver = MagicMock()
        driver.async_run_cmd_on_shell = AsyncMock(
            side_effect=[
                self._row("eth1/1", unicast_out=100),
                self._row("eth1/1", unicast_out=2100),
            ]
        )
        task, ixia = self._task(
            driver,
            [{"identifier": "FLOW", "tx_frames": 11000}],
            baseline_stats=[{"identifier": "FLOW", "tx_frames": 10000}],
        )
        base = {
            "hostname": "r1.example",
            "sample_id": "selected-core",
            "counter_interfaces": ["eth1/1"],
            "counter_direction": "egress",
            "counter_kind": "packets",
            "traffic_item": "FLOW",
            "ixia_counter_field": "tx_frames",
        }
        with patch(
            "taac.tasks.rbb_traffic_counter_correlation_task."
            "async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run({**base, "action": "snapshot"})
            await task.run(
                {
                    **base,
                    "action": "assert_at_least_ixia",
                    "traffic_item": "FLOW",
                    "ixia_counter_field": "tx_frames",
                    "tolerance_percent": 0,
                    "absolute_tolerance": 0,
                }
            )

        self.assertEqual(ixia.get_latest_stats.call_count, 2)

    async def test_ixia_share_accepts_ecmp_fraction(self) -> None:
        driver = MagicMock()
        driver.async_run_cmd_on_shell = AsyncMock(
            side_effect=[
                self._row("eth1/1", unicast_out=100),
                self._row("eth1/1", unicast_out=70100),
            ]
        )
        task, ixia = self._task(
            driver,
            [{"identifier": "FLOW", "tx_frames": 200000}],
            baseline_stats=[{"identifier": "FLOW", "tx_frames": 100000}],
        )
        base = {
            "hostname": "r1.example",
            "sample_id": "selected-core",
            "counter_interfaces": ["eth1/1"],
            "counter_direction": "egress",
            "counter_kind": "packets",
            "traffic_item": "FLOW",
            "ixia_counter_field": "tx_frames",
        }
        with patch(
            "taac.tasks.rbb_traffic_counter_correlation_task."
            "async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run({**base, "action": "snapshot"})
            await task.run(
                {
                    **base,
                    "action": "assert_ixia_share",
                    "traffic_item": "FLOW",
                    "ixia_counter_field": "tx_frames",
                    "min_ixia_share_percent": 10,
                }
            )

        self.assertEqual(ixia.get_latest_stats.call_count, 2)

    async def test_ixia_share_rejects_inactive_path(self) -> None:
        driver = MagicMock()
        driver.async_run_cmd_on_shell = AsyncMock(
            side_effect=[
                self._row("eth1/1", unicast_out=100),
                self._row("eth1/1", unicast_out=100),
            ]
        )
        task, _ = self._task(
            driver,
            [{"identifier": "FLOW", "tx_frames": 190000}],
            baseline_stats=[{"identifier": "FLOW", "tx_frames": 90000}],
        )
        base = {
            "hostname": "r1.example",
            "sample_id": "inactive-core",
            "counter_interfaces": ["eth1/1"],
            "counter_direction": "egress",
            "counter_kind": "packets",
            "traffic_item": "FLOW",
            "ixia_counter_field": "tx_frames",
        }
        with patch(
            "taac.tasks.rbb_traffic_counter_correlation_task."
            "async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run({**base, "action": "snapshot"})
            with self.assertRaisesRegex(TestCaseFailure, "required IXIA traffic share"):
                await task.run(
                    {
                        **base,
                        "action": "assert_ixia_share",
                        "traffic_item": "FLOW",
                        "ixia_counter_field": "tx_frames",
                        "min_ixia_share_percent": 1,
                    }
                )

    async def test_at_least_ixia_rejects_inactive_path(self) -> None:
        driver = MagicMock()
        driver.async_run_cmd_on_shell = AsyncMock(
            side_effect=[
                self._row("eth1/1", unicast_out=100),
                self._row("eth1/1", unicast_out=100),
            ]
        )
        task, _ = self._task(
            driver,
            [{"identifier": "FLOW", "tx_frames": 1005}],
            baseline_stats=[{"identifier": "FLOW", "tx_frames": 5}],
        )
        base = {
            "hostname": "r1.example",
            "sample_id": "inactive-core",
            "counter_interfaces": ["eth1/1"],
            "counter_direction": "egress",
            "counter_kind": "packets",
            "traffic_item": "FLOW",
            "ixia_counter_field": "tx_frames",
        }
        with patch(
            "taac.tasks.rbb_traffic_counter_correlation_task."
            "async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run({**base, "action": "snapshot"})
            with self.assertRaisesRegex(
                TestCaseFailure, "did not carry the IXIA traffic volume"
            ):
                await task.run(
                    {
                        **base,
                        "action": "assert_at_least_ixia",
                        "traffic_item": "FLOW",
                        "ixia_counter_field": "tx_frames",
                        "tolerance_percent": 0,
                        "absolute_tolerance": 0,
                    }
                )

    async def test_fails_if_one_member_moves_backwards(self) -> None:
        driver = MagicMock()
        driver.async_run_cmd_on_shell = AsyncMock(
            side_effect=[
                self._row("eth1/1", unicast_out=100),
                self._row("eth1/2", unicast_out=100),
                self._row("eth1/1", unicast_out=99),
                self._row("eth1/2", unicast_out=1200),
            ]
        )
        task, _ = self._task(
            driver,
            [{"identifier": "FLOW", "tx_frames": 2000}],
            baseline_stats=[{"identifier": "FLOW", "tx_frames": 1000}],
        )
        base = {
            "hostname": "r1.example",
            "sample_id": "core",
            "counter_interfaces": ["eth1/1", "eth1/2"],
            "counter_direction": "egress",
            "counter_kind": "packets",
            "traffic_item": "FLOW",
            "ixia_counter_field": "tx_frames",
        }
        with patch(
            "taac.tasks.rbb_traffic_counter_correlation_task."
            "async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run({**base, "action": "snapshot"})
            with self.assertRaisesRegex(TestCaseFailure, "eth1/1"):
                await task.run(
                    {
                        **base,
                        "action": "assert",
                        "traffic_item": "FLOW",
                        "ixia_counter_field": "tx_frames",
                    }
                )

    async def test_rejects_shell_metacharacters_before_driver_access(self) -> None:
        task, _ = self._task(MagicMock(), [])
        get_driver = AsyncMock()

        with patch(
            "taac.tasks.rbb_traffic_counter_correlation_task."
            "async_get_device_driver",
            get_driver,
        ):
            with self.assertRaisesRegex(ValueError, "invalid interface"):
                await task.run(
                    {
                        "hostname": "r1.example",
                        "action": "snapshot",
                        "sample_id": "unsafe",
                        "counter_interfaces": ["eth1/1; reboot"],
                        "counter_direction": "ingress",
                        "counter_kind": "packets",
                    }
                )

        get_driver.assert_not_awaited()

    def test_packet_parser_sums_unicast_multicast_and_broadcast(self) -> None:
        output = self._row(
            "eth1/5",
            unicast_in=10,
            multicast_in=2,
            broadcast_in=3,
            unicast_out=20,
            multicast_out=4,
            broadcast_out=5,
        )

        self.assertEqual(
            RbbTrafficCounterCorrelationTask._counter_value(
                output, "eth1/5", "ingress", "packets"
            ),
            15,
        )
        self.assertEqual(
            RbbTrafficCounterCorrelationTask._counter_value(
                output, "eth1/5", "egress", "packets"
            ),
            29,
        )

    async def test_fails_when_dut_and_ixia_are_outside_tolerance(self) -> None:
        driver = MagicMock()
        driver.async_run_cmd_on_shell = AsyncMock(
            side_effect=[
                self._row("eth1/1", unicast_in=0),
                self._row("eth1/1", unicast_in=100),
            ]
        )
        task, _ = self._task(
            driver,
            [{"identifier": "FLOW", "tx_frames": 1000}],
            baseline_stats=[{"identifier": "FLOW", "tx_frames": 0}],
        )
        base = {
            "hostname": "r1.example",
            "sample_id": "sample",
            "counter_interfaces": ["eth1/1"],
            "counter_direction": "ingress",
            "counter_kind": "packets",
            "traffic_item": "FLOW",
            "ixia_counter_field": "tx_frames",
        }
        with patch(
            "taac.tasks.rbb_traffic_counter_correlation_task.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run({**base, "action": "snapshot"})
            with self.assertRaisesRegex(TestCaseFailure, "correlation failed"):
                await task.run(
                    {
                        **base,
                        "action": "assert",
                        "traffic_item": "FLOW",
                        "ixia_counter_field": "tx_frames",
                        "tolerance_percent": 1,
                        "absolute_tolerance": 1,
                        "min_value": 1,
                    }
                )

    async def test_missing_ixia_counter_field_fails_closed(self) -> None:
        driver = MagicMock()
        driver.async_run_cmd_on_shell = AsyncMock(
            side_effect=[
                self._row("eth1/1", unicast_in=0),
                self._row("eth1/1", unicast_in=10),
            ]
        )
        task, _ = self._task(
            driver,
            [{"identifier": "FLOW", "frame_delta": 0}],
            baseline_stats=[{"identifier": "FLOW", "tx_frames": 0}],
        )
        base = {
            "hostname": "r1.example",
            "sample_id": "sample",
            "counter_interfaces": ["eth1/1"],
            "counter_direction": "ingress",
            "counter_kind": "packets",
            "traffic_item": "FLOW",
            "ixia_counter_field": "tx_frames",
        }
        with patch(
            "taac.tasks.rbb_traffic_counter_correlation_task.async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run({**base, "action": "snapshot"})
            with self.assertRaisesRegex(TestCaseFailure, "do not expose"):
                await task.run(
                    {
                        **base,
                        "action": "assert",
                        "traffic_item": "FLOW",
                        "ixia_counter_field": "tx_frames",
                    }
                )

    async def test_ixia_counter_reset_fails_closed(self) -> None:
        driver = MagicMock()
        driver.async_run_cmd_on_shell = AsyncMock(
            side_effect=[
                self._row("eth1/1", unicast_in=100),
                self._row("eth1/1", unicast_in=110),
            ]
        )
        task, _ = self._task(
            driver,
            [{"identifier": "FLOW", "tx_frames": 999}],
            baseline_stats=[{"identifier": "FLOW", "tx_frames": 1000}],
        )
        base = {
            "hostname": "r1.example",
            "sample_id": "reset",
            "counter_interfaces": ["eth1/1"],
            "counter_direction": "ingress",
            "counter_kind": "packets",
            "traffic_item": "FLOW",
            "ixia_counter_field": "tx_frames",
        }
        with patch(
            "taac.tasks.rbb_traffic_counter_correlation_task."
            "async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run({**base, "action": "snapshot"})
            with self.assertRaisesRegex(TestCaseFailure, "moved backwards"):
                await task.run({**base, "action": "assert"})

    async def test_ixia_counter_identity_change_fails_closed(self) -> None:
        driver = MagicMock()
        driver.async_run_cmd_on_shell = AsyncMock(
            side_effect=[
                self._row("eth1/1", unicast_in=100),
                self._row("eth1/1", unicast_in=110),
            ]
        )
        task, ixia = self._task(
            driver,
            [{"identifier": "FLOW", "tx_frames": 1010}],
            baseline_stats=[{"identifier": "FLOW", "tx_frames": 1000}],
        )
        base = {
            "hostname": "r1.example",
            "sample_id": "identity",
            "counter_interfaces": ["eth1/1"],
            "counter_direction": "ingress",
            "counter_kind": "packets",
            "traffic_item": "FLOW",
            "ixia_counter_field": "tx_frames",
        }
        with patch(
            "taac.tasks.rbb_traffic_counter_correlation_task."
            "async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run({**base, "action": "snapshot"})
            with self.assertRaisesRegex(TestCaseFailure, "identity changed"):
                await task.run(
                    {
                        **base,
                        "action": "assert",
                        "traffic_item": "OTHER_FLOW",
                    }
                )

        ixia.get_latest_stats.assert_called_once()

    async def test_ixia_assert_requires_snapshot_identity(self) -> None:
        driver = MagicMock()
        driver.async_run_cmd_on_shell = AsyncMock(
            side_effect=[
                self._row("eth1/1", unicast_in=100),
                self._row("eth1/1", unicast_in=110),
            ]
        )
        task, ixia = self._task(driver, [])
        base = {
            "hostname": "r1.example",
            "sample_id": "missing-identity",
            "counter_interfaces": ["eth1/1"],
            "counter_direction": "ingress",
            "counter_kind": "packets",
        }
        with patch(
            "taac.tasks.rbb_traffic_counter_correlation_task."
            "async_get_device_driver",
            AsyncMock(return_value=driver),
        ):
            await task.run({**base, "action": "snapshot"})
            with self.assertRaisesRegex(
                TestCaseFailure, "did not record an IXIA counter baseline"
            ):
                await task.run(
                    {
                        **base,
                        "action": "assert",
                        "traffic_item": "FLOW",
                        "ixia_counter_field": "tx_frames",
                    }
                )

        ixia.get_latest_stats.assert_not_called()

    async def test_snapshot_missing_ixia_row_fails_before_dut_read(self) -> None:
        task, _ = self._task(
            MagicMock(), [{"identifier": "OTHER_FLOW", "tx_frames": 0}]
        )
        get_driver = AsyncMock()
        with patch(
            "taac.tasks.rbb_traffic_counter_correlation_task."
            "async_get_device_driver",
            get_driver,
        ):
            with self.assertRaisesRegex(TestCaseFailure, "no row"):
                await task.run(
                    {
                        "hostname": "r1.example",
                        "action": "snapshot",
                        "sample_id": "missing-row",
                        "counter_interfaces": ["eth1/1"],
                        "counter_direction": "ingress",
                        "counter_kind": "packets",
                        "traffic_item": "FLOW",
                        "ixia_counter_field": "tx_frames",
                    }
                )

        get_driver.assert_not_awaited()


class RbbIxiaBgpLearnedRoutesTaskTest(unittest.IsolatedAsyncioTestCase):
    def test_table_parser_uses_network_and_prefix_length_columns(self) -> None:
        table = SimpleNamespace(
            Columns=["Network Address", "Prefix Length", "Next Hop"],
            Values=[
                ["2001:db8:100::", "64", "2001:db8::1"],
                ["2001:db8:100:1::", "64", "2001:db8::1"],
            ],
        )

        self.assertEqual(
            _table_prefixes(table),
            {"2001:db8:100::/64", "2001:db8:100:1::/64"},
        )

    async def test_exact_received_prefixes_pass(self) -> None:
        events = []
        table = SimpleNamespace(
            Columns=["IPv6 Prefix"],
            Values=[["2001:db8:100::/64"], ["2001:db8:100:1::/64"]],
        )
        learned = SimpleNamespace(
            State="ready",
            Table=SimpleNamespace(find=MagicMock(return_value=[table])),
        )
        peer = SimpleNamespace(
            FilterIpV6Unicast=SimpleNamespace(
                Values=["false"],
                Single=MagicMock(side_effect=lambda enabled: events.append("filter"))
            ),
            GetIPv6LearnedInfo=MagicMock(side_effect=lambda: events.append("learned")),
            LearnedInfo=SimpleNamespace(find=MagicMock(return_value=learned)),
        )
        ixia = MagicMock()
        ixia.find_bgp_ipv6_peer.return_value = peer
        ixia.apply_changes.side_effect = lambda: events.append("apply")
        task = RbbIxiaBgpLearnedRoutesTask(ixia=ixia, logger=MagicMock())

        await task.run(
            {
                "gate": "phase1:TC-05",
                "port_identifier": "r2.example:eth1/5",
                "expected_prefixes": [
                    "2001:db8:100::/64",
                    "2001:db8:100:1::/64",
                ],
                "timeout_seconds": 1,
                "poll_interval_seconds": 0.01,
            }
        )

        ixia.find_bgp_ipv6_peer.assert_called_once_with("r2.example:eth1/5")
        peer.GetIPv6LearnedInfo.assert_called_once_with()
        peer.LearnedInfo.find.assert_called_once_with()
        self.assertEqual(
            peer.FilterIpV6Unicast.Single.call_args_list,
            [unittest.mock.call(True), unittest.mock.call(False)],
        )
        self.assertEqual(ixia.apply_changes.call_count, 2)
        self.assertEqual(
            events, ["filter", "apply", "learned", "filter", "apply"]
        )

    async def test_missing_received_prefix_fails_after_timeout(self) -> None:
        table = SimpleNamespace(
            Columns=["IPv6 Prefix"],
            Values=[["2001:db8:100::/64"]],
        )
        peer = SimpleNamespace(
            FilterIpV6Unicast=SimpleNamespace(
                Values=[False], Single=MagicMock()
            ),
            GetIPv6LearnedInfo=MagicMock(),
            LearnedInfo=SimpleNamespace(find=MagicMock(return_value=SimpleNamespace(
                State="ready",
                Table=SimpleNamespace(find=MagicMock(return_value=[table])),
            ))),
        )
        ixia = MagicMock()
        ixia.find_bgp_ipv6_peer.return_value = peer
        task = RbbIxiaBgpLearnedRoutesTask(ixia=ixia, logger=MagicMock())

        with self.assertRaisesRegex(TestCaseFailure, "missing"):
            await task.run(
                {
                    "port_identifier": "r2.example:eth1/5",
                    "expected_prefixes": ["2001:db8:100:1::/64"],
                    "timeout_seconds": 0.01,
                    "poll_interval_seconds": 0.001,
                }
            )

        self.assertGreater(peer.GetIPv6LearnedInfo.call_count, 1)
        self.assertEqual(
            peer.FilterIpV6Unicast.Single.call_args_list,
            [unittest.mock.call(True), unittest.mock.call(False)],
        )

    async def test_existing_learned_route_filter_is_not_mutated(self) -> None:
        table = SimpleNamespace(
            Columns=["IPv6 Prefix"],
            Values=[["2001:db8:100::/64"]],
        )
        peer = SimpleNamespace(
            FilterIpV6Unicast=SimpleNamespace(
                Values=["true"], Single=MagicMock()
            ),
            GetIPv6LearnedInfo=MagicMock(),
            LearnedInfo=SimpleNamespace(find=MagicMock(return_value=SimpleNamespace(
                State="ready",
                Table=SimpleNamespace(find=MagicMock(return_value=[table])),
            ))),
        )
        ixia = MagicMock()
        ixia.find_bgp_ipv6_peer.return_value = peer
        task = RbbIxiaBgpLearnedRoutesTask(ixia=ixia, logger=MagicMock())

        await task.run(
            {
                "port_identifier": "r2.example:eth1/5",
                "expected_prefixes": ["2001:db8:100::/64"],
            }
        )

        peer.FilterIpV6Unicast.Single.assert_not_called()
        ixia.apply_changes.assert_not_called()

    async def test_primary_and_filter_restoration_failures_are_both_reported(
        self,
    ) -> None:
        filter_single = MagicMock(
            side_effect=[None, RuntimeError("restore failed")]
        )
        peer = SimpleNamespace(
            FilterIpV6Unicast=SimpleNamespace(
                Values=[False], Single=filter_single
            ),
            GetIPv6LearnedInfo=MagicMock(
                side_effect=RuntimeError("refresh failed")
            ),
            LearnedInfo=SimpleNamespace(find=MagicMock()),
        )
        ixia = MagicMock()
        ixia.find_bgp_ipv6_peer.return_value = peer
        task = RbbIxiaBgpLearnedRoutesTask(ixia=ixia, logger=MagicMock())

        with self.assertRaises(ExceptionGroup) as raised:
            await task.run(
                {
                    "port_identifier": "r2.example:eth1/5",
                    "expected_prefixes": ["2001:db8:100::/64"],
                }
            )

        self.assertEqual(len(raised.exception.exceptions), 2)
        messages = [str(error) for error in raised.exception.exceptions]
        self.assertTrue(any("failed to refresh" in message for message in messages))
        self.assertTrue(any("failed to restore" in message for message in messages))
        self.assertEqual(
            filter_single.call_args_list,
            [unittest.mock.call(True), unittest.mock.call(False)],
        )

    async def test_ambiguous_filter_enable_failure_attempts_restore(self) -> None:
        filter_single = MagicMock(
            side_effect=[RuntimeError("enable response lost"), None]
        )
        peer = SimpleNamespace(
            FilterIpV6Unicast=SimpleNamespace(
                Values=[False], Single=filter_single
            ),
            GetIPv6LearnedInfo=MagicMock(),
            LearnedInfo=SimpleNamespace(find=MagicMock()),
        )
        ixia = MagicMock()
        ixia.find_bgp_ipv6_peer.return_value = peer
        task = RbbIxiaBgpLearnedRoutesTask(ixia=ixia, logger=MagicMock())

        with self.assertRaisesRegex(TestCaseFailure, "failed to enable"):
            await task.run(
                {
                    "port_identifier": "r2.example:eth1/5",
                    "expected_prefixes": ["2001:db8:100::/64"],
                }
            )

        self.assertEqual(
            filter_single.call_args_list,
            [unittest.mock.call(True), unittest.mock.call(False)],
        )
        ixia.apply_changes.assert_called_once_with()

    async def test_cancellation_is_preserved_when_filter_restoration_fails(
        self,
    ) -> None:
        filter_single = MagicMock(
            side_effect=[None, RuntimeError("restore failed")]
        )
        peer = SimpleNamespace(
            FilterIpV6Unicast=SimpleNamespace(
                Values=[False], Single=filter_single
            ),
            GetIPv6LearnedInfo=MagicMock(side_effect=asyncio.CancelledError()),
            LearnedInfo=SimpleNamespace(find=MagicMock()),
        )
        ixia = MagicMock()
        ixia.find_bgp_ipv6_peer.return_value = peer
        task = RbbIxiaBgpLearnedRoutesTask(ixia=ixia, logger=MagicMock())

        with self.assertRaises(asyncio.CancelledError) as raised:
            await task.run(
                {
                    "port_identifier": "r2.example:eth1/5",
                    "expected_prefixes": ["2001:db8:100::/64"],
                }
            )

        self.assertTrue(
            any(
                "filter restoration also failed" in note
                for note in getattr(raised.exception, "__notes__", ())
            )
        )
        self.assertEqual(
            filter_single.call_args_list,
            [unittest.mock.call(True), unittest.mock.call(False)],
        )

    async def test_nonfinite_poll_timing_is_rejected(self) -> None:
        task = RbbIxiaBgpLearnedRoutesTask(ixia=MagicMock(), logger=MagicMock())

        for field, value in (
            ("timeout_seconds", float("nan")),
            ("timeout_seconds", float("inf")),
            ("poll_interval_seconds", float("-inf")),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaisesRegex(ValueError, "positive finite"):
                    await task.run(
                        {
                            "port_identifier": "r2.example:eth1/5",
                            "expected_prefixes": ["2001:db8:100::/64"],
                            field: value,
                        }
                    )

    async def test_unsupported_learned_info_backend_fails_closed(self) -> None:
        peer = SimpleNamespace(GetIPv6LearnedInfo=MagicMock())
        ixia = SimpleNamespace(
            find_bgp_ipv6_peer=MagicMock(return_value=peer),
            apply_changes=MagicMock(),
        )
        task = RbbIxiaBgpLearnedRoutesTask(ixia=ixia, logger=MagicMock())

        with self.assertRaisesRegex(TestCaseFailure, "missing methods"):
            await task.run(
                {
                    "port_identifier": "r2.example:eth1/5",
                    "expected_prefixes": ["2001:db8:100::/64"],
                }
            )

        ixia.apply_changes.assert_not_called()
        peer.GetIPv6LearnedInfo.assert_not_called()

    async def test_otg_backend_reports_learned_routes_as_unsupported(self) -> None:
        otg = OtgTrafficGen.__new__(OtgTrafficGen)
        task = RbbIxiaBgpLearnedRoutesTask(ixia=otg, logger=MagicMock())

        with self.assertRaisesRegex(
            TestCaseFailure, "requires the RESTPy/TaacIxia backend"
        ):
            await task.run(
                {
                    "port_identifier": "r2.example:eth1/5",
                    "expected_prefixes": ["2001:db8:100::/64"],
                }
            )


if __name__ == "__main__":
    unittest.main()
