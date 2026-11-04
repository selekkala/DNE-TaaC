# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Failure-path tests for guarded, best-effort RBB cleanup."""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from taac.constants import TestCaseFailure
from taac.driver.driver_constants import FbossSystemctlServiceName
from taac.tasks.rbb_best_effort_cleanup_task import RbbBestEffortCleanupTask

_DRIVER_PATH = "taac.tasks.rbb_best_effort_cleanup_task.async_get_device_driver"
_ROUTE_RUN_PATH = "taac.tasks.rbb_best_effort_cleanup_task.RbbSrv6DirectRouteTask.run"
_OPENR_RESTORE_PATH = "taac.tasks.rbb_best_effort_cleanup_task.RbbOpenrCorePathTask.run"


class RbbBestEffortCleanupTaskTest(unittest.IsolatedAsyncioTestCase):
    def test_task_is_registered(self) -> None:
        from taac.tasks.registry import TASK_NAME_TO_CLASS

        self.assertIs(
            TASK_NAME_TO_CLASS["rbb_best_effort_cleanup"],
            RbbBestEffortCleanupTask,
        )

    async def test_unarmed_dut_cleanup_never_contacts_or_mutates_dut(self) -> None:
        task = RbbBestEffortCleanupTask(
            logger=MagicMock(),
            shared_data={},
        )
        operations = [
            {
                "type": "start_service",
                "marker": "bgp-not-reached",
                "hostname": "r1.example",
                "service": "BGP",
            },
            {
                "type": "enable_interfaces",
                "marker": "outage-not-reached",
                "hostname": "r1.example",
                "interfaces": ["eth1/1"],
            },
        ]

        with patch(_DRIVER_PATH, new_callable=AsyncMock) as get_driver:
            await task.run({"action": "cleanup", "operations": operations})

        get_driver.assert_not_awaited()

    async def test_marker_is_shared_across_registered_task_instances(self) -> None:
        shared_data = {}
        marker = "phase2:TC-104:bgp-restart:r1"
        arm = RbbBestEffortCleanupTask(logger=MagicMock(), shared_data=shared_data)
        cleanup = RbbBestEffortCleanupTask(logger=MagicMock(), shared_data=shared_data)
        driver = MagicMock()
        driver.async_start_service = AsyncMock()

        await arm.run({"action": "arm", "marker": marker})
        with patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=driver):
            await cleanup.run(
                {
                    "action": "cleanup",
                    "operations": [
                        {
                            "type": "start_service",
                            "marker": marker,
                            "hostname": "r1.example",
                            "service": "BGP",
                        }
                    ],
                }
            )

        driver.async_start_service.assert_awaited_once_with(
            FbossSystemctlServiceName.BGP
        )

    async def test_failure_does_not_skip_later_independent_actions(self) -> None:
        shared_data = {}
        task = RbbBestEffortCleanupTask(logger=MagicMock(), shared_data=shared_data)
        await task.run({"action": "arm", "marker": "bgp"})
        await task.run({"action": "arm", "marker": "link"})

        driver = MagicMock()
        driver.async_start_service = AsyncMock(
            side_effect=RuntimeError("bgpd start failed")
        )
        driver.async_enable_ports_via_ssh = AsyncMock()
        operations = [
            {
                "type": "start_service",
                "marker": "bgp",
                "hostname": "r1.example",
                "service": "BGP",
            },
            {
                "type": "enable_interfaces",
                "marker": "link",
                "hostname": "r1.example",
                "interfaces": ["eth1/1", "eth1/2"],
            },
        ]

        with (
            patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=driver),
            self.assertRaisesRegex(TestCaseFailure, "every independent action"),
        ):
            await task.run({"action": "cleanup", "operations": operations})

        driver.async_start_service.assert_awaited_once()
        driver.async_enable_ports_via_ssh.assert_awaited_once_with(
            ["eth1/1", "eth1/2"], True
        )

    async def test_cancellation_is_deferred_until_all_actions_are_attempted(
        self,
    ) -> None:
        task = RbbBestEffortCleanupTask(logger=MagicMock(), shared_data={})
        task._run_operation = AsyncMock(
            side_effect=(
                asyncio.CancelledError("cleanup task cancelled"),
                None,
                RuntimeError("later cleanup failure"),
            )
        )
        operations = [
            {"type": "stop_traffic"},
            {"type": "stop_traffic"},
            {"type": "stop_traffic"},
        ]

        with self.assertRaises(asyncio.CancelledError) as raised:
            await task.run({"action": "cleanup", "operations": operations})

        self.assertEqual(task._run_operation.await_count, len(operations))
        notes = "\n".join(getattr(raised.exception, "__notes__", ()))
        self.assertIn("every independent eligible action was attempted", notes)
        self.assertIn("later cleanup failure", notes)

    async def test_interface_names_are_strictly_validated_before_device_access(
        self,
    ) -> None:
        task = RbbBestEffortCleanupTask(logger=MagicMock(), shared_data={})
        operation = {
            "type": "enable_interfaces",
            "marker": "link",
            "hostname": "r1.example",
        }

        for interface in (
            " eth1/1",
            "eth1/1 ",
            "eth1/1; reboot",
            "eth1/1 eth1/2",
            "$(reboot)",
            "`reboot`",
        ):
            with self.subTest(interface=interface):
                with (
                    patch(_DRIVER_PATH, new_callable=AsyncMock) as get_driver,
                    self.assertRaisesRegex(ValueError, "invalid interface name"),
                ):
                    await task.run(
                        {
                            "action": "cleanup",
                            "operations": [
                                {**operation, "interfaces": [interface]}
                            ],
                        }
                    )
                get_driver.assert_not_awaited()

    async def test_route_delete_failure_still_stops_ixia_traffic(self) -> None:
        ixia = MagicMock()
        task = RbbBestEffortCleanupTask(
            ixia=ixia,
            logger=MagicMock(),
            shared_data={},
        )
        operations = [
            {
                "type": "delete_direct_route",
                "hostname": "r1.example",
                "prefix": "2001:db8:10::/64",
                "client": "TE_AGENT",
            },
            {"type": "stop_traffic"},
        ]

        with (
            patch(
                _ROUTE_RUN_PATH,
                new_callable=AsyncMock,
                side_effect=RuntimeError("route delete failed"),
            ) as route_delete,
            self.assertRaisesRegex(TestCaseFailure, "delete_direct_route"),
        ):
            await task.run({"action": "cleanup", "operations": operations})

        route_delete.assert_awaited_once()
        ixia.stop_traffic.assert_called_once_with()

    async def test_openr_restore_failure_does_not_skip_peer_restore(self) -> None:
        task = RbbBestEffortCleanupTask(logger=MagicMock(), shared_data={})
        operations = [
            {
                "type": "restore_openr_core_path",
                "hostname": "r1.example",
                "sample_id": "tc08:r1",
                "gate": "phase1:TC-08_cleanup",
            },
            {
                "type": "restore_openr_core_path",
                "hostname": "r2.example",
                "sample_id": "tc08:r2",
            },
        ]

        with (
            patch(
                _OPENR_RESTORE_PATH,
                new_callable=AsyncMock,
                side_effect=(RuntimeError("R1 restore failed"), None),
            ) as restore,
            self.assertRaisesRegex(TestCaseFailure, "R1 restore failed"),
        ):
            await task.run({"action": "cleanup", "operations": operations})

        self.assertEqual(restore.await_count, 2)
        first, second = [call.args[0] for call in restore.await_args_list]
        self.assertEqual(first["hostname"], "r1.example")
        self.assertEqual(first["gate"], "phase1:TC-08_cleanup")
        self.assertEqual(second["hostname"], "r2.example")
        self.assertEqual(second["gate"], "rbb_openr_core_path_cleanup")

    async def test_disarmed_marker_preserves_recovered_state(self) -> None:
        shared_data = {}
        task = RbbBestEffortCleanupTask(logger=MagicMock(), shared_data=shared_data)
        await task.run({"action": "arm", "marker": "warmboot"})
        await task.run({"action": "disarm", "marker": "warmboot"})

        with patch(_DRIVER_PATH, new_callable=AsyncMock) as get_driver:
            await task.run(
                {
                    "action": "cleanup",
                    "operations": [
                        {
                            "type": "recover_split_agent",
                            "marker": "warmboot",
                            "hostname": "r1.example",
                            "hw_agent_indices": [0],
                        }
                    ],
                }
            )

        get_driver.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
