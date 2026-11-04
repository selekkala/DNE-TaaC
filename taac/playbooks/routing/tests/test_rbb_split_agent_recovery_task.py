# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Unit tests for dependency-safe RBB split-agent cleanup."""

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from taac.driver.driver_constants import FbossSystemctlServiceName
from taac.tasks.rbb_split_agent_recovery_task import RbbSplitAgentRecoveryTask

_DRIVER_PATH = "taac.tasks.rbb_split_agent_recovery_task.async_get_device_driver"


class RbbSplitAgentRecoveryTaskTest(unittest.IsolatedAsyncioTestCase):
    def test_task_is_registered(self) -> None:
        from taac.tasks.registry import TASK_NAME_TO_CLASS

        self.assertIs(
            TASK_NAME_TO_CLASS["rbb_split_agent_recovery"],
            RbbSplitAgentRecoveryTask,
        )

    def _driver(self, events: list[str]) -> MagicMock:
        driver = MagicMock()
        driver.HW_AGENT_SERVICE_BY_INDEX = {
            0: FbossSystemctlServiceName.FBOSS_HW_AGENT_0,
            1: FbossSystemctlServiceName.FBOSS_HW_AGENT_1,
        }

        async def start(service):
            events.append(f"start:{service.value}")

        async def wait_hw(*, switch_index, timeout):
            events.append(f"wait-hw:{switch_index}:{timeout}")
            return 1000 + switch_index

        async def wait_sw(timeout):
            events.append(f"wait-sw:{timeout}")

        driver.async_start_service = AsyncMock(side_effect=start)
        driver.async_wait_for_hw_agent_ready = AsyncMock(side_effect=wait_hw)
        driver.async_wait_for_agent_configured = AsyncMock(side_effect=wait_sw)
        return driver

    async def test_recovery_is_ordered_and_safe_to_repeat(self) -> None:
        events: list[str] = []
        driver = self._driver(events)
        task = RbbSplitAgentRecoveryTask(hostname="rbb-r1", logger=MagicMock())
        params = {
            "hostname": "rbb-r1",
            "hw_agent_indices": [1, 0],
            "hw_ready_timeout_seconds": 90,
            "sw_ready_timeout_seconds": 120,
        }
        expected = [
            "start:fboss_hw_agent@0",
            "wait-hw:0:90",
            "start:fboss_hw_agent@1",
            "wait-hw:1:90",
            "start:fboss_sw_agent",
            "wait-sw:120",
        ]

        with patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=driver):
            await task.run(params)
            await task.run(params)

        self.assertEqual(events, expected + expected)
        self.assertNotIn("start:wedge_agent", events)

    async def test_invalid_params_fail_before_device_contact(self) -> None:
        task = RbbSplitAgentRecoveryTask(hostname="rbb-r1", logger=MagicMock())
        invalid = (
            ({"hw_agent_indices": []}, "nonempty"),
            ({"hw_agent_indices": [0, 0]}, "unique"),
            ({"hw_agent_indices": [True]}, "non-negative integers"),
            ({"hw_ready_timeout_seconds": 0}, "positive integer"),
            ({"unexpected": True}, "unsupported fields"),
        )
        with patch(_DRIVER_PATH, new_callable=AsyncMock) as get_driver:
            for params, message in invalid:
                with (
                    self.subTest(params=params),
                    self.assertRaisesRegex(ValueError, message),
                ):
                    await task.run(params)
        get_driver.assert_not_awaited()

    async def test_unsupported_hw_index_does_not_mutate_services(self) -> None:
        events: list[str] = []
        driver = self._driver(events)
        task = RbbSplitAgentRecoveryTask(hostname="rbb-r1", logger=MagicMock())

        with (
            patch(_DRIVER_PATH, new_callable=AsyncMock, return_value=driver),
            self.assertRaisesRegex(ValueError, "unsupported HW agent indices"),
        ):
            await task.run({"hw_agent_indices": [2]})

        self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main()
