# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Bounded convergence tests for the reusable RBB state audit task."""

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from taac.constants import TestCaseFailure
from taac.tasks.rbb_state_audit_task import RbbStateAuditTask

_MODULE = "taac.tasks.rbb_state_audit_task"


class RbbStateAuditRetryTest(unittest.IsolatedAsyncioTestCase):
    async def test_retries_transient_state_until_exact_snapshot_passes(self) -> None:
        task = RbbStateAuditTask(hostname="rbb-r1", logger=MagicMock())
        task._run_once = AsyncMock(side_effect=[TestCaseFailure("not converged"), None])

        with (
            patch(f"{_MODULE}.time.monotonic", return_value=0),
            patch(f"{_MODULE}.asyncio.sleep", new_callable=AsyncMock) as sleep,
        ):
            await task.run(
                {
                    "interfaces_up": ["eth1/1"],
                    "timeout_seconds": 30,
                    "poll_interval_seconds": 2,
                }
            )

        self.assertEqual(task._run_once.await_count, 2)
        sleep.assert_awaited_once_with(2.0)
        forwarded = task._run_once.await_args_list[0].args[0]
        self.assertNotIn("timeout_seconds", forwarded)
        self.assertNotIn("poll_interval_seconds", forwarded)

    async def test_default_single_snapshot_does_not_retry(self) -> None:
        task = RbbStateAuditTask(hostname="rbb-r1", logger=MagicMock())
        task._run_once = AsyncMock(side_effect=TestCaseFailure("failed"))

        with self.assertRaisesRegex(TestCaseFailure, "failed"):
            await task.run({"interfaces_up": ["eth1/1"]})

        task._run_once.assert_awaited_once()

    async def test_invalid_retry_bounds_are_rejected_before_device_access(self) -> None:
        task = RbbStateAuditTask(hostname="rbb-r1", logger=MagicMock())
        for params, message in (
            ({"timeout_seconds": -1}, "non-negative"),
            ({"poll_interval_seconds": 0}, "positive"),
            ({"timeout_seconds": True}, "finite number"),
            ({"poll_interval_seconds": float("nan")}, "finite number"),
            ({"timeout_seconds": float("inf")}, "finite number"),
        ):
            with (
                self.subTest(params=params),
                self.assertRaisesRegex(ValueError, message),
            ):
                await task.run({"interfaces_up": ["eth1/1"], **params})


if __name__ == "__main__":
    unittest.main()
