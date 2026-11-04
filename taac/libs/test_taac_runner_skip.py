# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe

"""Regression tests for deliberate playbook-stage skips."""

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from taac.health_check.health_check import types as hc_types
from taac.libs.taac_runner import TaacRunner
from taac.steps.step import TestbedError
from taac.test_as_a_config import types as taac_types
from taac.utils.taac_test_summary import SectionStatus


class TaacRunnerSkipTest(unittest.IsolatedAsyncioTestCase):
    async def test_skip_marks_stage_skipped_without_hiding_exception(self) -> None:
        runner = MagicMock(spec=TaacRunner)
        runner.logger = MagicMock()
        runner.test_summary = MagicMock()
        section = MagicMock()
        runner.test_summary.start_section.return_value = section
        playbook_section = MagicMock()
        runner._current_playbook_section = playbook_section
        runner._get_stage_display_name.return_value = "unsupported feature"
        skip = unittest.SkipTest("forward references unsupported")
        runner.initialize_and_run_steps = AsyncMock(side_effect=skip)

        stage = taac_types.Stage(
            id="unsupported-feature",
            steps=[],
            iteration=1,
        )
        with self.assertRaises(unittest.SkipTest) as raised:
            await TaacRunner.async_run_stage(
                runner,
                stage,
                SimpleNamespace(name="dut1"),
                "skip-test",
                1,
                [],
            )

        self.assertIs(raised.exception, skip)
        runner.test_summary.end_section.assert_called_once_with(
            section,
            SectionStatus.SKIPPED,
            "forward references unsupported",
        )
        self.assertEqual(playbook_section.status, SectionStatus.SKIPPED)
        self.assertEqual(
            playbook_section.error_message, "forward references unsupported"
        )

    def test_clean_teardown_preserves_skipped_playbook_section(self) -> None:
        runner = MagicMock(spec=TaacRunner)
        runner.test_summary = MagicMock()
        section = MagicMock(
            status=SectionStatus.SKIPPED,
            error_message="forward references unsupported",
        )
        runner._current_playbook_section = section

        TaacRunner._finalize_playbook_section(runner, [], [])

        runner.test_summary.end_section.assert_called_once_with(
            section,
            SectionStatus.SKIPPED,
            "forward references unsupported",
        )

    def test_teardown_failure_overrides_skipped_playbook_section(self) -> None:
        runner = MagicMock(spec=TaacRunner)
        runner.test_summary = MagicMock()
        section = MagicMock(
            status=SectionStatus.SKIPPED,
            error_message="forward references unsupported",
        )
        runner._current_playbook_section = section

        TaacRunner._finalize_playbook_section(
            runner,
            [RuntimeError("cleanup failed")],
            [],
        )

        runner.test_summary.end_section.assert_called_once_with(
            section,
            SectionStatus.FAIL,
            "cleanup failed",
        )

    def test_clean_skip_overrides_pass_or_empty_check_results(self) -> None:
        skip = unittest.SkipTest("forward references unsupported")

        for results in (
            [],
            [SimpleNamespace(status=hc_types.HealthCheckStatus.PASS)],
        ):
            with self.subTest(results=results):
                self.assertEqual(
                    TaacRunner._playbook_status_override(skip, results),
                    hc_types.HealthCheckStatus.SKIP,
                )

    def test_skip_does_not_override_failed_check_result(self) -> None:
        results = [SimpleNamespace(status=hc_types.HealthCheckStatus.FAIL)]

        self.assertIsNone(
            TaacRunner._playbook_status_override(
                unittest.SkipTest("unsupported"),
                results,
            )
        )

    def test_late_cleanup_failure_overrides_skipped_section(self) -> None:
        section = SimpleNamespace(
            status=SectionStatus.SKIPPED,
            error_message="forward references unsupported",
        )

        TaacRunner._mark_skipped_section_cleanup_failure(
            section,
            RuntimeError("cleanup failed"),
        )

        self.assertEqual(section.status, SectionStatus.FAIL)
        self.assertEqual(
            section.error_message,
            "forward references unsupported; Cleanup failed: cleanup failed",
        )

    def test_late_infrastructure_cleanup_failure_is_not_downgraded(self) -> None:
        section = SimpleNamespace(
            status=SectionStatus.SKIPPED,
            error_message="forward references unsupported",
        )

        TaacRunner._mark_skipped_section_cleanup_failure(
            section,
            TestbedError("testbed unsafe"),
        )

        self.assertEqual(section.status, SectionStatus.INFRA_ERROR)
        self.assertIn("Cleanup failed: testbed unsafe", section.error_message)

    def test_late_cleanup_does_not_rewrite_existing_failure(self) -> None:
        section = SimpleNamespace(
            status=SectionStatus.FAIL,
            error_message="original failure",
        )

        TaacRunner._mark_skipped_section_cleanup_failure(
            section,
            RuntimeError("cleanup failed"),
        )

        self.assertEqual(section.status, SectionStatus.FAIL)
        self.assertEqual(section.error_message, "original failure")


if __name__ == "__main__":
    unittest.main()
