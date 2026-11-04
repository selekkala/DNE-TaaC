# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Playbook-scoped, best-effort cleanup for RBB SRv6 tests.

TAAC executes cleanup steps sequentially and stops the list when one step
raises.  RBB playbooks have independent resources to restore (DUT services,
interfaces, temporary routes, and IXIA traffic), so one failure must not hide
the remaining cleanup actions.

This registered task also supplies mutation markers.  A playbook arms a marker
immediately before a disruptive step and disarms it only after recovery is
verified.  Cleanup operations carrying that marker are skipped when the
disruption was never reached.  ``shared_data`` is scoped to one playbook by the
runner, so markers cannot leak into a later test case.
"""

from __future__ import annotations

import asyncio
import typing as t

from taac.constants import TestCaseFailure
from taac.driver.driver_constants import FbossSystemctlServiceName
from taac.tasks.base_task import BaseTask
from taac.tasks.rbb_input_validation import validated_fboss_interface_names
from taac.tasks.rbb_openr_core_path_task import RbbOpenrCorePathTask
from taac.tasks.rbb_split_agent_recovery_task import RbbSplitAgentRecoveryTask
from taac.tasks.rbb_srv6_direct_route_task import RbbSrv6DirectRouteTask
from taac.utils.driver_factory import async_get_device_driver
from taac.utils.oss_taac_lib_utils import ConsoleFileLogger

_ARM = "arm"
_DISARM = "disarm"
_CLEANUP = "cleanup"

_START_SERVICE = "start_service"
_RECOVER_SPLIT_AGENT = "recover_split_agent"
_ENABLE_INTERFACES = "enable_interfaces"
_DELETE_DIRECT_ROUTE = "delete_direct_route"
_STOP_TRAFFIC = "stop_traffic"
_RESTORE_OPENR_CORE_PATH = "restore_openr_core_path"

_SUPPORTED_OPERATIONS = frozenset(
    {
        _START_SERVICE,
        _RECOVER_SPLIT_AGENT,
        _ENABLE_INTERFACES,
        _DELETE_DIRECT_ROUTE,
        _STOP_TRAFFIC,
        _RESTORE_OPENR_CORE_PATH,
    }
)


def _required_string(value: t.Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a nonempty string")
    return value.strip()


class RbbBestEffortCleanupTask(BaseTask):
    """Guard and run independent RBB cleanup operations."""

    # pyrefly: ignore [bad-override-mutable-attribute]
    NAME: str = "rbb_best_effort_cleanup"

    def __init__(
        self,
        hostname: str | None = None,
        description: str | None = None,
        ixia: t.Any | None = None,
        logger: ConsoleFileLogger | None = None,
        shared_data: dict[t.Any, t.Any] | None = None,
    ) -> None:
        super().__init__(hostname, description, ixia, logger, shared_data)

    @staticmethod
    def _marker_key(marker: str) -> str:
        return f"armed:{marker}"

    def _is_armed(self, marker: str) -> bool:
        key = self._marker_key(marker)
        return key in self._data and self._data[key] is True

    def _set_marker(self, marker: str, armed: bool) -> None:
        self._data[self._marker_key(marker)] = armed

    @staticmethod
    def _validate_operation(raw: t.Any, index: int) -> dict[str, t.Any]:
        if not isinstance(raw, dict):
            raise TypeError(f"operations[{index}] must be a JSON object")
        operation = dict(raw)
        operation_type = _required_string(
            operation.get("type"), f"operations[{index}].type"
        )
        if operation_type not in _SUPPORTED_OPERATIONS:
            raise ValueError(
                f"operations[{index}].type {operation_type!r} is unsupported"
            )
        operation["type"] = operation_type

        marker = operation.get("marker")
        if marker is not None:
            operation["marker"] = _required_string(
                marker, f"operations[{index}].marker"
            )
        if (
            operation_type
            in {
                _START_SERVICE,
                _RECOVER_SPLIT_AGENT,
                _ENABLE_INTERFACES,
            }
            and marker is None
        ):
            raise ValueError(
                f"cleanup operation {operation_type!r} requires an armed marker"
            )

        if operation_type == _STOP_TRAFFIC:
            allowed = {"type", "marker"}
        elif operation_type == _RESTORE_OPENR_CORE_PATH:
            _required_string(operation.get("hostname"), "hostname")
            _required_string(operation.get("sample_id"), "sample_id")
            if "gate" in operation:
                _required_string(operation.get("gate"), "gate")
            allowed = {"type", "marker", "hostname", "sample_id", "gate"}
        elif operation_type == _START_SERVICE:
            _required_string(operation.get("hostname"), "hostname")
            service = _required_string(operation.get("service"), "service")
            if service not in FbossSystemctlServiceName.__members__:
                raise ValueError(f"unknown FBOSS service {service!r}")
            operation["service"] = service
            allowed = {"type", "marker", "hostname", "service"}
        elif operation_type == _ENABLE_INTERFACES:
            _required_string(operation.get("hostname"), "hostname")
            operation["interfaces"] = validated_fboss_interface_names(
                operation.get("interfaces"), "interfaces"
            )
            allowed = {"type", "marker", "hostname", "interfaces"}
        elif operation_type == _RECOVER_SPLIT_AGENT:
            _required_string(operation.get("hostname"), "hostname")
            allowed = {
                "type",
                "marker",
                "hostname",
                "hw_agent_indices",
                "hw_ready_timeout_seconds",
                "sw_ready_timeout_seconds",
            }
        else:
            # RbbSrv6DirectRouteTask owns detailed validation, including the
            # per-run ownership marker that protects pre-existing routes.
            _required_string(operation.get("hostname"), "hostname")
            _required_string(operation.get("prefix"), "prefix")
            allowed = {
                "type",
                "marker",
                "hostname",
                "prefix",
                "client",
                "srv6_segments",
                "srv6_tunnel_id",
            }

        unknown = sorted(set(operation) - allowed)
        if unknown:
            raise ValueError(
                f"cleanup operation {operation_type!r} has unsupported fields: "
                f"{unknown}"
            )
        return operation

    async def _run_operation(self, operation: dict[str, t.Any]) -> None:
        operation_type = operation["type"]
        if operation_type == _STOP_TRAFFIC:
            self.ixia.stop_traffic()
            return

        if operation_type == _RESTORE_OPENR_CORE_PATH:
            task = RbbOpenrCorePathTask(
                hostname=operation["hostname"],
                ixia=self._ixia,
                logger=self.logger,
                shared_data=self._shared_data,
            )
            await task.run(
                {
                    "action": "restore",
                    "hostname": operation["hostname"],
                    "sample_id": operation["sample_id"],
                    "gate": operation.get("gate", "rbb_openr_core_path_cleanup"),
                }
            )
            return

        hostname = operation["hostname"]
        if operation_type == _START_SERVICE:
            driver = await async_get_device_driver(hostname)
            await driver.async_start_service(
                FbossSystemctlServiceName[operation["service"]]
            )
            return

        if operation_type == _ENABLE_INTERFACES:
            driver = await async_get_device_driver(hostname)
            await driver.async_enable_ports_via_ssh(operation["interfaces"], True)
            return

        if operation_type == _RECOVER_SPLIT_AGENT:
            task = RbbSplitAgentRecoveryTask(
                hostname=hostname,
                ixia=self._ixia,
                logger=self.logger,
                shared_data=self._shared_data,
            )
            params = {
                key: value
                for key, value in operation.items()
                if key not in {"type", "marker"}
            }
            await task.run(params)
            return

        task = RbbSrv6DirectRouteTask(
            hostname=hostname,
            ixia=self._ixia,
            logger=self.logger,
            shared_data=self._shared_data,
        )
        params = {
            key: value
            for key, value in operation.items()
            if key not in {"type", "marker"}
        }
        params["action"] = "delete"
        await task.run(params)

    async def run(self, params: dict[str, t.Any]) -> None:
        action = params.get("action")
        if action in {_ARM, _DISARM}:
            unknown = sorted(set(params) - {"action", "marker"})
            if unknown:
                raise ValueError(
                    f"rbb_best_effort_cleanup {action!r} has unsupported fields: "
                    f"{unknown}"
                )
            marker = _required_string(params.get("marker"), "marker")
            self._set_marker(marker, action == _ARM)
            self.logger.info(
                f"RBB cleanup marker {marker!r} "
                f"{'armed' if action == _ARM else 'disarmed'}"
            )
            return

        if action != _CLEANUP:
            raise ValueError(
                "rbb_best_effort_cleanup action must be 'arm', 'disarm', or "
                f"'cleanup', got {action!r}"
            )
        unknown = sorted(set(params) - {"action", "operations"})
        if unknown:
            raise ValueError(
                f"rbb_best_effort_cleanup cleanup has unsupported fields: {unknown}"
            )
        raw_operations = params.get("operations")
        if not isinstance(raw_operations, list) or not raw_operations:
            raise ValueError("cleanup operations must be a nonempty list")

        # Validate the complete plan before the first side effect.
        operations = [
            self._validate_operation(operation, index)
            for index, operation in enumerate(raw_operations)
        ]
        failures: list[str] = []
        cancellation: asyncio.CancelledError | None = None
        for index, operation in enumerate(operations):
            marker = operation.get("marker")
            if marker is not None and not self._is_armed(marker):
                self.logger.info(
                    f"Cleanup [{index}] {operation['type']} skipped: marker "
                    f"{marker!r} is not armed"
                )
                continue
            try:
                await self._run_operation(operation)
            except asyncio.CancelledError as exc:
                message = (
                    f"[{index}] {operation['type']}: cleanup cancellation requested"
                )
                if cancellation is None:
                    cancellation = exc
                else:
                    cancellation.add_note(
                        "An additional cleanup action was cancelled: " + message
                    )
                self.logger.exception(
                    f"RBB cleanup was cancelled but will continue: {message}"
                )
            except Exception as exc:
                message = f"[{index}] {operation['type']}: {exc}"
                failures.append(message)
                self.logger.exception(
                    f"RBB cleanup failed but will continue: {message}"
                )

        if cancellation is not None:
            cancellation.add_note(
                "RBB cleanup cancellation was deferred until every independent "
                "eligible action was attempted."
            )
            if failures:
                cancellation.add_note(
                    "Additional cleanup failure(s): " + "; ".join(failures)
                )
            raise cancellation

        if failures:
            raise TestCaseFailure(
                "RBB cleanup completed with failure(s); every independent action "
                "was attempted: " + "; ".join(failures)
            )


__all__ = ["RbbBestEffortCleanupTask"]
