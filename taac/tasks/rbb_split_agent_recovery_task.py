# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Fail-safe split-agent recovery for RBB warmboot cleanup.

``Service.AGENT`` is the correct *restart* primitive in OSS because the FBOSS
driver expands it into warmboot-safe split-agent sequencing.  It is not a safe
cleanup *start* primitive: its systemd name is the monolithic ``wedge_agent``
unit, which pure-OSS split-agent images do not provide.

This task therefore names the split units directly.  It starts every selected
HW agent, waits until its Thrift service is ready, then starts the SW agent and
waits until the switch is configured.  ``systemctl start`` is idempotent, so
the same cleanup is safe when the warmboot already completed successfully.
"""

from __future__ import annotations

import typing as t

from taac.driver.driver_constants import FbossSystemctlServiceName
from taac.tasks.base_task import BaseTask
from taac.utils.driver_factory import async_get_device_driver
from taac.utils.oss_taac_lib_utils import ConsoleFileLogger


def _positive_int(value: t.Any, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


class RbbSplitAgentRecoveryTask(BaseTask):
    """Ensure split FBOSS agents are running in dependency-safe order."""

    # pyrefly: ignore [bad-override-mutable-attribute]
    NAME: str = "rbb_split_agent_recovery"

    def __init__(
        self,
        hostname: str | None = None,
        description: str | None = None,
        ixia: t.Any | None = None,
        logger: ConsoleFileLogger | None = None,
        shared_data: dict[t.Any, t.Any] | None = None,
    ) -> None:
        super().__init__(hostname, description, ixia, logger, shared_data)

    async def run(self, params: dict[str, t.Any]) -> None:
        unknown = sorted(
            set(params)
            - {
                "hostname",
                "hw_agent_indices",
                "hw_ready_timeout_seconds",
                "sw_ready_timeout_seconds",
            }
        )
        if unknown:
            raise ValueError(
                f"rbb_split_agent_recovery contains unsupported fields: {unknown}"
            )
        hostname = params.get("hostname") or self.hostname
        if not hostname:
            raise ValueError("rbb_split_agent_recovery requires 'hostname'")

        raw_indices = params.get("hw_agent_indices", [0])
        if (
            not isinstance(raw_indices, list)
            or not raw_indices
            or any(type(index) is not int or index < 0 for index in raw_indices)
            or len(set(raw_indices)) != len(raw_indices)
        ):
            raise ValueError(
                "hw_agent_indices must be a nonempty list of unique "
                "non-negative integers"
            )
        indices = sorted(raw_indices)
        hw_timeout = _positive_int(
            params.get("hw_ready_timeout_seconds", 180),
            "hw_ready_timeout_seconds",
        )
        sw_timeout = _positive_int(
            params.get("sw_ready_timeout_seconds", 180),
            "sw_ready_timeout_seconds",
        )

        driver = await async_get_device_driver(hostname)
        supported = driver.HW_AGENT_SERVICE_BY_INDEX
        missing = [index for index in indices if index not in supported]
        if missing:
            raise ValueError(
                f"unsupported HW agent indices {missing}; supported indices are "
                f"{sorted(supported)}"
            )

        # Do not use Service.AGENT here: a start maps to the absent monolithic
        # wedge_agent unit.  Starting an already-active split unit is a no-op,
        # which makes this sequence safe on both success and failure cleanup.
        for index in indices:
            await driver.async_start_service(supported[index])
            await driver.async_wait_for_hw_agent_ready(
                switch_index=index,
                timeout=hw_timeout,
            )

        await driver.async_start_service(FbossSystemctlServiceName.FBOSS_SW_AGENT)
        await driver.async_wait_for_agent_configured(sw_timeout)
        self.logger.info(
            f"{hostname} -- split-agent recovery complete for HW indices {indices}"
        )


__all__ = ["RbbSplitAgentRecoveryTask"]
