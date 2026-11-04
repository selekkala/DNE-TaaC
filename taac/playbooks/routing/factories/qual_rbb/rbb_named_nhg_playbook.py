# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Device-only playbooks for the named SRv6 NHG lifecycle.

Each playbook owns a complete transaction and leaves no dependency for a later
playbook. TC-07 therefore recreates TC-06's forward reference before adding
the group. On an FBOSS version that rejects forward references, the registered
task raises ``unittest.SkipTest`` and cleanup still verifies pristine state.
"""

from __future__ import annotations

import re
import typing as t

from taac.stages.stage_definitions import create_steps_stage
from taac.steps.step_definitions import create_run_task_step
from taac.test_as_a_config.types import Playbook, Step
from taac.testconfigs.routing.util.bgp_rbb_named_nhg_profiles import (
    RbbNamedNhgAction,
    RbbNamedNhgProfile,
)

_TASK_NAME = "rbb_srv6_named_nhg"


def _step(
    profile: RbbNamedNhgProfile,
    hostname: str,
    action: str,
    *,
    include_members: bool = False,
    expected_programmed: bool | None = None,
) -> Step:
    params = {
        "hostname": hostname,
        "action": action,
        **profile.task_params(include_members=include_members),
    }
    if expected_programmed is not None:
        params["expected_programmed"] = expected_programmed
    return create_run_task_step(
        task_name=_TASK_NAME,
        params_dict=params,
        description=f"[{profile.testplan_id}] {action} named SRv6 NHG lifecycle",
        start_traffic=False,
    )


def _stage(profile: RbbNamedNhgProfile, step: Step, label: str) -> t.Any:
    return create_steps_stage(
        steps=[step],
        description=f"{profile.testplan_id}: {label}",
    )


def _tc02_stages(profile: RbbNamedNhgProfile, hostname: str) -> list[t.Any]:
    return [
        _stage(
            profile,
            _step(profile, hostname, "precheck"),
            "refuse pre-existing test-owned names",
        ),
        _stage(
            profile,
            _step(profile, hostname, "program_nhg", include_members=True),
            "program the named SRv6 NHG and exact SID-list NHEs",
        ),
        _stage(
            profile,
            _step(
                profile,
                hostname,
                "verify_nhg",
                include_members=True,
            ),
            "verify exact unreferenced group and NHE readback",
        ),
        _stage(
            profile,
            _step(profile, hostname, "program_route"),
            "add a TE_AGENT route that references the named group",
        ),
        _stage(
            profile,
            _step(
                profile,
                hostname,
                "verify_nhg",
                include_members=True,
                expected_programmed=True,
            ),
            "verify the referenced group is programmed",
        ),
        _stage(
            profile,
            _step(profile, hostname, "verify_programmed"),
            "verify exact route ownership and resolved agent-FIB next hops",
        ),
    ]


def _tc06_stages(profile: RbbNamedNhgProfile, hostname: str) -> list[t.Any]:
    return [
        _stage(
            profile,
            _step(profile, hostname, "precheck"),
            "refuse pre-existing test-owned names",
        ),
        _stage(
            profile,
            _step(profile, hostname, "install_forward_ref"),
            "install the route before its named group or SKIP if unsupported",
        ),
        _stage(
            profile,
            _step(profile, hostname, "verify_rib_only"),
            "verify the TE_AGENT candidate is retained without resolved next hops",
        ),
    ]


def _tc07_stages(profile: RbbNamedNhgProfile, hostname: str) -> list[t.Any]:
    return [
        _stage(
            profile,
            _step(profile, hostname, "precheck"),
            "refuse pre-existing test-owned names",
        ),
        _stage(
            profile,
            _step(profile, hostname, "install_forward_ref"),
            "independently stage the forward reference or SKIP if unsupported",
        ),
        _stage(
            profile,
            _step(profile, hostname, "verify_rib_only"),
            "verify the unresolved route is RIB-only before NHG creation",
        ),
        _stage(
            profile,
            _step(profile, hostname, "program_nhg", include_members=True),
            "add the missing named SRv6 NHG",
        ),
        _stage(
            profile,
            _step(
                profile,
                hostname,
                "verify_nhg",
                include_members=True,
                expected_programmed=True,
            ),
            "verify exact NHE readback and programmed state",
        ),
        _stage(
            profile,
            _step(profile, hostname, "verify_programmed"),
            "verify the retained route transitioned into the resolved agent FIB",
        ),
    ]


def create_rbb_named_nhg_playbook(
    profile: RbbNamedNhgProfile,
    *,
    r1_hostname: str,
) -> Playbook:
    """Build one self-cleaning TC-02, TC-06, or TC-07 playbook."""
    if not r1_hostname.strip():
        raise ValueError("named-NHG playbook requires the R1 hostname")
    if profile.action is RbbNamedNhgAction.PROGRAM_AND_VERIFY:
        stages = _tc02_stages(profile, r1_hostname)
    elif profile.action is RbbNamedNhgAction.FORWARD_REFERENCE:
        stages = _tc06_stages(profile, r1_hostname)
    elif profile.action is RbbNamedNhgAction.RESOLVE_FORWARD_REFERENCE:
        stages = _tc07_stages(profile, r1_hostname)
    else:  # pragma: no cover - frozen enum exhaustiveness guard
        raise ValueError(f"unsupported named-NHG action {profile.action!r}")

    support_note = (
        " Forward-reference rejection is reported as SKIP, not PASS."
        if profile.requires_forward_reference_support
        else ""
    )
    limitation_note = (
        " Limitations: " + "; ".join(profile.unmet_requirements) + "."
        if profile.unmet_requirements
        else ""
    )
    return Playbook(
        name=profile.playbook_name,
        description=(
            f"{profile.testplan_id} [{profile.coverage.value.upper()}]: "
            f"{profile.title}.{support_note}{limitation_note}"
        ),
        prechecks=[],
        postchecks=[],
        stages=stages,
        cleanup_steps=[_step(profile, r1_hostname, "cleanup", include_members=True)],
        traffic_items_to_start=None,
        device_regexes=[f"^{re.escape(r1_hostname)}$"],
    )


__all__ = ["create_rbb_named_nhg_playbook"]
