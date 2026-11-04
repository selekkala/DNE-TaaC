"""OSS runner wrapper for two-node RBB SRv6 resilience tests.

This is intentionally separate from ``qual_rbb.py`` while the follow-up is
reviewed. It requires explicit live-traffic inputs and never changes BGP timers
or restarts OpenR by default.

Example::

    TAAC_RBB_INCLUDE_TRAFFIC=1 python3 -m taac.runner.oss_entry_point \
        --test-configs examples/rbb_srv6_resilience_config.py \
        --device-info-csv .taac/device_info.csv \
        --circuit-info-csv .taac/circuit_info.csv \
        --ixia-api-server "$TAAC_IXIA_API_SERVER" \
        --dut "$TAAC_RBB_R1_HOST" "$TAAC_RBB_R2_HOST"
"""

import os

from taac.testconfigs.routing.factories.qual_rbb.rbb_resilience_test_config import (
    create_rbb_resilience_test_config,
)
from taac.testconfigs.routing.util.bgp_rbb_resilience_profiles import (
    RESILIENCE_SUITE_TESTPLAN_IDS,
)


def _runtime_options() -> dict[str, object]:
    options: dict[str, object] = {}
    core_name = os.environ.get("TAAC_RBB_RESILIENCE_CORE_PC_NAME", "").strip()
    if core_name:
        options["core_pc_name"] = core_name

    core_index = os.environ.get("TAAC_RBB_RESILIENCE_CORE_PC_INDEX", "").strip()
    if core_index:
        try:
            parsed_index = int(core_index)
        except ValueError as error:
            raise ValueError(
                "TAAC_RBB_RESILIENCE_CORE_PC_INDEX must be a non-negative integer"
            ) from error
        if parsed_index < 0:
            raise ValueError(
                "TAAC_RBB_RESILIENCE_CORE_PC_INDEX must be a non-negative integer"
            )
        options["core_pc_index"] = parsed_index

    max_loss = os.environ.get("TAAC_RBB_RESILIENCE_MAX_LOSS_PCT", "").strip()
    if max_loss:
        options["disruption_loss_threshold_pct"] = max_loss

    min_share = os.environ.get(
        "TAAC_RBB_RESILIENCE_MIN_SELECTED_PATH_SHARE_PCT", ""
    ).strip()
    if min_share:
        try:
            parsed_share = float(min_share)
        except ValueError as error:
            raise ValueError(
                "TAAC_RBB_RESILIENCE_MIN_SELECTED_PATH_SHARE_PCT must be numeric"
            ) from error
        options["selected_path_min_traffic_percent"] = parsed_share
    return options


test_config = create_rbb_resilience_test_config(
    testplan_ids=RESILIENCE_SUITE_TESTPLAN_IDS,
    # TC-30 is executable but coverage-honest: route, End.DT46/MySID, service,
    # and traffic restoration are checked; QoS restoration is not claimed.
    allow_partial=True,
    **_runtime_options(),
)
