"""OSS runner wrapper for Phase-2 TC-24 final-uSID decapsulation.

TC-24 always reserves IXIA because its acceptance evidence includes no-loss
traffic plus R1 core-egress and R2 post-decap edge-egress counter deltas.  The
factory therefore requires explicit ``circuit_info.csv`` wiring and refuses the
documentation-only placeholder topology.

Example::

    TAAC_RBB_INCLUDE_TRAFFIC=1 python3 -m taac.runner.oss_entry_point \
        --test-configs examples/rbb_srv6_tail_decap_config.py \
        --device-info-csv .taac/device_info.csv \
        --circuit-info-csv .taac/circuit_info.csv \
        --ixia-api-server "$TAAC_IXIA_API_SERVER" \
        --dut "$TAAC_RBB_R1_HOST" "$TAAC_RBB_R2_HOST"

Credentials come from the optional runner secrets file or existing
``TAAC_SSH_*`` / ``TAAC_IXIA_*`` environment variables.  No lab address,
credential, chassis, or physical port is committed in this wrapper.
"""

from taac.testconfigs.routing.factories.qual_rbb.rbb_srv6_tail_decap_test_config import (
    create_rbb_srv6_tail_decap_test_config,
)

test_config = create_rbb_srv6_tail_decap_test_config()
