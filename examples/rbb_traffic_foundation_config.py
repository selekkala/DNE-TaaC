# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""OSS entry point for Phase-1 RBB bidirectional traffic foundations.

Run through ``taac.runner.oss_entry_point`` with the normal RBB device,
circuit, environment, and secret inputs.  Selecting this example explicitly
opts into the two declared IXIA ports; DUT configuration is still read-only
unless the existing bootstrap/edge-setup flags are enabled.
"""

from taac.testconfigs.routing.factories.qual_rbb.rbb_traffic_foundation_test_config import (
    create_rbb_traffic_foundation_test_config,
)

test_config = create_rbb_traffic_foundation_test_config()
