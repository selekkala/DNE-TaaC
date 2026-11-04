# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Runner wrapper for Phase-1 RBB IPv4 and dual-stack traffic cases.

The suite always reserves the two IXIA edges.  IPv4 addressing is supplied by
``TAAC_RBB_IXIA_*_V4`` variables (allowlisted defaults are available),
while physical wiring and credentials remain adopter-owned runtime inputs.
"""

from taac.testconfigs.routing.factories.qual_rbb.rbb_dual_stack_traffic_test_config import (
    create_rbb_dual_stack_traffic_test_config,
)

test_config = create_rbb_dual_stack_traffic_test_config()
