# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Entry point for the device-only named SRv6 NHG lifecycle suite.

Run through ``scripts/run-rbb-srv6.sh --suite named-nhg-lifecycle``. TC-02
programs and verifies an exact named NHG/NHE plus route. TC-06 and TC-07 run
only on FBOSS versions that retain missing-NHG forward references; versions
that reject the reference report those playbooks as SKIPPED.
"""

from taac.testconfigs.routing.factories.qual_rbb.rbb_named_nhg_test_config import (
    create_rbb_named_nhg_test_config,
)

test_config = create_rbb_named_nhg_test_config()
