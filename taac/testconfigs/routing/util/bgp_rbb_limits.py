# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Resource limits shared by RBB configuration validation and rendering."""

# Traffic-foundation profiles eagerly expand every advertised prefix into
# exact IXIA learned-route and DUT RIB/FIB expectations.  Keep each pool
# bounded so an accidental runtime value cannot exhaust runner memory while
# still allowing the planned 16K-prefix scale coverage.
MAX_RBB_ADVERTISED_PREFIX_COUNT: int = 16_384


__all__ = ["MAX_RBB_ADVERTISED_PREFIX_COUNT"]
