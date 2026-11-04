# Copyright (c) Meta Platforms, Inc. and affiliates.
# pyre-unsafe
"""Regression tests for the IXIA evidence used by RBB traffic cases."""

import unittest
from types import SimpleNamespace
from unittest import mock

from taac.constants import TestCaseFailure
from taac.ixia.ixia import DeviceGroupIndex, Ixia, IxiaSetupError, VportIndex
from taac.ixia.otg_traffic_gen import OtgTrafficGen
from taac.ixia.taac_ixia import TaacIxia
from taac.tasks.rbb_ixia_capability_task import RbbIxiaCapabilityTask


class _StatRow:
    def __init__(self, values):
        self._values = values
        self.Columns = list(values)

    def __getitem__(self, column):
        return self._values[column]


class RbbIxiaEvidenceContractTest(unittest.TestCase):
    def test_stats_reset_capability_matches_backend_behavior(self) -> None:
        restpy = TaacIxia.__new__(TaacIxia)
        otg = OtgTrafficGen.__new__(OtgTrafficGen)

        self.assertTrue(restpy.supports_controller_traffic_stats_reset())
        self.assertFalse(otg.supports_controller_traffic_stats_reset())

    def test_restpy_packet_loss_row_preserves_frame_and_byte_counters(self) -> None:
        stat = TaacIxia._packet_loss_stat(
            "Traffic Item Statistics",
            _StatRow(
                {
                    "Traffic Item": "RBB_FORWARD",
                    "Packet Loss Duration (ms)": "0",
                    "Loss %": "0",
                    "Frames Delta": "0",
                    "Tx Frames": "1000",
                    "Rx Frames": "999",
                    "Tx Bytes": "256000",
                    "Rx Bytes": "255744",
                }
            ),
        )

        self.assertEqual(stat["tx_frames"], 1000.0)
        self.assertEqual(stat["rx_frames"], 999.0)
        self.assertEqual(stat["tx_bytes"], 256000.0)
        self.assertEqual(stat["rx_bytes"], 255744.0)

    def test_otg_conversion_preserves_frame_and_byte_counters(self) -> None:
        otg = OtgTrafficGen.__new__(OtgTrafficGen)
        otg._flow_loss_accumulated = {}
        otg._flow_loss_start = {}

        stats = otg._flow_metrics_to_stats(
            [
                {
                    "name": "RBB_FORWARD",
                    "frames_tx": 1000,
                    "frames_rx": 999,
                    "bytes_tx": 256000,
                    "bytes_rx": 255744,
                    "loss": 0.1,
                }
            ]
        )

        self.assertEqual(stats[0]["tx_frames"], 1000)
        self.assertEqual(stats[0]["rx_frames"], 999)
        self.assertEqual(stats[0]["tx_bytes"], 256000)
        self.assertEqual(stats[0]["rx_bytes"], 255744)

    def test_peer_lookup_uses_normalized_port_and_dg_zero_stack(self) -> None:
        peer = object()
        peer_find = mock.MagicMock(return_value=[peer])
        ipv6 = SimpleNamespace(BgpIpv6Peer=SimpleNamespace(find=peer_find))
        ixia = Ixia.__new__(Ixia)
        ixia.vport_indices = {
            "R1:ETH1/5": VportIndex(
                name="VPORT_R1:ETH1/5",
                device_group_indices={
                    0: DeviceGroupIndex(device_group=object(), ipv6=ipv6)
                },
            )
        }
        ixia.find_ipv6s = mock.MagicMock()

        with mock.patch("taac.ixia.ixia.to_fb_uqdn", return_value="r1"):
            result = ixia.find_bgp_ipv6_peer("r1.example:eth1/5")

        self.assertIs(result, peer)
        peer_find.assert_called_once_with(Name=r"^BGP_PEER_V6_D0_R1:ETH1/5$")
        ixia.find_ipv6s.assert_not_called()

    def test_peer_lookup_rejects_duplicate_indexed_exact_names(self) -> None:
        ipv6 = SimpleNamespace(
            BgpIpv6Peer=SimpleNamespace(
                find=mock.MagicMock(return_value=[object(), object()])
            )
        )
        ixia = Ixia.__new__(Ixia)
        ixia.vport_indices = {
            "R1:ETH1/5": VportIndex(
                name="VPORT_R1:ETH1/5",
                device_group_indices={
                    0: DeviceGroupIndex(device_group=object(), ipv6=ipv6)
                },
            )
        }
        ixia.find_ipv6s = mock.MagicMock()

        with (
            mock.patch("taac.ixia.ixia.to_fb_uqdn", return_value="r1"),
            self.assertRaisesRegex(IxiaSetupError, "Multiple IPv6 BGP peers"),
        ):
            ixia.find_bgp_ipv6_peer("r1.example:eth1/5")

        ixia.find_ipv6s.assert_not_called()

    def test_peer_lookup_falls_back_to_exact_legacy_session_name(self) -> None:
        peer = object()
        peer_find = mock.MagicMock(return_value=[peer])
        ipv6 = SimpleNamespace(BgpIpv6Peer=SimpleNamespace(find=peer_find))
        ixia = Ixia.__new__(Ixia)
        ixia.vport_indices = {}
        ixia.find_ipv6s = mock.MagicMock(return_value=[ipv6])

        with mock.patch("taac.ixia.ixia.to_fb_uqdn", return_value="r1"):
            result = ixia.find_bgp_ipv6_peer("r1.example:eth1/5")

        self.assertIs(result, peer)
        ixia.find_ipv6s.assert_called_once_with(regex=".*")
        peer_find.assert_called_once_with(Name=r"^BGP_PEER_V6_D0_R1:ETH1/5$")

    def test_peer_lookup_escapes_regex_metacharacters_in_port_name(self) -> None:
        peer_find = mock.MagicMock(return_value=[])
        ipv6 = SimpleNamespace(BgpIpv6Peer=SimpleNamespace(find=peer_find))
        ixia = Ixia.__new__(Ixia)
        ixia.vport_indices = {}
        ixia.find_ipv6s = mock.MagicMock(return_value=[ipv6])

        with mock.patch("taac.ixia.ixia.to_fb_uqdn", return_value="r.1"):
            result = ixia.find_bgp_ipv6_peer("r.1.example:eth1/5+")

        self.assertIsNone(result)
        peer_find.assert_called_once_with(
            Name=r"^BGP_PEER_V6_D0_R\.1:ETH1/5\+$"
        )


class RbbIxiaCapabilityTaskTest(unittest.IsolatedAsyncioTestCase):
    async def test_controller_reset_capability_passes(self) -> None:
        ixia = SimpleNamespace(
            supports_controller_traffic_stats_reset=lambda: True
        )
        task = RbbIxiaCapabilityTask(ixia=ixia, logger=mock.MagicMock())

        await task.run(
            {
                "gate": "phase2:TC-15",
                "require_controller_traffic_stats_reset": True,
            }
        )

    async def test_missing_controller_reset_fails_closed(self) -> None:
        for ixia in (
            SimpleNamespace(),
            SimpleNamespace(supports_controller_traffic_stats_reset=lambda: False),
        ):
            with self.subTest(ixia=ixia):
                task = RbbIxiaCapabilityTask(ixia=ixia, logger=mock.MagicMock())
                with self.assertRaisesRegex(
                    TestCaseFailure, "isolated resilience loss windows"
                ):
                    await task.run(
                        {
                            "gate": "phase2:TC-15",
                            "require_controller_traffic_stats_reset": True,
                        }
                    )

    async def test_variable_l4_range_capability_is_explicit(self) -> None:
        supported = SimpleNamespace(supports_variable_l4_flow_ranges=lambda: True)
        await RbbIxiaCapabilityTask(ixia=supported, logger=mock.MagicMock()).run(
            {
                "gate": "phase1:TC-08",
                "require_variable_l4_flow_ranges": True,
            }
        )

        for ixia in (
            SimpleNamespace(),
            SimpleNamespace(supports_variable_l4_flow_ranges=lambda: False),
        ):
            with self.subTest(ixia=ixia):
                with self.assertRaisesRegex(
                    TestCaseFailure, "core ECMP distribution evidence"
                ):
                    await RbbIxiaCapabilityTask(ixia=ixia, logger=mock.MagicMock()).run(
                        {
                            "gate": "phase1:TC-08",
                            "require_variable_l4_flow_ranges": True,
                        }
                    )

    async def test_capability_task_is_registered(self) -> None:
        from taac.tasks.registry import TASK_NAME_TO_CLASS

        self.assertIs(
            TASK_NAME_TO_CLASS["rbb_ixia_capability"], RbbIxiaCapabilityTask
        )


if __name__ == "__main__":
    unittest.main()
