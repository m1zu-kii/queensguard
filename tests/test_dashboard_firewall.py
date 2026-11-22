import unittest
from unittest.mock import patch

import desktop_app
import windows_firewall


def ddos_result(ip: str, confidence: float = 0.99) -> dict[str, str | float]:
    return {
        "Unanimous Result": "DDoS",
        "Flow Timestamp": "2026-01-01 00:00:00",
        "Src IP": ip,
        "SVM Class": "DDoS",
        "SVM Confidence": confidence,
        "XGB Class": "DDoS",
        "XGB Confidence": confidence,
        "KNN Class": "DDoS",
        "KNN Confidence": confidence,
    }


class DashboardFirewallTests(unittest.TestCase):
    def test_firewall_blocking_is_off_by_default(self) -> None:
        api = desktop_app.DashboardApi()
        with (
            patch.object(windows_firewall, "block_inbound_ip") as block,
            patch.object(api, "_notify_live_verdict"),
        ):
            api._on_classifications([ddos_result("192.0.2.10")])

        block.assert_not_called()
        self.assertEqual(api.get_log()[0]["state"], "detected")
        self.assertEqual(
            api.get_status()["live_verdict_event"]["ips_blocked"],
            0,
        )

    def test_enabled_blocking_applies_one_rule_per_source_ip(self) -> None:
        api = desktop_app.DashboardApi(firewall_blocking_enabled=True)
        with (
            patch.object(
                windows_firewall,
                "block_inbound_ip",
                return_value="QueensGuard_InboundBlock_IPv4_192_0_2_10",
            ) as block,
            patch.object(api, "_notify_live_verdict"),
        ):
            api._on_classifications(
                [
                    ddos_result("192.0.2.10", 0.99),
                    ddos_result("192.0.2.10", 0.97),
                ]
            )

        block.assert_called_once_with("192.0.2.10")
        self.assertEqual(api.get_log()[0]["state"], "banned")
        event = api.get_status()["live_verdict_event"]
        self.assertEqual(event["ips_detected"], 1)
        self.assertEqual(event["ips_blocked"], 1)

    def test_firewall_failure_remains_visible_and_does_not_claim_blocked(self) -> None:
        api = desktop_app.DashboardApi(firewall_blocking_enabled=True)
        with (
            patch.object(
                windows_firewall,
                "block_inbound_ip",
                side_effect=windows_firewall.FirewallError("access denied"),
            ),
            patch.object(api, "_notify_live_verdict"),
        ):
            api._on_classifications([ddos_result("192.0.2.10")])

        self.assertEqual(api.get_log()[0]["state"], "detected")
        self.assertIn("access denied", api.get_log()[0]["reason"])
        self.assertEqual(api.get_status()["firewall_error"], "access denied")
        self.assertEqual(
            api.get_status()["live_verdict_event"]["ips_blocked"],
            0,
        )

    def test_allowlisting_unblocks_and_suppresses_future_auto_blocks(self) -> None:
        api = desktop_app.DashboardApi(firewall_blocking_enabled=True)
        with (
            patch.object(windows_firewall, "block_inbound_ip") as block,
            patch.object(
                windows_firewall,
                "unblock_inbound_ip",
                return_value="QueensGuard_InboundBlock_IPv4_192_0_2_10",
            ) as unblock,
            patch.object(api, "_notify_live_verdict"),
        ):
            api._on_classifications([ddos_result("192.0.2.10")])
            result = api.whitelist_ip("192.0.2.10")
            api._on_classifications([ddos_result("192.0.2.10")])

        self.assertTrue(result["ok"])
        block.assert_called_once_with("192.0.2.10")
        unblock.assert_called_once_with("192.0.2.10")
        self.assertEqual(api.get_log()[0]["state"], "pardoned")

    def test_disabled_manual_block_returns_an_explicit_error(self) -> None:
        api = desktop_app.DashboardApi()
        with patch.object(windows_firewall, "block_inbound_ip") as block:
            result = api.ban_ip("192.0.2.10")

        self.assertFalse(result["ok"])
        self.assertIn("--enable-firewall-blocking", result["error"])
        block.assert_not_called()


if __name__ == "__main__":
    unittest.main()
