import unittest
from unittest.mock import patch

import windows_firewall


class WindowsFirewallTests(unittest.TestCase):
    def test_blocks_only_the_validated_remote_ip_inbound(self) -> None:
        with (
            patch.object(windows_firewall, "require_windows_admin"),
            patch.object(windows_firewall, "_run_netsh") as run_netsh,
        ):
            name = windows_firewall.block_inbound_ip("192.0.2.10")

        self.assertEqual(name, "QueensGuard_InboundBlock_IPv4_192_0_2_10")
        run_netsh.assert_called_once_with(
            [
                "add",
                "rule",
                f"name={name}",
                "dir=in",
                "action=block",
                "remoteip=192.0.2.10",
                "protocol=any",
                "profile=any",
                "enable=yes",
            ]
        )

    def test_unban_deletes_only_the_matching_queens_guard_rule(self) -> None:
        with (
            patch.object(windows_firewall, "require_windows_admin"),
            patch.object(windows_firewall, "_run_netsh") as run_netsh,
        ):
            name = windows_firewall.unblock_inbound_ip("2001:db8::10")

        self.assertEqual(name, "QueensGuard_InboundBlock_IPv6_2001_db8__10")
        run_netsh.assert_called_once_with(["delete", "rule", f"name={name}"])

    def test_rejects_invalid_and_special_addresses_before_running_netsh(self) -> None:
        for ip in ("not-an-ip", "0.0.0.0", "224.0.0.1", "::1"):
            with self.subTest(ip=ip):
                with patch.object(windows_firewall, "_run_netsh") as run_netsh:
                    with self.assertRaises(windows_firewall.FirewallError):
                        windows_firewall.block_inbound_ip(ip)
                run_netsh.assert_not_called()


if __name__ == "__main__":
    unittest.main()
