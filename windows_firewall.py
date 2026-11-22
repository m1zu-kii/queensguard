import ctypes
import ipaddress
import platform
import subprocess


RULE_PREFIX = "QueensGuard_InboundBlock_"


class FirewallError(RuntimeError):
    pass


def _validated_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise FirewallError(f"Invalid IP address: {value!r}") from exc
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise FirewallError(
            f"Refusing to create an inbound block rule for special address {address}."
        )
    return address


def normalize_ip(value: str) -> str:
    return str(_validated_ip(value))


def rule_name(ip: str) -> str:
    address = _validated_ip(ip)
    token = str(address).replace(".", "_").replace(":", "_")
    return f"{RULE_PREFIX}IPv{address.version}_{token}"


def require_windows_admin() -> None:
    if platform.system() != "Windows":
        raise FirewallError("Inbound firewall blocking is supported only on Windows.")
    try:
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError) as exc:
        raise FirewallError(
            "Could not verify Windows administrator privileges."
        ) from exc
    if not is_admin:
        raise FirewallError(
            "Windows Firewall changes require administrator privileges. "
            "Restart Queen's Guard using Run as administrator."
        )


def _run_netsh(arguments: list[str]) -> None:
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", *arguments],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FirewallError(f"Could not run Windows Firewall command: {exc}") from exc
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise FirewallError(
            detail or f"netsh exited with status {result.returncode}."
        )


def block_inbound_ip(ip: str) -> str:
    address = _validated_ip(ip)
    require_windows_admin()
    name = rule_name(str(address))
    _run_netsh(
        [
            "add",
            "rule",
            f"name={name}",
            "dir=in",
            "action=block",
            f"remoteip={address}",
            "protocol=any",
            "profile=any",
            "enable=yes",
        ]
    )
    return name


def unblock_inbound_ip(ip: str) -> str:
    name = rule_name(ip)
    require_windows_admin()
    _run_netsh(["delete", "rule", f"name={name}"])
    return name
