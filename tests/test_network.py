"""Tests for network interface detection."""

from types import SimpleNamespace
from unittest.mock import patch

from seltransfer.network import NetworkInterface, get_all_interfaces, get_usable_interface


def test_network_interface_ipv4_validation():
    """Test IPv4 address validation."""
    iface = NetworkInterface(
        name="Ethernet",
        address="192.168.1.100",
        netmask="255.255.255.0"
    )
    assert iface.is_ipv4() is True


def test_network_interface_ipv6_detection():
    """Test IPv6 address detection (should return False for is_ipv4)."""
    iface = NetworkInterface(
        name="Ethernet",
        address="::1",
        netmask="::1"
    )
    assert iface.is_ipv4() is False


def test_loopback_detection():
    """Test loopback address detection."""
    loopback = NetworkInterface(
        name="Loopback",
        address="127.0.0.1",
        netmask="255.0.0.0"
    )
    assert loopback.is_loopback() is True

    real_interface = NetworkInterface(
        name="Ethernet",
        address="192.168.1.100",
        netmask="255.255.255.0"
    )
    assert real_interface.is_loopback() is False


def test_interface_usability():
    """Test interface usability check."""
    # Loopback is not usable
    loopback = NetworkInterface(
        name="Loopback",
        address="127.0.0.1",
        netmask="255.0.0.0"
    )
    assert loopback.is_usable() is False

    # IPv4 non-loopback is usable
    real_interface = NetworkInterface(
        name="Ethernet",
        address="192.168.1.100",
        netmask="255.255.255.0"
    )
    assert real_interface.is_usable() is True

    # IPv6 is not usable in current implementation
    ipv6_interface = NetworkInterface(
        name="Ethernet",
        address="fe80::1",
        netmask="ffff:ffff:ffff:ffff::"
    )
    assert ipv6_interface.is_usable() is False


def test_get_usable_interface_excludes_virtual():
    """Test that virtual interfaces are excluded by default."""
    exclude_keywords = ["Virtual", "Docker", "VMware"]

    # This would need to be tested with actual system interfaces
    # For now, just ensure the function doesn't crash
    result = get_usable_interface(exclude_keywords=exclude_keywords)

    if result:
        # If an interface is found, it should not be virtual
        assert not any(
            kw.lower() in result.name.lower() for kw in exclude_keywords
        )


def test_preferred_interface_selection():
    """Test that preferred interface is selected when available."""
    # This test would require mocking network interfaces
    # For now, just ensure the function handles the parameter
    result = get_usable_interface(preferred_interface="Ethernet")

    # Result can be None if interface doesn't exist, which is fine
    if result:
        assert "ethernet" in result.name.lower()


def test_interface_with_private_ip_ranges():
    """Test that common private IP ranges are recognized as IPv4."""
    private_ranges = [
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "192.168.43.1",
        "192.168.137.1",
    ]

    for ip in private_ranges:
        iface = NetworkInterface(
            name="Test",
            address=ip,
            netmask="255.255.255.0"
        )
        assert iface.is_ipv4() is True
        assert iface.is_usable() is True


def test_interface_selection_ignores_disconnected_and_virtual_adapters():
    addresses = {
        "VirtualBox Host": [SimpleNamespace(
            family=2, address="192.168.56.1", netmask="255.255.255.0", broadcast=None)],
        "Ethernet": [SimpleNamespace(
            family=2, address="10.20.30.40", netmask="255.255.255.0", broadcast=None)],
        "Wi-Fi": [SimpleNamespace(
            family=2, address="172.16.4.22", netmask="255.255.0.0", broadcast=None)],
        "Old Wi-Fi": [SimpleNamespace(
            family=2, address="192.168.1.9", netmask="255.255.255.0", broadcast=None)],
    }
    stats = {
        "VirtualBox Host": SimpleNamespace(isup=True),
        "Ethernet": SimpleNamespace(isup=True),
        "Wi-Fi": SimpleNamespace(isup=True),
        "Old Wi-Fi": SimpleNamespace(isup=False),
    }
    with patch("seltransfer.network.psutil.net_if_addrs", return_value=addresses), \
            patch("seltransfer.network.psutil.net_if_stats", return_value=stats):
        interfaces = get_all_interfaces()
        selected = get_usable_interface()

    assert selected.name == "Wi-Fi"
    assert selected.address == "172.16.4.22"
    assert next(iface for iface in interfaces if iface.name ==
                "VirtualBox Host").is_virtual


def test_explicit_interface_can_select_hotspot_or_virtual_adapter():
    iface = NetworkInterface("vEthernet (Hotspot)",
                             "10.0.0.2", "255.255.255.0", is_virtual=True)
    with patch("seltransfer.network.get_all_interfaces", return_value=[iface]):
        assert get_usable_interface("vEthernet (Hotspot)") == iface
