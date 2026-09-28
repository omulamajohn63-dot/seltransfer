"""Network interface detection based on the local adapter table."""

import ipaddress
from dataclasses import dataclass

import psutil


@dataclass
class NetworkInterface:
    """Represents a network interface with its properties."""

    name: str
    address: str
    netmask: str
    broadcast: str | None = None
    status: str = "Connected"
    interface_type: str = "Other"
    is_physical: bool = True
    is_virtual: bool = False

    def is_ipv4(self) -> bool:
        """Check if this is an IPv4 interface."""
        try:
            return isinstance(ipaddress.ip_address(self.address), ipaddress.IPv4Address)
        except ValueError:
            return False

    def is_loopback(self) -> bool:
        """Check if this is a loopback interface."""
        try:
            return ipaddress.ip_address(self.address).is_loopback
        except ValueError:
            return False

    def is_usable(self) -> bool:
        """Check if this interface is usable for file transfer."""
        return (
            self.is_ipv4()
            and not self.is_loopback()
            and self.status.casefold() not in {"disconnected", "down", "disabled"}
        )


VIRTUAL_KEYWORDS = (
    "virtualbox", "vmware", "hyper-v", "docker", "vethernet",
    "wsl", "vpn", "tun", "tap", "loopback",
)
HOTSPOT_KEYWORDS = ("mobile hotspot", "wi-fi direct",
                    "wifi direct", "hosted network")


def _interface_details(name: str) -> tuple[str, bool, bool]:
    """Infer display type and virtual status from common Windows adapter names."""
    lowered = name.casefold()
    is_hotspot = any(keyword in lowered for keyword in HOTSPOT_KEYWORDS)
    is_virtual = any(
        keyword in lowered for keyword in VIRTUAL_KEYWORDS) and not is_hotspot

    if is_virtual:
        interface_type = "Virtual"
    elif any(keyword in lowered for keyword in ("wi-fi", "wifi", "wireless", "wlan")):
        interface_type = "Wi-Fi"
    elif any(keyword in lowered for keyword in ("ethernet", "lan")):
        interface_type = "Ethernet"
    elif is_hotspot:
        interface_type = "Wi-Fi hotspot"
    else:
        interface_type = "Other"
    return interface_type, not is_virtual, is_virtual


def get_all_interfaces() -> list[NetworkInterface]:
    """
    Enumerate all network interfaces and return usable ones.

    Returns:
        List of NetworkInterface objects.
    """
    interfaces: list[NetworkInterface] = []
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for name, adapter_addresses in addresses.items():
        interface_type, is_physical, is_virtual = _interface_details(name)
        adapter_stats = stats.get(name)
        status = "Connected" if adapter_stats and adapter_stats.isup else "Disconnected"
        ipv4_addresses = [
            address for address in adapter_addresses if address.family == 2]

        if not ipv4_addresses:
            interfaces.append(NetworkInterface(
                name=name, address="", netmask="", status=status,
                interface_type=interface_type, is_physical=is_physical, is_virtual=is_virtual,
            ))
            continue

        for address in ipv4_addresses:
            interfaces.append(NetworkInterface(
                name=name, address=address.address, netmask=address.netmask or "",
                broadcast=address.broadcast, status=status, interface_type=interface_type,
                is_physical=is_physical, is_virtual=is_virtual,
            ))
    return interfaces


def get_usable_interface(
    preferred_interface: str | None = None,
    exclude_keywords: list[str] | None = None,
) -> NetworkInterface | None:
    """
    Get a usable network interface.

    Args:
        preferred_interface: Prefer this interface name if available.
        exclude_keywords: List of keywords to exclude from interface names.

    Returns:
        A NetworkInterface or None if no usable interface found.
    """
    if exclude_keywords is None:
        exclude_keywords = [
            "Loopback",
            "VirtualBox",
            "VMware",
            "Hyper-V",
            "Docker",
            "vEthernet",
        ]

    all_interfaces = get_all_interfaces()

    # Explicit selection is allowed to choose a virtual adapter when requested.
    if preferred_interface:
        requested = preferred_interface.casefold().strip()
        return next(
            (iface for iface in all_interfaces
             if iface.name.casefold() == requested and iface.is_usable()),
            None,
        )

    usable = [
        iface
        for iface in all_interfaces
        if iface.is_usable()
        and not iface.is_virtual
        and not any(keyword.casefold() in iface.name.casefold() for keyword in exclude_keywords)
    ]

    if not usable:
        return None

    priority = {"Wi-Fi hotspot": 0, "Wi-Fi": 1, "Ethernet": 2, "Other": 3}
    return min(usable, key=lambda iface: (
        priority.get(iface.interface_type, 4), iface.name.casefold()))
