"""Network detection utilities."""


from . import NetworkInterface, get_all_interfaces, get_usable_interface

__all__ = ["detect_network", "list_all_interfaces"]


def detect_network(
    preferred_interface: str | None = None,
    exclude_keywords: list[str] | None = None,
) -> NetworkInterface | None:
    """
    Detect and return a usable network interface for SELTRANSFER.

    Args:
        preferred_interface: Prefer this interface if available.
        exclude_keywords: Keywords to exclude from interface names.

    Returns:
        A NetworkInterface or None if no usable interface found.
    """
    return get_usable_interface(preferred_interface, exclude_keywords)


def list_all_interfaces() -> list[NetworkInterface]:
    """
    List all available network interfaces (including loopback).

    Returns:
        List of all NetworkInterface objects.
    """
    return get_all_interfaces()
