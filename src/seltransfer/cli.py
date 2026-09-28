"""Command-line interface for SELTRANSFER."""

import hashlib
import json
import logging
import secrets
import signal
import socket
import subprocess
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import typer
import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .network.detection import detect_network, list_all_interfaces
from .server.app import create_app

console = Console()
app = typer.Typer(
    help="SELTRANSFER - offline file sharing across a local Wi-Fi or hotspot.",
    epilog=(
        "Examples:\n"
        "  seltransfer start\n"
        "  seltransfer devices\n"
        "  seltransfer discover\n"
        "  seltransfer send report.pdf --to DEVICE_ID\n"
        "  seltransfer history"
    ),
)


@app.command()
def start(
    port: int = typer.Option(8765, "--port", "-p", help="Server port"),
    interface: str | None = typer.Option(
        None, "--interface", "-i", help="Network interface name"),
    host: str = typer.Option("0.0.0.0", "--host", "-h",
                             help="Bind host address"),
) -> None:
    """Start the local server and display a phone connection QR code."""
    console.print(Panel(Text("SELTRANSFER\nOFFLINE FILE TRANSFER",
                  justify="center", style="bold cyan")))
    net_interface = detect_network(preferred_interface=interface)
    if not net_interface:
        if interface:
            console.print(
                f"[red]Interface '{interface}' was not found or has no active IPv4 address.[/red]")
            console.print(
                "Run [bold]seltransfer devices[/bold] to see available interfaces.")
        else:
            console.print("[red]No usable network interface found.[/red]")
        raise typer.Exit(code=1)

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((host, port))
    except OSError as error:
        console.print(
            f"[red]TCP port {port} is already in use on {host}.[/red]")
        console.print(
                        f"Stop the existing process or choose another port: "
                        f"seltransfer start --port {port + 1}")
        console.print(f"Check the owner with: netstat -ano | findstr :{port}")
        raise typer.Exit(code=1) from error
    finally:
        probe.close()

    server_url = f"http://{net_interface.address}:{port}"
    console.print(
        f"[green]✓ Network detected[/green] {net_interface.name} ({net_interface.interface_type})")
    console.print(f"  IP Address: {net_interface.address}")
    console.print(f"[green]✓ Server binding:[/green] {host}:{port}")
    console.print(f"[bold]Phone URL:[/bold] {server_url}")
    console.print("\n[bold]SCAN TO CONNECT[/bold]\n")
    try:
        import qrcode
        qr = qrcode.QRCode(
            version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=1, border=1)
        qr.add_data(server_url)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
    except Exception as error:  # noqa: BLE001 - qrcode is optional and must never block startup
        console.print(f"[yellow]Could not render QR code: {error}[/yellow]")
    console.print(f"\n[bold]URL:[/bold] {server_url}")
    console.print(
        "\n[dim]Phone: connect to the same Wi-Fi/hotspot, scan the QR code, "
        "and open the URL.\n"
        f"If it does not open, run 'seltransfer doctor --port {port}' or "
        f"'seltransfer allow-firewall --port {port}'.[/dim]\n")

    fastapi_app = create_app(
        server_port=port, local_address=net_interface.address)
    server = uvicorn.Server(uvicorn.Config(
        app=fastapi_app, host=host, port=port, log_level="info", access_log=False,
    ))

    def handle_shutdown(signum, frame):
        server.should_exit = True

    signal.signal(signal.SIGINT, handle_shutdown)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    console.print("[green]✓ Server started[/green]")
    console.print(
        f"[yellow]Waiting for device connection...[/yellow] Phone URL: {server_url}\n")
    try:
        server.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped[/yellow]")


@app.command()
def devices() -> None:
    """List all local network interfaces and the recommended adapter."""
    console.print("[bold]Available Network Interfaces[/bold]\n")
    interfaces = list_all_interfaces()
    table = Table(show_header=True, header_style="bold")
    table.add_column("Name", style="cyan")
    table.add_column("IPv4 Address", style="green")
    table.add_column("Status", style="yellow")
    table.add_column("Type", style="magenta")
    for iface in interfaces:
        table.add_row(iface.name, iface.address or "-",
                      iface.status, iface.interface_type)
    console.print(table)
    recommended = detect_network()
    if recommended:
        console.print(
            f"\n[bold]Recommended interface:[/bold] {recommended.name} ({recommended.address})")


@app.command()
def doctor(
    port: int = typer.Option(8765, "--port", "-p",
                             help="Server port to diagnose"),
) -> None:
    """Diagnose local adapters and the local SELTRANSFER server."""
    console.print("[bold]SELTRANSFER NETWORK DIAGNOSTICS[/bold]\n")
    interfaces = list_all_interfaces()
    recommended = detect_network()
    console.print(
                "[green]✓[/green] Network adapter detected" if interfaces
                else "[red]✗[/red] No network adapter detected")
    console.print(
                "[green]✓[/green] IPv4 address detected" if recommended
                else "[red]✗[/red] No active IPv4 address detected")
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            console.print(
                f"[green]✓[/green] Server is listening on 0.0.0.0:{port}")
        with urlopen(f"http://127.0.0.1:{port}/api/status", timeout=1) as response:
            console.print(
                f"[green]✓[/green] Local HTTP request successful ({response.status})")
    except OSError:
        console.print(
            f"[yellow]![/yellow] Server is not listening on port {port}")
    console.print("\n[bold]Detected interfaces:[/bold]")
    for iface in interfaces:
        console.print(
            f"  {iface.name}: {iface.address or '-'} ({iface.status}, {iface.interface_type})")
    if recommended:
        console.print(
            f"\n[bold]Recommended interface:[/bold] {recommended.name}")
        console.print(
            f"[bold]Phone connection URL:[/bold] http://{recommended.address}:{port}")
    console.print(
        f"\n[yellow]WARNING:[/yellow] Windows Firewall may be blocking TCP port {port}.")
    console.print(f"Run: seltransfer allow-firewall --port {port}")


@app.command()
def allow_firewall(
    port: int = typer.Option(8765, "--port", "-p", help="TCP port to allow"),
) -> None:
    """Add an inbound Windows Firewall rule for the selected TCP port."""
    rule_name = "SELTRANSFER"
    base = ["netsh", "advfirewall", "firewall"]
    check = subprocess.run(
        base + ["show", "rule", f"name={rule_name}"],
        capture_output=True, text=True, check=False)
    if "No rules match" not in check.stdout and check.returncode == 0:
        console.print(
            f"[green]✓ Firewall rule already exists[/green] (port {port})")
        return
    command = base + ["add", "rule", f"name={rule_name}", "dir=in",
                      "action=allow", "protocol=tcp", f"localport={port}", "program=System"]
    try:
        subprocess.run(command, check=True, capture_output=True)
        console.print(
            f"[green]✓ Firewall rule added for TCP port {port}[/green]")
    except (subprocess.CalledProcessError, OSError):
        console.print("[red]✗ Could not add the firewall rule.[/red]")
        console.print("Open PowerShell as Administrator and rerun:")
        console.print(
                    f"netsh advfirewall firewall add rule name={rule_name} dir=in "
                    f"action=allow protocol=tcp localport={port} program=System")


@app.command()
def history() -> None:
    """Show durable transfer history."""
    from .config import get_settings
    from .storage import HistoryStore
    table = Table("Date", "Sender", "Receiver", "Files", "Bytes", "Status")
    for item in HistoryStore(get_settings().transfer_history_db).list_recent():
        table.add_row(item["created_at"], item["sender_id"][:8], item["receiver_id"][:8],
                      str(item["file_count"]), str(item["total_bytes"]), item["status"])
    console.print(table if table.rows else "No transfer history.")


@app.command()
def status() -> None:
    """Show the local server status."""
    port = 8765
    try:
        with urlopen(f"http://127.0.0.1:{port}/api/status", timeout=1) as response:
            console.print(json.loads(response.read()))
    except OSError:
        console.print(
            f"[yellow]SELTRANSFER is not listening on port {port}.[/yellow]")


@app.command()
def discover() -> None:
    """Show devices discovered by a running local server."""
    try:
        with urlopen("http://127.0.0.1:8765/api/devices", timeout=2) as response:
            data = json.loads(response.read())
        table = Table("Name", "Type", "IP", "Port", "Status", "Device ID")
        for device in data["devices"]:
            table.add_row(device["name"], device["type"], device["ip"], str(device["port"]),
                          device["status"], device["device_id"])
        console.print(table)
    except OSError:
        console.print(
            "[yellow]Start SELTRANSFER first: seltransfer start[/yellow]")


@app.command("send")
def send_files(paths: list[Path] = typer.Argument(...),
               to: str | None = typer.Option(None, "--to"),
               port: int = typer.Option(8765, "--port")) -> None:
    """Send selected files directly to a discovered device."""
    files = []
    for path in paths:
        if not path.is_file():
            raise typer.BadParameter(f"not a file: {path}")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        files.append(
            {"name": path.name, "size": path.stat().st_size, "sha256": digest.hexdigest()})
    if not to:
        console.print("Pass --to with a discovered device ID.")
        raise typer.Exit(2)
    local = f"http://127.0.0.1:{port}"
    try:
        with urlopen(f"{local}/api/devices", timeout=5) as response:
            devices = json.loads(response.read())["devices"]
        destination = next(
            (device for device in devices if device["device_id"] == to), None)
        if not destination:
            raise ValueError(f"device not found: {to}")

        # A browser receiver (a phone) has no server of its own: it is a client of
        # ours, so its transfers live on this machine. Only a native peer needs to
        # be addressed directly.
        if destination.get("node_type") == "browser":
            base = local
        else:
            if not destination.get("port"):
                raise ValueError(
                    f"{destination['name']} has no reachable address; "
                    "is it running SELTRANSFER?")
            base = f"http://{destination['ip']}:{destination['port']}"

        # Creating a transfer requires the destination to be paired. Pairing is
        # idempotent, and the device was just listed successfully, so a failure
        # here is worth surfacing rather than swallowing.
        pair = Request(f"{local}/api/devices/{to}/pair", data=b"",
                       headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(pair, timeout=5):
            pass

        # The upload token is ours to choose. The destination will not hand a
        # token back to us, because only its own node may read one, so we
        # generate it and present the same value when pushing the bytes.
        token = secrets.token_urlsafe(32)
        body = json.dumps({"receiver_id": to, "files": files}).encode()
        request = Request(f"{local}/api/transfers", data=body,
                          headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(request, timeout=5) as response:
            transfer = json.loads(response.read())
        incoming = {"transfer_id": transfer["transfer_id"], "sender": transfer["sender"],
                    "files": files, "total_bytes": transfer["total_bytes"],
                    "token": token}
        request = Request(f"{base}/api/incoming-transfers", data=json.dumps(incoming).encode(),
                          headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(request, timeout=5):
            pass
        console.print(
                    f"Requesting transfer to {destination['name']} "
                    f"({destination['ip']}:{destination['port']})...")
        accepted = None
        for _ in range(120):
            with urlopen(f"{base}/api/incoming-transfers/{transfer['transfer_id']}",
                         timeout=5) as response:
                state = json.loads(response.read())
            if state["status"] == "ACCEPTED":
                accepted = state
                break
            if state["status"] == "REJECTED":
                raise ValueError("receiver rejected the transfer")
            import time
            time.sleep(1)
        if not accepted:
            raise ValueError("timed out waiting for receiver")
        for index, path in enumerate(paths):
            with path.open("rb") as source:
                upload = Request(
                    f"{base}/api/incoming-transfers/"
                    f"{transfer['transfer_id']}/files/{index}",
                    data=source,
                    headers={"x-seltransfer-token": token},
                    method="PUT")
                with urlopen(upload, timeout=300) as response:
                    result = json.loads(response.read())
            if result["status"] == "FAILED":
                raise ValueError("receiver failed verification")
        console.print("Transfer verified by receiver.")
    except HTTPError as error:
        detail = ""
        try:
            detail = json.loads(error.read()).get("detail", "")
        except Exception:  # noqa: BLE001 - best-effort error text only
            detail = ""
        console.print(f"[red]Transfer failed ({error.code}): {detail}[/red]")
        raise typer.Exit(1) from error
    except OSError as error:
        console.print(f"[red]Could not create transfer: {error}[/red]")
        raise typer.Exit(1) from error
    except ValueError as error:
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(1) from error


@app.command()
def version() -> None:
    """Show application version."""
    console.print(f"[bold]SELTRANSFER[/bold] version {__version__}")


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """SELTRANSFER - Offline file transfer for local networks."""
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


if __name__ == "__main__":
    app()
