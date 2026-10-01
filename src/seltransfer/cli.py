"""Command-line interface for SELTRANSFER."""

import hashlib
import json
import logging
import re
import secrets
import signal
import socket
import subprocess
import sys
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
from .config import get_settings, read_local_token
from .network.detection import detect_network, list_all_interfaces
from .server.app import create_app


def _configure_console_streams() -> None:
    """Make stdout and stderr able to carry the symbols this CLI prints.

    Windows consoles default to a legacy code page, so a byte like the check mark
    in "✓ Network detected" raises UnicodeEncodeError. Rich's legacy renderer
    encodes with the stream's own encoding, and a frozen build inherits whatever
    the parent process gave it, which is often a redirected pipe. The packaged
    executable crashed on startup for exactly that reason.

    Forcing UTF-8 with replacement keeps the output readable and makes the
    un-encodable case degrade to '?' instead of killing the process.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):  # pragma: no cover - unusual stream
            pass


_configure_console_streams()

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


def _local_base(port: int) -> str:
    """Base URL for talking to the local server, honouring the configured port.

    These commands used to hardcode 8765, so a server started on another port was
    invisible to ``status`` and ``discover``.
    """
    return f"http://127.0.0.1:{port}"


def _local_headers(port: int) -> dict[str, str]:
    """Headers that identify this process as the local CLI.

    The server treats a request without a browser session and without this token
    as anonymous, and rejects anonymous callers from pairing, history, and
    transfer state. The token is only readable in this user's application
    directory.
    """
    token = read_local_token() or ""
    return {"x-seltransfer-local": token, "x-seltransfer-port": str(port)}


@app.command()
def start(
    port: int = typer.Option(8765, "--port", "-p", help="Server port"),
    interface: str | None = typer.Option(
        None, "--interface", "-i", help="Network interface name"),
    host: str = typer.Option("0.0.0.0", "--host", "-h",
                             help="Bind host address"),
    tls: bool = typer.Option(
        False, "--tls", help="Serve HTTPS using the configured certificate"),
) -> None:
    """Start the local server and display a phone connection QR code."""
    console.print(Panel(Text("SELTRANSFER\nOFFLINE FILE TRANSFER",
                  justify="center", style="bold cyan")))
    settings = get_settings()
    if tls:
        settings.tls_enabled = True
    # Refuse to start a half-configured TLS server: a missing certificate would
    # otherwise fail deep inside uvicorn, after the QR has already been printed.
    problem = settings.validate_tls()
    if problem:
        console.print(f"[red]{problem}[/red]")
        raise typer.Exit(code=1)
    if settings.https_enabled:
        console.print(
            "[green]✓ TLS enabled[/green] "
            f"certificate: {settings.tls_certfile}")
        console.print(
            "[yellow]The certificate is not issued by a public authority, so a "
            "phone will warn before it connects.[/yellow]")

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

    scheme = settings.scheme()
    server_url = f"{scheme}://{net_interface.address}:{port}"
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
        ssl_certfile=str(settings.tls_certfile) if settings.https_enabled else None,
        ssl_keyfile=str(settings.tls_keyfile) if settings.https_enabled else None,
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
            f"[bold]Phone connection URL:[/bold] "
            f"{get_settings().scheme()}://{recommended.address}:{port}")
    console.print(
        f"\n[yellow]WARNING:[/yellow] Windows Firewall may be blocking TCP port {port}.")
    console.print(f"Run: seltransfer allow-firewall --port {port}")


@app.command()
def allow_firewall(
    port: int = typer.Option(8765, "--port", "-p", help="TCP port to allow"),
    remove: bool = typer.Option(
        False, "--remove", help="Remove the rule instead of adding it"),
    profile: str = typer.Option(
        "any", "--profile",
        help="Firewall profiles to apply the rule to: any, private, domain, public, "
             "or a comma-separated list"),
) -> None:
    """Add or remove the inbound Windows Firewall rule for SELTRANSFER.

    The rule is scoped to the program that actually listens, to TCP only, to the
    local subnet, and (by default) to every firewall profile. ``seltransfer
    allow-firewall --remove --port 8765`` undoes it.
    """
    # Why the rule is shaped this way:
    #  - program=sys.executable, not "System". The old value matched no real
    #    process, which is a plausible reason a hotspot connection still failed
    #    after running this command.
    #  - remoteip=localsubnet, because the server binds 0.0.0.0 and a rule with
    #    no remote scope would accept the internet.
    #  - the name carries the port, so a second port can be opened without
    #    deleting the first. The old single name reported "already exists" and
    #    did nothing when asked for a different port.
    #  - profile defaults to "any". An earlier version used "private,domain",
    #    which silently excluded the public profile - and Windows classifies a
    #    phone hotspot as *public*. The rule therefore did nothing on the exact
    #    setup this command exists for. The exposure is unchanged, because
    #    remoteip=localsubnet is what limits it, not the profile.
    base = ["netsh", "advfirewall", "firewall"]
    rule_name = firewall_rule_name(port)
    # sys.executable is python.exe for a source install and SELTRANSFER.exe for a
    # frozen build, so the rule follows the thing that actually binds the port.
    program = str(Path(sys.executable).resolve())
    profiles = normalise_firewall_profiles(profile)

    if remove:
        subprocess.run(base + ["delete", "rule", f"name={rule_name}"],
                       capture_output=True, text=True, check=False)
        console.print(f"[green]✓[/green] Firewall rule removed: {rule_name}")
        return

    check = subprocess.run(base + ["show", "rule", f"name={rule_name}"],
                           capture_output=True, text=True, check=False)
    # `netsh ... show rule` reports a missing rule in its *output*, not reliably in
    # its exit code, so both have to be consulted. Requiring non-empty output also
    # avoids concluding "already exists" from a blank response.
    exists = (check.returncode == 0 and (check.stdout or "").strip()
              and "No rules match" not in check.stdout)
    if exists:
        existing = parse_rule_profiles(check.stdout)
        # `profile=any` is reported by netsh as the literal list of all three
        # profiles, and netsh capitalises them, so compare as sets.
        #
        # Only ever widen. Narrowing a rule someone already has would silently
        # re-break a hotspot that works today, and there is no reason to ask for
        # it: the exposure is bounded by remoteip=localsubnet either way.
        covers = (existing is None or existing == "any"
                  or set(existing.split(",")) >= set(profiles.split(",")))
        if covers:
            console.print(
                f"[green]✓[/green] Firewall rule already exists ({rule_name})")
            return
        # A rule left by an older version can exist and still not cover the profile
        # this machine is on. Returning "already exists" there is what made the
        # original profile=private,domain problem survive the fix, so widen the
        # existing rule in place rather than asking for a manual delete.
        updated = subprocess.run(
            [*base, "set", "rule", f"name={rule_name}", "new", f"profile={profiles}"],
            capture_output=True, text=True, check=False)
        if updated.returncode == 0:
            console.print(
                f"[green]✓[/green] Firewall rule updated ({rule_name}): "
                f"profile {existing} -> {profiles}")
            return
        console.print(
            f"[yellow]![/yellow] Firewall rule {rule_name} exists with profile "
            f"{existing}, which does not cover this connection.")
        console.print(
            f"  Remove it and re-run: seltransfer allow-firewall --remove "
            f"--port {port}  then  seltransfer allow-firewall --port {port}")
        return


    command = [
        *base, "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=allow",
        "protocol=tcp",
        f"localport={port}",
        f"program={program}",
        # The only exposure this tool needs. Without it the rule would accept
        # traffic from anywhere that can route to this machine.
        "remoteip=localsubnet",
        f"profile={profiles}",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            console.print(
                f"[green]✓ Firewall rule added[/green] {rule_name}\n"
                f"  program: {program}\n"
                f"  port: {port} (TCP, inbound, local subnet only)\n"
                f"  profiles: {profiles}")
            active = current_firewall_profile()
            if active and active not in profiles and profiles != "any":
                console.print(
                    f"[yellow]![/yellow] This connection is on the "
                    f"[bold]{active}[/bold] profile, which the rule does not "
                    f"cover. Re-run with --profile {active}.")
        else:
            raise subprocess.CalledProcessError(result.returncode, command,
                                                result.stdout, result.stderr)
    except (subprocess.CalledProcessError, OSError):
        console.print("[red]✗ Could not add the firewall rule.[/red]")
        console.print(
            "This needs Administrator rights. Open PowerShell as Administrator "
            "and run:")
        console.print(
            f"  netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in "
            f"action=allow protocol=tcp localport={port} "
            f"program=\"{program}\" remoteip=localsubnet "
            f"profile={profiles}")
        console.print(
            f"To undo: netsh advfirewall firewall delete rule name=\"{rule_name}\"")


def firewall_rule_name(port: int) -> str:
    """Rule name including the port, so several ports can coexist."""
    return f"SELTRANSFER (TCP {port})"


def normalise_firewall_profiles(profile: str) -> str:
    """Validate and canonicalise the ``--profile`` value.

    ``any`` is passed through, because it is what netsh wants. Otherwise the value
    is checked against the real profile names rather than handed to netsh, so a
    typo produces an error instead of a rule that silently applies to nothing.
    """
    allowed = {"private", "domain", "public"}
    wanted = {item.strip().lower() for item in profile.split(",") if item.strip()}
    if not wanted:
        raise typer.BadParameter("give at least one profile, or 'any'")
    if wanted == {"any"}:
        return "any"
    unknown = wanted - allowed
    if unknown:
        raise typer.BadParameter(
            f"unknown profile(s): {', '.join(sorted(unknown))}. "
            "Use any, private, domain, public, or a comma-separated list.")
    # Canonical order, so the same request always produces the same rule.
    return ",".join(name for name in ("domain", "private", "public") if name in wanted)


def parse_rule_profiles(output: str) -> str | None:
    """Pull the profiles an existing rule applies to out of ``show rule`` output.

    netsh prints ``Profiles:  Domain,Private,Public`` - capitalised, comma
    separated, and with a rule created as ``profile=any`` reported as the full
    list of the three concrete profiles. Returned in the same canonical order as
    ``normalise_firewall_profiles`` so the two can be compared directly, with the
    all-profiles case collapsed to ``"any"``.
    """
    match = re.search(r"^\s*Profiles:\s*(.+)$", output or "", re.MULTILINE | re.IGNORECASE)
    if not match:
        return None
    wanted = {item.strip().lower() for item in match.group(1).split(",") if item.strip()}
    if wanted == {"any"}:
        return "any"
    known = {name for name in ("domain", "private", "public") if name in wanted}
    if not known:
        # An unrecognised value means "cannot tell", not "matches nothing".
        return None
    if len(known) == 3:
        return "any"
    return ",".join(name for name in ("domain", "private", "public") if name in known)


def parse_firewall_profile(output: str) -> str | None:
    """Pull the active profile name out of ``netsh ... show currentprofile``.

    The first line reads ``Public Profile Settings:``, so the name is the word
    *before* "Profile". Matching the wrong side of the word returns "settings",
    which looks plausible and is always wrong.
    """
    match = re.search(r"^\s*([A-Za-z]+)\s+Profile", output or "", re.MULTILINE)
    return match.group(1).lower() if match else None


def current_firewall_profile() -> str | None:
    """The active firewall profile name, if it can be read.

    Used only to warn when the rule does not cover the profile the machine is
    actually on - the case that made the original profile=private,domain rule
    useless on a hotspot.
    """
    result = subprocess.run(
        ["netsh", "advfirewall", "show", "currentprofile"],
        capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return None
    return parse_firewall_profile(result.stdout)


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
def status(
    port: int | None = typer.Option(None, "--port", "-p", help="Server port to query"),
) -> None:
    """Show the local server status."""
    port = port or get_settings().server_port
    try:
        with urlopen(Request(f"{_local_base(port)}/api/status",
                             headers=_local_headers(port)), timeout=2) as response:
            console.print(json.loads(response.read()))
    except OSError:
        console.print(
            f"[yellow]SELTRANSFER is not listening on port {port}.[/yellow]")


@app.command()
def discover(
    port: int | None = typer.Option(None, "--port", "-p", help="Server port to query"),
) -> None:
    """Show devices discovered by a running local server."""
    port = port or get_settings().server_port
    try:
        with urlopen(Request(f"{_local_base(port)}/api/devices",
                             headers=_local_headers(port)), timeout=3) as response:
            data = json.loads(response.read())
        table = Table("Name", "Type", "IP", "Port", "Status", "Paired", "Device ID")
        paired = set(data.get("paired_devices", []))
        for device in data["devices"]:
            table.add_row(device["name"], device["type"], device["ip"] or "-",
                          str(device["port"]), device["status"],
                          "yes" if device["device_id"] in paired else "no",
                          device["device_id"])
        console.print(table)
    except OSError:
        console.print(
            "[yellow]Start SELTRANSFER first: seltransfer start[/yellow]")


@app.command("send")
def send_files(paths: list[Path] = typer.Argument(...),
               to: str | None = typer.Option(None, "--to"),
               port: int | None = typer.Option(
                   None, "--port", "-p", help="Local server port")) -> None:
    """Send selected files directly to a discovered device."""
    port = port or get_settings().server_port
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
    local = _local_base(port)
    headers = _local_headers(port)
    try:
        with urlopen(Request(f"{local}/api/devices", headers=headers),
                     timeout=5) as response:
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

        # Creating a transfer requires the destination to be paired. The CLI holds
        # the local token, which is proof of intent the server accepts, so pairing
        # is a single call. Pairing is idempotent.
        pair = Request(f"{local}/api/devices/{to}/pair", data=b"",
                       headers={**headers, "Content-Type": "application/json"},
                       method="POST")
        with urlopen(pair, timeout=5) as response:
            if response.status != 200:
                raise ValueError(f"could not pair with {destination['name']}")

        # The upload token is ours to choose. The destination will not hand a
        # token back to us, because only its own node may read one, so we
        # generate it and present the same value when pushing the bytes.
        token = secrets.token_urlsafe(32)
        body = json.dumps({"receiver_id": to, "files": files}).encode()
        request = Request(f"{local}/api/transfers", data=body,
                          headers={**headers, "Content-Type": "application/json"},
                          method="POST")
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
