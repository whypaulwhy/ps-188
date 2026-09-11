#!/usr/bin/env python3
"""Check whether a phone on the same network can reach this checkpoint.

    python tools/demo_preflight.py
    python tools/demo_preflight.py --port 8188

Run it on the machine serving the console, while the server is running. It
answers one question — can another device on this network reach it, and if not,
which of the three usual causes is it — because the failure modes are
indistinguishable from the phone's end, where every one of them looks like
"this site can't be reached".

It changes nothing. Opening a firewall port is a security decision and needs
administrator rights, so this prints the command and lets a person run it.

**Only for demonstrations.** Reaching the console from another device means
binding to the local network, and there is no authentication: anyone on that
network can screen documents and record decisions under any name they type. Use
a phone hotspot or a home network, never a campus or public one, and stop the
server afterwards.
"""

from __future__ import annotations

import argparse
import platform
import shutil
import socket
import subprocess
import sys

DEFAULT_PORT = 8188
"""The port the demonstration instructions use."""


def local_addresses() -> list[str]:
    """Return this machine's addresses on the local network, best effort.

    Returns:
        Every non-loopback IPv4 address found, most likely first.
    """
    found: list[str] = []
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Nothing is sent; this just asks the routing table which address would
        # be used to reach the wider network.
        probe.connect(("10.255.255.255", 1))
        found.append(probe.getsockname()[0])
    except OSError:
        pass
    finally:
        probe.close()

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            address = info[4][0]
            if not address.startswith(("127.", "169.254.")) and address not in found:
                found.append(address)
    except socket.gaierror:
        pass
    return found


def reachable(host: str, port: int, *, timeout: float = 2.0) -> bool:
    """Report whether a TCP connection to host:port succeeds.

    Args:
        host: Address to try.
        port: Port to try.
        timeout: How long to wait.

    Returns:
        Whether the port accepted a connection.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def windows_network_category() -> str | None:
    """Return the Windows network category, or None if it cannot be read."""
    if platform.system() != "Windows":
        return None
    # S607: `powershell` is resolved from PATH rather than an absolute path. Its
    # location differs across Windows installations, and this is a diagnostic
    # that reads one value, on a machine the operator is already sitting at.
    executable = shutil.which("powershell")
    if executable is None:
        return None
    try:
        finished = subprocess.run(  # noqa: S603
            [
                executable,
                "-NoProfile",
                "-Command",
                "(Get-NetConnectionProfile | Select-Object -First 1).NetworkCategory",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    category = finished.stdout.strip()
    return category or None


def print_code(url: str) -> None:
    """Draw an address as a QR code, so nobody has to type an IP address into a phone.

    Args:
        url: The address to encode.
    """
    import segno

    # On Windows segno writes to the console directly, so flush to keep the order.
    sys.stdout.flush()
    try:
        segno.make_qr(url).terminal()
    except (OSError, UnicodeError):
        print("  (The code could not be drawn in this window. Type the address instead.)")


def main(argv: list[str] | None = None) -> int:
    """Report whether a phone could reach this checkpoint, and what to fix."""
    parser = argparse.ArgumentParser(
        prog="python tools/demo_preflight.py",
        description="Check whether another device on this network can reach the console.",
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port the server uses.")
    arguments = parser.parse_args(argv)
    port = arguments.port

    print(f"Checking port {port}.\n")

    on_loopback = reachable("127.0.0.1", port)
    print(f"  server answers on 127.0.0.1  : {'yes' if on_loopback else 'NO'}")
    if not on_loopback:
        print("\nThe server is not running, or is on another port.")
        print("Start it, then run this again:")
        print("  uv run uvicorn api.app:create_app --factory --host 0.0.0.0 --port " + str(port))
        return 1

    addresses = local_addresses()
    if not addresses:
        print("\nThis machine has no address on a local network. Is it connected to wifi?")
        return 1

    address = addresses[0]
    on_network = reachable(address, port)
    print(f"  server answers on {address:<12}: {'yes' if on_network else 'NO'}")

    category = windows_network_category()
    if category is not None:
        print(f"  windows network category   : {category}")

    if not on_network:
        print("\nThe server is running but bound to loopback only.")
        print("Restart it with --host 0.0.0.0 rather than the default:")
        print("  uv run uvicorn api.app:create_app --factory --host 0.0.0.0 --port " + str(port))
        return 1

    capture = f"http://{address}:{port}/console/capture"
    print(f"\nThis machine can reach itself at {address}:{port}.")
    print(f"On the phone, open:  {capture}")
    print("  or point the phone's camera at this code:\n")
    print_code(capture)
    print(f"\n  The plain upload page, with no camera step: http://{address}:{port}/console/submit")
    print("  Note http, not https. There is no TLS here and https will not connect.")

    if platform.system() == "Windows":
        print("\nIf the phone still cannot reach it, the firewall is blocking the port.")
        if category is not None and category != "Private":
            print(f"  This network is {category}. A Private-profile rule will not apply to it.")
            print("  In an Administrator PowerShell, first:")
            print("    Set-NetConnectionProfile -NetworkCategory Private")
        print("  Then, in an Administrator PowerShell:")
        print(
            f'    New-NetFirewallRule -DisplayName "SENTINEL ID demo {port}" '
            f"-Direction Inbound -LocalPort {port} -Protocol TCP -Action Allow -Profile Private"
        )
        print("\n  Remove it when the demonstration is over:")
        print(f'    Remove-NetFirewallRule -DisplayName "SENTINEL ID demo {port}"')

    print("\nRemember: there is no authentication. Anyone on this network can screen")
    print("documents and record decisions under any name. Stop the server afterwards.")
    return 0


if __name__ == "__main__":  # pragma: no cover - the process entry point
    raise SystemExit(main(sys.argv[1:]))
