# TRENDnet TEW-751DR — Unauthenticated Stack Buffer Overflow in `wfadev.cgi` (`SOAPAction`)

| Field | Value |
|---|---|
| **Product** | TRENDnet TEW-751DR (N600 wireless router); TEW-733GR ships the identical `cgibin` |
| **Firmware** | 1.03B01 |
| **Platform** | MIPS32 little-endian, uClibc; UPnP/WFA HTTP service on TCP 49152 |
| **Vulnerability class** | CWE-121 — Stack-based Buffer Overflow |
| **CVSS v3.1** | `CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` = **7.5 (High)** |
| **Authentication required** | None |
| **Attack vector** | Adjacent network (UPnP/WFA control plane) |
| **Impact** | Remote crash of the CGI (SIGSEGV); code execution **not** demonstrated |
| **Status** | Confirmed (dynamic: SIGSEGV reproduced, boundary measured) |
| **CVE ID** | *Submitted to VulDB on 2026-11-03 (CNA moderation pending)* |
| **Disclosure** | Public advisory (this repository); earlier copy at https://gist.github.com/qwq-nm/4120495fb8a560921da0f102fa90fa0d |

> **Scope note.** The overflow is proven to the level of "unauthenticated request kills the
> CGI". No control-flow hijack, no ROP chain and no code execution were achieved or are
> claimed. The binary has no stack canary and is a non-PIE `ET_EXEC`, which is why the
> overflow is reported at all; exploitability beyond the crash was not studied.

---

## 0. Repository layout

| Path | Content |
|---|---|
| `README.md` | This advisory |
| `poc/replay_wfadev_overflow.sh` | Length sweep against the vendor CGI in a QEMU user-mode chroot |
| `evidence/01-replay.png` | Terminal capture of the control / trigger / sweep runs |
| `evidence/02-raw-transcript.txt` | Raw transcript of the same runs |

---

## 1. Summary

`/wfadev.cgi` is the WFA (Wi-Fi Alliance) control endpoint of the UPnP stack, exposed on
`http://<device>:49152/wfadev.cgi`. `wfadev_main` (`0x40fafc` in `htdocs/cgibin`) performs
no session check. The part of the `SOAPAction` header before `#` is copied into a
4100-byte stack buffer (`acStack_1020`) with **unbounded `sprintf`** calls in the shared
response builder `FUN_0040ed90`:

```c
char acStack_1020[4100];
sprintf(acStack_1020, "<s:Envelope ...><s:Body>\n");
sprintf(acStack_1020 + iVar1, "<u:%sResponse xmlns:u=\"%s\" />\n", action, soapaction);
```

The same value is also reflected into the XML response (`xmlns:u="…"`), so the overflow
point and the reflection point are the same `sprintf`.

Measured boundary (single variable: prefix length `N`):

| `N` | Result |
|---|---|
| 26 | `HTTP/1.1 200 OK`, normal SOAP response |
| 3860 / 3900 | exit 0 |
| **3940** and above | SIGSEGV (`EXIT=139`) |
| 4200 | SIGSEGV (`EXIT=139`) |

## 2. Affected components

| Item | Value |
|---|---|
| Firmware image SHA-256 | `fe1168fc2b2bf4744df3a7145eeaf11b2c5272ae502c8f2993e5c614499322ec` |
| `htdocs/cgibin` SHA-256 | `e27547940d0ae75233fc6b2b64c50d37fc3b55d4dea9d86bbb86dd448f08a7eb` (byte-identical on TEW-751DR and TEW-733GR) |
| Vulnerable function | `FUN_0040ed90` (4100-byte stack buffer), reached from `wfadev_main @ 0x40fafc` |
| Binary properties | MIPS32 LE, not stripped, non-PIE `ET_EXEC`, `readelf -s \| grep stack_chk` = 0 |
| Firmware download | `https://download.trendnet.com/TEW-751DR/firmware/TEW-751DRv1_(FW1.03B01).zip` |

TEW-752DRU 1.03B01 ships a **different** `cgibin`; it was not decompiled for this entry
and is not claimed as affected by this finding.

## 3. Technical details

### 3.1 Entry point

```text
POST /wfadev.cgi?service=WFAWLANConfig1
SOAPAction: "A"*N + "#SetAPSettings"

cgibin :: wfadev_main @ 0x40fafc
  → getenv("HTTP_SOAPACTION")
  → strchr(soapaction, '#')            /* action = text after '#' */
  → table lookup of the 14 WFA actions
  → FUN_0040ed90(action, soapaction)   /* response builder */
        sprintf(acStack_1020 + len, "<u:%sResponse xmlns:u=\"%s\" />\n",
                action, soapaction)    ← unbounded, copies the whole prefix
```

`SetAPSettings` is one of the table entries whose handler only emits a response (no
external script), which makes the `SOAPAction` string the only variable that matters.

### 3.2 Verification status

- **Dynamically confirmed**: the vendor CGI, running in a QEMU MIPS user-mode chroot,
  returns 200 for `N ≤ 3900` and dies with SIGSEGV from `N = 3940`.
- **Not done**: code execution, control-flow analysis, testing on hardware, and a
  separate run on TEW-733GR (same binary hash, different device).
- The binary was not modified; only the CGI environment was supplied by the harness.

## 4. Proof of concept

```bash
ROOTFS=/path/to/extracted/rootfs ./poc/replay_wfadev_overflow.sh
```

The script sends `N = 26 / 3900 / 4000` and sweeps `3860…4200`, printing the CGI exit code
for each request. Expected: `EXIT=0` up to 3900, `EXIT=139` from 3940.

Request shape:

```http
POST /wfadev.cgi?service=WFAWLANConfig1 HTTP/1.1
Host: 192.168.10.1:49152
SOAPAction: AAAA…AAAA#SetAPSettings
Content-Type: text/xml
Content-Length: 4

<a/>
```

## 5. Impact

- An unauthenticated LAN peer can crash the WFA CGI with a single request; the UPnP
  daemon respawns it per request, so this is not a persistent outage, but it is a
  reliable remote DoS of that endpoint.
- The overflow is a classic stack smash in a non-PIE, non-canary binary. On MIPS with
  the usual stack layout this is a plausible code-execution primitive, but **no**
  exploitation was demonstrated, so it is not claimed.

## 6. Existing CVEs and differences

No public advisory was located for `/wfadev.cgi` on the 1.03B01 firmware line (search
date 2026-11-03). The `/soap.cgi?service=` command injection in the same firmware is a
separate defect (different endpoint, different sink) and is reported separately.

## 7. Mitigation

- Replace every `sprintf` in `FUN_0040ed90` with `snprintf` and track the remaining
  length; reject a `SOAPAction` longer than a few hundred bytes at the entry point.
- Restrict the WFA endpoint to the LAN (or to the WFA registration window) and disable
  the UPnP control plane when it is not needed.
- Rebuild the CGI with stack protector and PIE; the current binary has neither.

## 8. Disclosure timeline

| Date | Event |
|---|---|
| 2026-10-30 | Static analysis of `wfadev_main` / `FUN_0040ed90` |
| 2026-10-31 | Boundary measured in emulation (3900 ok, 3940 SIGSEGV) |
| 2026-11-03 | CVE requested via VulDB (vendor/CNA channel) |
| 2026-11-03 | Submitted to VulDB (CNA channel); moderation pending |
| 2026-11-03 | Public advisory published here |

## 9. Notes on scope and integrity

- Emulation only, no physical device; the harness supplies the CGI environment directly.
- No exploit payload is published; the PoC only varies the length of a header.
- No personal information is included.

## 10. References

- Vendor: TRENDnet — https://www.trendnet.com
- CWE-121: https://cwe.mitre.org/data/definitions/121.html
