# Tenda AC10U V1.0 — Unauthenticated telnetd activation with hard-coded root credential

| Field | Value |
|---|---|
| **Product** | Tenda AC10U (V1.0, AC1200) |
| **Firmware** | V15.03.06.48_multi_TDE01 (build 2018-02-11) |
| **Platform** | MIPS32 little-endian, uClibc, Realtek RTL8197DN |
| **Vulnerability class** | CWE-306 — Missing Authentication for Critical Function |
| **Related weakness** | CWE-798 — Use of Hard-coded Credentials |
| **CVSS v3.1** | `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = **8.8 (High)** |
| **Authentication required** | None (factory/reset state, `sys.userpass` empty) |
| **Attack vector** | Adjacent network (LAN) |
| **Impact** | Unauthenticated start of telnetd; root shell via shipped credential |
| **Status** | Confirmed (dynamic: telnetd, login, root shell, code execution) |
| **CVE ID** | *Requested — VulDB submission pending* |
| **Disclosure** | Public advisory (this repository) |

> **Scope note.** This finding covers two linked defects: (a) an unauthenticated HTTP
> endpoint that starts `telnetd`, and (b) a hard-coded root credential in the shipped
> filesystem. The plaintext credential is **redacted** from this advisory and disclosed
> privately to the CNA/vendor.

---

## 0. Repository layout

| Path | Content |
|---|---|
| `README.md` | This advisory |
| `poc/verify_c3.py` | Sanitized check: `GET /goform/telnet` → verify TCP 23 is listening |
| `evidence/telnet_listen.txt` | Sanitized transcript of the listener check |
| `evidence/root_shell.txt` | Sanitized root-shell transcript (credential redacted) |

---

## 1. Summary

Tenda AC10U V1.0 firmware V15.03.06.48_multi_TDE01 allows an unauthenticated LAN peer
to start a telnet daemon through the web management interface. In the factory/reset
state — i.e. whenever no administrative password has been set — `R7WebsSecurityHandler@0x434e80`
serves `/goform/telnet` without any credential. The handler `TendaTelnet@0x45bb48`
then executes:

```c
doSystemCmd("killall -9 telnetd");
doSystemCmd("telnetd -b %s &", GetValue("lan.ip"));
```

The shipped root filesystem (`etc_ro/passwd`, `etc_ro/shadow`) contains a hard-coded
root credential that matches a well-known Tenda default. An adjacent-network attacker
can therefore start `telnetd` and authenticate as root, obtaining a root shell and
arbitrary command execution. The plaintext credential is redacted from this public
advisory; the exact value is provided to the CNA and vendor.

## 2. Affected components

| Item | Value |
|---|---|
| Firmware image SHA-256 | `0bace3ed6a9b9b0a5c033bde4b0d122e6bd4494b35f28c0531abbd0bfb9edbdf` |
| `bin/httpd` SHA-256 | `a4067dde7928a1ef3838624d2b3eaa125bfdbbd923a05587e1dfc7ceb18161c9` |
| `bin/httpd` properties | MIPS32 LE, uClibc, not stripped (DWARF present), non-PIE |
| Factory config | `webroot_ro/default.cfg:304` → `sys.userpass=` (empty) |
| Credential store | `etc_ro/passwd`, `etc_ro/shadow` |

Only the AC10U V1.0 / V15.03.06.48 image above was analysed.

## 3. Technical details

### 3.1 Authentication gate

`R7WebsSecurityHandler@0x434e80` contains:

```c
if ((!strncmp(url, "/goform/telnet") || !strncmp(url, "/goform/ate"))
    && !g_Pass[0]) {
    /* request is handled without authentication */
}
```

`g_Pass` is populated from `sys.userpass`, which is empty in the factory/reset state,
so `/goform/telnet` is served without a session.

### 3.2 telnetd activation

```
GET /goform/telnet
  -> R7WebsSecurityHandler@0x434e80   (bypass while g_Pass[0] == 0)
  -> TendaTelnet@0x45bb48
     -> doSystemCmd("killall -9 telnetd")
     -> doSystemCmd("telnetd -b %s &", GetValue("lan.ip"))
```

No credential, CSRF token, or session is required. The daemon listens on TCP 23 on the
LAN address.

### 3.3 Hard-coded root credential

The image ships two MD5-crypt hashes for `root` in `etc_ro/shadow`. Both resolve to the
same well-known Tenda default credential. The hashes and the plaintext value are omitted
here and supplied privately to the CNA/vendor so that the advisory does not publish a
working backdoor credential for deployed devices.

### 3.4 Verification status (accurate scope)

- **Dynamically confirmed** in QEMU user-mode + chroot: `telnetd` listens on
  `192.168.0.1:23`; `root` login with the shipped credential succeeds; the shell runs
  as `uid=0`; arbitrary MIPS code execution was demonstrated (`/tmp/rceproof`).
- **Not closed end-to-end in emulation**: the HTTP `GET /goform/telnet` step depends on
  `GetValue("lan.ip")`, which reads bare NVRAM backed by flash and cannot be populated
  in this emulation. The telnetd start was therefore exercised through the same
  `doSystemCmd("telnetd -b %s &")` path directly. On physical hardware the HTTP request
  is the first verification point.
- The vulnerable code was not modified; environment setup is described in Section 4.3.

## 4. Proof of concept

Precondition: factory/reset state (`sys.userpass` empty), LAN reachability.

### 4.1 Sanitized verification

`poc/verify_c3.py` performs the unauthenticated HTTP request and checks that TCP 23 is
listening. It does **not** contain or transmit any credential:

```python
GET http://<device>/goform/telnet      # unauthenticated in factory state
connect TCP <device>:23                # expect LISTEN
```

Expected result: port 23 `LISTEN` shortly after the HTTP request.

### 4.2 Full chain (sanitized)

| Step | Action | Observed result |
|---|---|---|
| 1 | `GET /goform/telnet` (no credential) | handler executes `telnetd -b <lan_ip> &` |
| 2 | TCP connect to `<lan_ip>`:23 | `LISTEN` |
| 3 | telnet login, `root` + shipped credential | `~ #` prompt |
| 4 | `id` | `uid=0(root) gid=0(root)` |
| 5 | execute a test binary | `C3_RCE_OK uid=0 euid=0` |

Step 3 credential: **redacted** in this advisory; the value is provided to the CNA and
vendor. The sanitized transcript is `evidence/root_shell.txt`.

### 4.3 Dynamic verification environment

- QEMU user-mode (`qemu-mipsel-static`) with chroot over the extracted rootfs.
- `devpts` mounted so that `telnetd`/`login` can allocate a TTY.
- httpd started with the same environment patches used for the ATE finding (hardware
  setting branches at `0x433c8a` / `0x433cd7` / `0x433d2b`; `Set_Mfg_Button_Test@0x7098`
  neutralised). The telnet code path itself was not modified.
- Because `GetValue("lan.ip")` reads bare NVRAM, telnetd was started by invoking the
  same `doSystemCmd` command directly; the HTTP entry point remains a static link.

## 5. Impact

- Unauthenticated activation of a remote shell service on the LAN.
- Root shell and arbitrary code execution using the shipped credential.
- Full device compromise: configuration exfiltration, persistence, traffic interception.
- Existing deployments that never changed the default root credential are exposed even
  after the administrative web password is set, because the credential lives in the
  read-only filesystem.

## 6. Existing CVEs and differences

| CVE | Product / version | Mechanism | Difference |
|---|---|---|---|
| CVE-2018-5770 | Tenda AC15 | `/goform/telnet` starts telnetd + default account | Different model and firmware line; this report adds the exact credential location and CWE-798 classification |
| CVE-2020-10988 | Tenda AC15 `15.03.05.19` | `tenda_login` hard-coded telnet credential | Different model and firmware generation |
| CVE-2024-46436 | Tenda W18E | Hard-coded credential → telnet root | Different product line (enterprise) |

This is a well-populated category for Tenda. The tested image is the AC10U **V1.0**
running the **V15.03** MIPS/uClibc generation (build 2018-02-11, RTL8197DN), which is a
different hardware revision and firmware generation from the entries above. If the
reviewer treats this as an affected-product extension rather than a new defect, the
request is to at least record the AC10U V1.0 / V15.03.06.48 image, the exact handler
offset, and the CWE-306/CWE-798 classification.

## 7. Mitigation

- Do not expose the web management interface to untrusted segments; set an
  administrative password even on isolated deployments (removes the `!g_Pass[0]`
  condition, though not the hard-coded credential).
- Change the root credential; the shipped hash lives in the read-only filesystem, so a
  firmware update is required to remove it.
- Block TCP 23 on the LAN/WAN boundary.
- Vendor-side: remove the debug `/goform/telnet` endpoint from production firmware or
  require an authenticated session; remove or randomise the hard-coded root credential;
  bind telnetd to loopback or disable it entirely.

## 8. Disclosure timeline

| Date | Event |
|---|---|
| 2026-10-29 | Static analysis of the authentication gate and `TendaTelnet` handler |
| 2026-10-30 | Dynamic confirmation: telnetd listener, root login, root shell, code execution |
| 2026-11-03 | Public advisory published; CVE request via VulDB — in progress |

## 9. Notes on scope and integrity of the report

- The HTTP trigger was not closed end-to-end in emulation (NVRAM dependency, see
  Section 3.4). The handler code and the `doSystemCmd` call are established statically;
  telnetd start-up, login, root shell, and code execution are dynamically confirmed.
- No personal information, contact address, or identifier of the researcher is included
  in this document or its attachments.
- The plaintext credential is deliberately withheld from this public advisory. The
  unredacted evidence is available privately to the CNA or vendor on request.

## 10. References

- Vendor: Tenda — https://www.tendacn.com
- CWE-306: https://cwe.mitre.org/data/definitions/306.html
- CWE-798: https://cwe.mitre.org/data/definitions/798.html
