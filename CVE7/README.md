# ASUS RT-AC68U — Path Traversal in the AiDisk Shared-Folder Creation Endpoint

| Field | Value |
|---|---|
| **Product** | ASUS RT-AC68U (dual-band wireless router) |
| **Firmware** | 3.0.0.4.384_81049 |
| **Platform** | ARM little-endian, uClibc; closed-source `httpd` + `libdisk.so` |
| **Vulnerability class** | CWE-22 — Improper Limitation of a Pathname to a Restricted Directory |
| **Related weakness** | CWE-73 — External Control of File Name or Path |
| **CVSS v3.1** | `CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N` = **2.4 (Low)** |
| **Authentication required** | Administrator session (`asus_token`) |
| **Attack vector** | Adjacent network (LAN) |
| **Impact** | Directory creation (mode `0777`) outside the shared folder; demonstrated in `/tmp`, not on persistent storage. Integrity only (`C:N/I:L/A:N`) |
| **Status** | Confirmed (dynamic: vendor `httpd` in emulation, real ext4 mount) |
| **CVE ID** | *Submitted to VulDB 2026-11-03 — entry 1071804 (moderation pending)* |
| **Disclosure** | Public advisory (this repository) |

> **Scope note.** The `httpd` binary under test is the vendor's own, run with
> `qemu-arm-static` + `chroot`; `libnvram` is a stub (user `admin`, share pool `test`,
> doc root `/www`). The share is a real ext4 mount at `/tmp/mnt/test` inside the chroot,
> because the mount layout decides which filesystem operations are possible (Section 6).
> Physical hardware was not used.
>
> On this firmware `/etc` is a **symlink** to `tmp/etc` (`ls -ld /etc` → `etc -> tmp/etc`).
> The `/etc/...` test therefore landed in `/tmp/etc/...`, i.e. inside the same tmpfs, and
> is **not** evidence that a root-owned directory outside tmpfs can be reached. That
> inference was withdrawn (see Section 9 and `evidence/04-errata-etc-symlink.txt`).

---

## 0. Repository layout

| Path | Content |
|---|---|
| `README.md` | This advisory |
| `poc/poc_create_sharedfolder_traversal.py` | Control + traversal requests against a live device (optional Burp proxy) |
| `evidence/01-traversal-result.png` | Terminal capture: control and traversal runs |
| `evidence/02-raw-transcript.txt` | Raw session log, including the sibling `modify_sharedfolder` re-test |
| `evidence/03-replay-transcript.txt` | Output of the one-shot replay script |
| `evidence/04-errata-etc-symlink.txt` | How the `/etc` claim was corrected (`/etc` is a symlink to `tmp/etc`) |

---

## 1. Summary

The AiDisk page set under `/www/aidisk/` lets an authenticated administrator create a
shared folder on an attached USB disk. `POST /aidisk/create_sharedfolder.asp` takes
`account`, `pool` and `folder`, requires only `pool` and `folder` to be non-empty
(`account` may be empty), and passes `folder` to `libdisk.so::add_folder()`:

```c
snprintf(path, size, "%s/%s", mount_path, folder);
umask(0);
mkdir(path, 0777);            /* sink */
```

`..`, `/`, `\` and length are not validated, and the operation is not anchored to a
directory descriptor. With `folder=../../NEW_OUTSIDE_DIR` and the share mounted at
`/tmp/mnt/test`, the directory `/tmp/NEW_OUTSIDE_DIR` is created with mode `0777`,
outside the shared folder.

## 2. Affected components

| Item | Value |
|---|---|
| Firmware image SHA-256 | `68a8cf0c223e18d4a1bc91ed4cb6d382ac1f5f8b2c1a0c8d027135c07dec227b` |
| `/usr/sbin/httpd` SHA-256 | `34f18fd6abc66ecd7589177d029e81dc9df7e0c6d5de47c7cacc3710aa1f71ce` |
| `/lib/libdisk.so` SHA-256 | `33750e4597621ab7862105d78f8622e27a459e3b95c54eef8174010788d5b8ed` |
| `add_folder()` offset | `0x21fa8` |
| Firmware download | `https://dlcdnets.asus.com/pub/ASUS/wireless/RT-AC68U/FW_RT_AC68U_300438481049.zip` |

Only the 384_81049 image above was analysed. Other ASUS models shipping the same
`libdisk.so` helper are plausibly affected but were not tested.

## 3. Technical details

### 3.1 Data flow

```text
POST /aidisk/create_sharedfolder.asp   (params: account, pool, folder)
  → httpd: ASP builtin create_sharedfolder()
  → httpd: FUN_00023700
        get_parameter("pool")   → get_mount_path(pool, buf, 0x1000)
        get_parameter("folder") → passed through without validation
  → libdisk.so: add_folder(account, mount_path, folder)      @ 0x21fa8
        snprintf(path, size, "%s/%s", mount_path, folder)
        umask(0)
        mkdir(path, 0777)                                     ← sink
```

`add_folder()` contains no `..` check, no prefix check and no `openat()`/`mkdirat()`
anchoring. `umask(0)` makes the result world-writable.

### 3.2 Observed behaviour

Same `asus_token`, same `pool=test`, only `folder` changes:

| `folder` | Response | Result on disk |
|---|---|---|
| `poc_inside_dir` (control) | `create_sharedfolder_success()` | inside the share |
| `../../NEW_OUTSIDE_DIR` | `create_sharedfolder_success()` | `/tmp/NEW_OUTSIDE_DIR`, `drwxrwxrwx` — outside the share |
| `../../etc/CNVD_ETC_DIR` | `create_sharedfolder_success()` | `/tmp/etc/CNVD_ETC_DIR` — `/etc` is a symlink to `tmp/etc`, so this is still tmpfs (scope check only) |
| `../../jffs/CNVD_JFFS_DIR` | `create_sharedfolder_error(Action5)` | not created — persistent path not available in emulation |

The first two rows are the vulnerability: a `..` in `folder` escapes the share mount.
The third row shows why the earlier "writes to root-owned `/etc`" wording was wrong,
and the fourth shows that the persistent partition was never reached.

### 3.3 Verification status (accurate scope)

- **Dynamically confirmed**: the vendor `httpd` served the request, the builtin ran,
  `libdisk.so::add_folder()` executed, and the directory appeared outside the share.
- **Not exercised**: physical hardware, real `nvram` (a stub supplies the pool name),
  writes to persistent storage, and other ASUS models.
- The vulnerable code was not modified; the only environment change was the nvram stub.

## 4. Proof of concept

```bash
TARGET=http://192.168.1.1 POOL=test USE_BURP=0 \
  python3 poc/poc_create_sharedfolder_traversal.py
```

`USERNAME` defaults to `admin`; `PASSWORD` is read from the environment and falls back
to the factory value. Set `PASSWORD` in the environment if it was changed.

The script logs in with `POST /login.cgi` (`login_authorization=base64(user:pass)`) to
obtain `asus_token`, then issues the control request and the traversal request, and
reports whether both succeeded. It **creates two directories and nothing else** — it
does not read, modify or delete existing files.

Expected output:

```text
[>] POST /login.cgi -> 200  asus_token=...
[>] 对照（共享目录内）: pool=test folder='poc_inside_dir' -> HTTP 200 success=True error=False
[>] 穿越（共享目录外）: pool=test folder='../../POC_OUTSIDE_DIR' -> HTTP 200 success=True error=False
[+] 漏洞成立：两次都成功，说明 ../ 没被过滤。
```

Manual equivalent (one variable: `folder`):

```http
POST /aidisk/create_sharedfolder.asp HTTP/1.1
Host: 192.168.1.1
Cookie: asus_token=<token>
Content-Type: application/x-www-form-urlencoded

account=&pool=test&folder=../../NEW_OUTSIDE_DIR
```

## 5. Impact

- Directory creation outside the intended share, with mode `0777`, as uid 0. The uid is
  the one inherited from the emulation chroot; the uid of `httpd` on a shipped device was
  not measured.
- Demonstrated in `/tmp`, which is world-writable on this firmware; the impact is
  therefore limited to integrity (`I:L`). No file content is exposed (`C:N`), and no
  availability impact was demonstrated (`A:N`).
- Writing to persistent or read-only partitions was **not** demonstrated (`/jffs`
  returned `Action5`), and no escalation chain is claimed.

## 6. False positive actively excluded

The sibling endpoint `modify_sharedfolder` (rename) looks equally vulnerable but is
**not**: `libdisk.so::mod_folder()` uses `rename(2)` (`rename @ 0x127d7`), and on a real
device the share is a separate filesystem, so a `../../` target returns `EXDEV`
(measured: `modify_sharedfolder_error(alert_msg.Action7)`). An earlier "successful
traversal rename" was an artefact of a fabricated `/proc/mounts` entry that put the
share and `/tmp` on the same superblock; that claim was withdrawn. `mkdir(2)`, unlike
`rename(2)`, does cross filesystem boundaries, so `create_sharedfolder` stands.

## 7. Existing CVEs and differences

No public advisory was located for `/aidisk/create_sharedfolder.asp` or for
`libdisk.so::add_folder()` (search date 2026-11-03). ASUS AiDisk path-handling issues
have been reported for other pages and other models; the endpoint and the sink above
are specific to this firmware, and the report does not claim shared code with them.

## 8. Mitigation

- Resolve `pool` server-side against the mounted share list; do not accept a path from
  the client.
- Normalize `folder` and reject `..`, `/`, `\`, control characters, a leading `.`, and
  names longer than 255 bytes.
- Use `openat(share_dirfd, name)` + `mkdirat()` so the operation cannot escape the share.
- Drop `umask(0)`; create directories with `0755` or per policy.
- Apply the same validation to the `create` / `modify` / `delete` handlers.

## 9. Disclosure timeline

| Date | Event |
|---|---|
| 2026-10-30 | Static analysis: missing validation in `create_sharedfolder` → `add_folder()` |
| 2026-11-03 | `httpd` emulation built; traversal reproduced on a real ext4 mount |
| 2026-11-03 | External adversarial review (`gpt-5` via `gpt_ask.py review` profile): `not_refuted` |
| 2026-11-03 | Sibling `modify_sharedfolder` withdrawn as a false positive (EXDEV) |
| 2026-11-03 | **Erratum**: `/etc` is a symlink to `tmp/etc`, so the `/etc/...` run landed in tmpfs; the "any root-writable path" inference was withdrawn. As no availability impact was demonstrated, the vector became `C:N/I:L/A:N` and the base score **2.4 (Low)** |
| 2026-11-03 | CVE requested via VulDB (vendor/CNA channel); public advisory published here |

No vendor response had been received at publication time; the vendor was contacted
through the CNA submission (VulDB).

## 10. Notes on scope and integrity of the report

- Evidence is from emulation with a stubbed `nvram`, not from hardware.
- No personal information, contact address or researcher identifier is included in this
  document or its attachments.
- The PoC only creates directories; no destructive or exfiltration payload is published.

## 11. References

- Vendor: ASUS — https://www.asus.com
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- CWE-73: https://cwe.mitre.org/data/definitions/73.html
