# ZTE ZXHN F670L — Stack-Based Buffer Overflow in httpd `nextpage` Handling

| | |
|---|---|
| **Vendor** | ZTE Corporation |
| **Product** | ZXHN F670L (GPON ONT / home gateway) |
| **Component** | `bin/httpd` — `webd_getenv` (reached via `getpage.gch`) |
| **Affected version** | firmware `V1.1.20P3N6B` |
| **Fixed version** | None |
| **Likely also affected** | other ZTE ZXHN models sharing the same web framework (e.g. ZXHN H298N — same `webd_getenv`/`webd_setenv`/`nextpage` implementation, statically confirmed) |
| **CWE** | CWE-121 Stack-based Buffer Overflow |
| **CVSS 3.1** | 9.8 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (assumes the trigger page is reachable pre-auth; a conservative 8.8 `PR:L` applies if the page requires authentication — see Stated Boundaries) |

## Summary

The web server `bin/httpd` publishes HTTP request parameters as environment-style
key/value entries and reads them back with `getenv`-like accessors. The HTTP parameter
`nextpage` is user controlled and is copied into a fixed-size **260-byte** stack buffer
by `webd_getenv` using an unbounded `strcpy`. Because the stored value may be up to
**1024 bytes** (`webd_setenv` bounds the value only by `cmp r0,#0x400`), the copy
overwrites the saved return address — the buffer sits exactly **296 bytes** below it —
allowing full control of the program counter.

## Root Cause

```
webSetEnv (0x192b0)
  -> webd_setenv (0x2a170)   ; webd_setenv(obj+0x84 /*name*/, obj+0x104 /*value*/)
                             ; value length limited only by: cmp r0,#0x400 / bls  (<= 1024)

webd_getenv (0x2a404)
  -> strcpy(dst, entry->value)   @ 0x2a460   ; no length check   <-- flaw

consumers (dest buffers are 260 bytes, value can be 1024):
  f_set_inst            (0x3192c) -> buf at fp-296
  f_del_inst            (0x3137c) -> buf at fp-288
  IsCSRFTokenCheckPassed(0x2f080) -> buf at fp-272
```

Stack layout (`f_set_inst`):

```
push {r4-r9, sl, fp, lr}      ; 9 registers
add  fp, sp, #32              ; fp -> saved lr
sub  sp, #564
memset(fp-296, 0, 260)        ; char buf[260] -> [fp-296, fp-36]
...
webd_getenv("nextpage", fp-296)   ; unbounded strcpy -> overwrites lr
```

## Trigger Surface

`set_inst` is invoked by almost every configuration page (`common_gch.gch`,
`app_list_conf_gch.gch`, `dev_ping_gch.gch`, `dhcp_basic_gch.gch`, ...), reachable
via e.g. `GET /getpage.gch?pid=1002&nextpage=<value>`. `f_del_inst` and
`IsCSRFTokenCheckPassed` have their own trigger pages.

## Attack Chain

1. Request a CGI page with an over-long `nextpage` value (> 296 bytes).
2. The value is stored via `webd_setenv` (limit 1024) and read back by `webd_getenv`.
3. `strcpy` overflows the 260-byte stack buffer and overwrites the saved return address.
4. `GNU_STACK = RW` (NX on) prevents ret2shellcode; the binary is non-PIE (`ET_EXEC`)
   and ships usable ROP gadgets (`pop {r4, pc} @ 0x180d0`) and an imported sink
   (`execlp@PLT @ 0x177d0`), so a ROP chain yields code execution.

## Evidence

- **Control-flow hijack (dynamic).** Under `qemu-arm-static -g` + `gdb-multiarch`,
  calling the vulnerable path with a 1000-byte value:
  ```
  setenv("nextpage", <1000 x 'A'>) ; webd_getenv("nextpage", <stack buffer>)
  -> SIGSEGV, PC = 0x41414140        # saved return address overwritten by 'AAAA'
  ```
- **In-process command execution (dynamic, ASLR-independent).** A self-contained ARM
  stub resolves the httpd runtime base with `adr` (no leak needed), forces GOT
  resolution of `malloc` through its PLT (lazy binding), derives
  `libc_base = GOT[malloc] - 0x48278`, and calls `system`. `sh -c 'id; uname -m'`
  produced the target process's identity and the emulated machine type — i.e. arbitrary
  command execution inside the httpd process was reproduced.
- The vulnerable code is instruction-identical across the firmware build examined.

## Reproduction

Performed against the vendor's publicly distributed firmware
(SHA-256 `792b400c…8bf2`, matching the vendor's SHA256SUMS) in an isolated
`qemu-arm-static` emulation environment — no real device, no internet. The two
necessary exploitation stages (return-address control and in-process command
execution) were each independently reproduced.

## Stated Boundaries

- **End-to-end chain not closed in a live HTTP flow.** `webd_setenv`/`webd_getenv`
  require an HTTP request context to initialize; the `cspd` shared-memory backend does
  not run under qemu-user, so the `HTTP nextpage -> overflow` segment could not be
  exercised end-to-end in this environment. The primitive itself (unbounded `strcpy`
  into a 260-byte buffer) and the resulting control-flow hijack are proven.
- **Authentication of the trigger page not dynamically verified.** `PR:N` (9.8) is
  assumed from the framework layout; if the endpoint requires authentication the score
  is 8.8 (`PR:L`).

## Fix Recommendation

1. In `webd_getenv`, replace the unbounded `strcpy` with a length-checked copy
   (`strncpy` / `snprintf`, or validate `strlen(value) < dstsize`).
2. Align the `webd_setenv` 1024-byte value bound with **every** consumer buffer
   (currently 260 bytes ≪ 1024).
3. Validate/whitelist the `nextpage` parameter (a `webd_exe_file` whitelist exists but
   does not cover the environment-variable injection path).

## References

- Duplicate check: no entry in NVD (366,857 records) references `webd_getenv`,
  `webd_setenv` or `getpage.gch`; the 26 `nextpage` hits are all non-ZTE.
- Closest prior ZTE work: CVE-2024-45413 / 45414 / 45415 / 45416 — different functions
  (`rsa_decrypt`, `webPrivateDecrypt`, `check_data_integrity`, `session_init`),
  different models (none is F670/F670L) and a different web framework
  (Lua + `/var/lua_session` vs. thttpd + `<% %>`). This report is a distinct issue.
- Reported to the vendor's security response team. No public advisory.
