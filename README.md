# CVE advisories

Public advisories for vulnerabilities found during firmware and embedded-device
research. Each directory is self-contained: `README.md` (advisory), `LICENSE`, and —
where the finding was reproduced dynamically — `poc/` and `evidence/`.

| Entry | Product | Firmware / version | Weakness | CVSS v3.1 | Status |
|---|---|---|---|---|---|
| [CVE1](CVE1/) | TOTOLINK EX200 | — | CWE-121 stack buffer overflow, `setStaticDhcpConfig` (`comment`) | — | advisory only |
| [CVE2](CVE2/) | TOTOLINK EX200 | — | CWE-121 stack buffer overflow, `setWiFiAclAddConfig` (`macAddress`) | — | advisory only |
| [cve3](cve3/) | Tenda AC10U V1.0 | V15.03.06.48_multi_TDE01 | CWE-78 unauthenticated command injection, ATE service (UDP 7329) | 8.8 High | confirmed (emulation) |
| [CVE4](CVE4/) | Tenda AC10U V1.0 | V15.03.06.48_multi_TDE01 | CWE-306 / CWE-798 unauthenticated `telnetd` start + shipped root credential | 8.8 High | confirmed (emulation) |
| [CVE5](CVE5/) | TRENDnet TEW-751DR | 1.03B01 | CWE-78 unauthenticated command injection via UPnP GENA `CALLBACK` header | 7.5 High | confirmed on 751DR (script-generation replay); 752DRU shares the PHP files, 733GR shares `cgibin`, neither individually verified |
| [CVE6](CVE6/) | TRENDnet TEW-824DRU | 1.00b18 | CWE-78 stored command injection in System Log settings (+ CWE-121) | 6.8 Medium | confirmed (vendor CGI, emulation) |
| [CVE7](CVE7/) | ASUS RT-AC68U | 3.0.0.4.384_81049 | CWE-22 path traversal in AiDisk `create_sharedfolder` | 2.4 Low | confirmed (vendor httpd, emulation) |

Notes on evidence levels:

- **confirmed (emulation)** — the vulnerable vendor binary or script was executed in a
  QEMU user-mode chroot and produced the documented effect. Physical hardware was not
  used. Each advisory states exactly which hop was not exercised.
- **script-generation replay** (CVE5) — the vendor's PHP generated the shell script and
  the vendor's shell executed it; the PHP interpreter/timer hop on the device is
  established statically and is not claimed as executed.
- **advisory only** — static analysis without a dynamic reproduction in this repository.

Entries are numbered in publication order. Local submission packages (with the full
Chinese/English report groups and CNVD forms where applicable) are tracked separately;
the advisory here is the authoritative public text.

## Scoring note

CVSS v3.1 base scores are recomputed from the published vector and checked against known
anchor vectors before publication. The `PR:H` weight is `0.27` when `S:U` and `0.50` when
`S:C`; swapping the two silently produces plausible-but-wrong scores.

- CVE6: `AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` = **6.8 (Medium)** — re-verified.
- CVE7: impact narrowed to integrity only, because no availability impact was
  demonstrated; vector `C:N/I:L/A:N` = **2.4 (Low)** (an earlier draft used `A:L` and 3.5).

## Disclosure policy

- Findings are published only after the vendor or a CNA has been given the material,
  or after the coordinated-disclosure window has expired.
- No credential, persistence mechanism, or turnkey exploitation payload is published.
- Proof-of-concept code is limited to what is needed to verify the defect, and is
  marked with its authorization requirements.
- No personal information about the researcher is included.

## License

Each directory is released under the MIT License (see the `LICENSE` file in it).
