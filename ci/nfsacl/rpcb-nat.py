#!/usr/bin/env python3
# The runner's port 111 for the illumos client, in front of the NetBSD
# VM's rpcbind.  rpcb-nat.py LISTEN-PORT RPCBIND-PORT GUEST-ADDR CLIENT-ADDR
#
# Both VMs are QEMU user-mode guests at the same address (anyvm gives
# each net 192.168.122.0/24 and the guest .10), and each reaches the
# runner as 192.168.122.2.  Versions 3 and 4 of rpcbind answer GETADDR
# and GETADDRLIST with a universal address on the server's own address,
# as RFC 1833 has them do, so the NetBSD VM names 192.168.122.10 --
# which for the OmniOS VM is itself -- and the mount goes nowhere.
# Version 2's GETPORT carries only a port, which is why the Linux
# client on the runner never saw this.  So, as a NAT's helper for
# SunRPC does, the replies of those two procedures have GUEST-ADDR in
# their universal addresses replaced by CLIENT-ADDR; everything else
# passes through as it came.
import socket, struct, sys, threading

LPORT, RPORT = int(sys.argv[1]), int(sys.argv[2])
GUEST, CLIENT = sys.argv[3], sys.argv[4]
calls = {}
lock = threading.Lock()

def xstr(b, o):
    n = struct.unpack(">I", b[o:o + 4])[0]
    return b[o + 4:o + 4 + n].decode(), o + 4 + n + (-n % 4)

def pstr(s):
    b = s.encode()
    return struct.pack(">I", len(b)) + b + b"\0" * (-len(b) % 4)

def fix(ua):
    h, _, p = ua.rpartition(".")
    h, _, q = h.rpartition(".")
    if h == GUEST:
        print("rpcb-nat: %s -> %s" % (ua, CLIENT + "." + q + "." + p), flush=True)
        return CLIENT + "." + q + "." + p
    return ua

def note(m):
    if len(m) >= 24 and struct.unpack(">I", m[4:8])[0] == 0:
        xid, _, _, prog, vers, proc = struct.unpack(">6I", m[:24])
        with lock:
            calls[xid] = (vers, proc)

def rewrite(m):
    if len(m) < 24:
        return m
    xid, mtype, rstat = struct.unpack(">3I", m[:12])
    with lock:
        vp = calls.pop(xid, None)
    if mtype != 1 or rstat != 0 or vp is None or vp[0] < 3:
        return m
    vl = struct.unpack(">I", m[16:20])[0]
    o = 20 + vl + (-vl % 4)
    if struct.unpack(">I", m[o:o + 4])[0] != 0:
        return m
    o += 4
    head, body = m[:o], m[o:]
    if vp[1] == 3:				# GETADDR
        ua, _ = xstr(body, 0)
        return head + pstr(fix(ua))
    if vp[1] == 11 and vp[0] == 4:		# GETADDRLIST
        out, i = b"", 0
        while struct.unpack(">I", body[i:i + 4])[0]:
            out += body[i:i + 4]; i += 4
            ua, i = xstr(body, i)
            nid, i = xstr(body, i)		# rpcb_entry, RFC 1833
            sem = body[i:i + 4]; i += 4
            fam, i = xstr(body, i)
            pr, i = xstr(body, i)
            out += pstr(fix(ua)) + pstr(nid) + sem + pstr(fam) + pstr(pr)
        return head + out + body[i:]
    return m

def records(k):
    m = b""
    while True:
        h = k.recv(4, socket.MSG_WAITALL)
        if len(h) < 4:
            return
        n = struct.unpack(">I", h)[0]
        d = k.recv(n & 0x7fffffff, socket.MSG_WAITALL)
        if len(d) < (n & 0x7fffffff):
            return
        m += d
        if n & 0x80000000:
            yield m
            m = b""

def send(k, m):
    k.sendall(struct.pack(">I", 0x80000000 | len(m)) + m)

def tcpconn(c):
    try:
        s = socket.create_connection(("127.0.0.1", RPORT))
        def back():
            try:
                for m in records(s):
                    send(c, rewrite(m))
            except OSError:
                pass
            c.close()
        threading.Thread(target=back, daemon=True).start()
        for m in records(c):
            note(m)
            send(s, m)
    except OSError:
        pass
    c.close()

def tcp():
    l = socket.socket()
    l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    l.bind(("127.0.0.1", LPORT))
    l.listen(16)
    while True:
        c, _ = l.accept()
        threading.Thread(target=tcpconn, args=(c,), daemon=True).start()

def udp():
    l = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    l.bind(("127.0.0.1", LPORT))
    while True:
        m, peer = l.recvfrom(65536)
        note(m)
        def one(m=m, peer=peer):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(10)
            try:
                s.sendto(m, ("127.0.0.1", RPORT))
                l.sendto(rewrite(s.recv(65536)), peer)
            except OSError:
                pass
            s.close()
        threading.Thread(target=one, daemon=True).start()

threading.Thread(target=udp, daemon=True).start()
tcp()
