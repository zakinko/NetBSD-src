#!/usr/bin/env python3
# The AUTH_TLS probe of RFC 9289 s4.1 and the hand-off, from the client
# side.  probe1.py HOST PORT PHASE, PHASE "nodaemon" or "daemon".
import socket, ssl, struct, sys, time

HOST, PORT, PHASE = sys.argv[1], int(sys.argv[2]), sys.argv[3]
AUTH_NONE, AUTH_SYS, AUTH_TLS = 0, 1, 7      # RFC 5531 s8.2, RFC 9289 s7.1
fails = 0
xid = 0x5100

def ok(cond, what):
    global fails
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        fails += 1

def call(prog, vers, proc, cred=(AUTH_NONE, b""), verf=(AUTH_NONE, b"")):
    global xid
    xid += 1
    def auth(a):
        f, b = a
        return struct.pack(">II", f, len(b)) + b + b"\0" * (-len(b) % 4)
    m = struct.pack(">IIIIII", xid, 0, 2, prog, vers, proc) + auth(cred) + auth(verf)
    return xid, struct.pack(">I", 0x80000000 | len(m)) + m

def recv_reply(s, timeout=5):
    s.settimeout(timeout)
    try:
        h = b""
        while len(h) < 4:
            c = s.recv(4 - len(h))
            if not c:
                return None
            h += c
        n = struct.unpack(">I", h)[0] & 0x7fffffff
        b = b""
        while len(b) < n:
            c = s.recv(n - len(b))
            if not c:
                return None
            b += c
    except socket.timeout:
        return "timeout"
    x, mtype, rstat = struct.unpack(">III", b[:12])
    r = {"xid": x, "rstat": rstat}
    if rstat == 0:
        vf, vl = struct.unpack(">II", b[12:20])
        r["vflavor"], r["verf"] = vf, b[20:20 + vl]
        o = 20 + vl + (-vl % 4)
        r["astat"] = struct.unpack(">I", b[o:o + 4])[0]
    else:
        r["reject"] = struct.unpack(">I", b[12:16])[0]
        if r["reject"] == 1:
            r["auth"] = struct.unpack(">I", b[16:20])[0]
    return r

def conn():
    return socket.create_connection((HOST, PORT), timeout=10)

def probe(prog, vers, proc=0, **kw):
    s = conn()
    x, m = call(prog, vers, proc, cred=kw.get("cred", (AUTH_TLS, b"")),
                verf=kw.get("verf", (AUTH_NONE, b"")))
    s.sendall(m)
    return s, recv_reply(s)

STARTTLS = b"STARTTLS"

for prog, vers, name in ((100003, 4, "NFSv4"), (100003, 3, "NFSv3")):
    s, r = probe(prog, vers)
    print(name, "probe:", r)
    if not isinstance(r, dict):
        ok(False, f"{name}: probe answered")
        continue
    if PHASE == "nodaemon":
        ok(r["rstat"] == 0 and r["vflavor"] == AUTH_NONE and r["verf"] != STARTTLS,
           f"{name}: without a daemon no STARTTLS (s4.1)")
        x, m = call(prog, vers, 0)
        s.sendall(m)
        r2 = recv_reply(s)
        ok(isinstance(r2, dict) and r2["rstat"] == 0 and r2["astat"] == 0,
           f"{name}: the connection stays RPC")
    else:
        ok(r["rstat"] == 0 and r["vflavor"] == AUTH_NONE and r["verf"] == STARTTLS
           and r["astat"] == 0, f"{name}: MSG_ACCEPTED, AUTH_NONE verifier STARTTLS (s4.1)")
        # The ClientHello on the same connection, s4.1; the stand-in
        # daemon reads it and fails the handshake.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.set_alpn_protocols(["sunrpc"])
        try:
            t = ctx.wrap_socket(s, server_hostname="server")
            ok(False, f"{name}: handshake against the stand-in should fail")
        except (ssl.SSLError, OSError) as e:
            ok(True, f"{name}: ClientHello sent, handshake ended by the stand-in ({type(e).__name__})")
    s.close()

# s4.1 MUST: AUTH_TLS on a procedure other than NULL is AUTH_BADCRED.
s, r = probe(100003, 4, proc=1)
ok(isinstance(r, dict) and r["rstat"] == 1 and r.get("reject") == 1 and r.get("auth") == 1,
   f"AUTH_TLS on COMPOUND: MSG_DENIED AUTH_ERROR AUTH_BADCRED (s4.1) {r}")
s.close()
s, r = probe(100003, 4, cred=(AUTH_TLS, b"abcd"))
ok(isinstance(r, dict) and r["rstat"] == 1 and r.get("auth") == 1,
   f"AUTH_TLS with a credential body: AUTH_BADCRED {r}")
s.close()
s, r = probe(100003, 4, verf=(AUTH_SYS, b""))
ok(isinstance(r, dict) and r["rstat"] == 1 and r.get("auth") == 3,
   f"AUTH_TLS with a non-AUTH_NONE verifier: AUTH_BADVERF {r}")
s.close()

if PHASE == "daemon":
    # s5.1.1: a call sent behind the probe, before any handshake, is
    # not answered as RPC.
    s = conn()
    _, m1 = call(100003, 4, 0, cred=(AUTH_TLS, b""))
    x2, m2 = call(100003, 4, 0)
    s.sendall(m1 + m2)
    r1 = recv_reply(s)
    ok(isinstance(r1, dict) and r1.get("verf") == STARTTLS, "pipelined: the probe answered with STARTTLS")
    r2 = recv_reply(s, timeout=3)
    ok(not isinstance(r2, dict), f"pipelined: the call behind it got no RPC reply (s5.1.1) {r2}")
    s.close()

# Plain RPC is unaffected.
s = conn()
x, m = call(100003, 4, 0, cred=(AUTH_SYS, struct.pack(">II", 0, 0) + struct.pack(">III", 0, 0, 0)))
s.sendall(m)
r = recv_reply(s)
ok(isinstance(r, dict) and r["rstat"] == 0 and r["astat"] == 0, "AUTH_SYS NULL still served")
s.close()
print("probe1", PHASE, "failures", fails)
sys.exit(1 if fails else 0)
