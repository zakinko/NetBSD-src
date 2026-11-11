#!/usr/bin/env python3
# The handshake of RFC 9289 s5 against rpc.tlsservd, from the client
# side.  probe2.py HOST PORT CADIR MODE, MODE "anon" or "mutual".
# After a handshake a NULL call is made over the kernel's record layer.
import socket, ssl, struct, sys

HOST, PORT, CA, MODE = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
fails = 0

def ok(cond, what):
    global fails
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        fails += 1

def starttls():
    s = socket.create_connection((HOST, PORT), timeout=10)
    m = struct.pack(">IIIIIIIIII", 0x7100, 0, 2, 100003, 4, 0, 7, 0, 0, 0)
    s.sendall(struct.pack(">I", 0x80000000 | len(m)) + m)
    r = s.recv(64)
    assert r[24:32] == b"STARTTLS", r  # mark, xid, mtype, stat, flavor, len
    return s

def ctx(minv=ssl.TLSVersion.TLSv1_3, maxv=ssl.TLSVersion.TLSv1_3, alpn=("sunrpc",), cert=None):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.load_verify_locations(CA + "/ca.pem")
    c.minimum_version, c.maximum_version = minv, maxv
    if alpn is not None:
        c.set_alpn_protocols(list(alpn))
    if cert:
        c.load_cert_chain(CA + "/" + cert + ".pem", CA + "/" + cert + ".key")
    return c

def shake(c, name):
    s = starttls()
    try:
        t = c.wrap_socket(s, server_hostname="localhost")
        info = (t.version(), t.cipher()[0], t.selected_alpn_protocol())
        t.settimeout(5)
        m = struct.pack(">IIIIIIIIII", 0x7200, 0, 2, 100003, 4, 0, 0, 0, 0, 0)
        try:
            t.sendall(struct.pack(">I", 0x80000000 | len(m)) + m)
            tail = t.recv(64)
            tail = "reply" if len(tail) >= 28 and tail[4:8] == m[:4] and tail[12:16] == b"\0\0\0\0" else repr(tail)
        except (ssl.SSLError, OSError) as e:
            tail = type(e).__name__
        t.close()
        return True, info, tail
    except (ssl.SSLError, OSError) as e:
        return False, str(e), None

if MODE == "anon":
    good, info, tail = shake(ctx(), "anon")
    ok(good and info == ("TLSv1.3", "TLS_AES_128_GCM_SHA256", "sunrpc"),
       f"anonymous client: TLS 1.3, TLS_AES_128_GCM_SHA256, ALPN sunrpc (s5) {info}")
    ok(good and tail == "reply",
       f"then a NULL call over the kernel's record layer: {tail}")
    good, info, _ = shake(ctx(), "anon")
    good2, info2, _ = shake(ctx(cert="client"), "anon+cert")
    ok(good2, f"client with a certificate, -m not given: {info2}")
    good, info, _ = shake(ctx(minv=ssl.TLSVersion.TLSv1_2, maxv=ssl.TLSVersion.TLSv1_2), "tls12")
    ok(not good, f"TLS 1.2 refused (s5 MUST NOT): {info}")
    good, info, _ = shake(ctx(alpn=("h2",)), "h2")
    # Python's ssl has no name for alert 120; the handshake failing is
    # what is measured, the alert is in rpc.tlsservd's log.
    ok(not good, f"ALPN without sunrpc: handshake refused (RFC 7301 s3.2): {info}")
    good, info, _ = shake(ctx(alpn=None), "noalpn")
    ok(good, f"no ALPN at all: accepted and logged, s5 leaves it the client's MUST: {info}")
else:
    # TLS 1.3 checks the client's certificate after the client's
    # Finished: the client sees its handshake complete and the refusal
    # as the connection ending before any reply.
    good, info, tail = shake(ctx(), "nocert")
    ok(not good or tail != "reply", f"-m: a client without a certificate refused (s4.2): {info} {tail}")
    good, info, tail = shake(ctx(cert="client"), "cert")
    ok(good and tail == "reply", f"-m: a client with a certificate from the CA: {info} {tail}")
    good, info, tail = shake(ctx(cert="rogue"), "rogue")
    ok(not good or tail != "reply", f"-m: a certificate from another CA refused: {info} {tail}")
print("probe2", MODE, "failures", fails)
sys.exit(1 if fails else 0)
