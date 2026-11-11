#!/usr/bin/env python3
"""For pynfs, which speaks only plain TCP: take each connection on
LPORT, open one to HOST:2049, ask for TLS with the AUTH_TLS probe of
RFC 9289 s4.1, shake hands, and relay.  tlsproxy.py LPORT HOST CAFILE"""
import socket, ssl, struct, sys, threading

LPORT, HOST, CA = int(sys.argv[1]), sys.argv[2], sys.argv[3]

def tls_to_server():
    s = socket.create_connection((HOST, 2049))
    m = struct.pack(">IIIIIIIIII", 1, 0, 2, 100003, 4, 0, 7, 0, 0, 0)
    s.sendall(struct.pack(">I", 0x80000000 | len(m)) + m)
    r = b""
    while len(r) < 36:
        d = s.recv(36 - len(r))
        if not d:
            raise EOFError
        r += d
    assert r[24:32] == b"STARTTLS", r
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.minimum_version = ssl.TLSVersion.TLSv1_3
    c.set_alpn_protocols(["sunrpc"])
    c.load_verify_locations(CA)
    return c.wrap_socket(s, server_hostname="localhost")

def pump(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    for x in (a, b):
        try:
            x.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

def serve(c):
    try:
        t = tls_to_server()
    except Exception as e:
        print("handshake:", e, flush=True)
        c.close()
        return
    threading.Thread(target=pump, args=(c, t), daemon=True).start()
    pump(t, c)

l = socket.socket()
l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind(("127.0.0.1", LPORT))
l.listen(64)
print("listening", LPORT, flush=True)
while True:
    c, _ = l.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
