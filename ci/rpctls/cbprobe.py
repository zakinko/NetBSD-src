#!/usr/bin/env python3
"""RPCSEC_GSS version 2 channel bindings over RPC-with-TLS, by hand: the
Linux client sends only version 1.  RFC 5403 s3.3, s3.4, RFC 9289 s4.2.1,
RFC 9266.  cbprobe.py HOST CAFILE"""
import hashlib, random, socket, struct, sys
import gssapi
from OpenSSL import SSL

HOST, CA = sys.argv[1:3]
PROG, VERS, GSS, AUTH_NONE, AUTH_TLS = 100003, 4, 6, 0, 7
DATA, INIT, BIND = 0, 1, 4
NONE, INTEG, PRIV, CHANNEL = 1, 2, 3, 4
BADCRED, BADVERF, CREDPROBLEM = 1, 3, 13
# RFC 4055 s2.1, the DER content octets, and with the tag of X.690 s8.19
SHA256 = bytes.fromhex('608648016503040201')
SHA256T = bytes.fromhex('0609') + SHA256
SHA1T = bytes.fromhex('06052b0e03021a')
LABEL = b'EXPORTER-Channel-Binding'      # RFC 9266 s2
fails = 0

def p32(*v): return b''.join(struct.pack('>I', x) for x in v)
def opaque(b): return p32(len(b)) + b + b'\0' * (-len(b) % 4)

def check(name, ok, detail=''):
    global fails
    print(('ok   ' if ok else 'FAIL ') + name + (' ' + str(detail) if detail else ''))
    if not ok: fails += 1

class Conn:
    def __init__(self, tls=True):
        s = socket.create_connection((HOST, 2049)); s.settimeout(10)
        self.raw, self.t, self.exporter = s, None, None
        if not tls: return
        self.send(p32(1, 0, 2, PROG, VERS, 0, AUTH_TLS, 0, AUTH_NONE, 0))
        r = self.recv()
        assert r[12:20] == b'\0\0\0\0\0\0\0\x08' and r[20:28] == b'STARTTLS', r
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
        ctx.set_alpn_protos([b'sunrpc'])
        ctx.load_verify_locations(CA)
        ctx.set_verify(SSL.VERIFY_PEER, lambda *a: a[-1])
        self.t = SSL.Connection(ctx, s)
        self.t.set_connect_state()
        s.setblocking(True)
        self.t.do_handshake()
        self.exporter = self.t.export_keying_material(LABEL, 32)
    def send(self, b):
        m = p32(0x80000000 | len(b)) + b
        (self.t or self.raw).sendall(m)
    def rd(self, n):
        o = b''
        while len(o) < n:
            d = (self.t or self.raw).recv(n - len(o))
            if not d: raise EOFError
            o += d
        return o
    def recv(self):
        h = struct.unpack('>I', self.rd(4))[0]
        return self.rd(h & 0x7fffffff)

class Reply:
    def __init__(self, b):
        self.xid, _, self.stat = struct.unpack('>III', b[:12])
        if self.stat == 1:
            self.rej, self.why = struct.unpack('>II', b[12:20]); self.astat = None; return
        self.vflavor, vl = struct.unpack('>II', b[12:20])
        self.verf = b[20:20 + vl]
        o = 20 + vl + (-vl % 4)
        self.astat = struct.unpack('>I', b[o:o + 4])[0]
        self.res = b[o + 4:]

def header(xid, proc, cred):
    return p32(xid, 0, 2, PROG, VERS, proc, GSS) + opaque(cred)

def cred(vers, gproc, seq, svc, handle):
    return p32(vers, gproc, seq, svc) + opaque(handle)

class Ctx:
    def __init__(self, conn, vers=2):
        self.c, self.vers, self.seq = conn, vers, random.randrange(1000, 2000)
        self.g = gssapi.SecurityContext(name=gssapi.Name('nfs@' + HOST,
            gssapi.NameType.hostbased_service), usage='initiate',
            flags=[gssapi.RequirementFlag.mutual_authentication,
                   gssapi.RequirementFlag.integrity])
        tok = self.g.step()
        self.c.send(header(random.getrandbits(32), 0, cred(vers, INIT, 0, NONE, b''))
                    + p32(0, 0) + opaque(tok))
        r = Reply(self.c.recv())
        assert r.stat == 0 and r.astat == 0, 'INIT'
        b = r.res
        hl = struct.unpack('>I', b[:4])[0]
        self.handle = b[4:4 + hl]; o = 4 + hl + (-hl % 4)
        major, _, self.window, tl = struct.unpack('>IIII', b[o:o + 16])
        t = b[o + 16:o + 16 + tl]
        if t: self.g.step(t)

    def bind(self, cb, prefix=b'tls-exporter', oid=SHA256T, hashf=hashlib.sha256):
        """RFC 5403 s3.3: the verifier is rgss2_bind_chan_verf_args."""
        self.seq += 1
        h = header(random.getrandbits(32), 0, cred(self.vers, BIND, self.seq, NONE, self.handle))
        hsh = hashf(prefix + b':' + cb).digest()
        mic = self.g.get_signature(h + opaque(hsh))
        v = opaque(prefix) + opaque(oid) + opaque(mic)
        self.c.send(h + p32(GSS) + opaque(v))
        r = Reply(self.c.recv())
        r.seq, r.hash = self.seq, hsh
        return r

    def verify_bind(self, r, hsh):
        """rbcvr_mic = GetMIC(rgss2_bind_chan_MIC_in_res)"""
        st = struct.unpack('>I', r.verf[:4])[0]
        if st == 0: res = r.verf[:4]
        else:
            n = struct.unpack('>I', r.verf[4:8])[0]; o = 8
            for _ in range(n):
                l = struct.unpack('>I', r.verf[o:o + 4])[0]; o += 4 + l + (-l % 4)
            res = r.verf[:o]
        ml = struct.unpack('>I', r.verf[len(res):len(res) + 4])[0]
        mic = r.verf[len(res) + 4:len(res) + 4 + ml]
        self.g.verify_signature(p32(r.seq) + opaque(hsh) + res, mic)
        return st, res

    def chan(self, proc=0, args=b''):
        """RFC 5403 s3.4: channel_prot, AUTH_NONE verifier of length zero."""
        self.seq += 1
        h = header(random.getrandbits(32), proc, cred(self.vers, DATA, self.seq, CHANNEL, self.handle))
        self.c.send(h + p32(AUTH_NONE, 0) + args)
        return Reply(self.c.recv())

def denied(r, why): return r.stat == 1 and r.rej == 1 and r.why == why

# PUTROOTFH, GETATTR(type): a COMPOUND that needs no state
COMPOUND = opaque(b'') + p32(0, 2, 24, 9, 1, 1 << 1)

c1 = Conn()
x = Ctx(c1)
r = x.bind(c1.exporter)
st, _ = x.verify_bind(r, r.hash)
check('BIND_CHANNEL over TLS, tls-exporter, SHA-256: RGSS2_BIND_CHAN_OK (s3.3)',
      r.stat == 0 and r.vflavor == GSS and st == 0, st)
r = x.chan()
check('channel_prot NULL after the bind: accepted, AUTH_NONE verifier of length 0 (s3.4)',
      r.stat == 0 and r.astat == 0 and r.vflavor == AUTH_NONE and r.verf == b'')
r = x.chan(1, COMPOUND)
check('channel_prot COMPOUND PUTROOTFH GETATTR: NFS4_OK',
      r.stat == 0 and r.astat == 0 and r.res[:4] == p32(0), r.res[:8].hex() if r.astat == 0 else r.__dict__)

c2 = Conn()
r = Ctx(c2).bind(c1.exporter)
check('bindings of another TLS connection: MSG_DENIED RPCSEC_GSS_CREDPROBLEM (RFC 2203 s5.3.3.4.2)',
      denied(r, CREDPROBLEM), r.__dict__.get('why'))
y = Ctx(c2)
r = y.chan()
check('channel_prot without a bind: AUTH_BADCRED', denied(r, BADCRED), r.__dict__.get('why'))
x.c = c2
r = x.chan()
check('channel_prot of a context bound on another connection: AUTH_BADCRED (s3.4, "the secure channel still exists")',
      denied(r, BADCRED), r.__dict__.get('why'))
x.c = c1

r = y.bind(c2.exporter, oid=SHA1T, hashf=hashlib.sha1)
st, res = y.verify_bind(r, hashlib.sha256(b'tls-exporter:' + c2.exporter).digest())
check('SHA-1: RGSS2_BIND_CHAN_HASH_NOTSUPP naming SHA-256, MIC over the SHA-256 hash (s3.3)',
      st == 2 and SHA256T in res, res.hex())
r = y.bind(c2.exporter, oid=SHA256)
st, _ = y.verify_bind(r, r.hash)
check('the OID as content octets, without the DER tag: OK', st == 0, st)
r = Ctx(c2).bind(c2.exporter, prefix=b'tls-unique')
check('prefix tls-unique: RGSS2_BIND_CHAN_PREF_NOTSUPP naming tls-exporter',
      r.stat == 0 and struct.unpack('>I', r.verf[:4])[0] == 1 and b'tls-exporter' in r.verf)
v1 = Ctx(c2, vers=1)
r = v1.chan()
check('channel_prot under version 1: AUTH_BADCRED', denied(r, BADCRED), r.__dict__.get('why'))

c3 = Conn(tls=False)
z = Ctx(c3)
r = z.bind(b'\0' * 32)
check('BIND_CHANNEL over plain TCP: PREF_NOTSUPP with no prefixes',
      r.stat == 0 and r.verf[:8] == p32(1, 0))
print('cbprobe failures', fails)
sys.exit(1 if fails else 0)
