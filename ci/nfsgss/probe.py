#!/usr/bin/env python3
"""RPCSEC_GSS by hand against the server: what a client cannot be made to
do.  Every line is a case from RFC 2203 or 5403.  probe.py HOST EXPORTS..."""
import random, socket, struct, sys
import gssapi

import os, time
HOST, ALL, PONLY, SYSONLY = sys.argv[1:5]
MODE = os.environ.get('PROBE', '')
PROG, VERS = 100003, 4
GSS = 6
DATA, INIT, CONT, DESTROY, BIND = 0, 1, 2, 3, 4
NONE, INTEG, PRIV, CHANNEL = 1, 2, 3, 4
MAXSEQ = 0x80000000
CREDPROBLEM, CTXPROBLEM = 13, 14
fails = 0

def p32(*v): return b''.join(struct.pack('>I', x) for x in v)
def opaque(b): return p32(len(b)) + b + b'\0' * (-len(b) % 4)

class C:
    def __init__(self):
        self.s = socket.create_connection((HOST, 2049)); self.s.settimeout(6)
    def send(self, b): self.s.sendall(p32(0x80000000 | len(b)) + b)
    def recv(self):
        out = b''
        while True:
            h = self.rd(4); m = struct.unpack('>I', h)[0]
            out += self.rd(m & 0x7fffffff)
            if m & 0x80000000: return out
    def rd(self, n):
        o = b''
        while len(o) < n:
            d = self.s.recv(n - len(o))
            if not d: raise EOFError
            o += d
        return o

class Reply:
    def __init__(self, b):
        self.b = b
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
    def __init__(self, vers=1):
        self.c = C(); self.vers = vers; self.seq = random.randrange(1000, 2000)
        self.g = gssapi.SecurityContext(name=gssapi.Name('nfs@' + HOST,
            gssapi.NameType.hostbased_service), usage='initiate',
            flags=[gssapi.RequirementFlag.mutual_authentication,
                   gssapi.RequirementFlag.integrity,
                   gssapi.RequirementFlag.confidentiality])
        tok = self.g.step()
        self.xid = random.getrandbits(32)
        self.initmsg = header(self.xid, 0, cred(vers, INIT, 0, NONE, b'')) + p32(0, 0) + opaque(tok)
        self.c.send(self.initmsg)
        r = Reply(self.c.recv())
        assert r.stat == 0 and r.astat == 0, 'INIT'
        self.init_reply = r
        b = r.res
        hl = struct.unpack('>I', b[:4])[0]
        self.handle = b[4:4 + hl]; o = 4 + hl + (-hl % 4)
        self.major, _, self.window, tl = struct.unpack('>IIII', b[o:o + 16])
        t = b[o + 16:o + 16 + tl]
        if t: self.g.step(t)
        self.g.verify_signature(p32(self.window), r.verf)

    def call(self, svc=NONE, proc=0, args=b'', gproc=DATA, seq=None, handle=None,
             vers=None, mutate=None, inner=None):
        if seq is None:
            self.seq += 1; seq = self.seq
        xid = random.getrandbits(32)
        cr = cred(vers or self.vers, gproc, seq, svc, self.handle if handle is None else handle)
        h = header(xid, proc, cr)
        mic = self.g.get_signature(h)
        body = args
        s = p32(seq if inner is None else inner) + args
        if svc == INTEG:
            body = opaque(s) + opaque(self.g.get_signature(s))
        elif svc == PRIV:
            body = opaque(self.g.wrap(s, True).message)
        if mutate: h, mic, body = mutate(h, mic, body)
        self.c.send(h + p32(GSS) + opaque(mic) + body)
        try:
            r = Reply(self.c.recv())
        except socket.timeout:
            return None
        r.seq = seq; r.svc = svc
        return r

    def results(self, r):
        self.g.verify_signature(p32(r.seq), r.verf)
        if r.svc == NONE: return r.res
        n = struct.unpack('>I', r.res[:4])[0]
        d = r.res[4:4 + n]
        if r.svc == INTEG:
            o = 4 + n + (-n % 4)
            m = struct.unpack('>I', r.res[o:o + 4])[0]
            self.g.verify_signature(d, r.res[o + 4:o + 4 + m])
        else:
            d = self.g.unwrap(d).message
        assert struct.unpack('>I', d[:4])[0] == r.seq
        return d[4:]

def check(name, ok, detail=''):
    global fails
    print(('ok   ' if ok else 'FAIL ') + name, detail)
    if not ok: fails += 1

def denied(r, why): return r is not None and r.stat == 1 and r.rej == 1 and r.why == why
def accepted(r, st): return r is not None and r.stat == 0 and r.astat == st

def compound(*ops):
    return opaque(b'') + p32(0, len(ops)) + b''.join(ops)
OP_GETATTR, OP_LOOKUP, OP_PUTROOTFH, OP_SECINFO = 9, 15, 24, 33
GETATTR = p32(OP_GETATTR, 1, 0x10)
ROOT = p32(OP_PUTROOTFH)
def lookup(path):
    return [p32(OP_LOOKUP) + opaque(c.encode()) for c in path.strip('/').split('/')]
def compstat(res):
    return struct.unpack('>I', res[:4])[0]

if MODE == 'refused':
    c = C()
    g = gssapi.SecurityContext(name=gssapi.Name('nfs@' + HOST, gssapi.NameType.hostbased_service),
                               usage='initiate')
    c.send(header(1, 0, cred(1, INIT, 0, NONE, b'')) + p32(0, 0) + opaque(g.step()))
    r = Reply(c.recv())
    hl, ma = struct.unpack('>II', r.res[:8])
    check('a principal with no account: GSS_S_UNAUTHORIZED, no handle',
          accepted(r, 0) and hl == 0 and ma == 0xf0000, hex(ma))
    sys.exit(1 if fails else 0)
if MODE == 'expiry':
    x = Ctx()
    r = x.call()
    check('a context in its time', accepted(r, 0))
    time.sleep(130)
    check('past the ticket: CTXPROBLEM, s5.3.3.3', denied(x.call(), CTXPROBLEM))
    sys.exit(1 if fails else 0)

x = Ctx()
check('INIT gives a handle, GSS_S_COMPLETE, the window MIC verified',
      x.major == 0 and len(x.handle) > 0, f'window {x.window}')
x.c.send(x.initmsg)
r = Reply(x.c.recv())
hl = struct.unpack('>I', r.res[:4])[0]
check('a retransmitted INIT gets the same handle', r.res[4:4 + hl] == x.handle)
x.g.verify_signature(p32(x.window), r.verf)
for s, n in ((NONE, 'none'), (INTEG, 'integrity'), (PRIV, 'privacy')):
    r = x.call(s)
    check(f'NULLPROC under {n}', accepted(r, 0)); x.results(r)
    r = x.call(s, 1, compound(ROOT, GETATTR))
    check(f'COMPOUND under {n}', accepted(r, 0) and compstat(x.results(r)) == 0)
r = x.call(NONE, 1, compound(ROOT, *lookup(ALL), GETATTR))
check('allowed flavor walks in', accepted(r, 0) and compstat(x.results(r)) == 0)
r = x.call(NONE, 1, compound(ROOT, *lookup(PONLY), GETATTR))
check('krb5 on a krb5p export: NFS4ERR_WRONGSEC', accepted(r, 0) and compstat(x.results(r)) == 10016)
r = x.call(PRIV, 1, compound(ROOT, *lookup(PONLY), GETATTR))
check('krb5p on the krb5p export', accepted(r, 0) and compstat(x.results(r)) == 0)
name = PONLY.strip('/').split('/')
r = x.call(NONE, 1, compound(ROOT, *lookup('/'.join(name[:-1])), p32(OP_SECINFO) + opaque(name[-1].encode())))
res = x.results(r)
check('SECINFO under a flavor the object refuses', accepted(r, 0) and compstat(res) == 0 and b'\x2a\x86\x48\x86\xf7\x12\x01\x02\x02' in res, res[-40:].hex())
s = x.seq + 1
x.seq = s
r = x.call(seq=s)
check('a new sequence number', accepted(r, 0))
check('the same one again is dropped, s5.3.3.1', x.call(seq=s) is None)
check('well below the window is dropped', x.call(seq=max(0, s - x.window - 1)) is None)
x.seq += 10
r = x.call()
check('a gap is fine', accepted(r, 0))
r = x.call(seq=x.seq - 3)
check('late, in the window, and not seen', accepted(r, 0))
OP_SETATTR = 34
def setowner(owner):
    return p32(OP_SETATTR) + b'\0' * 16 + p32(2, 0, 1 << 4) + opaque(opaque(owner))
PUTROOT_ALL = [ROOT, *lookup(ALL)]
r = x.call(NONE, 1, compound(*PUTROOT_ALL, setowner(b'2097')))
st = compstat(x.results(r))
check('a numeric owner under GSS: NFS4ERR_BADOWNER', accepted(r, 0) and st == 10039, str(st))
flip = lambda h, m, b: (h, bytes([m[0] ^ 1]) + m[1:], b)
check('bad header MIC: CREDPROBLEM, s5.3.3.4.2', denied(x.call(mutate=flip), CREDPROBLEM))
def badb(h, m, b): return h, m, b[:-1] + bytes([b[-1] ^ 1])
check('bad MIC of the arguments: GARBAGE_ARGS', accepted(x.call(INTEG, mutate=badb), 4))
check('bad wrap of the arguments: GARBAGE_ARGS', accepted(x.call(PRIV, mutate=badb), 4))
check('body seq differs under integrity: GARBAGE_ARGS', accepted(x.call(INTEG, inner=1), 4))
check('body seq differs under privacy: GARBAGE_ARGS', accepted(x.call(PRIV, inner=1), 4))
check('seq at MAXSEQ: CTXPROBLEM', denied(x.call(seq=MAXSEQ), CTXPROBLEM))
check('unknown handle: CREDPROBLEM', denied(x.call(handle=b'\1' * 16), CREDPROBLEM))
check('a bad service: AUTH_BADCRED', denied(x.call(9), 1))
check('channel_prot unbound: AUTH_BADCRED', denied(x.call(CHANNEL), 1))
check('credential version differing from the context: AUTH_BADCRED', denied(x.call(vers=2), 1))
check('an unknown version: AUTH_REJECTEDCRED', denied(x.call(vers=3), 2))
check('DESTROY with a procedure: AUTH_BADCRED', denied(x.call(proc=1, gproc=DESTROY), 1))
check('BIND_CHANNEL under version 1: AUTH_BADCRED', denied(x.call(gproc=BIND), 1))
r = x.call(gproc=DESTROY)
check('DESTROY', accepted(r, 0)); x.g.verify_signature(p32(r.seq), r.verf)
check('after DESTROY: CREDPROBLEM', denied(x.call(), CREDPROBLEM))

y = Ctx(2)
r = y.call()
check('a version 2 context', accepted(r, 0))
check('version 1 on it: AUTH_BADCRED', denied(y.call(vers=1), 1))
xid = random.getrandbits(32)
y.seq += 1
h = header(xid, 0, cred(2, BIND, y.seq, NONE, y.handle))
verf = opaque(b'tls-unique') + opaque(b'\x2b\x0e\x03\x02\x1a') + opaque(y.g.get_signature(h + opaque(b'\0' * 20)))
y.c.send(h + p32(GSS) + opaque(verf))
r = Reply(y.c.recv())
check('BIND_CHANNEL: PREF_NOTSUPP, an empty list, a MIC', accepted(r, 0) and r.verf[:8] == p32(1, 0))
ml = struct.unpack('>I', r.verf[8:12])[0]
y.g.verify_signature(p32(y.seq, 0, 1, 0), r.verf[12:12 + ml])

# Versions 2 and 3 of NFS, with a handle from MOUNT.
def mnt(vers, path):
    s = socket.create_connection((HOST, 4002)); s.settimeout(6)
    b = p32(random.getrandbits(32), 0, 2, 100005, vers, 1, 0, 0, 0, 0) + opaque(path.encode())
    s.sendall(p32(0x80000000 | len(b)) + b)
    h = s.recv(4); n = struct.unpack('>I', h)[0] & 0x7fffffff
    d = b''
    while len(d) < n: d += s.recv(n - len(d))
    s.close()
    st = struct.unpack('>I', d[24:28])[0]
    assert st == 0, f'MNT {path} {st}'
    if vers == 1: return d[28:60]
    l = struct.unpack('>I', d[28:32])[0]
    fl = d[32 + l + (-l % 4):]
    return d[32:32 + l], [struct.unpack('>I', fl[4 + 4 * i:8 + 4 * i])[0] for i in range(struct.unpack('>I', fl[:4])[0])]

fh2 = mnt(1, ALL)
fh3, fl = mnt(3, ALL)
check('MOUNT 3 lists the flavors of the export', fl == [390005, 390004, 390003], str(fl))
fh3p, fl = mnt(3, PONLY)
check('MOUNT 3 lists krb5p alone', fl == [390005], str(fl))
for v, arg, parg in ((2, fh2, mnt(1, PONLY)), (3, opaque(fh3), opaque(fh3p))):
    VERS = v
    z = Ctx()
    for s, n in ((NONE, 'krb5'), (INTEG, 'krb5i'), (PRIV, 'krb5p')):
        r = z.call(s)
        check(f'v{v} NULL under {n}', accepted(r, 0))
        r = z.call(s, 1, arg)
        ok = accepted(r, 0)
        check(f'v{v} GETATTR under {n}', ok and compstat(z.results(r)) == 0)
    check(f'v{v} replay dropped', z.call(seq=z.seq) is None)
    r = z.call(NONE, 1, parg)
    check(f'v{v} krb5 on a krb5p export: AUTH_TOOWEAK', denied(r, 5), r and r.__dict__.get('why', r.b[:40].hex()))
    r = z.call(PRIV, 1, parg)
    check(f'v{v} krb5p there', accepted(r, 0) and compstat(z.results(r)) == 0)
VERS = 4

c = C()
xid = random.getrandbits(32)
c.send(header(xid, 0, cred(1, INIT, 0, NONE, b'')) + p32(0, 0) + opaque(b'not a token'))
r = Reply(c.recv())
hl, = struct.unpack('>I', r.res[:4])
ma, = struct.unpack('>I', r.res[4:8])
check('a bad token: a major status and no handle, NULL verifier',
      accepted(r, 0) and hl == 0 and ma != 0 and r.vflavor == 0, hex(ma))
c.send(header(xid + 1, 1, cred(1, INIT, 0, NONE, b'')) + p32(0, 0) + opaque(b''))
check('INIT with a procedure: AUTH_BADCRED', denied(Reply(c.recv()), 1))
c.send(header(xid + 2, 0, cred(1, CONT, 0, NONE, b'\2' * 16)) + p32(0, 0) + opaque(b'x'))
r = Reply(c.recv())
ma = struct.unpack('>I', r.res[4:8])[0]
check('CONTINUE_INIT with no context: GSS_S_NO_CONTEXT', accepted(r, 0) and ma == 8 << 16)
print('probe failures:', fails)
sys.exit(1 if fails else 0)
