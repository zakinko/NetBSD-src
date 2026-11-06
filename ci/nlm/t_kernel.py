#!/usr/bin/python3
"""The sections of tools/nlm-audit/t.py of 2026-11-06 that speak to the
lock manager, for the lock manager in the kernel, from the Linux client's
address over the tun link.  The calls, arguments and order are that
tool's; what differs is AUTH_SYS, which the audit's AUTH_NONE would be
refused (its T17), and files made over ssh.  T11, T12 and the grace period
are in rawnlm.c, as they need a port mapper at the client."""
import random, socket, struct, subprocess, time
S = '10.77.0.2'; ME = '10.77.0.1'
NLM = 100021; SM = 100024; PM = 100000
def p(*a): print(*a, flush=True)
def u(i): return struct.pack('>I', i & 0xffffffff)
def h(i): return struct.pack('>Q', i)
def o(b):
    if isinstance(b, str): b = b.encode()
    return u(len(b)) + b + b'\0' * ((4 - len(b) % 4) % 4)
class R:
    def __init__(s, b): s.b = b; s.i = 0
    def u(s): v = struct.unpack('>I', s.b[s.i:s.i+4])[0]; s.i += 4; return v
    def h(s): v = struct.unpack('>Q', s.b[s.i:s.i+8])[0]; s.i += 8; return v
    def o(s): n = s.u(); v = s.b[s.i:s.i+n]; s.i += n + (4 - n % 4) % 4; return v
xid = [random.randrange(1 << 30)]
AUTH = u(1) + u(20) + u(0) + u(0) + u(0) + u(0) + u(0)
def call(port, prog, vers, proc, args=b'', tmo=3, auth=AUTH):
    xid[0] += 1; x = xid[0]
    m = u(x) + u(0) + u(2) + u(prog) + u(vers) + u(proc) + auth + u(0) + u(0) + args
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.settimeout(tmo)
    c.sendto(m, (S, port))
    try: b, _ = c.recvfrom(65536)
    except socket.timeout: return None
    finally: c.close()
    r = R(b); r.u(); r.u(); st = r.u()
    if st: return ('denied', r.u())
    r.u(); r.o(); return (r.u(), r)
def getport(prog, vers): return call(111, PM, 2, 3, u(prog) + u(vers) + u(17) + u(0))[1].u()
ck = b'ck01'
A = dict(n='audita', o='ownerA', s=1); B = dict(n='auditb', o='ownerB', s=2); C = dict(n='auditc', o='ownerC', s=3)
def lk(v, c, fh, off, ln):
    w = u if v < 4 else h
    return o(c['n']) + o(fh) + o(c['o']) + u(c['s']) + w(off) + w(ln)
def largs(v, c, fh, off, ln, ex=1, bl=0, rc=0, st=1):
    return o(ck) + u(bl) + u(ex) + lk(v, c, fh, off, ln) + u(rc) + u(st)
def res(q):
    if q is None: return 'noreply'
    if q[0] != 0: return 'rpcerr%s' % (q[0],)
    q[1].o(); return q[1].u()
class N:
    def __init__(s, v=4): s.v = v; s.pu = getport(NLM, v)
    def lock(s, c, fh, off, ln, ex=1, bl=0, rc=0, st=1):
        return res(call(s.pu, NLM, s.v, 2, largs(s.v, c, fh, off, ln, ex, bl, rc, st), tmo=45))
    def nm(s, c, fh, off, ln, ex=1): return res(call(s.pu, NLM, s.v, 22, largs(s.v, c, fh, off, ln, ex, 0, 0, 0)))
    def test(s, c, fh, off, ln, ex=1):
        q = call(s.pu, NLM, s.v, 1, o(ck) + u(ex) + lk(s.v, c, fh, off, ln))
        if q is None or q[0] != 0: return res(q)
        r = q[1]; r.o(); t = r.u()
        return t
    def unlock(s, c, fh, off, ln): return res(call(s.pu, NLM, s.v, 4, o(ck) + lk(s.v, c, fh, off, ln)))
    def cancel(s, c, fh, off, ln, ex=1, bl=1): return res(call(s.pu, NLM, s.v, 3, o(ck) + u(bl) + u(ex) + lk(s.v, c, fh, off, ln)))
    def share(s, c, fh, mode, acc, proc=20):
        q = call(s.pu, NLM, s.v, proc, o(ck) + o(c['n']) + o(fh) + o(c['o']) + u(mode) + u(acc) + u(0))
        if q is None or q[0] != 0: return res(q)
        r = q[1]; r.o(); return r.u()
    def freeall(s, n): return call(s.pu, NLM, s.v, 23, o(n) + u(0))
fails = 0
def want(what, got, w):
    global fails
    ok = got == w
    fails += not ok
    p(('ok   ' if ok else 'FAIL ') + f'{what} = {got}' + ('' if ok else f', wanted {w}'))
fn = [0]
def newfile():
    fn[0] += 1; f = '/export/ffs/t%d' % fn[0]
    x = subprocess.check_output(['ssh', 'netbsd', f'touch {f}; chmod 666 {f}; /var/tmp/gfh {f}'], text=True, stderr=subprocess.DEVNULL)
    return bytes.fromhex(x.strip())
def pad(fh): return fh + b'\0' * (32 - len(fh))
def sect(x): p('=== ' + x)
for name, v in (('v4', 4), ('v1', 1), ('v3', 3)):
    n = N(v); F = (lambda: newfile()) if v == 4 else (lambda: pad(newfile()))
    sect('T1 LOCK ' + name); fh = F(); want('LOCK', n.lock(A, fh, 0, 10), 0); n.unlock(A, fh, 0, 10)
    sect('T2 disjoint ' + name); fh = F(); n.lock(A, fh, 0, 10); want('B [100,10)', n.lock(B, fh, 100, 10), 0); want('TEST B', n.test(B, fh, 100, 10), 0)
    sect('T3 shared ' + name); fh = F(); n.lock(A, fh, 0, 10, ex=0); want('B sh', n.lock(B, fh, 0, 10, ex=0), 0); want('TEST B sh', n.test(B, fh, 0, 10, ex=0), 0); want('TEST B ex', n.test(B, fh, 0, 10), 1)
    sect('T4 own TEST ' + name); fh = F(); n.lock(A, fh, 0, 10); want('TEST A', n.test(A, fh, 0, 10), 0)
    sect('T5 partial ' + name); fh = F(); n.lock(A, fh, 0, 100); n.unlock(A, fh, 10, 10); want('B [50,1)', n.lock(B, fh, 50, 1), 1); want('TEST B [15,1)', n.test(B, fh, 15, 1), 0)
    sect('T6 two ranges ' + name); fh = F(); n.lock(A, fh, 0, 10); n.lock(A, fh, 100, 10); want('TEST B', n.test(B, fh, 100, 10), 1); n.unlock(A, fh, 0, 10); want('B [100,10)', n.lock(B, fh, 100, 10), 1)
    sect('T7 upgrade ' + name); fh = F(); n.lock(A, fh, 0, 10, ex=0); want('A ex', n.lock(A, fh, 0, 10), 0); want('TEST B sh', n.test(B, fh, 0, 10, ex=0), 1)
    sect('T8 CANCEL held ' + name); fh = F(); n.lock(A, fh, 0, 10); p('cancel', n.cancel(A, fh, 0, 10, bl=0)); want('B', n.lock(B, fh, 0, 10), 1)
    sect('T9 CANCEL waiting ' + name); fh = F(); n.lock(A, fh, 0, 10); want('B block', n.lock(B, fh, 0, 10, bl=1), 3); want('cancel', n.cancel(B, fh, 0, 10), 0); n.unlock(A, fh, 0, 10); want('C', n.lock(C, fh, 0, 10), 0)
    fh = F(); p('cancel no match', n.cancel(A, fh, 0, 10))
    fh = F(); n.lock(A, fh, 0, 10); n.lock(B, fh, 0, 10, bl=1); p('cancel other type', n.cancel(B, fh, 0, 10, ex=0)); n.unlock(A, fh, 0, 10); time.sleep(1); want('C meets B', n.lock(C, fh, 0, 10), 1)
    for c in (A, B, C): n.freeall(c['n'])
n = N(4); n1 = N(1); n3 = N(3)
sect('T10 block, CANCEL, retry against a server process')
fh = newfile(); f = '/export/ffs/t%d' % fn[0]
h_ = subprocess.Popen(['ssh', 'netbsd', f'/var/tmp/try -h 8 {f} 0'], stderr=subprocess.DEVNULL); time.sleep(2)
want('B block', n.lock(B, fh, 0, 1, bl=1), 3); want('cancel', n.cancel(B, fh, 0, 1), 0); want('B again', n.lock(B, fh, 0, 1, bl=1), 3); want('C', n.lock(C, fh, 0, 1), 1)
n.cancel(B, fh, 0, 1); h_.wait(); time.sleep(.5); want('after release, C', n.lock(C, fh, 0, 1), 0)
sect('T13 NM_LOCK SHARE FREE_ALL')
for name, nn in (('v4', n), ('v3', n3)):
    fh = newfile(); fx = fh if nn is n else pad(fh)
    n.lock(A, fh, 0, 10); want(name + ' B NM', nn.nm(B, fx, 0, 10), 1)
    fh = newfile(); fx = fh if nn is n else pad(fh); nn.nm(B, fx, 0, 10); want(name + ' C', n.lock(C, fh, 0, 10), 1)
    fh = newfile(); fx = fh if nn is n else pad(fh); want(name + ' A SHARE', nn.share(A, fx, 3, 3), 0); want(name + ' B SHARE', nn.share(B, fx, 3, 3), 1); nn.share(A, fx, 3, 3, proc=21)
    fh = newfile(); n.lock(A, fh, 0, 10); nn.freeall(A['n']); want(name + ' B after FREE_ALL', n.lock(B, fh, 0, 10), 0)
    for c in (A, B, C): n.freeall(c['n'])
sect('T14 handles')
fh = newfile(); n.lock(A, fh, 0, 10)
want('TEST empty fh', n.test(B, b'', 0, 1), 7); want('TEST prefix fh', n.test(B, fh[:8], 0, 1), 7)
bad = bytes(len(fh)); want('TEST zero fh', n.test(B, bad, 0, 1), 7); want('LOCK zero fh', n.lock(B, bad, 0, 1), 7); want('LOCK zero fh v1', n1.lock(B, pad(bad), 0, 1), 1)
fh = newfile(); want('v1 padded', n1.lock(A, pad(fh), 0, 1), 0); want('raw handle sees it', n.test(B, fh, 0, 1), 1)
p('fh of 1025', res(call(n.pu, NLM, 4, 2, largs(4, A, b'x' * 1025, 0, 1))))
sect('T15 long caller_name')
L = dict(n='h' * 200, o='o', s=9); fh = newfile(); want('LOCK', n.lock(L, fh, 0, 1), 0); want('UNLOCK', n.unlock(L, fh, 0, 1), 0); want('C', n.lock(C, fh, 0, 1), 0)
sect('T16 offsets')
fh = newfile(); want('2^63', n.lock(A, fh, 1 << 63, 1), 8); want('len 2^64-1', n.lock(B, fh, 5, (1 << 64) - 1), 8)
sect('T17 AUTH_NONE')
want('LOCK AUTH_NONE', res(call(n.pu, NLM, 4, 2, largs(4, A, newfile(), 0, 1), auth=u(0) + u(0))), 9)
sect('T18 SM_NOTIFY end to end')
ps = getport(SM, 1); fh = newfile(); want('lock state 3', n.lock(A, fh, 0, 10, st=3), 0); time.sleep(.2)
call(ps, SM, 1, 6, o(ME) + u(3), tmo=2); time.sleep(1.5); want('same state, B', n.lock(B, fh, 0, 10), 1)
call(ps, SM, 1, 6, o(ME) + u(5), tmo=2); time.sleep(1.5); want('state 5, B', n.lock(B, fh, 0, 10), 0); n.unlock(B, fh, 0, 10)
sect('T19 monitor failure')
X = dict(n='nosuch.invalid', o='x', s=8); fh = newfile(); t = time.time(); want('unresolvable name', n.lock(X, fh, 0, 1), 0); p('%.1f s' % (time.time() - t))
# statd down is in rawnlm -n, with addresses it does not know yet.
sect('share reservations against NFSv4 OPEN')
def compound(sock, ops, n):
    xid[0] += 1
    m = u(xid[0]) + u(0) + u(2) + u(100003) + u(4) + u(1) + AUTH + u(0) + u(0) + o(b'') + u(0) + u(n) + ops
    sock.sendall(u(0x80000000 | len(m)) + m)
    b = b''
    while len(b) < 4 or len(b) < 4 + (struct.unpack('>I', b[:4])[0] & 0x7fffffff):
        b += sock.recv(65536)
    r = R(b[4:]); r.u(); r.u(); r.u(); r.u(); r.o(); r.u()
    st = r.u(); r.o(); r.u()
    return st, r
k = socket.create_connection((S, 2049), 5); k.settimeout(10)
st, r = compound(k, u(35) + b'NLMTEST!' + o('nlm-share-test') + u(0x40000000) + o('tcp') + o(ME + '.1.1') + u(1), 1)
r.u(); r.u(); clid = r.b[r.i:r.i+8]; conf = r.b[r.i+8:r.i+16]
want('SETCLIENTID', st, 0)
want('CONFIRM', compound(k, u(36) + clid + conf, 1)[0], 0)
def v4open(name, owner, acc, deny):
    ops = u(24) + u(15) + o('export') + u(15) + o('ffs')
    ops += u(18) + u(1) + u(acc) + u(deny) + clid + o(owner) + u(0) + u(0) + o(name)
    return compound(k, ops, 4)[0]
fh = newfile(); name = 't%d' % fn[0]
want('v4 OPEN deny write', v4open(name, 'o1', 1, 2), 0)
want('NLM write is refused', n.share(A, fh, 0, 2), 1)
want('NLM read passes', n.share(A, fh, 0, 1), 0)
want('  and that NLM share stays', v4open(name, 'o2', 1, 0), 0)
want('UNSHARE', n.share(A, fh, 0, 1, proc=21), 0)
fh = newfile(); name = 't%d' % fn[0]
want('NLM deny write', n.share(A, fh, 2, 1), 0)
want('v4 OPEN for write is refused', v4open(name, 'o3', 2, 0), 10015)
want('v4 OPEN for read passes', v4open(name, 'o4', 1, 0), 0)
want('v4 deny read is refused', v4open(name, 'o5', 1, 1), 10015)
want('UNSHARE', n.share(A, fh, 2, 1, proc=21), 0)
want('v4 write passes now', v4open(name, 'o6', 2, 0), 0)
k.close()
p('t_kernel failures:', fails)
