#!/usr/bin/env python3
# A client of NFS version 4.1 on RPC-over-RDMA with its backchannel on the
# same connection, RFC 8167, that holds a read delegation while a second
# client on TCP opens the file for writing: the server recalls by a
# reverse Call, this answers it and returns the delegation, and then the
# forward channel must still answer.  It is what the Linux client met in
# runs 43007424174 and 43030049194, where the server stopped answering
# after the recall.  Needs no network beyond the two forwarded ports.
# recall41.py HOST RDMAPORT TCPPORT EXPORT/PATH
import socket, struct, sys, time, threading
sys.path.insert(0, __import__('os').path.dirname(__file__))
from badpeer_lib import Peer

HOST, RPORT, TPORT = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
PATH = [c.encode() for c in sys.argv[4].strip('/').split('/')]
fails = 0

def check(name, ok, detail=''):
    global fails
    print(('ok   ' if ok else 'FAIL ') + name, detail, flush=True)
    fails += 0 if ok else 1

# XDR
u32 = lambda v: struct.pack('>I', v)
u64 = lambda v: struct.pack('>Q', v)
def opq(b):
    return u32(len(b)) + b + bytes((4 - len(b) % 4) % 4)

class R:
    def __init__(self, b, off=0):
        self.b, self.o = b, off
    def u32(self):
        v = struct.unpack('>I', self.b[self.o:self.o + 4])[0]; self.o += 4; return v
    def u64(self):
        v = struct.unpack('>Q', self.b[self.o:self.o + 8])[0]; self.o += 8; return v
    def fixed(self, n):
        v = self.b[self.o:self.o + n]; self.o += n; return v
    def opq(self):
        n = self.u32(); v = self.fixed(n); self.o += (4 - n % 4) % 4; return v
    def bitmap(self):
        return [self.u32() for _ in range(self.u32())]

AUTH_SYS = u32(1) + opq(u32(0) + opq(b'badpeer') + u32(0) + u32(0) + u32(0))
NONE = u32(0) + u32(0)

def rpc_call(xid, proc, body, prog=100003, vers=4):
    return u32(xid) + u32(0) + u32(2) + u32(prog) + u32(vers) + u32(proc) + \
        AUTH_SYS + NONE + body

def rpc_reply_results(m):
    """The results of an accepted, successful reply, or None."""
    r = R(m)
    xid, mt, st = r.u32(), r.u32(), r.u32()
    if mt != 1 or st != 0:
        return None
    r.u32(); r.opq()
    if r.u32() != 0:
        return None
    return r

def compound(minor, ops):
    return opq(b'') + u32(minor) + u32(len(ops)) + b''.join(ops)

OP_SEQUENCE, OP_PUTROOTFH, OP_LOOKUP, OP_OPEN, OP_GETFH, OP_CLOSE = 53, 24, 15, 18, 10, 4
OP_DELEGRETURN, OP_PUTFH, OP_EXCHANGE_ID, OP_CREATE_SESSION = 8, 22, 42, 43
OP_RECLAIM_COMPLETE = 58

def chan():
    # headerpad, maxreq, maxresp, maxcached, maxops, maxreqs, rdma_ird<1>
    return u32(0) + u32(65536) + u32(65536) + u32(4096) + u32(16) + u32(8) + u32(0)

class Client:
    """One client of 4.1: the transport is a function from a call to its reply."""
    def __init__(self, call, name, back):
        self.call, self.xid, self.seq = call, 100, 1
        verf = struct.pack('>Q', int(time.time() * 1000))
        r = self.compound([u32(OP_EXCHANGE_ID) + verf + opq(name) + u32(1) + u32(0) + u32(0)])
        assert r.u32() == OP_EXCHANGE_ID and r.u32() == 0
        self.clid, csseq = r.u64(), r.u32()
        flags = 2 if back else 0        # CREATE_SESSION4_FLAG_CONN_BACK_CHAN
        r = self.compound([u32(OP_CREATE_SESSION) + u64(self.clid) + u32(csseq) +
                           u32(flags) + chan() + chan() + u32(0x40000000) +
                           u32(1) + u32(0)])     # one AUTH_NONE
        assert r.u32() == OP_CREATE_SESSION and r.u32() == 0, 'CREATE_SESSION'
        self.sid = r.fixed(16)
        r = self.seqd([u32(OP_RECLAIM_COMPLETE) + u32(0)])

    def compound(self, ops, minor=1):
        self.xid += 1
        m = self.call(self.xid, rpc_call(self.xid, 1, compound(minor, ops)))
        r = rpc_reply_results(m)
        assert r is not None, m[:64].hex()
        st = r.u32(); r.opq(); r.u32()
        self.last = st
        return r

    def seqd(self, ops):
        s = u32(OP_SEQUENCE) + self.sid + u32(self.seq) + u32(0) + u32(0) + u32(0)
        self.seq += 1
        r = self.compound([s] + ops)
        assert r.u32() == OP_SEQUENCE
        if r.u32() != 0:
            return None
        r.fixed(16 + 5 * 4)
        return r

def path_ops():
    return [u32(OP_PUTROOTFH)] + [u32(OP_LOOKUP) + opq(c) for c in PATH]

def open_op(clid, access, create, name):
    how = u32(1) + u32(0) + u32(0) + u32(0) if create else u32(0)   # UNCHECKED4, empty fattr4
    return u32(OP_OPEN) + u32(0) + u32(access) + u32(0) + u64(clid) + opq(b'o' + name) + \
        how + u32(0) + opq(name)

def skip_ok(r, op):
    o, st = r.u32(), r.u32()
    assert o == op, (o, op)
    return st

def read_open(r):
    """OPEN4resok up to the delegation: (stateid, delegation type, its stateid)."""
    sid = r.fixed(16)
    r.u32(); r.u64(); r.u64()       # change_info4
    r.u32(); r.bitmap()             # rflags, attrset
    dt = r.u32()
    dsid = r.fixed(16) if dt in (1, 2) else None
    return sid, dt, dsid

# The RDMA side: replies to our calls on a queue, reverse Calls answered.
class RdmaPeer:
    def __init__(self):
        self.p = Peer(HOST, RPORT)
        self.p.s.settimeout(None)       # the reader waits as long as it must
        self.tx = threading.Lock()      # MSN goes up one Send at a time
        self.replies = {}
        self.cv = threading.Condition()
        self.calls = []
        self.recall = None
        self.answer = True
        threading.Thread(target=self.reader, daemon=True).start()

    def reader(self):
        while True:
            try:
                m = self.p.recv_msg()
            except Exception as e:
                with self.cv:
                    self.dead = repr(e); self.cv.notify_all()
                return
            xid, vers, credit, proc = struct.unpack('>IIII', m[:16])
            rpc = m[28:]
            mt = struct.unpack('>I', rpc[4:8])[0]
            if mt == 0:
                self.reverse(xid, rpc)
            else:
                with self.cv:
                    self.replies[xid] = rpc; self.cv.notify_all()

    def reverse(self, xid, rpc):
        """A reverse Call, RFC 8167 s5.1: CB_NULL or CB_COMPOUND."""
        r = R(rpc)
        r.u32(); r.u32(); r.u32(); prog, vers, proc = r.u32(), r.u32(), r.u32()
        r.u32(); r.opq(); r.u32(); r.opq()      # cred, verf
        self.calls.append((prog, vers, proc))
        res = b''
        if proc == 1:
            r.opq(); r.u32(); r.u32()           # tag, minor, callback_ident
            n = r.u32()
            out = []
            for _ in range(n):
                op = r.u32()
                if op == 11:                    # CB_SEQUENCE
                    sid = r.fixed(16); seq, slot, hi = r.u32(), r.u32(), r.u32()
                    r.u32()
                    for _ in range(r.u32()):    # referring call lists
                        r.fixed(16)
                        for _ in range(r.u32()):
                            r.u32(); r.u32()
                    out.append(u32(11) + u32(0) + sid + u32(seq) + u32(slot) + u32(hi) + u32(hi))
                elif op == 4:                   # CB_RECALL
                    self.recall = r.fixed(16); r.u32(); r.opq()
                    out.append(u32(4) + u32(0))
                else:
                    out.append(u32(op) + u32(10004))     # NFS4ERR_NOTSUPP
                    break
            res = u32(0) + opq(b'') + u32(len(out)) + b''.join(out)
        if not self.answer:
            return
        reply = u32(xid) + u32(1) + u32(0) + NONE + u32(0) + res
        # RFC 8167 s5.2: the XID of the Call, our version, a grant.
        with self.tx:
            self.p.send(struct.pack('>IIII', xid, 1, 4, 0) + bytes(12) + reply)

    def call(self, xid, msg, t=20):
        with self.tx:
            self.p.send(struct.pack('>IIII', xid, 1, 8, 0) + bytes(12) + msg)
        end = time.time() + t
        with self.cv:
            while xid not in self.replies:
                if getattr(self, 'dead', None) or time.time() > end:
                    raise TimeoutError('no reply to %#x: %s' % (xid, getattr(self, 'dead', 'timeout')))
                self.cv.wait(1)
            return self.replies.pop(xid)

def tcp_call_fn():
    # The tunnel carries 2049 on the loopback only.
    s = socket.create_connection(("127.0.0.1", TPORT), timeout=30)
    def call(xid, msg):
        s.sendall(u32(0x80000000 | len(msg)) + msg)
        while True:
            h = b''
            while len(h) < 4:
                h += s.recv(4 - len(h))
            n = struct.unpack('>I', h)[0] & 0x7fffffff
            b = b''
            while len(b) < n:
                b += s.recv(n - len(b))
            if struct.unpack('>I', b[:4])[0] == xid:
                return b
    return call

rp = RdmaPeer()
a = Client(rp.call, b'badpeer-a-%d' % time.time(), True)
check('4.1 session with a backchannel on RDMA', a.sid is not None)
time.sleep(2)
check('CB_NULL came as a reverse Call', (0x40000000, 4, 0) in rp.calls, rp.calls)

# The file, made and closed, then opened for reading: a read delegation.
name = b'recall-%d' % time.time()
r = a.seqd(path_ops() + [open_op(a.clid, 3, True, name)])
for op in [OP_PUTROOTFH] + [OP_LOOKUP] * len(PATH):
    assert skip_ok(r, op) == 0
assert skip_ok(r, OP_OPEN) == 0
sid, dt, dsid = read_open(r)
# GETFH comes after the rest of OPEN4resok; ask for it on its own.
r = a.seqd(path_ops() + [u32(OP_LOOKUP) + opq(name), u32(OP_GETFH)])
for op in [OP_PUTROOTFH] + [OP_LOOKUP] * (len(PATH) + 1):
    assert skip_ok(r, op) == 0
assert skip_ok(r, OP_GETFH) == 0
fh = r.opq()
a.seqd([u32(OP_PUTFH) + opq(fh), u32(OP_CLOSE) + u32(0) + sid])
if dsid:
    a.seqd([u32(OP_PUTFH) + opq(fh), u32(OP_DELEGRETURN) + dsid])
r = a.seqd(path_ops() + [open_op(a.clid, 1, False, name)])
for op in [OP_PUTROOTFH] + [OP_LOOKUP] * len(PATH):
    assert skip_ok(r, op) == 0
assert skip_ok(r, OP_OPEN) == 0
sid, dt, dsid = read_open(r)
check('a read delegation', dt == 1, dt)

# The second client, on TCP, opens for writing.
b = Client(tcp_call_fn(), b'badpeer-b-%d' % time.time(), False)
done = {}
def conflict():
    try:
        r = b.seqd(path_ops() + [open_op(b.clid, 2, False, name)])
        done['st'] = b.last
    except Exception as e:
        done['st'] = repr(e)
t = threading.Thread(target=conflict, daemon=True)
t.start()
end = time.time() + 20
while rp.recall is None and time.time() < end:
    time.sleep(0.2)
check('CB_RECALL came as a reverse Call', rp.recall is not None,
      (rp.calls, rp.recall and rp.recall.hex(), dsid and dsid.hex()))
if rp.recall is not None:
    # As the Linux client does with the file still open: the open is
    # moved off the delegation first, OPEN with CLAIM_DELEG_CUR_FH (5),
    # RFC 8881 s18.16.3, and the delegation is then returned.
    try:
        a.seqd([u32(OP_PUTFH) + opq(fh),
                u32(OP_OPEN) + u32(0) + u32(1) + u32(0) + u64(a.clid) +
                opq(b'o' + name) + u32(0) + u32(5) + dsid])
        check('OPEN by CLAIM_DELEG_CUR_FH answered', a.last == 0, a.last)
    except Exception as e:
        check('OPEN by CLAIM_DELEG_CUR_FH answered', False, repr(e))
    try:
        a.seqd([u32(OP_PUTFH) + opq(fh), u32(OP_DELEGRETURN) + dsid])
        check('DELEGRETURN answered', a.last == 0, a.last)
    except Exception as e:
        check('DELEGRETURN answered', False, repr(e))
t.join(30)
check('the second open went through', done.get('st') in (0, 10008), done)
# The forward channel afterwards, which is where the Linux client stopped.
for i in range(5):
    try:
        a.seqd([u32(OP_PUTFH) + opq(fh), u32(OP_CLOSE) + u32(0) + sid] if i == 0 else [])
        ok = True
    except Exception as e:
        ok = repr(e)
    check('forward call %d after the recall' % i, ok is True, ok)
    if ok is not True:
        break
# And a fresh connection, which in the stalls was never read.
try:
    p2 = Peer(HOST, RPORT)
    check('a new connection is served', True)
except Exception as e:
    check('a new connection is served', False, repr(e))
print('FAILS:', fails)
sys.exit(fails != 0)
