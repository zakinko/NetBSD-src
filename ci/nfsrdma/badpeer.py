#!/usr/bin/env python3
# A peer that speaks iWARP over a socket, to reach what a well-behaved
# client does not: the error paths of RFC 8166 s4.5, a Long Call, the
# CRC, and the things that lose the connection.  badpeer.py HOST PORT
import socket, struct, sys, time

HOST, PORT = sys.argv[1], int(sys.argv[2])
fails = 0

def check(name, ok, detail=''):
    global fails
    print(('ok   ' if ok else 'FAIL ') + name, detail)
    fails += 0 if ok else 1

TAB = []
for i in range(256):
    c = i
    for _ in range(8):
        c = c >> 1 ^ 0x82f63b78 if c & 1 else c >> 1
    TAB.append(c)

def crc32c(b):
    c = 0xffffffff
    for x in b:
        c = TAB[(c ^ x) & 0xff] ^ c >> 8
    return ~c & 0xffffffff

class Peer:
    def __init__(self, crc=False):
        self.s = socket.create_connection((HOST, PORT), timeout=10)
        self.crc = crc
        self.msn = 1
        f = b'MPA ID Req Frame' + bytes([0x40 if crc else 0, 1]) + struct.pack('>H', 0)
        self.s.sendall(f)
        h = self.need(20)
        assert h[:16] == b'MPA ID Rep Frame', h
        self.flags = h[16]
        self.rev = h[17]
        self.pd = self.need(struct.unpack('>H', h[18:20])[0])
        self.buf = b''

    def need(self, n):
        b = b''
        while len(b) < n:
            d = self.s.recv(n - len(b))
            if not d:
                raise EOFError
            b += d
        return b

    def fpdu(self, ulpdu):
        pad = (4 - (2 + len(ulpdu)) % 4) % 4
        b = struct.pack('>H', len(ulpdu)) + ulpdu + bytes(pad)
        crc = crc32c(b) if self.crc else 0
        # RFC 5044 s4.4 Figure 5: the check value goes out low octet first.
        self.s.sendall(b + struct.pack('<I', crc))

    def send(self, msg, msn=None):
        hdr = bytes([0x41, 0x43]) + bytes(4) + struct.pack('>III', 0, msn or self.msn, 0)
        self.msn += 1
        self.fpdu(hdr + msg)

    def recv(self):
        """One segment: (op, tagged, last, stag or msn, to or qn, payload)."""
        n = struct.unpack('>H', self.need(2))[0]
        pad = (4 - (2 + n) % 4) % 4
        rest = self.need(n + pad + 4)
        u = rest[:n]
        if self.crc:
            want = struct.unpack('<I', rest[n + pad:])[0]
            got = crc32c(struct.pack('>H', n) + u + bytes(pad))
            check('crc on what the server sent', want == got, hex(want))
        op = u[1] & 15
        if u[0] & 0x80:
            stag, to = struct.unpack('>IQ', u[2:14])
            return op, True, bool(u[0] & 0x40), stag, to, u[14:]
        _, qn, msn, mo = struct.unpack('>IIII', u[2:18])
        return op, False, bool(u[0] & 0x40), msn, qn, u[18:]

    def recv_msg(self):
        op, tagged, last, a, b, d = self.recv()
        assert op == 3 and not tagged and last, (op, tagged, last)
        return d

    def expect_nothing(self, t=1.0):
        self.s.settimeout(t)
        try:
            self.s.recv(1)
            return False
        except socket.timeout:
            return True
        finally:
            self.s.settimeout(10)

def rdma(xid, vers=1, proc=0, tail=b'\0' * 12):
    return struct.pack('>IIII', xid, vers, 8, proc) + tail

def null_call(xid, prog=100003, vers=4, proc=0):
    return struct.pack('>IIIIII', xid, 0, 2, prog, vers, proc) + bytes(16)

def is_error(m, xid, vers, err):
    w = struct.unpack('>%dI' % (len(m) // 4), m)
    return w[0] == xid and w[1] == vers and w[3] == 4 and w[4] == err, w

def null_ok(p, xid):
    p.send(rdma(xid) + null_call(xid))
    m = p.recv_msg()
    w = struct.unpack('>7I', m[:28])
    return w[0] == xid and w[1] == 1 and w[2] == 32 and w[3] == 0 and \
        struct.unpack('>I', m[28:32])[0] == xid, w

p = Peer()
check('mpa reply', p.rev == 1 and p.flags == 0, (p.rev, p.flags, p.pd.hex()))
check('NULL', *null_ok(p, 1))

# s4.5: under 28 bytes, no answer at all.
p.send(bytes(27))
check('short message is ignored', p.expect_nothing())

p.send(rdma(2, vers=2) + null_call(2))
m = p.recv_msg()
ok, w = is_error(m, 2, 2, 1)
check('ERR_VERS', ok and w[5:7] == (1, 1), w)

for name, msg in (
    ('RDMA_MSGP', rdma(3, proc=2, tail=bytes(20))),
    ('unknown proc', rdma(3, proc=9)),
    ('RDMA_NOMSG with nothing', rdma(3, proc=1)),
    ('xid of the header and call differ', rdma(3) + null_call(4)),
    ('an optional of 2', rdma(3, tail=struct.pack('>III', 2, 0, 0))),
    ('position not a multiple of 4',
     rdma(3, tail=struct.pack('>IIIIQIII', 1, 6, 1, 4, 0, 0, 0, 0)) + null_call(3)),
    ('Read chunk on an ineligible item',
     rdma(3, tail=struct.pack('>IIIIQIII', 1, 40, 1, 4, 0, 0, 0, 0)) + null_call(3)),
    ('Position past the stream',
     rdma(3, tail=struct.pack('>IIIIQIII', 1, 4000, 1, 4, 0, 0, 0, 0)) + null_call(3)),
    ('Read chunk over the limit',
     rdma(3, tail=struct.pack('>IIIIQIII', 1, 0, 1, 0x7fffffff, 0, 0, 0, 0))),
):
    p.send(msg)
    m = p.recv_msg()
    ok, w = is_error(m, 3, 1, 2)
    check('ERR_CHUNK: ' + name, ok, w)

# s4.6.2 and s4.2.4: silence.
p.send(rdma(5, proc=3))
p.send(struct.pack('>IIIII', 5, 1, 8, 4, 2) + bytes(8))
check('RDMA_DONE, RDMA_ERROR are ignored', p.expect_nothing())

# RFC 8167: a Reply on a server goes no further.
p.send(rdma(6) + struct.pack('>III', 6, 1, 0))
check('a reverse Reply is ignored', p.expect_nothing())
check('NULL afterwards', *null_ok(p, 7))

# RFC 5531 by RDMA: a program with nobody behind it.
p.send(rdma(8) + null_call(8, prog=400000))
m = p.recv_msg()
check('PROG_UNAVAIL by RDMA_MSG', struct.unpack('>I', m[12:16])[0] == 0 and
      struct.unpack('>I', m[28 + 20:28 + 24])[0] == 1, m.hex())

# A Long Call: all of it by a Position Zero Read chunk, in two segments.
call = null_call(9)
tail = struct.pack('>IIIIQ', 1, 0, 0x1111, 20, 0x100) + \
    struct.pack('>IIIIQ', 1, 0, 0x2222, len(call) - 20, 0x200) + bytes(12)
p.send(rdma(9, proc=1, tail=tail))
for stag, off, data in ((0x1111, 0x100, call[:20]), (0x2222, 0x200, call[20:])):
    op, tagged, last, msn, qn, d = p.recv()
    sink, sinkto, size, src, srcto = struct.unpack('>IQIIQ', d)
    check('Read Request', op == 1 and qn == 1 and src == stag and
          srcto == off and size == len(data), (op, qn, hex(src), size))
    # Cut in two, as a peer may.
    h = lambda L, to: bytes([0xc1 if L else 0x81, 0x42]) + struct.pack('>IQ', sink, to)
    p.fpdu(h(False, sinkto) + data[:5])
    p.fpdu(h(True, sinkto + 5) + data[5:])
m = p.recv_msg()
check('Long Call answered', struct.unpack('>I', m[:4])[0] == 9 and
      struct.unpack('>I', m[28:32])[0] == 9, m[:36].hex())

# A Write chunk offered and not used comes back with empty segments,
# s4.3.2.2, and a Reply chunk the same, s4.3.3.
seg = lambda h, l, o: struct.pack('>IIQ', h, l, o)
tail = struct.pack('>III', 0, 1, 2) + seg(7, 100, 1) + seg(8, 200, 2) + \
    struct.pack('>II', 0, 1) + struct.pack('>I', 1) + seg(9, 300, 3)
msg = struct.pack('>IIII', 10, 1, 8, 0) + tail + null_call(10)
p.send(msg)
m = p.recv_msg()
want = struct.pack('>III', 0, 1, 2) + seg(7, 0, 1) + seg(8, 0, 2) + \
    struct.pack('>II', 0, 1) + struct.pack('>I', 1) + seg(9, 0, 3)
check('unused Write and Reply chunks', m[16:16 + len(want)] == want,
      m[16:16 + len(want)].hex())

# Data for no Read in progress ends the connection.
p.fpdu(bytes([0xc1, 0x42]) + struct.pack('>IQ', 0xdead, 0) + b'x')
try:
    op = None
    while True:
        op = p.recv()[0]
except (EOFError, ConnectionError, socket.timeout) as e:
    check('stray tagged data closes', op == 7 and not isinstance(e, socket.timeout), (op, repr(e)))

# A Send out of sequence, s4.3 of RFC 5041.
p = Peer()
p.send(rdma(11) + null_call(11), msn=5)
try:
    p.recv()
    p.recv()
    check('bad MSN closes', False)
except (EOFError, ConnectionError):
    check('bad MSN closes', True)

# Garbage for an MPA Request.
s = socket.create_connection((HOST, PORT), timeout=10)
s.sendall(b'GET / HTTP/1.0\r\n\r\n' + bytes(20))
try:
    check('bad key closes', s.recv(1) == b'')
except ConnectionError:
    check('bad key closes', True)

# The CRC, both ways.
p = Peer(crc=True)
check('mpa with C', p.flags & 0x40 != 0, p.flags)
check('NULL with CRC', *null_ok(p, 12))
# And a wrong one.
n = rdma(13) + null_call(13)
hdr = bytes([0x41, 0x43]) + bytes(4) + struct.pack('>III', 0, p.msn, 0)
u = hdr + n
pad = (4 - (2 + len(u)) % 4) % 4
p.s.sendall(struct.pack('>H', len(u)) + u + bytes(pad) + b'BAD!')
try:
    while True:
        p.recv()
except (EOFError, ConnectionError):
    check('bad CRC closes', True)

print('FAILS:', fails)
sys.exit(fails != 0)
