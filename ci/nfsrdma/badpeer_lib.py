#!/usr/bin/env python3
# The iWARP peer of badpeer.py, for the other scripts here.
import socket, struct

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
    def __init__(self, host, port, crc=False):
        self.s = socket.create_connection((host, port), timeout=10)
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
            assert want == got, 'crc on what the server sent'
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

