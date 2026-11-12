# rpcs.py PCAP PORT: NFSv4 COMPOUND calls and replies on PORT, in order:
# per record, direction, xid, ops (call) or status and first op statuses.
import struct, sys
from collections import defaultdict
data = open(sys.argv[1], 'rb').read(); port = int(sys.argv[2])
off = 24; streams = defaultdict(bytearray); seen = defaultdict(set); order = []
while off + 16 <= len(data):
    ts, tu, il, ol = struct.unpack('<IIII', data[off:off+16]); off += 16
    p = data[off:off+il]; off += il
    if len(p) < 34 or p[12:14] != b'\x08\x00': continue
    ihl = (p[14] & 15) * 4; ip = p[14:]
    if ip[9] != 6: continue
    tcp = ip[ihl:]; sp, dp, seq = struct.unpack('>HHI', tcp[:8]); th = (tcp[12] >> 4) * 4
    pay = tcp[th:struct.unpack('>H', ip[2:4])[0] - ihl]
    if not pay or port not in (sp, dp): continue
    key = (sp, dp)
    if seq in seen[key]: continue
    seen[key].add(seq); streams[key] += pay
    buf = streams[key]
    while len(buf) >= 4:
        n = struct.unpack('>I', buf[:4])[0] & 0x7fffffff
        if len(buf) < 4 + n: break
        rec = bytes(buf[4:4+n]); del buf[:4+n]
        order.append(('C' if dp == port else 'R', sp if dp == port else dp, rec))
def u(b, o): return struct.unpack('>I', b[o:o+4])[0], o + 4
def op(b, o): return o
for d, cport, r in order:
    xid, o = u(r, 0); mt, o = u(r, o)
    try:
        if mt == 0:
            o += 12; proc = struct.unpack('>I', r[o:o+4])[0]; o += 4
            for _ in range(2):
                fl, o = u(r, o); ln, o = u(r, o); o += (ln + 3) & ~3
            if proc == 0: print(d, cport, hex(xid), 'NULL'); continue
            tl, o = u(r, o); o += (tl + 3) & ~3; mv, o = u(r, o); nops, o = u(r, o)
            ops = []
            for i in range(nops):
                on, o = u(r, o); ops.append(on)
                if i == 0 and on == 53: o += 32
                elif on == 22: fl, o = u(r, o); o += (fl + 3) & ~3
                elif on == 38: o += 16; off_ = struct.unpack('>Q', r[o:o+8])[0]; o += 8; st, o = u(r, o); cnt, o = u(r, o); ops.append('off=%d len=%d stable=%d' % (off_, cnt, st)); break
                else: break
            print(d, cport, hex(xid), 'call', ops)
        else:
            rs, o = u(r, o)
            fl, o = u(r, o); vl, o = u(r, o); o += (vl + 3) & ~3
            ast, o = u(r, o)
            if ast != 0: print(d, cport, hex(xid), 'accept_stat', ast); continue
            if len(r) <= o: print(d, cport, hex(xid), 'NULL reply'); continue
            st, o = u(r, o); tl, o = u(r, o); o += (tl + 3) & ~3; n, o = u(r, o)
            if n and struct.unpack('>I', r[o:o+4])[0] == 42 and struct.unpack('>I', r[o+4:o+8])[0] == 0:
                cid = r[o+8:o+16].hex(); fl = struct.unpack('>I', r[o+20:o+24])[0]
                q = o + 24 + 4 + 8; ml = struct.unpack('>I', r[q:q+4])[0]
                print(d, cport, hex(xid), 'reply', st, 'EXCHANGE_ID clientid', cid, 'flags %#x' % fl, 'major', r[q+4:q+4+ml]); continue
            res = []
            for i in range(n):
                on, o = u(r, o); s, o = u(r, o); res.append((on, s))
                if s != 0: break
                if on == 53: o += 36
                elif on == 22: pass
                elif on == 38: cnt, o = u(r, o); com, o = u(r, o); res.append('count=%d committed=%d' % (cnt, com)); break
                else: break
            print(d, cport, hex(xid), 'reply', st, res)
    except Exception as e:
        print(d, cport, hex(xid), 'parse error', e)
