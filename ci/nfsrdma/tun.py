#!/usr/bin/python3
"""One end of a point-to-point IP link over stdin and stdout, with a tun
device, for what port forwarding cannot do: the server has to be able to
reach the client.  Each packet is sent with a two-byte length.
tun.py NAME, on Linux."""
import fcntl, os, select, struct, sys
TUNSETIFF, IFF_TUN, IFF_NO_PI = 0x400454ca, 1, 0x1000
t = os.open('/dev/net/tun', os.O_RDWR)
fcntl.ioctl(t, TUNSETIFF, struct.pack('16sH', sys.argv[1].encode(), IFF_TUN | IFF_NO_PI))
buf = b''
while True:
    r, _, _ = select.select([t, 0], [], [])
    if t in r:
        p = os.read(t, 65535)
        os.write(1, struct.pack('>H', len(p)) + p)
    if 0 in r:
        d = os.read(0, 65536)
        if not d:
            break
        buf += d
        while len(buf) >= 2:
            n = struct.unpack('>H', buf[:2])[0]
            if len(buf) < 2 + n:
                break
            os.write(t, buf[2:2 + n])
            buf = buf[2 + n:]
