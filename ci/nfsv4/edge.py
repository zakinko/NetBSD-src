#!/usr/bin/env python3
"""Edges of COMMIT and READDIR that pynfs does not try.  Run from pynfs's
nfs4.0 directory: edge.py EXPORT.  Exit status 1 means something went wrong.
"""
import os, sys
sys.path.insert(0, os.getcwd())
import use_local
sys.path.insert(0, os.path.join(os.getcwd(), 'lib'))
import nfs4lib, nfs_ops
from xdrdef.nfs4_const import *
op = nfs_ops.NFS4ops()
nfs4lib.SHOW_TRAFFIC = 0

export = sys.argv[1].strip('/').encode().split(b'/')
fails = 0

def want(name, got, *ok):
    global fails
    print('%s %s: %s' % ('ok    ' if got in ok else 'FAILED', name, got))
    fails += got not in ok

c = nfs4lib.NFS4Client(b'edge%d' % os.getpid(), host=b'127.0.0.1', port=2049,
                       homedir=export)
c.init_connection()
path = export + [b'edge%d' % os.getpid()]
fh, sid = c.create_confirm(b'edge', path, access=OPEN4_SHARE_ACCESS_BOTH,
                           deny=OPEN4_SHARE_DENY_NONE)
# Past the direct blocks, so that indirect blocks are in the way.
r = c.compound([op.putfh(fh), op.write(sid, 4 << 20, UNSTABLE4, b'x' * 4096)])
want('WRITE', r.status, NFS4_OK)

for off, cnt in ((0, 0), (4 << 20, 0), (4096, 0), (4 << 20, 0xffffffff),
                 (1 << 40, 1), (1 << 40, 0), (1 << 62, 1), (1 << 62, 0),
                 (1, (1 << 32) - 1)):
    r = c.compound([op.putfh(fh), op.commit(off, cnt)])
    want('COMMIT %#x %#x' % (off, cnt), r.status, NFS4_OK)
# Past the bounds, with count 32 bits wide: s16.3.4
r = c.compound([op.putfh(fh), op.commit((1 << 63) - 1, 2)])
want('COMMIT over 2^63', r.status, NFS4ERR_INVAL)

d = export
for ck in ((1 << 63) + 2, (1 << 63) + 3, (1 << 63) + 10, (1 << 64) - 1):
    r = c.compound(c.use_obj(d) + [op.readdir(ck, b'', 4096, 4096,
                                              nfs4lib.list2bitmap([FATTR4_TYPE]))])
    want('READDIR cookie %#x' % ck, r.status,
         NFS4ERR_BAD_COOKIE)
r = c.compound(c.use_obj(d) + [op.readdir((1 << 62), b'', 4096, 4096, nfs4lib.list2bitmap([FATTR4_TYPE]))])
want('READDIR cookie 2^62', r.status, NFS4_OK, NFS4ERR_BAD_COOKIE)
print('failures: %d' % fails)
sys.exit(1 if fails else 0)
