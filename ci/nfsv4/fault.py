#!/usr/bin/env python3
"""In pynfs's nfs4.0 directory: the errors RFC 7530 asks for in cases
the server cannot otherwise be made to reach, through the counters
vfs.nfsv4.fault_* (nth call fails once).  fault.py EXPORT
"""
import os, subprocess, sys
sys.path.insert(0, os.getcwd())
import use_local
sys.path.insert(0, os.path.join(os.getcwd(), 'lib'))
import nfs4lib, nfs_ops, rpc.rpc as rpc
from xdrdef.nfs4_const import *
op = nfs_ops.NFS4ops()
nfs4lib.SHOW_TRAFFIC = 0

fails = 0
def want(name, got, *ok):
    global fails
    print('%s %s: %r' % ('ok    ' if got in ok else 'FAILED', name, got))
    fails += got not in ok

def sysctl(name, n):
    subprocess.run(['ssh', '-o', 'LogLevel=ERROR', 'netbsd',
                    'sysctl -w vfs.nfsv4.%s=%d' % (name, n)], check=True)

export = sys.argv[1].strip('/').encode().split(b'/')
c = nfs4lib.NFS4Client(b'fault%d' % os.getpid(), host=b'127.0.0.1',
                       port=2049, homedir=export,
                       sec_list=[rpc.SecAuthSys(0, b'x', 0, 0, [])])
c.init_connection()
bm = nfs4lib.list2bitmap([FATTR4_SIZE, FATTR4_TIME_MODIFY])

# s16.7.4: supported but not obtainable is an error, and no values.
sysctl('fault_getattr', 2)
r = c.compound(c.use_obj(export) + [op.getattr(bm)])
want('GETATTR before the nth', r.status, NFS4_OK)
r = c.compound(c.use_obj(export) + [op.getattr(bm)])
want('GETATTR whose values cannot be had', r.status, NFS4ERR_IO)
want('no GETATTR result with the error', r.resarray[-1].resop, OP_GETATTR)
want('  ... and it carries no attributes',
     getattr(r.resarray[-1], 'switch', None) is None or
     getattr(r.resarray[-1].switch, 'switch', None) is None, True)
r = c.compound(c.use_obj(export) + [op.getattr(bm)])
want('GETATTR after, counter spent', r.status, NFS4_OK)

# s16.28.5: a lease that cannot be renewed is not CB_PATH_DOWN.
sysctl('fault_renew', 1)
r = c.compound([op.renew(c.clientid)])
want('RENEW that cannot renew', r.status, NFS4ERR_RESOURCE)
r = c.compound([op.renew(c.clientid)])
want('RENEW after, counter spent', r.status, NFS4_OK)
sysctl('fault_getattr', 0)
sysctl('fault_renew', 0)
print('failures: %d' % fails)
sys.exit(1 if fails else 0)
