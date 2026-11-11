#!/usr/bin/env python3
"""RFC 7530 s16.26.5 both ways, by vfs.nfsv4.remove_past_deny.  From pynfs's
nfs4.0 directory: t40rm.py EXPORT.  Failures are the measurement."""
import os, subprocess, sys
sys.path.insert(0, os.getcwd())
import use_local
sys.path.insert(0, os.path.join(os.getcwd(), 'lib'))
import nfs4lib, nfs_ops
from xdrdef.nfs4_const import *
op = nfs_ops.NFS4ops()
nfs4lib.SHOW_TRAFFIC = 0
export = sys.argv[1].strip('/').encode().split(b'/')
fails = 0
def t(name, got, want):
    global fails
    print("%s %s: got %s, want %s" % ("ok  " if got == want else "FAIL", name, got, want))
    fails += got != want
def sc(v):
    subprocess.call(["ssh", "netbsd", "sudo sysctl -w %s || sysctl -w %s" % (v, v)])
c = nfs4lib.NFS4Client(b't40rm%d' % os.getpid(), host=b'127.0.0.1', port=2049,
                       homedir=export)
c.init_connection()
r = c.compound([op.putrootfh()] + [op.lookup(x) for x in export] + [op.getfh()])
dirfh = r.resarray[-1].switch.switch.object
for v, want in ((0, NFS4ERR_FILE_OPEN), (1, NFS4_OK)):
    sc("vfs.nfsv4.remove_past_deny=%d" % v)
    name = b'rm%d_%d' % (v, os.getpid())
    fh, sid = c.create_confirm(b'o%d' % v, export + [name],
                               access=OPEN4_SHARE_ACCESS_BOTH,
                               deny=OPEN4_SHARE_DENY_WRITE)
    r = c.compound([op.putfh(dirfh), op.remove(name)])
    t("s16.26.5 remove_past_deny=%d" % v, r.status, want)
    c.close_file(b'o%d' % v, fh, sid)
sc("vfs.nfsv4.remove_past_deny=1")
print("failures:", fails)
