#!/usr/bin/env python3
"""The optional parts pynfs has no test for.  From pynfs's nfs4.0 directory:
more.py attrs EXPORT | fair EXPORT | moved EXPORT | cbgetattr PATH SIZE
Exit status 1 means something went wrong.
"""
import os, subprocess, sys, time
sys.path.insert(0, os.getcwd())
import use_local
sys.path.insert(0, os.path.join(os.getcwd(), 'lib'))
import nfs4lib, nfs_ops, rpc.rpc as rpc
from xdrdef.nfs4_const import *
op = nfs_ops.NFS4ops()

fails = 0
def want(name, got, *ok):
    global fails
    print('%s %s: %r' % ('ok    ' if got in ok else 'FAILED', name, got))
    fails += got not in ok

def client(name, export, uid=0):
    c = nfs4lib.NFS4Client(b'%s%d' % (name, os.getpid()), host=b'127.0.0.1',
                           port=2049, homedir=export,
                           sec_list=[rpc.SecAuthSys(0, b'x', uid, uid, [])])
    c.init_connection()
    return c

what, arg = sys.argv[1:3]
export = arg.strip('/').encode().split(b'/')

if what == 'attrs':
    c = client(b'attrs', export)
    path = export + [b'at%d' % os.getpid()]
    fh, sid = c.create_confirm(b'o', path, access=OPEN4_SHARE_ACCESS_BOTH,
                               deny=OPEN4_SHARE_DENY_NONE)
    sup = c.do_getattr(FATTR4_SUPPORTED_ATTRS, path)
    print('supported', sup)
    if FATTR4_HIDDEN not in sup:
        print('not on this file system')
        sys.exit(0)
    for a, v in ((FATTR4_HIDDEN, True), (FATTR4_ARCHIVE, True),
                 (FATTR4_SYSTEM, True), (FATTR4_MIMETYPE, b'text/plain')):
        r = c.compound([op.putfh(fh), op.setattr(sid, {a: v})])
        want('SETATTR %d' % a, r.status, NFS4_OK)
        want('GETATTR %d' % a, c.do_getattr(a, path), v)
elif what == 'fair':
    c1, c2, c3 = client(b'f1', export), client(b'f2', export), client(b'f3', export)
    path = export + [b'fair%d' % os.getpid()]
    fh1, s1 = c1.create_confirm(b'o', path, access=OPEN4_SHARE_ACCESS_BOTH,
                                deny=OPEN4_SHARE_DENY_NONE, attrs={FATTR4_MODE: 0o666})
    fh2, s2 = c2.open_confirm(b'o', path, access=OPEN4_SHARE_ACCESS_BOTH,
                              deny=OPEN4_SHARE_DENY_NONE)
    fh3, s3 = c3.open_confirm(b'o', path, access=OPEN4_SHARE_ACCESS_BOTH,
                              deny=OPEN4_SHARE_DENY_NONE)
    r1 = c1.lock_file(b'o', fh1, s1, type=WRITE_LT)
    want('c1 LOCK', r1.status, NFS4_OK)
    r = c2.lock_file(b'o', fh2, s2, type=WRITEW_LT)
    want('c2 WRITEW, denied', r.status, NFS4ERR_DENIED)
    r = c1.unlock_file(1, fh1, r1.lockid)
    want('c1 LOCKU', r.status, NFS4_OK)
    r = c3.lock_file(b'o', fh3, s3, type=WRITE_LT)
    want('c3 LOCK, behind c2, s9.4', r.status, NFS4ERR_DENIED)
    r = c2.lock_file(b'o', fh2, s2, type=WRITEW_LT)
    want('c2 WRITEW, its turn', r.status, NFS4_OK)
elif what == 'moved':
    c, c2 = client(b'm1', export), client(b'm2', export)
    path = export + [b'mv%d' % os.getpid()]
    fh, sid = c.create_confirm(b'o', path, access=OPEN4_SHARE_ACCESS_BOTH,
                               deny=OPEN4_SHARE_DENY_NONE)
    r = c.compound([op.renew(c.clientid)])
    want('RENEW before', r.status, NFS4_OK)
    subprocess.check_call(['ssh', 'netbsd', 'sysctl', '-w',
        "'vfs.nfsv4.moved=%s srv9:/moved'" % arg])
    r = c.compound([op.renew(c.clientid)])
    want('RENEW, s9.14.3', r.status, NFS4ERR_LEASE_MOVED)
    r = c2.compound([op.renew(c2.clientid)])
    want('RENEW of a client with no state there', r.status, NFS4_OK)
    r = c.compound([op.putfh(fh), op.getfh()])
    want('GETFH, s8.2', r.status, NFS4ERR_MOVED)
    r = c.compound([op.putfh(fh), op.getattr(nfs4lib.list2bitmap([FATTR4_SIZE]))])
    want('GETATTR without fs_locations, s8.3.1', r.status, NFS4ERR_MOVED)
    r = c.compound([op.putfh(fh),
                    op.getattr(nfs4lib.list2bitmap([FATTR4_FS_LOCATIONS])),
                    op.renew(c.clientid)])
    want('probe and RENEW', r.status, NFS4_OK)
    print(r.resarray[1].switch.switch.obj_attributes)
    r = c.compound([op.renew(c.clientid)])
    want('RENEW after', r.status, NFS4_OK)
elif what == 'cbgetattr':
    size = int(sys.argv[3])
    path = export
    c = client(b'cg', export[:-1])
    c.homedir = export[:-1]
    r = c.compound(c.use_obj(path) + [op.getattr(nfs4lib.list2bitmap([FATTR4_SIZE]))])
    print('status', r.status)
    while r.status == NFS4ERR_DELAY:
        time.sleep(1)
        r = c.compound(c.use_obj(path) + [op.getattr(nfs4lib.list2bitmap([FATTR4_SIZE]))])
    want('GETATTR', r.status, NFS4_OK)
    want('size the holder has', r.resarray[-1].switch.switch.obj_attributes[FATTR4_SIZE], size)
print('failures: %d' % fails)
sys.exit(1 if fails else 0)
