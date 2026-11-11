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
nfs4lib.SHOW_TRAFFIC = 0

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

def prev(c, owner, path):
    # nfs4lib's open() has no way to fill in this arm of the claim.
    from xdrdef.nfs4_type import open_owner4, openflag4, open_claim4
    claim = open_claim4(CLAIM_DELEGATE_PREV, file_delegate_prev=path[-1])
    return c.compound(c.use_obj(path[:-1]) +
                      [op.open(0, OPEN4_SHARE_ACCESS_READ, OPEN4_SHARE_DENY_NONE,
                               open_owner4(c.clientid, owner),
                               openflag4(OPEN4_NOCREATE), claim), op.getfh()])

what, arg = sys.argv[1:3]
export = arg.strip('/').encode().split(b'/')

if what == 'attrs':
    c = client(b'attrs', export)
    path = export + [b'at%d' % os.getpid()]
    fh, sid = c.create_confirm(b'o', path, access=OPEN4_SHARE_ACCESS_BOTH,
                               deny=OPEN4_SHARE_DENY_NONE)
    sup = c.do_getattr(FATTR4_SUPPORTED_ATTRS, path)
    print('supported', sup)
    if not sup & (1 << FATTR4_HIDDEN):
        print('not on this file system')
        sys.exit(0)
    for a, v in ((FATTR4_HIDDEN, True), (FATTR4_ARCHIVE, True),
                 (FATTR4_SYSTEM, True), (FATTR4_MIMETYPE, b'text/plain')):
        r = c.compound([op.putfh(fh), op.setattr(sid, {a: v})])
        want('SETATTR %d' % a, r.status, NFS4_OK)
        want('GETATTR %d' % a, c.do_getattr(a, path), v)
elif what == 'quota':
    c = client(b'quota', export)
    path = export + [b'q%d' % os.getpid()]
    fh, sid = c.create_confirm(b'o', path, access=OPEN4_SHARE_ACCESS_BOTH,
                               deny=OPEN4_SHARE_DENY_NONE)
    sup = c.do_getattr(FATTR4_SUPPORTED_ATTRS, path)
    want('in supported_attrs', bool(sup & (1 << FATTR4_QUOTA_USED)), True)
    r = c.compound([op.putfh(fh), op.write(sid, 0, FILE_SYNC4, b'x' * 65536)])
    want('WRITE', r.status, NFS4_OK)
    used = c.do_getattr(FATTR4_QUOTA_USED, path)
    hard = c.do_getattr(FATTR4_QUOTA_AVAIL_HARD, path)
    soft = c.do_getattr(FATTR4_QUOTA_AVAIL_SOFT, path)
    print('used', used, 'hard', hard, 'soft', soft)
    subprocess.call(['ssh', 'netbsd', 'repquota', '-u', arg])
    want('used is bytes of the write or more', used >= 65536, True)
    want('hard is soft + 1000 blocks', hard - soft, 1000 * 512, 1000 * 1024)
elif what == 'prev':
    # s10.2.1: a client restarts, and takes its delegation back.
    time.sleep(0)
    cid = b'prev%d' % os.getpid()
    c = nfs4lib.NFS4Client(cid, host=b'127.0.0.1', port=2049, homedir=export,
                           sec_list=[rpc.SecAuthSys(0, b'x', 0, 0, [])])
    c.init_connection(cid, cb_ident=0)
    time.sleep(2)
    path = export + [b'pv%d' % os.getpid()]
    r = c.create_file(b'o', path, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
    fh, sid = c.confirm(b'o', r)
    r = c.open_file(b'o', path, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
    d = r.resarray[-2].switch.switch.delegation
    want('a read delegation', d.delegation_type, OPEN_DELEGATE_READ)
    c.verifier = b'restart1'
    c.init_connection(cid, cb_ident=0)
    r = prev(c, b'o2', path)
    want('CLAIM_DELEGATE_PREV', r.status, NFS4_OK)
    if r.status == NFS4_OK:
        want('it came back', r.resarray[-2].switch.switch.delegation.delegation_type,
             OPEN_DELEGATE_READ)
    r = c.compound([op.delegpurge(c.clientid)])
    want('DELEGPURGE', r.status, NFS4_OK)
    r = prev(c, b'o3', path)
    want('after DELEGPURGE, s16.16.5', r.status, NFS4ERR_INVAL)
elif what == 'fair':
    c1, c2, c3 = client(b'f1', export), client(b'f2', export), client(b'f3', export)
    path = export + [b'fair%d' % os.getpid()]
    fh1, s1 = c1.create_confirm(b'o', path, access=OPEN4_SHARE_ACCESS_BOTH,
                                deny=OPEN4_SHARE_DENY_NONE, attrs={FATTR4_MODE: 0o666})
    fh2, s2 = c2.open_confirm(b'o', path, access=OPEN4_SHARE_ACCESS_BOTH,
                              deny=OPEN4_SHARE_DENY_NONE)
    fh3, s3 = c3.open_confirm(b'o', path, access=OPEN4_SHARE_ACCESS_BOTH,
                              deny=OPEN4_SHARE_DENY_NONE)
    r1 = c1.lock_file(b'o', fh1, s1, type=WRITE_LT, lockowner=b'lo1')
    want('c1 LOCK', r1.status, NFS4_OK)
    r = c2.lock_file(b'o', fh2, s2, type=WRITEW_LT, lockowner=b'lo2')
    want('c2 WRITEW, denied', r.status, NFS4ERR_DENIED)
    r = c1.unlock_file(1, fh1, r1.lockid)
    want('c1 LOCKU', r.status, NFS4_OK)
    r = c3.lock_file(b'o', fh3, s3, type=WRITE_LT, lockowner=b'lo3')
    want('c3 LOCK, behind c2, s9.4', r.status, NFS4ERR_DENIED)
    r = c2.lock_file(b'o', fh2, s2, type=WRITEW_LT, lockowner=b'lo2')
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
    # time_modify too: cbgetattr.sh compares it with the server's stat,
    # as the constructed time is to be written to the file (s10.4.3).
    bm = nfs4lib.list2bitmap([FATTR4_SIZE, FATTR4_TIME_MODIFY])
    r = c.compound(c.use_obj(path) + [op.getattr(bm)])
    print('status', r.status)
    while r.status == NFS4ERR_DELAY:
        time.sleep(1)
        r = c.compound(c.use_obj(path) + [op.getattr(bm)])
    want('GETATTR', r.status, NFS4_OK)
    a = r.resarray[-1].switch.switch.obj_attributes
    want('size the holder has', a[FATTR4_SIZE], size)
    print('time_modify %d %d' % (a[FATTR4_TIME_MODIFY].seconds,
                                 a[FATTR4_TIME_MODIFY].nseconds))
print('failures: %d' % fails)
sys.exit(1 if fails else 0)
