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
elif what == 'damage':
    # s9.6.3.4.3: a damaged record means NFS4ERR_NO_GRACE for all.
    c = client(b'dmg', export)
    path = export + [b'dm%d' % os.getpid()]
    fh, sid = c.create_confirm(b'o', path, access=OPEN4_SHARE_ACCESS_BOTH,
                               deny=OPEN4_SHARE_DENY_NONE)
    subprocess.check_call(['ssh', 'netbsd', 'sh /var/tmp/nfsv4/restart.sh damage'])
    print(subprocess.run(['ssh', 'netbsd', 'dmesg | grep -c "stable storage damaged"'],
                         capture_output=True, text=True).stdout)
    c = client(b'dmg', export)
    r = c.open_file(b'o9', fh, claim_type=CLAIM_PREVIOUS, deleg_type=OPEN_DELEGATE_NONE)
    want('reclaim after damage', r.status, NFS4ERR_NO_GRACE)
    r = c.open_file(b'o8', path, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
    want('no grace period', r.status, NFS4_OK)
elif what == 'movedtime':
    # s9.14.3: normal handling after two leases, for a client that never probes.
    c = client(b'mt', export)
    path = export + [b'mt%d' % os.getpid()]
    fh, sid = c.create_confirm(b'o', path, access=OPEN4_SHARE_ACCESS_BOTH,
                               deny=OPEN4_SHARE_DENY_NONE)
    subprocess.check_call(['ssh', 'netbsd', 'sysctl', '-w',
        "'vfs.nfsv4.moved=%s srv9:/moved'" % arg])
    t0 = time.time()
    r = c.compound([op.renew(c.clientid)])
    want('RENEW', r.status, NFS4ERR_LEASE_MOVED)
    r = c.compound(c.use_obj([]) + [op.getattr(nfs4lib.list2bitmap([FATTR4_TYPE]))])
    want('GETATTR elsewhere does not say it, s13.1.11.1', r.status, NFS4_OK)
    while time.time() - t0 < 195:
        time.sleep(30)
        r = c.compound([op.renew(c.clientid)])
        print(int(time.time() - t0), r.status)
    want('RENEW past two leases', r.status, NFS4_OK)
elif what == 'indirect':
    # COMMIT from an offset to the end must get the indirect block out.
    c = client(b'ind', export)
    path = export + [b'in%d' % os.getpid()]
    fh, sid = c.create_confirm(b'o', path, access=OPEN4_SHARE_ACCESS_BOTH,
                               deny=OPEN4_SHARE_DENY_NONE)
    ino = c.do_getattr(FATTR4_FILEID, path)
    def fib():
        o = subprocess.run(['ssh', 'netbsd', '/var/tmp/nfsv4/fib /dev/rvnd2d %d' % ino],
                           capture_output=True, text=True).stdout
        print(o.strip())
        return int(o.split()[-1])
    r = c.compound([op.putfh(fh), op.write(sid, 4 << 20, UNSTABLE4, b'x' * 4096)])
    want('WRITE', r.status, NFS4_OK)
    want('not on disk yet, or the test proves nothing', fib(), 0)
    r = c.compound([op.putfh(fh), op.commit(4 << 20, 0)])
    want('COMMIT', r.status, NFS4_OK)
    want('on disk', fib() > 0, True)
elif what == 'utf8':
    c = client(b'u8', export)
    r = c.compound(c.use_obj(export) + [c.open(b'o', b'bad\xff\xfename', OPEN4_CREATE,
                                              UNCHECKED4, {}, None,
                                              OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_DENY_NONE)])
    want('invalid UTF-8 on utf8only=on, s12.7', r.status, NFS4ERR_INVAL)
elif what == 'aclmode':
    from xdrdef.nfs4_type import nfsace4, stateid4
    c = client(b'am', export)
    path = export + [b'am%d' % os.getpid()]
    fh, sid = c.create_confirm(b'o', path, access=OPEN4_SHARE_ACCESS_BOTH,
                               deny=OPEN4_SHARE_DENY_NONE)
    A = ACE4_ACCESS_ALLOWED_ACE_TYPE
    base = [nfsace4(A, 0, ACE4_READ_DATA | ACE4_WRITE_DATA | ACE4_READ_ACL | ACE4_WRITE_ACL |
                    ACE4_READ_ATTRIBUTES | ACE4_WRITE_ATTRIBUTES, b'OWNER@'),
            nfsace4(A, 0, ACE4_READ_ATTRIBUTES, b'GROUP@')]
    # s6.2.1.3.1: EXECUTE does not bring READ_DATA with it.
    acl = base + [nfsace4(A, 0, ACE4_EXECUTE | ACE4_READ_ATTRIBUTES, b'EVERYONE@')]
    r = c.compound([op.putfh(fh), op.setattr(sid, {FATTR4_ACL: acl})])
    want('SETATTR acl', r.status, NFS4_OK)
    got = c.do_getattr(FATTR4_ACL, path)
    e = [x for x in got if x.who == b'EVERYONE@' and x.type == A]
    print(got)
    want('EXECUTE alone stays alone', bool(e) and all(not x.access_mask & ACE4_READ_DATA for x in e), True)
    # s6.2.1.4.1: the group flag on a special who is ignored.
    acl = base + [nfsace4(A, ACE4_IDENTIFIER_GROUP, ACE4_READ_ATTRIBUTES, b'EVERYONE@')]
    r = c.compound([op.putfh(fh), op.setattr(sid, {FATTR4_ACL: acl})])
    want('group flag on EVERYONE@', r.status, NFS4_OK)
    got = c.do_getattr(FATTR4_ACL, path)
    want('not kept, s6.2.1.5', any(x.who == b'EVERYONE@' and x.flag & ACE4_IDENTIFIER_GROUP for x in got), False)
    # s6.4.1.3: mode, then ACL.
    r = c.compound([op.putfh(fh), op.setattr(sid, {FATTR4_MODE: 0o600, FATTR4_ACL: base})])
    want('mode and acl together', r.status, NFS4_OK)
    got = c.do_getattr(FATTR4_ACL, path)
    want('the ACL as given is what stands', any(x.who == b'OWNER@' and x.access_mask & ACE4_WRITE_DATA for x in got), True)
    # s6.4.2, s6.4.1.2: mode follows from the ACL.
    m = c.do_getattr(FATTR4_MODE, path)
    want('mode from the ACL', m & 0o777, 0o600)
    r = c.compound([op.putfh(fh), op.setattr(sid, {FATTR4_MODE: 0o640})])
    want('SETATTR mode', r.status, NFS4_OK)
    want('mode reads back, s6.4.1.1', c.do_getattr(FATTR4_MODE, path) & 0o777, 0o640)
    # s6.4.3: a create with a mode under an inheritable ACE.
    d = export + [b'ad%d' % os.getpid()]
    r = c.create_obj(d)
    want('mkdir', r.status, NFS4_OK)
    dr = c.compound(c.use_obj(d) + [op.setattr(b'\0' * 0 and None or c.stateid0 if hasattr(c, 'stateid0') else nfs4lib.stateid4(0, b'\0' * 12),
        {FATTR4_ACL: base + [nfsace4(A, ACE4_FILE_INHERIT_ACE, ACE4_READ_DATA, b'EVERYONE@')]})])
    want('inheritable ACE', dr.status, NFS4_OK)
    r = c.create_file(b'o2', d + [b'f'], attrs={FATTR4_MODE: 0o640}, access=OPEN4_SHARE_ACCESS_BOTH,
                      deny=OPEN4_SHARE_DENY_NONE)
    want('create under it', r.status, NFS4_OK)
    want('mode wins, s6.4.3', c.do_getattr(FATTR4_MODE, d + [b'f']) & 0o777, 0o640)
    # s6.4.3.1: a directory gets a file-inherit ACE as inherit-only.
    dr = c.create_obj(d + [b'sub'])
    want('mkdir under it', dr.status, NFS4_OK)
    got = c.do_getattr(FATTR4_ACL, d + [b'sub'])
    print(got)
    x = [a for a in got if a.flag & ACE4_FILE_INHERIT_ACE]
    want('inherit-only on a directory', bool(x) and all(a.flag & ACE4_INHERIT_ONLY_ACE for a in x), True)
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
    def get():
        r = c.compound(c.use_obj(path) + [op.getattr(nfs4lib.list2bitmap([FATTR4_SIZE, FATTR4_CHANGE]))])
        while r.status == NFS4ERR_DELAY:
            time.sleep(1)
            r = c.compound(c.use_obj(path) + [op.getattr(nfs4lib.list2bitmap([FATTR4_SIZE, FATTR4_CHANGE]))])
        want('GETATTR', r.status, NFS4_OK)
        return r.resarray[-1].switch.switch.obj_attributes
    a = get()
    want('size the holder has', a[FATTR4_SIZE], size)
    b = get()
    print(a, b)
    want('change goes on, s10.4.3', b[FATTR4_CHANGE] > a[FATTR4_CHANGE], True)
print('failures: %d' % fails)
sys.exit(1 if fails else 0)
