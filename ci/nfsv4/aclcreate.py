#!/usr/bin/env python3
"""Inheritance on a create with neither mode nor ACL, RFC 8881 s6.4.3,
case 4, both ways of vfs.nfsv4.excl_inherit and vfs.nfsv4.create_mode_mask.
From pynfs's nfs4.0 directory: aclcreate.py EXPORT, on a file system with
NFSv4 ACLs.  Exit status 1 means something went wrong.
"""
import os, subprocess, sys
sys.path.insert(0, os.getcwd())
import use_local
sys.path.insert(0, os.path.join(os.getcwd(), 'lib'))
import nfs4lib, nfs_ops, rpc.rpc as rpc
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import nfsace4, stateid4
op = nfs_ops.NFS4ops()
nfs4lib.SHOW_TRAFFIC = 0

export = sys.argv[1].strip('/').encode().split(b'/')
fails = 0
def t(name, got, want):
    global fails
    ok = got == want
    print('%s %s: got %r, want %r' % ('ok    ' if ok else 'FAILED', name, got, want))
    fails += not ok
def sc(v):
    subprocess.call(['ssh', 'netbsd', 'sysctl -w ' + v])

root = rpc.SecAuthSys(0, b'x', 0, 0, [])
c = nfs4lib.NFS4Client(b'aclc%d' % os.getpid(), host=b'127.0.0.1', port=2049,
                       homedir=export, sec_list=[root])
c.init_connection()
pid = b'%d' % os.getpid()
d = export + [b'acld' + pid]
r = c.create_obj(d, attrs={FATTR4_MODE: 0o755})
t('CREATE the parent', r.status, NFS4_OK)
INH = ACE4_FILE_INHERIT_ACE | ACE4_DIRECTORY_INHERIT_ACE
RW = ACE4_READ_DATA | ACE4_WRITE_DATA | ACE4_READ_ACL
acl = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, INH, RW, b'1234'),
       nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, 0x1f01ff, b'OWNER@'),
       nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, ACE4_READ_ACL, b'EVERYONE@')]
r = c.compound(c.use_obj(d) + [op.setattr(stateid4(0, b'\0' * 12), {FATTR4_ACL: acl})])
t('SETATTR the inheritable ACL', r.status, NFS4_OK)

def the1234(path):
    """The ACE of 1234, its mask, or None; and the mode."""
    a = c.do_getattrdict(path, [FATTR4_ACL, FATTR4_MODE])
    m = [e.access_mask for e in a.get(FATTR4_ACL, []) if e.who == b'1234']
    return (m[0] if m else None), a.get(FATTR4_MODE)

def make(name, how):
    p = d + [name]
    if how == 'dir':
        r = c.create_obj(p, attrs={})
    else:
        r = c.create_file(name, p, attrs={}, mode=how, verifier=b'12345678')
    if r.status != NFS4_OK:
        t('create ' + name.decode(), r.status, NFS4_OK)
        return None, None
    return the1234(p)

n = [0]
def nm(s):
    n[0] += 1
    return b'%s%d' % (s, n[0])

sc('vfs.nfsv4.create_mode_mask=0')
sc('vfs.nfsv4.excl_inherit=0')
m, mode = make(nm(b'u'), UNCHECKED4)
t('s6.4.3 UNCHECKED4, inherited unchanged', m and m & RW, RW)
t('s6.4.3 no SUID, SGID or SVTX', mode is not None and mode & 0o7000, 0)
m, mode = make(nm(b'd'), 'dir')
t('s6.4.3 CREATE of a directory, inherited unchanged', m and m & RW, RW)
m, mode = make(nm(b'x'), EXCLUSIVE4)
t('s6.4.3 EXCLUSIVE4, nothing inherited', m, None)
t('s6.4.3 EXCLUSIVE4, all access denied: mode', mode, 0)

sc('vfs.nfsv4.create_mode_mask=1')
sc('vfs.nfsv4.excl_inherit=1')
m, mode = make(nm(b'u'), UNCHECKED4)
t('option: UNCHECKED4, masked by 0644', m is not None and m & ACE4_WRITE_DATA, 0)
m, mode = make(nm(b'x'), EXCLUSIVE4)
t('option: EXCLUSIVE4, inherited by the file system', m is not None, True)

sc('vfs.nfsv4.create_mode_mask=0')
sc('vfs.nfsv4.excl_inherit=0')
print('failures: %d' % fails)
sys.exit(1 if fails else 0)
