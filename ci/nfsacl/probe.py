#!/usr/bin/env python3
# NFSACL version 3 by hand, against the published XDR (illumos
# usr/src/head/rpcsvc/nfs_acl.x) and the Linux server's behaviour
# (fs/nfsd/nfs3acl.c, fs/nfs_common/nfsacl.c).  Every reply is decoded
# to its last byte, so that a word too many or too few is a failure.
# probe.py HOST MOUNTPORT
import hashlib
import os
import socket
import struct
import subprocess
import sys
import time

HOST = sys.argv[1]
MPORT = int(sys.argv[2])
PROG, NFS, MOUNT = 100227, 100003, 100005
# nfs_acl.x:45-51, 58-60, 83-86.
USER_OBJ, USER, GROUP_OBJ, GROUP, CLASS_OBJ, OTHER_OBJ = 1, 2, 4, 8, 0x10, 0x20
DEFAULT = 0x1000
NA_ACL, NA_ACLCNT, NA_DFACL, NA_DFACLCNT = 1, 2, 4, 8
# RFC 5531 s9: accept_stat.
SUCCESS, PROG_UNAVAIL, PROG_MISMATCH, PROC_UNAVAIL, GARBAGE_ARGS = 0, 1, 2, 3, 4
# RFC 1813 s2.6.
OK, PERM, ACCES, INVAL, STALE, BADHANDLE, NOTSUPP = 0, 1, 13, 22, 70, 10001, 10004

fails = 0
xid = int(time.time()) & 0xffffff


def check(what, cond, detail=''):
    global fails
    print('%s: %s %s' % ('ok' if cond else 'FAILED', what, detail))
    if not cond:
        fails += 1


def ssh(cmd):
    return subprocess.run(['ssh', 'netbsd', cmd], check=True,
                          capture_output=True, text=True).stdout


class R:
    """A cursor over a reply that must be read to the end."""
    def __init__(self, b):
        self.b, self.p = b, 0

    def u(self):
        v, = struct.unpack('>I', self.b[self.p:self.p + 4])
        self.p += 4
        return v

    def opaque(self, n):
        v = self.b[self.p:self.p + n]
        self.p += (n + 3) & ~3
        return v

    def done(self):
        return self.p == len(self.b)


def u32(*v):
    return b''.join(struct.pack('>I', x & 0xffffffff) for x in v)


def opq(b):
    return u32(len(b)) + b + b'\0' * ((4 - len(b) % 4) % 4)


def authsys(uid=0, gid=0):
    body = u32(0) + opq(b'probe') + u32(uid, gid, 0)
    return u32(1) + opq(body)


def call(port, prog, vers, proc, args=b'', cred=None):
    global xid
    xid += 1
    if cred is None:
        cred = authsys()
    msg = u32(xid, 0, 2, prog, vers, proc) + cred + u32(0, 0) + args
    s = socket.create_connection((HOST, port), timeout=30)
    s.sendall(u32(0x80000000 | len(msg)) + msg)
    data = b''
    while True:
        hdr = b''
        while len(hdr) < 4:
            c = s.recv(4 - len(hdr))
            if not c:
                raise IOError('closed')
            hdr += c
        n, = struct.unpack('>I', hdr)
        frag = b''
        while len(frag) < (n & 0x7fffffff):
            c = s.recv((n & 0x7fffffff) - len(frag))
            if not c:
                raise IOError('closed')
            frag += c
        data += frag
        if n & 0x80000000:
            break
    s.close()
    r = R(data)
    assert r.u() == xid and r.u() == 1        # REPLY
    assert r.u() == 0                         # MSG_ACCEPTED
    r.u(); r.opaque(r.u())                    # verifier
    return r.u(), r


def mnt(path):
    st, r = call(MPORT, MOUNT, 3, 1, opq(path.encode()))
    assert st == SUCCESS and r.u() == 0, path
    fh = r.opaque(r.u())
    return fh


def lookup(dfh, name):
    st, r = call(2049, NFS, 3, 3, opq(dfh) + opq(name.encode()))
    assert st == SUCCESS and r.u() == 0, name
    return r.opaque(r.u())


def post_op_attr(r):
    if r.u():
        return r.opaque(84)
    return None


def getacl(fh, mask, cred=None):
    st, r = call(2049, PROG, 3, 1, opq(fh) + u32(mask), cred)
    assert st == SUCCESS, st
    out = {'status': r.u()}
    out['attr'] = post_op_attr(r)
    if out['status'] == OK:
        out['mask'] = r.u()
        for k in ('acl', 'dfacl'):
            cnt = r.u()
            n = r.u()
            ents = [(r.u(), r.u(), r.u()) for _ in range(n)]
            out[k + 'cnt'], out[k] = cnt, ents
    out['end'] = r.done()
    return out


def ents(lst, flag=0):
    return u32(len(lst), len(lst)) + b''.join(
        u32(t | flag, i, p) for t, i, p in lst)


def setacl(fh, mask, acl, dfacl, raw=None):
    body = raw if raw is not None else \
        opq(fh) + u32(mask) + ents(acl) + ents(dfacl, DEFAULT)
    st, r = call(2049, PROG, 3, 2, body)
    if st != SUCCESS:
        return st, None, None
    status = r.u()
    attr = post_op_attr(r)
    return st, status, r.done()


def lines(path, d=''):
    out = ssh('getfacl -n -q %s %s' % (d, path))
    return [l for l in out.splitlines() if l.strip() and not l.startswith('#')]


def mode_uid_gid(attr):
    t, mode, nlink, uid, gid = struct.unpack('>5I', attr[:20])
    return mode, uid, gid


print('=== the program, its versions and procedures')
st, r = call(2049, PROG, 3, 0)
check('NULL v3 is SUCCESS with no results', st == SUCCESS and r.done())
st, r = call(2049, PROG, 3, 0, cred=u32(0, 0))
check('NULL v3 under AUTH_NONE', st == SUCCESS and r.done())
st, r = call(2049, PROG, 2, 0)
check('NULL v2 is SUCCESS with no results', st == SUCCESS and r.done())
for v in (1, 4):
    st, r = call(2049, PROG, v, 0)
    lo, hi = (r.u(), r.u()) if st == PROG_MISMATCH else (None, None)
    check('version %d is PROG_MISMATCH 2..3' % v,
          st == PROG_MISMATCH and (lo, hi) == (2, 3) and r.done(),
          '(%s %s %s)' % (st, lo, hi))
for v, p in ((3, 4), (3, 100), (2, 6)):
    st, r = call(2049, PROG, v, p)
    check('v%d procedure %d is PROC_UNAVAIL' % (v, p),
          st == PROC_UNAVAIL and r.done(), '(%s)' % st)
st, r = call(2049, 100099, 1, 0)
check('another program is PROG_UNAVAIL', st == PROG_UNAVAIL)

print('=== GETACL on FFS with POSIX.1e ACLs')
ssh('cd /export/pacl && rm -rf pf pm pd && touch pf pm && mkdir pd && '
    'chown 1:2 pf pm pd && chmod 640 pf pm && chmod 750 pd && '
    'setfacl -m u:2097:rw,g:3001:r,m::rw pf && '
    'setfacl -d -m u::rwx,g::rx,o::-,u:2098:rx,m::rx pd')
root = mnt('/export/pacl')
pf, pm, pd = lookup(root, 'pf'), lookup(root, 'pm'), lookup(root, 'pd')

g = getacl(pf, NA_ACL | NA_ACLCNT | NA_DFACL | NA_DFACLCNT)
check('status and the end of the reply', g['status'] == OK and g['end'], str(g['status']))
check('post_op_attr follows', g['attr'] is not None)
check('the mask is the call\'s', g['mask'] == 0xf)
want = {(USER_OBJ, 1, 6), (USER, 2097, 6), (GROUP_OBJ, 2, 4),
        (GROUP, 3001, 4), (CLASS_OBJ, 0, 6), (OTHER_OBJ, 0, 0)}
check('entries, with the owner and group in the _OBJ ids',
      g['aclcnt'] == 6 and set(g['acl']) == want, str(g['acl']))
check('no default ACL on a file', (g['dfaclcnt'], g['dfacl']) == (0, []))

g = getacl(pf, NA_ACLCNT)
check('ACLCNT alone: the count and an empty array',
      g['status'] == OK and g['aclcnt'] == 6 and g['acl'] == [] and
      g['dfaclcnt'] == 0 and g['end'], str(g))

g = getacl(pm, NA_ACL)
check('a file with no ACL: four entries, the mask of the group, in order',
      g['acl'] == [(USER_OBJ, 1, 6), (GROUP_OBJ, 2, 4), (CLASS_OBJ, 0, 4),
                   (OTHER_OBJ, 0, 0)] and g['end'], str(g['acl']))

g = getacl(pd, NA_ACL | NA_DFACL)
check('a directory: the default entries carry 0x1000',
      g['status'] == OK and g['dfaclcnt'] == 5 and
      all(t & DEFAULT for t, i, p in g['dfacl']) and
      set((t & ~DEFAULT, i, p) for t, i, p in g['dfacl']) ==
      {(USER_OBJ, 1, 7), (GROUP_OBJ, 2, 5), (USER, 2098, 5),
       (CLASS_OBJ, 0, 5), (OTHER_OBJ, 0, 0)}, str(g['dfacl']))
check('a directory: the access ACL of mode 750',
      g['acl'] == [(USER_OBJ, 1, 7), (GROUP_OBJ, 2, 5), (CLASS_OBJ, 0, 5),
                   (OTHER_OBJ, 0, 0)], str(g['acl']))

g = getacl(pf, 0x10)
check('a mask over the four is NFS3ERR_INVAL with attributes',
      g['status'] == INVAL and g['attr'] is not None and g['end'], str(g['status']))
g = getacl(b'\x01' * 32, NA_ACL)
check('a handle of no export', g['status'] in (STALE, BADHANDLE, ACCES) and
      g['end'], str(g['status']))
g = getacl(pf, NA_ACL, cred=u32(0, 0))
check('AUTH_NONE is NFS3ERR_ACCES', g['status'] == ACCES and g['end'], str(g['status']))
st, r = call(2049, PROG, 3, 1, u32(65) + b'\0' * 68 + u32(1))
check('a handle longer than 64 is GARBAGE_ARGS', st == GARBAGE_ARGS)

print('=== SETACL on FFS with POSIX.1e ACLs')
acl5 = [(USER_OBJ, 1, 6), (USER, 2097, 4), (GROUP_OBJ, 2, 4),
        (CLASS_OBJ, 0, 6), (OTHER_OBJ, 0, 0)]
st, status, end = setacl(pm, NA_ACL, acl5, [])
check('set five entries', status == OK and end, str(status))
g = getacl(pm, NA_ACL)
check('read back', set(g['acl']) == set(acl5), str(g['acl']))
check('the server agrees',
      'user:2097:r--' in ssh('getfacl -n /export/pacl/pm'))
check('the mode has the mask', ssh('ls -ln /export/pacl/pm').startswith('-rw-rw----'))

st, status, end = setacl(pm, NA_ACL, [(USER_OBJ, 99, 7), (GROUP_OBJ, 99, 5),
                                      (CLASS_OBJ, 99, 5), (OTHER_OBJ, 99, 1)], [])
check('a Solaris minimal ACL, mask equal to the group', status == OK, str(status))
check('stored as three entries', len(lines('/export/pacl/pm')) == 3,
      str(lines('/export/pacl/pm')))
g = getacl(pm, NA_ACL)
check('and sent as four', g['acl'] == [(USER_OBJ, 1, 7), (GROUP_OBJ, 2, 5),
                                       (CLASS_OBJ, 0, 5), (OTHER_OBJ, 0, 1)],
      str(g['acl']))

st, status, end = setacl(pm, NA_ACL, [(USER_OBJ, 0, 6), (USER, 2097, 4),
                                      (GROUP_OBJ, 0, 4), (OTHER_OBJ, 0, 0)], [])
check('a named entry and no mask is NFS3ERR_INVAL', status == INVAL, str(status))
st, status, end = setacl(pm, NA_ACL, [(USER_OBJ, 0, 6), (USER, 2097, 0x8),
                                      (GROUP_OBJ, 0, 4), (CLASS_OBJ, 0, 4),
                                      (OTHER_OBJ, 0, 0)], [])
check('ACL_USER with a bit over rwx is NFS3ERR_INVAL', status == INVAL, str(status))
st, status, end = setacl(pm, NA_ACL, [(USER_OBJ, 0, 6), (USER, 2097, 4),
                                      (GROUP_OBJ, 0, 4), (CLASS_OBJ, 0, 0xff),
                                      (OTHER_OBJ, 0, 0)], [])
check('extra bits of the mask are dropped, as Solaris sends them', status == OK,
      str(status))
st, status, end = setacl(pm, NA_ACL, [(USER_OBJ, 0, 8), (GROUP_OBJ, 0, 4),
                                      (OTHER_OBJ, 0, 0)], [])
check('USER_OBJ with a bit over rwx is GARBAGE_ARGS', st == GARBAGE_ARGS, str(st))
st, status, end = setacl(pm, NA_ACL, [(0x40, 0, 4)], [])
check('an unknown tag in a list asked for is GARBAGE_ARGS', st == GARBAGE_ARGS, str(st))
st, status, end = setacl(pm, 0, [(0x40, 0, 4)], [])
check('in a list not asked for it is skipped', status == OK, str((st, status)))
st, status, end = setacl(pm, NA_ACL, [(USER, 0xffffffff, 4)], [])
check('ACL_USER of id -1 is GARBAGE_ARGS', st == GARBAGE_ARGS, str(st))
st, status, end = setacl(pm, 0x10, [], [])
check('a mask over the four is GARBAGE_ARGS', st == GARBAGE_ARGS, str(st))
raw = opq(pm) + u32(NA_ACL, 1025, 1025) + u32(1, 0, 6) * 1025 + u32(0, 0)
st, status, end = setacl(pm, 0, [], [], raw=raw)
check('1025 entries is GARBAGE_ARGS', st == GARBAGE_ARGS, str(st))
raw = opq(pm) + u32(NA_ACL, 4, 3) + u32(1, 0, 6, 4, 0, 4, 0x20, 0, 0) + u32(0, 0)
st, status, end = setacl(pm, 0, [], [], raw=raw)
check('a count that is not the array\'s is GARBAGE_ARGS', st == GARBAGE_ARGS, str(st))
st, status, end = setacl(pm, NA_DFACL, [], [(USER_OBJ, 0, 7), (GROUP_OBJ, 0, 5),
                                            (OTHER_OBJ, 0, 0)])
check('a default ACL on a file is NFS3ERR_ACCES', status == ACCES, str(status))
st, status, end = setacl(pm, NA_DFACL, [], [])
check('removing the default ACL of a file is NFS3_OK', status == OK, str(status))
st, status, end = setacl(pm, NA_ACL, [], [])
check('an empty access ACL leaves the ACL of the mode', status == OK and
      len(lines('/export/pacl/pm')) == 3, str(status))

st, status, end = setacl(pd, NA_ACL | NA_DFACL,
                         [(USER_OBJ, 0, 7), (GROUP_OBJ, 0, 5), (OTHER_OBJ, 0, 0)],
                         [(USER_OBJ, 0, 7), (USER, 2097, 7), (GROUP_OBJ, 0, 5),
                          (CLASS_OBJ, 0, 7), (OTHER_OBJ, 0, 0)])
check('both lists of a directory', status == OK, str(status))
check('the server has the default', 'user:2097:rwx' in
      ssh('getfacl -n -d /export/pacl/pd'))
st, status, end = setacl(pd, NA_ACL | NA_DFACL,
                         [(USER_OBJ, 0, 7), (GROUP_OBJ, 0, 5), (OTHER_OBJ, 0, 0)], [])
check('an empty default removes it', status == OK and
      lines('/export/pacl/pd', '-d') == [], str(status))

ssh('chmod 640 /export/pacl/pm && chown 2098 /export/pacl/pm')
st, r = call(2049, PROG, 3, 2, opq(pm) + u32(NA_ACL) +
             ents([(USER_OBJ, 0, 7), (GROUP_OBJ, 0, 7), (OTHER_OBJ, 0, 7)]) +
             u32(0, 0), cred=authsys(2097, 2097))
st2 = r.u() if st == SUCCESS else None
check('not the owner: NFS3ERR_PERM or NFS3ERR_ACCES', st2 in (PERM, ACCES), str(st2))


def mnt2(path):
    # MOUNT version 1, RFC 1094 Appendix A: fhstatus, a 32-byte fhandle.
    st, r = call(MPORT, MOUNT, 1, 1, opq(path.encode()))
    assert st == SUCCESS and r.u() == 0, path
    return r.opaque(32)


def lookup2(dfh, name):
    # NFS version 2 LOOKUP, RFC 1094 s2.2.5: diropres.
    st, r = call(2049, NFS, 2, 4, dfh + opq(name.encode()))
    assert st == SUCCESS and r.u() == 0, name
    return r.opaque(32)


def v2(proc, args, cred=None):
    st, r = call(2049, PROG, 2, proc, args, cred)
    assert st == SUCCESS, st
    return r


def noposix(export, name):
    print('=== %s, no POSIX.1e ACLs' % export)
    ssh('cd %s && rm -rf %s && touch %s && chmod 754 %s' % (export, name, name, name))
    fh = lookup(mnt(export), name)
    g = getacl(fh, NA_ACL | NA_DFACL)
    mode, uid, gid = mode_uid_gid(g['attr'])
    check('GETACL makes the ACL of the mode', g['status'] == OK and g['end'] and
          g['acl'] == [(USER_OBJ, uid, 7), (GROUP_OBJ, gid, 5),
                       (CLASS_OBJ, 0, 5), (OTHER_OBJ, 0, 4)] and
          (g['dfaclcnt'], g['dfacl']) == (0, []), str(g))
    st, status, end = setacl(fh, NA_ACL, [(USER_OBJ, 0, 7), (GROUP_OBJ, 0, 5),
                                          (OTHER_OBJ, 0, 4)], [])
    check('SETACL is NFS3ERR_NOTSUPP', status == NOTSUPP and end, str(status))
    st, status, end = setacl(fh, 0, [], [])
    check('SETACL that asks for nothing is NFS3_OK', status == OK, str(status))
    ssh('rm -f %s/%s' % (export, name))


print('=== version 2')
ssh('cd /export/pacl && rm -rf pf pm pd && touch pf pm && mkdir pd && '
    'chown 1:2 pf pm pd && chmod 640 pf pm && chmod 750 pd && '
    'setfacl -m u:2097:rw,g:3001:r,m::rw pf')
root2 = mnt2('/export/pacl')
pf2, pm2, pd2 = lookup2(root2, 'pf'), lookup2(root2, 'pm'), lookup2(root2, 'pd')
r = v2(1, pf2 + u32(0xf))
st = r.u()
fa = r.opaque(68) if st == OK else None
if st == OK:
    mask = r.u()
    lists = []
    for _ in range(2):
        cnt, n = r.u(), r.u()
        lists.append((cnt, [(r.u(), r.u(), r.u()) for _ in range(n)]))
check('GETACL2: NFS_OK, fattr, the mask and the lists, to the end',
      st == OK and r.done() and mask == 0xf and
      set(lists[0][1]) == {(USER_OBJ, 1, 6), (USER, 2097, 6), (GROUP_OBJ, 2, 4),
                           (GROUP, 3001, 4), (CLASS_OBJ, 0, 6), (OTHER_OBJ, 0, 0)}
      and lists[1] == (0, []), str((st, lists if st == OK else None)))
check('GETACL2: the fattr is of a regular file, mode 0100640 with the mask',
      fa is not None and struct.unpack('>2I', fa[:8])[0] == 1, '')
r = v2(1, pf2 + u32(0x10))
st = r.u()
check('GETACL2: a mask over the four is NFSERR_IO, status alone', st == 5 and r.done(),
      str(st))
r = v2(1, b'\x01' * 32 + u32(1))
st = r.u()
check('GETACL2: a handle of no export', st in (STALE, ACCES) and r.done(), str(st))
r = v2(2, pm2 + u32(NA_ACL) + ents(acl5) + ents([], DEFAULT))
st = r.u()
ok2 = st == OK and len(r.opaque(68)) == 68 and r.done()
check('SETACL2: attrstat', ok2, str(st))
check('SETACL2: the server has it', 'user:2097:r--' in ssh('getfacl -n /export/pacl/pm'))
r = v2(3, pf2)
st = r.u()
check('GETATTR2: attrstat', st == OK and len(r.opaque(68)) == 68 and r.done(), str(st))
r = v2(4, pf2 + u32(0x3f))
st = r.u()
got = (r.opaque(68), r.u())[1] if st == OK else None
check('ACCESS2 of root on a file of 0640: READ MODIFY EXTEND',
      st == OK and got == 0x1 | 0x4 | 0x8 and r.done(), str((st, got)))
r = v2(4, pd2 + u32(0x3f))
st = r.u()
got = (r.opaque(68), r.u())[1] if st == OK else None
check('ACCESS2 of root on a directory: all six', st == OK and got == 0x3f, str((st, got)))
r = v2(4, pf2 + u32(0x3f), cred=authsys(2097, 2097))
st = r.u()
got = (r.opaque(68), r.u())[1] if st == OK else None
check('ACCESS2 of a named user with rw- in the ACL',
      st == OK and got == 0x1 | 0x4 | 0x8, str((st, got)))
r = v2(4, pf2 + u32(0x3f), cred=authsys(2098, 2098))
st = r.u()
got = (r.opaque(68), r.u())[1] if st == OK else None
check('ACCESS2 of another user: nothing', st == OK and got == 0, str((st, got)))
ssh('cd /export/tmpfs && rm -f n2 && touch n2')
t2 = lookup2(mnt2('/export/tmpfs'), 'n2')
r = v2(2, t2 + u32(NA_ACL) + ents([(USER_OBJ, 0, 6), (GROUP_OBJ, 0, 4),
                                   (OTHER_OBJ, 0, 4)]) + ents([], DEFAULT))
st = r.u()
check('SETACL2 on tmpfs is 45, illumos\' NFSERR_OPNOTSUPP', st == 45 and r.done(), str(st))
ssh('rm -f /export/tmpfs/n2')

noposix('/export/tmpfs', 'nf')
noposix('/export/acl', 'nf')
if ssh('test -d /tank/x && echo y || :').strip() == 'y':
    noposix('/tank/x', 'nf')
else:
    print('(no /tank/x)')
ssh('rm -rf /export/pacl/pf /export/pacl/pm /export/pacl/pd')


# Named attributes: GETXATTRDIR, then NFS itself on the handles it
# leads to (nfs_srvxattr.c), and handles made to be wrong.
def nfs3(proc, args, cred=None):
    st, r = call(2049, NFS, 3, proc, args, cred)
    # A reply with no status is a failure of its own, said as such; the
    # checks after it then see SERVERFAULT rather than a traceback.
    if st != SUCCESS or r.done():
        check('NFS3 procedure %d answered with a status' % proc, False,
              'accept_stat %d, %d bytes of result' % (st, len(r.b) - r.p))
        r = R(u32(10006))
    return st, r


def wcc(r):
    if r.u():
        r.opaque(24)
    post_op_attr(r)


def ftype_mode(attr):
    return struct.unpack('>2I', attr[:8])


SATTR3_NONE = u32(0, 0, 0, 0, 0, 0)

print('=== named attributes, version 3')
ssh('cd /export/pacl && rm -f xf xe && touch xf xe && chmod 640 xf && '
    'setextattr user a1 hello xf && lsextattr user xf')
root = mnt('/export/pacl')
xf, xe = lookup(root, 'xf'), lookup(root, 'xe')
st, r = call(2049, PROG, 3, 3, opq(xe) + u32(0))
s3 = r.u()
check('GETXATTRDIR3 of a file with none: NOENT, status alone',
      st == SUCCESS and s3 == 2 and r.done(), str((st, s3)))
st, r = call(2049, PROG, 3, 3, opq(xf) + u32(0))
s3 = r.u()
dfh = r.opaque(r.u()) if s3 == OK else b''
da = post_op_attr(r) if s3 == OK else None
check('GETXATTRDIR3: the handle and a directory of 01777, to the end',
      s3 == OK and r.done() and da is not None and
      ftype_mode(da) == (2, 0o1777) and len(dfh) % 4 == 0 and
      len(dfh) > len(xf), str((s3, len(dfh), da and ftype_mode(da))))
st, r = call(2049, PROG, 3, 3, opq(xe) + u32(1))
s3 = r.u()
check('GETXATTRDIR3 with create of a file with none', s3 == OK, str(s3))

st, r = nfs3(3, opq(dfh) + opq(b'a1'))
s3 = r.u()
afh = r.opaque(r.u()) if s3 == OK else b''
check('LOOKUP3 of a1', s3 == OK, str(s3))
st, r = nfs3(1, opq(afh))
s3 = r.u()
aa = r.opaque(84) if s3 == OK else None
check('GETATTR3 of a1: a regular file of 5 bytes',
      s3 == OK and r.done() and ftype_mode(aa)[0] == 1 and
      struct.unpack('>Q', aa[20:28])[0] == 5, str(s3))
st, r = nfs3(6, opq(afh) + u32(0, 0, 100))
s3 = r.u()
if s3 == OK:
    post_op_attr(r)
    cnt, eof, data = r.u(), r.u(), r.opaque(r.u())
check('READ3 of a1', s3 == OK and r.done() and data == b'hello' and eof == 1,
      str(s3))
st, r = nfs3(16, opq(dfh) + u32(0, 0, 0, 0, 4096))
s3 = r.u()
names = []
if s3 == OK:
    post_op_attr(r)
    r.opaque(8)
    while r.u():
        r.u(); r.u()
        names.append(r.opaque(r.u()).decode())
        r.u(); r.u()
    eof = r.u()
check('READDIR3: . .. a1', s3 == OK and r.done() and names == ['.', '..', 'a1'],
      str((s3, names)))
st, r = nfs3(8, opq(dfh) + opq(b'a2') + u32(1) + SATTR3_NONE)
s3 = r.u()
a2 = b''
if s3 == OK and r.u():
    a2 = r.opaque(r.u())
check('CREATE3 GUARDED of a2 gives its handle', s3 == OK and a2, str(s3))
st, r = nfs3(7, opq(a2) + u32(0, 0, 3, 2) + opq(b'xyz'))
s3 = r.u()
check('WRITE3 to a2', s3 == OK, str(s3))
check('the server has a2', ssh('getextattr -q user a2 /export/pacl/xf').strip()
      == 'xyz')
st, r = nfs3(8, opq(dfh) + opq(b'a2') + u32(1) + SATTR3_NONE)
s3 = r.u()
check('CREATE3 GUARDED of a2 again: EXIST', s3 == 17, str(s3))
st, r = nfs3(14, opq(dfh) + opq(b'a2') + opq(dfh) + opq(b'a3'))
s3 = r.u()
check('RENAME3 a2 to a3', s3 == OK and
      sorted(ssh('lsextattr -q user /export/pacl/xf').split()) == ['a1', 'a3'],
      str(s3))
st, r = nfs3(12, opq(dfh) + opq(b'a3'))
s3 = r.u()
check('REMOVE3 of a3', s3 == OK and
      ssh('lsextattr -q user /export/pacl/xf').split() == ['a1'], str(s3))

print('=== named attributes: handles that are wrong')
for proc, args, what in (
        (9, opq(dfh) + opq(b'd') + SATTR3_NONE, 'MKDIR3 in it'),
        (5, opq(afh), 'READLINK3 of an attribute'),
        (15, opq(afh) + opq(root) + opq(b'l'), 'LINK3 of an attribute'),
        (14, opq(dfh) + opq(b'a1') + opq(root) + opq(b'x'),
         'RENAME3 out of it'),
        (2, opq(afh) + u32(1, 0o777) + u32(0, 0, 0, 0, 0, 0),
         'SETATTR3 of the mode')):
    st, r = nfs3(proc, args)
    s3 = r.u() if st == SUCCESS else None
    check('%s is refused' % what, s3 not in (None, OK), str(s3))
check('the file\'s mode is untouched',
      ssh('stat -f %Lp /export/pacl/xf').strip() == '640')
for proc, args, what in (
        (15, opq(xe) + opq(dfh) + opq(b'l'), 'LINK3 into it'),
        (14, opq(root) + opq(b'xe') + opq(dfh) + opq(b'x'), 'RENAME3 into it')):
    st, r = nfs3(proc, args)
    s3 = r.u() if st == SUCCESS else None
    check('%s: STALE, not taken for the file' % what, s3 == STALE, str(s3))
check('nothing was linked or renamed',
      ssh('ls /export/pacl').split().count('xe') == 1 and
      'l' not in ssh('ls /export/pacl').split())
bad = afh[:-1] + bytes([afh[-1] ^ 1]) if afh[-1] != 0 else \
    afh[:len(xf) + 1] + bytes([afh[len(xf) + 1] ^ 1]) + afh[len(xf) + 2:]
st, r = nfs3(1, opq(bad))
s3 = r.u() if st == SUCCESS else None
check('a key changed: STALE', s3 == STALE, str(s3))
for n, what in ((63, '63 bytes'), (64, '64 bytes')):
    h = (dfh + b'\x07' * 64)[:n]
    st, r = nfs3(1, opq(h))
    s3 = r.u() if st == SUCCESS else None
    check('a handle of %s past the mark: STALE' % what, s3 in (STALE, BADHANDLE),
          str((st, s3)))
st, r = nfs3(1, opq(dfh + b'\x07' * (65 - len(dfh))))
check('65 bytes: GARBAGE_ARGS', st == GARBAGE_ARGS, str(st))
h = bytearray(dfh)
h[len(xf)] = 3
st, r = nfs3(1, opq(bytes(h)))
s3 = r.u() if st == SUCCESS else None
check('a mark of type 3: STALE', s3 == STALE, str(s3))
g = getacl(afh, NA_ACL)
check('GETACL3 of an attribute: the ACL of its mode, 0640, as illumos\' '
      'fs_fab_acl()', g['status'] == OK and g['end'] and
      g['attr'] is not None and ftype_mode(g['attr'])[0] == 1 and
      g['acl'] == [(USER_OBJ, mode_uid_gid(g['attr'])[1], 6),
                   (GROUP_OBJ, mode_uid_gid(g['attr'])[2], 4),
                   (CLASS_OBJ, 0, 4), (OTHER_OBJ, 0, 0)], str(g))
st, status, end = setacl(afh, NA_ACL, [(USER_OBJ, 0, 7), (GROUP_OBJ, 0, 4),
                                       (OTHER_OBJ, 0, 0)], [])
check('SETACL3 of an attribute: NOTSUPP', status == NOTSUPP and end, str(status))
st, r = call(2049, PROG, 3, 3, opq(afh) + u32(1))
s3 = r.u()
check('GETXATTRDIR3 of an attribute: INVAL', s3 == INVAL and r.done(), str(s3))
ssh('rmextattr user a1 /export/pacl/xf')
st, r = nfs3(1, opq(afh))
s3 = r.u() if st == SUCCESS else None
check('an attribute gone: STALE', s3 == STALE, str(s3))
for e in ('/export/tmpfs',):
    ssh('touch %s/xn' % e)
    fh = lookup(mnt(e), 'xn')
    st, r = call(2049, PROG, 3, 3, opq(fh) + u32(1))
    s3 = r.u()
    check('GETXATTRDIR3 where there are no extended attributes: NOTSUPP',
          s3 == NOTSUPP and r.done(), str(s3))
    ssh('rm -f %s/xn' % e)

print('=== named attributes, version 2')
ssh('setextattr user a1 hello /export/pacl/xf')
root2 = mnt2('/export/pacl')
xf2 = lookup2(root2, 'xf')
r = v2(5, xf2 + u32(0))
st = r.u()
d2 = r.opaque(32) if st == OK else b''
fa = r.opaque(68) if st == OK else None
check('GETXATTRDIR2: the handle, all ones at the end, and a directory',
      st == OK and r.done() and d2[28:] == b'\xff' * 4 and
      ftype_mode(fa)[0] == 2, str(st))


def nfs2(proc, args):
    st, r = call(2049, NFS, 2, proc, args)
    return r.u() if st == SUCCESS else None, r


s2, r = nfs2(4, d2 + opq(b'a1'))
a12 = r.opaque(32) if s2 == OK else b''
check('LOOKUP2 of a1', s2 == OK, str(s2))
s2, r = nfs2(6, a12 + u32(0, 100, 0))
data = (r.opaque(68), r.opaque(r.u()))[1] if s2 == OK else None
check('READ2 of a1', s2 == OK and r.done() and data == b'hello', str(s2))
SATTR2 = u32(0o100644, 0xffffffff, 0xffffffff, 0, 0xffffffff, 0xffffffff,
             0xffffffff, 0xffffffff)
s2, r = nfs2(9, d2 + opq(b'b1') + SATTR2)
b12 = r.opaque(32) if s2 == OK else b''
check('CREATE2 of b1', s2 == OK, str(s2))
s2, r = nfs2(8, b12 + u32(0, 0, 0) + opq(b'abc'))
check('WRITE2 to b1', s2 == OK and
      ssh('getextattr -q user b1 /export/pacl/xf').strip() == 'abc', str(s2))
s2, r = nfs2(1, xf2[:28] + b'\xff' * 4)
fa = r.opaque(68) if s2 == OK else None
check('GETATTR2 of the four bytes all ones: the directory',
      s2 == OK and ftype_mode(fa)[0] == 2, str(s2))


def key4(name):
    v, = struct.unpack('>I', hashlib.sha256(name.encode()).digest()[:4])
    return 1 if v == 0 else 0xfffffffe if v == 0xffffffff else v


seen, pair = {}, None
for i in range(1 << 20):
    n = 'c%d' % i
    k = key4(n)
    if k in seen:
        pair = (seen[k], n)
        break
    seen[k] = n
print('names of one 32-bit key: %s' % (pair,))
ssh('setextattr user %s one /export/pacl/xf' % pair[0])
s2, r = nfs2(9, d2 + opq(pair[1].encode()) + SATTR2)
check('CREATE2 of a name whose key another has: EXIST', s2 == 17, str(s2))
s2, r = nfs2(4, d2 + opq(pair[0].encode()))
h0 = r.opaque(32) if s2 == OK else b''
ssh('setextattr user %s two /export/pacl/xf' % pair[1])
s2, r = nfs2(1, h0)
check('two names of one key behind a handle: IO, not either', s2 == 5, str(s2))
ssh('rm -f /export/pacl/xf /export/pacl/xe')
print('failures: %d' % fails)
sys.exit(1 if fails else 0)
