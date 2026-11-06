#!/usr/bin/env python3
"""name@domain, RFC 7530 s5.9 and s12.6.  From pynfs's nfs4.0 directory:
owner.py EXPORT, with the table loaded: u 1234 alice, g 5678 staff, domain
example.org.  Exit status 1 means something went wrong.
"""
import os, sys
sys.path.insert(0, os.getcwd())
import use_local
sys.path.insert(0, os.path.join(os.getcwd(), 'lib'))
import nfs4lib, nfs_ops, rpc.rpc as rpc
from xdrdef.nfs4_const import *
op = nfs_ops.NFS4ops()
nfs4lib.SHOW_TRAFFIC = 0

export = sys.argv[1].strip('/').encode().split(b'/')
fails = 0
root = rpc.SecAuthSys(0, b'x', 0, 0, [])
c = nfs4lib.NFS4Client(b'owner%d' % os.getpid(), host=b'127.0.0.1', port=2049,
                       homedir=export, sec_list=[root])
c.init_connection()
path = export + [b'own%d' % os.getpid()]
fh, sid = c.create_confirm(b'o', path, access=OPEN4_SHARE_ACCESS_BOTH,
                           deny=OPEN4_SHARE_DENY_NONE)

def setattr_(name, attr, val, want):
    global fails
    r = c.compound([op.putfh(fh), op.setattr(sid, {attr: val})])
    ok = r.status == want
    print('%s SETATTR %s: %s, wanted %s' % ('ok    ' if ok else 'FAILED', name, r.status, want))
    fails += not ok

def get(attr, want):
    global fails
    v = c.do_getattr(attr, path)
    ok = v == want
    print('%s GETATTR: %r, wanted %r' % ('ok    ' if ok else 'FAILED', v, want))
    fails += not ok

setattr_('alice@example.org', FATTR4_OWNER, b'alice@example.org', NFS4_OK)
get(FATTR4_OWNER, b'alice@example.org')
setattr_('staff group', FATTR4_OWNER_GROUP, b'staff@EXAMPLE.org', NFS4_OK)
get(FATTR4_OWNER_GROUP, b'staff@example.org')
setattr_('number', FATTR4_OWNER, b'1234', NFS4_OK)
get(FATTR4_OWNER, b'alice@example.org')
setattr_('unmapped number', FATTR4_OWNER, b'4321', NFS4_OK)
get(FATTR4_OWNER, b'4321')
setattr_('unknown name', FATTR4_OWNER, b'bob@example.org', NFS4ERR_BADOWNER)
setattr_('other domain', FATTR4_OWNER, b'alice@example.com', NFS4ERR_BADOWNER)
setattr_('bad label', FATTR4_OWNER, b'alice@-bad.org', NFS4ERR_INVAL)
setattr_('bad UTF-8', FATTR4_OWNER, b'alice@\xc0\xaf.org', NFS4ERR_INVAL)
# bücher.example = xn--bcher-kva.example, s12.6 by RFC 3492
setattr_('bad Punycode', FATTR4_OWNER, b'alice@xn--a-.org', NFS4ERR_INVAL)
print('failures: %d' % fails)
sys.exit(1 if fails else 0)
