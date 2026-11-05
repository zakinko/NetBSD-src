#!/usr/bin/env python3
"""Named attributes and fs_locations, which pynfs's 4.0 suite does not
touch.  Run from pynfs's nfs4.0 directory: named-attr.py EXPORT [SERVERCMD]

Prints a line for each step and FAILED for each that went wrong.  Exit
status 1 means the machinery itself did not work.
"""
import os, sys, subprocess
sys.path.insert(0, os.getcwd())
import use_local
import nfs4lib, nfs_ops
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
op = nfs_ops.NFS4ops()

export = sys.argv[1].strip('/').encode().split(b'/')
fails = 0

def want(name, got, *ok):
    global fails
    if got in ok:
        print('ok   %s: %s' % (name, got))
    else:
        print('FAILED %s: %s, wanted %s' % (name, got, ok))
        fails += 1

c = nfs4lib.NFS4Client(b'namedattr%d' % os.getpid(), host=b'127.0.0.1',
                       port=2049, homedir=export)
c.init_connection()
path = export + [b'na%d' % os.getpid()]
fh, sid = c.create_confirm(b'naowner', path, access=OPEN4_SHARE_ACCESS_BOTH,
                           deny=OPEN4_SHARE_DENY_NONE)

r = c.compound([op.putfh(fh), op.openattr(False)])
want('OPENATTR(FALSE) with none', r.status, NFS4ERR_NOENT, NFS4ERR_NOTSUPP)
if r.status == NFS4ERR_NOTSUPP:
    print('not supported here')
    sys.exit(0)

r = c.compound([op.putfh(fh), op.openattr(True), op.getfh()])
want('OPENATTR(TRUE)', r.status, NFS4_OK)
adir = r.resarray[-1].switch.switch.object

r = c.compound([op.putfh(adir), op.openattr(True)])
want('OPENATTR on the directory, s5.3', r.status, NFS4ERR_INVAL)
r = c.compound([op.putfh(adir), op.create(createtype4(NF4DIR), b'd', {})])
want('CREATE there, s5.3', r.status, NFS4ERR_INVAL)
r = c.compound([op.putfh(adir), op.getattr(nfs4lib.list2bitmap([FATTR4_TYPE]))])
want('GETATTR(type)', r.status, NFS4_OK)

r = c.compound([op.putfh(adir),
                c.open(b'naowner2', b'one', OPEN4_CREATE, GUARDED4, {}, None,
                       OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_DENY_NONE),
                op.getfh()])
want('OPEN GUARDED4 create', r.status, NFS4_OK)
res = r.resarray[-2].switch.switch
afh = r.resarray[-1].switch.switch.object
c.advance_seqid(b'naowner2', r)
stateid = res.stateid
if res.rflags & OPEN4_RESULT_CONFIRM:
    seq = c.get_seqid(b'naowner2')
    r = c.compound([op.putfh(afh), op.open_confirm(stateid, seq)])
    want('OPEN_CONFIRM', r.status, NFS4_OK)
    c.advance_seqid(b'naowner2', r)
    stateid = r.resarray[-1].switch.switch.open_stateid

r = c.compound([op.putfh(afh), op.write(stateid, 0, FILE_SYNC4, b'hello ')])
want('WRITE', r.status, NFS4_OK)
r = c.compound([op.putfh(afh), op.write(stateid, 6, FILE_SYNC4, b'world')])
want('WRITE at an offset', r.status, NFS4_OK)
r = c.compound([op.putfh(afh), op.read(stateid, 0, 100)])
want('READ', r.status, NFS4_OK)
d = r.resarray[-1].switch.switch
if d.data != b'hello world' or not d.eof:
    print('FAILED read back %r eof %s' % (d.data, d.eof))
    fails += 1
r = c.compound([op.putfh(afh), op.read(stateid, 6, 3)])
d = r.resarray[-1].switch.switch
if d.data != b'wor' or d.eof:
    print('FAILED partial read %r eof %s' % (d.data, d.eof))
    fails += 1
r = c.compound([op.putfh(fh), op.read(stateid, 0, 10)])
want("the attribute's stateid on the file", r.status, NFS4ERR_BAD_STATEID)

if len(sys.argv) > 2:
    p = b'/' + b'/'.join(path)
    out = subprocess.run(sys.argv[2:] + [p.decode()], capture_output=True,
                         text=True).stdout
    print('server says: %r' % out)
    if 'hello world' not in out:
        print('FAILED the server has no such extended attribute')
        fails += 1

r = c.compound([op.putfh(adir),
                op.readdir(0, b'', 4096, 4096, nfs4lib.list2bitmap([FATTR4_TYPE]))])
want('READDIR', r.status, NFS4_OK)
names = []
e = r.resarray[-1].switch.switch.reply.entries
for x in e:
    names.append(x.name)
print('names', names)
if b'one' not in names:
    print('FAILED one is not listed')
    fails += 1

r = c.compound([op.putfh(adir), op.lookup(b'one'), op.getfh()])
want('LOOKUP', r.status, NFS4_OK)
r = c.compound([op.putfh(adir), op.lookup(b'nonesuch')])
want('LOOKUP of none', r.status, NFS4ERR_NOENT)
r = c.compound([op.putfh(afh), op.lookupp(), op.lookupp(), op.getfh()])
want('LOOKUPP twice, to the file', r.status, NFS4_OK)
if r.status == NFS4_OK and r.resarray[-1].switch.switch.object != fh:
    print('FAILED LOOKUPP came to some other handle')
    fails += 1
r = c.compound([op.putfh(afh), op.close(c.get_seqid(b'naowner2'), stateid)])
want('CLOSE', r.status, NFS4_OK)
c.advance_seqid(b'naowner2', r)
r = c.compound([op.putfh(adir), op.savefh(), op.putfh(adir), op.rename(b'one', b'two')])
want('RENAME', r.status, NFS4_OK)
r = c.compound([op.putfh(adir), op.remove(b'two')])
want('REMOVE', r.status, NFS4_OK)
r = c.compound([op.putfh(adir), op.remove(b'two')])
want('REMOVE again', r.status, NFS4ERR_NOENT)

r = c.compound([op.putfh(fh), op.getattr(nfs4lib.list2bitmap([FATTR4_FS_LOCATIONS]))])
want('GETATTR(fs_locations)', r.status, NFS4_OK)
print('fs_locations:', r.resarray[-1].switch.switch.obj_attributes)

print('failures: %d' % fails)
sys.exit(1 if fails else 0)
