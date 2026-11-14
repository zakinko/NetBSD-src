#!/usr/bin/env python3
"""READ_PLUS of zeros that are stored, RFC 7862 s15.10.3: "If data to be
returned is comprised entirely of zeros, then the server SHOULD return
that data as a hole instead."  By default; vfs.nfsv4.read_plus_zero_data
sends them as data.  Run from pynfs's nfs4.1 directory: rp42.py EXPORT.
The sysctl is set with ssh, as in t41b.py.  Failures are the
measurement."""
import subprocess, sys, time, traceback
import nfs_ops, nfs4client
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
from server41tests.environment import create_file, check
op = nfs_ops.NFS4ops()
fails = 0
def t(name, got, want):
    global fails
    ok = got == want
    print("%s %s: got %s, want %s" % ("ok  " if ok else "FAIL", name, got, want))
    sys.stdout.flush()
    if not ok:
        fails += 1
sc = lambda v: subprocess.call(["ssh", "netbsd", "sudo sysctl -w %s || sysctl -w %s" % (v, v)])

export = sys.argv[1].strip('/').encode().split(b'/')
stamp = b"%d" % int(time.time())
c = nfs4client.NFS4Client(b'127.0.0.1', 2049, 2)
c.homedir = export
try:
    s = c.new_client_session(stamp + b"rp")
    res = create_file(s, stamp + b"z", path=export + [stamp + b"z"])
    check(res)
    fh, sid = res.resarray[-1].object, res.resarray[-2].stateid
    # 8192 zeros written, so stored, then data after them.
    for off, data in ((0, b"\0" * 4096), (4096, b"\0" * 4096), (8192, b"tail")):
        check(s.compound([op.putfh(fh), op.write(sid, off, FILE_SYNC4, data)]))
    def kinds(off, n):
        res = s.compound([op.putfh(fh), op.read_plus(sid, off, n)])
        if res.status != NFS4_OK:
            return res.status
        out = []
        for x in res.resarray[-1].rpr_contents:
            if x.rpc_content == NFS4_CONTENT_DATA:
                out.append(("data", x.rpc_data.d_offset, len(x.rpc_data.d_data)))
            else:
                out.append(("hole", x.rpc_hole.di_offset, x.rpc_hole.di_length))
        return out
    t("s15.10.3 zeros stored, as a hole", kinds(0, 4096), [("hole", 0, 4096)])
    t("s15.10.3 the data after them stays data", kinds(8192, 4096), [("data", 8192, 4)])
    t("s15.10.3 zeros and data, data", kinds(4096, 8192)[0][0] if isinstance(kinds(4096, 8192), list) else None,
      "data")
    sc("vfs.nfsv4.read_plus_zero_data=1")
    t("read_plus_zero_data: zeros stored, as data", kinds(0, 4096), [("data", 0, 4096)])
    sc("vfs.nfsv4.read_plus_zero_data=0")
    t("read_plus_zero_data off again: a hole", kinds(0, 4096), [("hole", 0, 4096)])
    s.compound([op.putfh(fh), op.close(0, sid)])
except Exception:
    traceback.print_exc()
    t("exception", "exception", "none")
print("failures:", fails)
sys.exit(0)
