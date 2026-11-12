#!/usr/bin/env python3
"""Two errata of RFC 5661 that RFC 8881 did not take in.  Run from
pynfs's nfs4.1 directory: errata41.py PNFS_EXPORT ACL_EXPORT.

3065-3068: LAYOUTCOMMIT's loca_offset and loca_length are to be
ignored, and a client may send 0 for both.  With
vfs.nfsv4.layoutcommit_range they are checked as s18.42.3 has it.

4492: OPENATTR on an object that cannot have named attributes, in a
file system that has them, is NFS4ERR_WRONG_TYPE, not NFS4ERR_NOTSUPP.

Failures are the measurement."""
import subprocess, sys, time, traceback
import nfs_ops, nfs4client, nfs4lib
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
from server41tests.environment import create_file, check, use_obj
op = nfs_ops.NFS4ops()
fails = 0
def t(name, got, want):
    global fails
    want = want if isinstance(want, (list, tuple)) else [want]
    ok = got in want
    print("%s %s: got %s, want %s" % ("ok  " if ok else "FAIL", name, got, want))
    sys.stdout.flush()
    if not ok:
        fails += 1

def vm(cmd):
    p = subprocess.run(["ssh", "-o", "LogLevel=ERROR", "netbsd", cmd],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.stdout.decode().strip()

ANY = 0xffffffffffffffff
pexp = sys.argv[1].strip('/').encode().split(b'/')
aexp = sys.argv[2].strip('/').encode().split(b'/')
stamp = b"%d" % int(time.time())
c = nfs4client.NFS4Client(b'127.0.0.1', 2049, 1)
try:
    # errata 3065-3068
    print(vm("sysctl -w 'vfs.nfsv4.pnfs_ds=tcp 127.0.0.1.8.1'"))
    c.homedir = pexp
    s = c.new_pnfs_client_session(stamp + b"lc")
    res = create_file(s, stamp + b"lc", path=pexp + [stamp + b"lc"])
    check(res)
    fh, osid = res.resarray[-1].object, res.resarray[-2].stateid
    res = s.compound([op.putfh(fh), op.layoutget(False,
        LAYOUT4_NFSV4_1_FILES, LAYOUTIOMODE4_RW, 0, ANY, 0, osid, 4096)])
    check(res)
    lsid = res.resarray[-1].logr_stateid
    def commit(last):
        return s.compound([op.putfh(fh), op.layoutcommit(0, 0, False, lsid,
            newoffset4(True, last), newtime4(False),
            layoutupdate4(LAYOUT4_NFSV4_1_FILES, b""))])
    res = commit(9999)
    t("errata 3065-3068: LAYOUTCOMMIT of offset 0, length 0", res.status,
      NFS4_OK)
    if res.status == NFS4_OK:
        ns = res.resarray[-1].locr_newsize
        t("errata 3065-3068: the size", (ns.ns_sizechanged, ns.ns_size),
          [(True, 10000)])
    print(vm("sysctl -w vfs.nfsv4.layoutcommit_range=1"))
    t("layoutcommit_range: the range is checked, s18.42.3",
      commit(19999).status, NFS4ERR_INVAL)
    print(vm("sysctl -w vfs.nfsv4.layoutcommit_range=0"))
    s.compound([op.putfh(fh), op.layoutreturn(False, LAYOUT4_NFSV4_1_FILES,
        LAYOUTIOMODE4_ANY, layoutreturn4(LAYOUTRETURN4_FILE,
        layoutreturn_file4(0, ANY, lsid, b"")))])
    s.compound([op.putfh(fh), op.close(0, osid)])
    print(vm("sysctl -w vfs.nfsv4.pnfs_ds="))

    # errata 4492: a device node on FFS with extended attributes, which
    # FFS will not give them (ffs_listextattr(): VCHR and VBLK).
    c.homedir = aexp
    s2 = c.new_client_session(stamp + b"oa")
    res = s2.compound(use_obj(aexp) + [op.create(createtype4(NF4CHR,
        devdata=specdata4(1, 1)), stamp + b"chr", {FATTR4_MODE: 0o644}),
        op.getfh()])
    t("CREATE of a device node", res.status, NFS4_OK)
    if res.status == NFS4_OK:
        cfh = res.resarray[-1].object
        res = s2.compound([op.putfh(cfh), op.openattr(False)])
        t("errata 4492: OPENATTR on a device node", res.status,
          NFS4ERR_WRONG_TYPE)
        res = s2.compound(use_obj(aexp) + [op.openattr(False)])
        t("OPENATTR on the directory still answers", res.status,
          [NFS4_OK, NFS4ERR_NOENT])
        s2.compound(use_obj(aexp) + [op.remove(stamp + b"chr")])
except Exception:
    traceback.print_exc()
    t("exception", "exception", "none")
print("failures:", fails)
sys.exit(0)
