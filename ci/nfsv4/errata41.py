#!/usr/bin/env python3
"""Errata of RFC 5661 that RFC 8881 did not take in.  Run from
pynfs's nfs4.1 directory: errata41.py PNFS_EXPORT ACL_EXPORT.

3065-3068: LAYOUTCOMMIT's loca_offset and loca_length are to be
ignored, and a client may send 0 for both.  With
vfs.nfsv4.layoutcommit_range they are checked as s18.42.3 has it.

4492: OPENATTR on an object that cannot have named attributes, in a
file system that has them, is NFS4ERR_WRONG_TYPE, not NFS4ERR_NOTSUPP.

4712: RENAME is allowed where the file grants ACE4_DELETE and its
directory does not grant ACE4_DELETE_CHILD, as REMOVE is (RFC 8881,
6.2.1.3.2).  The objects are made as uid 0 and renamed or removed as
AUTH_SYS uid 1111 gid 37, who owns none of them; the answers wanted
are FreeBSD's on UFS and ZFS, measured 2026-11-13.

Failures are the measurement."""
import subprocess, sys, time, traceback
import nfs_ops, nfs4client, nfs4lib
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
from server41tests.environment import create_file, check, use_obj
from rpc.security import AuthSys
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

    # errata 4712
    root = AuthSys().init_cred(uid=0, gid=0, name=b"errata41")
    user = AuthSys().init_cred(uid=1111, gid=37, name=b"errata41")
    c.set_cred(root)
    s3 = c.new_client_session(stamp + b"e4712")
    anon = stateid4(0, b'\0' * 12)
    R = (ACE4_READ_DATA | ACE4_EXECUTE | ACE4_READ_ATTRIBUTES |
         ACE4_READ_ACL | ACE4_READ_NAMED_ATTRS | ACE4_SYNCHRONIZE)
    W = ACE4_ADD_FILE | ACE4_ADD_SUBDIRECTORY
    A, D = ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_ACCESS_DENIED_ACE_TYPE
    own = nfsace4(A, 0, 0x1f01ff, b"OWNER@")
    def ev(t, m):
        return nfsace4(t, 0, m, b"EVERYONE@")
    ACLS = {
        "nodc-nowrite": [own, ev(D, W | ACE4_DELETE_CHILD), ev(A, R)],
        "nodc-write": [own, ev(D, ACE4_DELETE_CHILD), ev(A, R | W)],
        "nodc-absent-write": [own, ev(A, R | W)],
        "nodc-absent-nowrite": [own, ev(A, R)],
        "full": [own, ev(A, R | W | ACE4_DELETE_CHILD)],
        "del": [own, ev(A, R | ACE4_DELETE)],
        "nodel": [own, ev(D, ACE4_DELETE), ev(A, R)],
        "plain": [own, ev(A, R)],
    }
    res = s3.compound(use_obj(aexp) + [op.create(createtype4(NF4DIR),
        stamp + b"e4712", {FATTR4_MODE: 0o777}), op.getfh()])
    check(res)
    top = res.resarray[-1].object
    def mk(parent, n, kind, dir):
        if dir:
            res = s3.compound([op.putfh(parent), op.create(
                createtype4(NF4DIR), n, {FATTR4_MODE: 0o755}), op.getfh()])
            check(res)
            fh = res.resarray[-1].object
        else:
            res = s3.compound([op.putfh(parent), op.open(0,
                OPEN4_SHARE_ACCESS_WRITE | OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
                OPEN4_SHARE_DENY_NONE,
                open_owner4(s3.client.clientid, stamp + n),
                openflag4(OPEN4_CREATE, createhow4(GUARDED4,
                    {FATTR4_MODE: 0o644})),
                open_claim4(CLAIM_NULL, n)), op.getfh()])
            check(res)
            fh = res.resarray[-1].object
            s3.compound([op.putfh(fh),
                op.close(0, res.resarray[-2].stateid)])
        if kind:
            check(s3.compound([op.putfh(fh),
                op.setattr(anon, {FATTR4_ACL: ACLS[kind]})]))
        return fh
    def rename(case, sdir, file, tdir, want):
        d = mk(top, b"rename " + case.encode(), None, True)
        sd = mk(d, b"src", sdir, True)
        td = mk(d, b"tgt", tdir, True) if tdir else sd
        mk(sd, b"f", file, False)
        res = s3.compound([op.putfh(sd), op.savefh(), op.putfh(td),
            op.rename(b"f", b"g")], credinfo=user)
        t("errata 4712: RENAME, %s" % case, res.status, want)
    def remove(case, dir, file, want):
        d = mk(top, b"remove " + case.encode(), None, True)
        sd = mk(d, b"src", dir, True)
        mk(sd, b"f", file, False)
        res = s3.compound([op.putfh(sd), op.remove(b"f")], credinfo=user)
        t("errata 4712: REMOVE, %s" % case, res.status, want)
    # The file grants DELETE; the directory denies DELETE_CHILD, or
    # neither grants nor denies it.
    rename("dir denies DELETE_CHILD and write, to another dir",
           "nodc-nowrite", "del", "full", NFS4_OK)
    rename("dir denies DELETE_CHILD, same dir", "nodc-write", "del", None,
           NFS4_OK)
    rename("dir silent on DELETE_CHILD, same dir", "nodc-absent-write",
           "del", None, NFS4_OK)
    rename("dir silent on DELETE_CHILD, no write, to another dir",
           "nodc-absent-nowrite", "del", "full", NFS4_OK)
    remove("dir denies DELETE_CHILD and write", "nodc-nowrite", "del",
           NFS4_OK)
    remove("dir denies DELETE_CHILD", "nodc-write", "del", NFS4_OK)
    remove("dir silent on DELETE_CHILD, no write", "nodc-absent-nowrite",
           "del", NFS4_OK)
    # The directory grants DELETE_CHILD, which the file's denial of
    # DELETE does not override.
    rename("dir grants DELETE_CHILD, file denies DELETE", "full", "nodel",
           None, NFS4_OK)
    remove("dir grants DELETE_CHILD, file denies DELETE", "full", "nodel",
           NFS4_OK)
    # Neither grants: refused.  Both: allowed.
    rename("neither grants", "nodc-write", "plain", None,
           [NFS4ERR_PERM, NFS4ERR_ACCESS])
    remove("neither grants", "nodc-write", "plain",
           [NFS4ERR_PERM, NFS4ERR_ACCESS])
    rename("dir grants DELETE_CHILD", "full", "plain", None, NFS4_OK)
    remove("dir grants DELETE_CHILD", "full", "plain", NFS4_OK)

    # RFC 8881 s20.2.3: CB_RECALL carries the stateid of the delegation
    # as it was given; s8.2.2's seqid 0 is for what a client sends.
    recalled = []
    def op_cb_recall(self, arg, env):
        recalled.append(arg)
        return nfs4client.encode_status(NFS4_OK)
    nfs4client.NFS4Client.op_cb_recall = op_cb_recall
    c.homedir = pexp
    sa = c.new_client_session(stamp + b"rca")
    time.sleep(2)		# the probe of the backchannel
    res = create_file(sa, stamp + b"rc", path=pexp + [stamp + b"rc"])
    check(res)
    rfh, rsid = res.resarray[-1].object, res.resarray[-2].stateid
    sa.compound([op.putfh(rfh), op.close(0, rsid)])
    res = sa.compound([op.putfh(rfh), op.want_delegation(
        OPEN4_SHARE_ACCESS_WANT_READ_DELEG, deleg_claim4(CLAIM_FH))])
    dsid = None
    if res.status == NFS4_OK and \
       res.resarray[-1].wdr_resok4.delegation_type == OPEN_DELEGATE_READ:
        dsid = res.resarray[-1].wdr_resok4.read.stateid
    t("a read delegation", dsid is not None, True)
    if dsid is not None:
        sb = c.new_client_session(stamp + b"rcb")
        sb.compound(use_obj(pexp) + [op.open(0, OPEN4_SHARE_ACCESS_WRITE,
            OPEN4_SHARE_DENY_NONE, open_owner4(0, b"rcb"),
            openflag4(OPEN4_NOCREATE), open_claim4(CLAIM_NULL,
            stamp + b"rc"))], handle_state_errors=False)
        for i in range(10):
            if recalled:
                break
            time.sleep(1)
        got = recalled[0].stateid if recalled else None
        print("delegation stateid seqid %d, CB_RECALL's %s" % (dsid.seqid,
              got.seqid if got is not None else None))
        t("s20.2.3 CB_RECALL's stateid is the delegation's",
          (got.seqid, got.other) if got is not None else None,
          [(dsid.seqid, dsid.other)])
        sa.compound([op.putfh(rfh), op.delegreturn(dsid)])
except Exception:
    traceback.print_exc()
    t("exception", "exception", "none")
print("failures:", fails)
sys.exit(0)
