#!/usr/bin/env python3
"""pNFS, the file layout with this server as its own data server, RFC
8881 s12, s13.  Run from pynfs's nfs4.1 directory: pnfs.py EXPORT.  It
turns pNFS on with vfs.nfsv4.pnfs_ds and off again at the end.
Failures are the measurement."""
import subprocess, sys, time, traceback
import nfs_ops, nfs4client, nfs4lib
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
from xdrdef.nfs4_pack import NFS4Unpacker
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

UADDR = "127.0.0.1.8.1"		# 2049, RFC 5665 s5.2.3.3
ANY = 0xffffffffffffffff
recalls = []
orig = nfs4client.NFS4Client.op_cb_layoutrecall
def spy(self, arg, env):
    recalls.append(arg)
    return orig(self, arg, env)
nfs4client.NFS4Client.op_cb_layoutrecall = spy

export = sys.argv[1].strip('/').encode().split(b'/')
stamp = b"%d" % int(time.time())
print(vm("sysctl -w 'vfs.nfsv4.pnfs_ds=tcp %s'" % UADDR))
c = nfs4client.NFS4Client(b'127.0.0.1', 2049, 1)
c.homedir = export
try:
    # s13.1, Table 8
    cl = c.new_client(stamp + b"mds", flags=EXCHGID4_FLAG_USE_PNFS_MDS)
    t("s13.1 roles asked MDS", cl.flags & EXCHGID4_FLAG_MASK_PNFS,
      EXCHGID4_FLAG_USE_PNFS_MDS | EXCHGID4_FLAG_USE_PNFS_DS)
    cl = c.new_client(stamp + b"non", flags=EXCHGID4_FLAG_USE_NON_PNFS)
    t("s13.1 roles asked NON_PNFS", cl.flags & EXCHGID4_FLAG_MASK_PNFS,
      EXCHGID4_FLAG_USE_NON_PNFS)
    s = c.new_pnfs_client_session(stamp + b"a")
    time.sleep(2)		# the probe of the backchannel

    # s5.12
    res = s.compound(use_obj(export) + [op.getattr(nfs4lib.list2bitmap(
        [FATTR4_FS_LAYOUT_TYPES, FATTR4_SUPPORTED_ATTRS]))])
    check(res)
    a = res.resarray[-1].obj_attributes
    t("s5.12.1 fs_layout_type", list(a.get(FATTR4_FS_LAYOUT_TYPES, [])),
      [[LAYOUT4_NFSV4_1_FILES]])
    sup = a[FATTR4_SUPPORTED_ATTRS]
    for n in (62, 63, 64, 65, 66):
        t("s5.12 supported %d" % n, n in nfs4lib.bitmap2list(sup), True)
    res = create_file(s, stamp + b"f", path=export + [stamp + b"f"])
    check(res)
    fh = res.resarray[-1].object
    osid = res.resarray[-2].stateid
    res = s.compound([op.putfh(fh), op.getattr(nfs4lib.list2bitmap(
        [FATTR4_LAYOUT_TYPES, FATTR4_LAYOUT_BLKSIZE,
         FATTR4_LAYOUT_ALIGNMENT]))])
    check(res)
    a = res.resarray[-1].obj_attributes
    t("s5.12.5 layout_type", list(a.get(FATTR4_LAYOUT_TYPES, [])),
      [[LAYOUT4_NFSV4_1_FILES]])
    t("s5.12.3 layout_blksize", a.get(FATTR4_LAYOUT_BLKSIZE), 131072)
    t("s5.12.2 layout_alignment", a.get(FATTR4_LAYOUT_ALIGNMENT), 131072)
    res = s.compound([op.putfh(fh), op.getattr(nfs4lib.list2bitmap(
        [FATTR4_LAYOUT_HINT]))])
    t("s5.12.4 layout_hint is W only, GETATTR", res.status, NFS4ERR_INVAL)
    hint = layouthint4(LAYOUT4_NFSV4_1_FILES, b"")
    res = s.compound([op.putfh(fh), op.setattr(osid,
        {FATTR4_LAYOUT_HINT: hint})])
    t("s5.12.4 layout_hint SETATTR", res.status, NFS4_OK)

    # s18.43
    def lget(sid, iomode=LAYOUTIOMODE4_RW, typ=LAYOUT4_NFSV4_1_FILES,
             off=0, length=ANY, minlen=0, maxcount=4096):
        return s.compound([op.putfh(fh), op.layoutget(False, typ, iomode,
            off, length, minlen, sid, maxcount)])
    t("s18.43.3 iomode ANY", lget(osid, LAYOUTIOMODE4_ANY).status,
      NFS4ERR_BADIOMODE)
    t("s18.43.3 type block", lget(osid, typ=LAYOUT4_BLOCK_VOLUME).status,
      NFS4ERR_UNKNOWN_LAYOUTTYPE)
    t("s18.43.3 length < minlength", lget(osid, length=10, minlen=20).status,
      NFS4ERR_INVAL)
    t("s18.43.3 offset + length past 2^64", lget(osid, off=10,
      length=ANY - 1).status, NFS4ERR_INVAL)
    t("s18.43.3 maxcount too small", lget(osid, maxcount=20).status,
      NFS4ERR_TOOSMALL)
    res = lget(osid)
    t("s18.43 LAYOUTGET", res.status, NFS4_OK)
    r = res.resarray[-1]
    lsid = r.logr_stateid
    t("s12.5.3 first seqid", lsid.seqid, 1)
    lo = r.logr_layout[0]
    t("s18.43.3 offset", lo.lo_offset, 0)
    t("s18.43.3 length", lo.lo_length, ANY)
    t("s18.43.3 iomode", lo.lo_iomode, LAYOUTIOMODE4_RW)
    t("s18.43.3 type", lo.lo_content.loc_type, LAYOUT4_NFSV4_1_FILES)
    fl = NFS4Unpacker(lo.lo_content.loc_body).unpack_nfsv4_1_file_layout4()
    t("s13.3 the fh of the file", fl.nfl_fh_list, [fh])
    t("s13.3 stripe unit", fl.nfl_util & NFL4_UFLG_STRIPE_UNIT_SIZE_MASK,
      131072)
    t("s13.3 sparse", fl.nfl_util & NFL4_UFLG_DENSE, 0)
    devid = fl.nfl_deviceid
    t("s18.43.3 open stateid once a layout is held", lget(osid).status,
      NFS4ERR_BAD_STATEID)
    res = lget(lsid, LAYOUTIOMODE4_READ)
    t("s18.43 LAYOUTGET with the layout stateid", res.status, NFS4_OK)
    lsid = res.resarray[-1].logr_stateid
    t("s12.5.3 seqid goes up", lsid.seqid, 2)
    bad = stateid4(lsid.seqid + 5, lsid.other)
    t("s12.5.5.2.1.4 seqid ahead", lget(bad).status, NFS4ERR_BAD_STATEID)
    old = stateid4(1, lsid.other)
    t("s12.5.5.2.1.4 seqid behind, in range", lget(old).status, NFS4_OK)
    lsid = stateid4(lsid.seqid + 1, lsid.other)

    # s18.40, s18.41
    res = s.compound([op.putfh(fh), op.getdevicelist(LAYOUT4_NFSV4_1_FILES,
        16, 0, b"\0" * 8)])
    t("s18.41 GETDEVICELIST", res.status, NFS4_OK)
    if res.status == NFS4_OK:
        t("s18.41 the one device", res.resarray[-1].gdlr_deviceid_list,
          [devid])
        t("s18.41 eof", res.resarray[-1].gdlr_eof, True)
    res = s.compound([op.getdeviceinfo(devid, LAYOUT4_NFSV4_1_FILES,
        4096, 0)])
    t("s18.40 GETDEVICEINFO", res.status, NFS4_OK)
    if res.status == NFS4_OK:
        da = NFS4Unpacker(res.resarray[-1].da_addr_body
                          ).unpack_nfsv4_1_file_layout_ds_addr4()
        t("s13.3 stripe indices", da.nflda_stripe_indices, [0])
        na = da.nflda_multipath_ds_list[0][0]
        t("s13.3 netid", na.na_r_netid, b"tcp")
        t("s13.3 uaddr", na.na_r_addr, UADDR.encode())
    res = s.compound([op.getdeviceinfo(devid, LAYOUT4_NFSV4_1_FILES, 0, 0)])
    t("s18.40.3 maxcount 0", res.status, NFS4_OK)
    if res.status == NFS4_OK:
        t("s18.40.3 maxcount 0, empty body",
          res.resarray[-1].da_addr_body, b"")
    res = s.compound([op.getdeviceinfo(devid, LAYOUT4_NFSV4_1_FILES, 12, 0)])
    t("s18.40.3 too small", res.status, NFS4ERR_TOOSMALL)
    res = s.compound([op.getdeviceinfo(b"x" * 16, LAYOUT4_NFSV4_1_FILES,
        4096, 0)])
    t("s18.40.3 unknown device", res.status, NFS4ERR_NOENT)

    # s13.9.1, the data server
    res = s.compound([op.putfh(fh), op.write(lsid, 0, FILE_SYNC4, b"x" * 10)])
    t("s13.9.1 WRITE with a layout stateid", res.status, NFS4ERR_BAD_STATEID)
    res = s.compound([op.putfh(fh), op.write(stateid4(0, osid.other), 0,
        FILE_SYNC4, b"x" * 10)])
    t("s13.9.1 WRITE with the open stateid, seqid 0", res.status, NFS4_OK)

    # s18.42
    res = s.compound([op.putfh(fh), op.layoutcommit(0, ANY, False, lsid,
        newoffset4(True, 9999), newtime4(False),
        layoutupdate4(LAYOUT4_NFSV4_1_FILES, b""))])
    t("s18.42 LAYOUTCOMMIT", res.status, NFS4_OK)
    if res.status == NFS4_OK:
        t("s12.5.4.2 new size", (res.resarray[-1].ns_sizechanged,
          getattr(res.resarray[-1], "ns_size", None)), (True, 10000))

    # s20.3, s12.5.5.2.1.3
    vm("sysctl -w vfs.nfsv4.layout_recall=1")
    for i in range(10):
        if recalls:
            break
        time.sleep(1)
    t("s20.3 CB_LAYOUTRECALL came", len(recalls) > 0, True)
    rsid = None
    if recalls:
        rc = recalls[0].clora_recall
        rsid = rc.lor_layout.lor_stateid
        t("s20.3 of the file", rc.lor_layout.lor_fh, fh)
        t("s12.5.3 recall seqid one past", rsid.seqid, lsid.seqid + 1)
        time.sleep(1)
        t("s12.5.5.2.1.3 LAYOUTGET after the answer", lget(rsid).status,
          NFS4ERR_RETURNCONFLICT)
        rsid_ = rsid
    else:
        rsid_ = lsid
    # s18.44
    res = s.compound([op.putfh(fh), op.layoutreturn(False,
        LAYOUT4_NFSV4_1_FILES, LAYOUTIOMODE4_ANY, layoutreturn4(
        LAYOUTRETURN4_FILE, layoutreturn_file4(0, ANY, rsid_, b"")))])
    t("s18.44 LAYOUTRETURN of all", res.status, NFS4_OK)
    if res.status == NFS4_OK:
        t("s18.44.3 no stateid left", res.resarray[-1].lrs_present, False)
    t("s12.5.3 returned stateid is no more", lget(rsid_).status,
      NFS4ERR_BAD_STATEID)
    res = lget(osid)
    t("s18.43 again with the open stateid", res.status, NFS4_OK)
    res = s.compound([op.putfh(fh), op.layoutreturn(False,
        LAYOUT4_NFSV4_1_FILES, LAYOUTIOMODE4_ANY,
        layoutreturn4(LAYOUTRETURN4_ALL))])
    t("s18.44 LAYOUTRETURN4_ALL", res.status, NFS4_OK)
    res = s.compound([op.putfh(fh), op.layoutreturn(True,
        LAYOUT4_NFSV4_1_FILES, LAYOUTIOMODE4_ANY,
        layoutreturn4(LAYOUTRETURN4_ALL))])
    t("s18.44.3 reclaim with ALL", res.status, NFS4ERR_INVAL)

    # s18.16.3
    res = s.compound(use_obj(export) + [op.open(0, OPEN4_SHARE_ACCESS_BOTH,
        OPEN4_SHARE_DENY_NONE, open_owner4(0, b"x"), openflag4(OPEN4_CREATE,
        createhow4(EXCLUSIVE4, createverf=b"12345678")),
        open_claim4(CLAIM_NULL, stamp + b"ex"))])
    t("s18.16.3 EXCLUSIVE4 under an MDS client ID", res.status,
      NFS4ERR_INVAL)
except Exception:
    traceback.print_exc()
    t("exception", "exception", "none")
finally:
    print(vm("sysctl -w vfs.nfsv4.pnfs_ds="))

# Off: a NON_PNFS server, s13.1.
try:
    cl = c.new_client(stamp + b"off", flags=EXCHGID4_FLAG_USE_PNFS_MDS)
    t("s13.1 off: NON_PNFS", cl.flags & EXCHGID4_FLAG_MASK_PNFS,
      EXCHGID4_FLAG_USE_NON_PNFS)
except Exception:
    traceback.print_exc()
    t("exception", "exception", "none")
print("failures:", fails)
sys.exit(0)
