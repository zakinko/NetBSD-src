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
# pynfs's own handler sends LAYOUTRETURN before it answers (run
# 43076329181); this one only answers, so that the conflicts of
# s12.5.5.2.1.3 can be seen before the return.  pynfs's encode_status
# takes the type of the reply from the caller's name, so each of these
# is named op_cb_<operation>; named otherwise they answered
# NFS4ERR_SERVERFAULT (run 43132086169).
def op_cb_layoutrecall(self, arg, env):
    recalls.append(arg)
    return nfs4client.encode_status(NFS4_OK)
nfs4client.NFS4Client.op_cb_layoutrecall = op_cb_layoutrecall
seqs = []
cb_sequence = nfs4client.NFS4Client.op_cb_sequence
def seqspy(self, arg, env):
    seqs.append(arg)
    return cb_sequence(self, arg, env)
nfs4client.NFS4Client.op_cb_sequence = seqspy
devnotes = []
def op_cb_notify_deviceid(self, arg, env):
    devnotes.append(arg)
    return nfs4client.encode_status(NFS4_OK)
nfs4client.NFS4Client.op_cb_notify_deviceid = op_cb_notify_deviceid
rcas = []
def op_cb_recall_any(self, arg, env):
    rcas.append(arg)
    return nfs4client.encode_status(NFS4_OK)
nfs4client.NFS4Client.op_cb_recall_any = op_cb_recall_any
avails = []
def op_cb_recallable_obj_avail(self, arg, env):
    avails.append(arg)
    return nfs4client.encode_status(NFS4_OK)
nfs4client.NFS4Client.op_cb_recallable_obj_avail = op_cb_recallable_obj_avail
def wait(l, n=10):
    for i in range(n):
        if l:
            return True
        time.sleep(1)
    return False

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
    t("s13.3 the fh of the file", fl.nfl_fh_list, [[fh]])
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
        0, 0, b"\0" * 8)])
    t("s18.41.3 maxdevices 0", res.status, NFS4ERR_INVAL)
    res = s.compound([op.putfh(fh), op.getdevicelist(LAYOUT4_NFSV4_1_FILES,
        16, 0, b"\0" * 8)])
    t("s18.41 GETDEVICELIST", res.status, NFS4_OK)
    if res.status == NFS4_OK:
        t("s18.41 the one device", res.resarray[-1].gdlr_deviceid_list,
          [[devid]])
        t("s18.41 eof", res.resarray[-1].gdlr_eof, True)
    res = s.compound([op.getdeviceinfo(devid, LAYOUT4_NFSV4_1_FILES,
        4096, 0)])
    t("s18.40 GETDEVICEINFO", res.status, NFS4_OK)
    if res.status == NFS4_OK:
        da = NFS4Unpacker(res.resarray[-1].da_addr_body
                          ).unpack_nfsv4_1_file_layout_ds_addr4()
        t("s13.3 stripe indices", da.nflda_stripe_indices, [[0]])
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
          getattr(res.resarray[-1], "ns_size", None)), [(True, 10000)])

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
        res = s.compound([op.test_stateid([rsid, lsid])])
        t("s18.48.3 TEST_STATEID of the recall's and an older seqid",
          getattr(res.resarray[-1], "tsr_status_codes", res.status), [[0, 0]])
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

    # s12.2.10, s13.5, s18.40.3, s18.43.4, s20.3.4, s20.12: a device
    # replaced while a layout refers to it
    res = s.compound([op.getdeviceinfo(devid, LAYOUT4_NFSV4_1_FILES, 0,
        nfs4lib.list2bitmap([NOTIFY_DEVICEID4_DELETE]))])
    t("s18.40.3 GETDEVICEINFO asking for DELETE", res.status, NFS4_OK)
    if res.status == NFS4_OK:
        t("s18.40.3 gdir_notification", nfs4lib.bitmap2list(
          res.resarray[-1].gdir_notification), [[NOTIFY_DEVICEID4_DELETE]])
    # The last request on the slot, for s2.10.6.3 below.
    res = lget(osid)
    t("s18.43 a layout before the device changes", res.status, NFS4_OK)
    lsid = res.resarray[-1].logr_stateid if res.status == NFS4_OK else osid
    del recalls[:]
    del seqs[:]
    del devnotes[:]
    print(vm("sysctl -w 'vfs.nfsv4.pnfs_ds=tcp %s'" % UADDR))
    t("s20.3.4 CB_LAYOUTRECALL on a new device", wait(recalls), True)
    # s2.10.6.3: the slot has seen nothing since the LAYOUTGET.
    ref = [a for a in seqs if a.csa_referring_call_lists]
    t("s2.10.6.3 CB_LAYOUTRECALL refers to the LAYOUTGET", len(ref) > 0,
      True)
    # s18.40.3: the last bitmap asked for is the one used, and an empty
    # one turns the notifications off, so ask for DELETE again.
    res = s.compound([op.getdeviceinfo(devid, LAYOUT4_NFSV4_1_FILES, 4096,
        nfs4lib.list2bitmap([NOTIFY_DEVICEID4_DELETE]))])
    t("s18.43.4 the old device ID while the layout is held", res.status,
      NFS4_OK)
    t("s20.12.3 no DELETE while the layout is held", len(devnotes), 0)
    rsid_ = recalls[0].clora_recall.lor_layout.lor_stateid if recalls \
        else lsid
    res = s.compound([op.putfh(fh), op.layoutreturn(False,
        LAYOUT4_NFSV4_1_FILES, LAYOUTIOMODE4_ANY, layoutreturn4(
        LAYOUTRETURN4_FILE, layoutreturn_file4(0, ANY, rsid_, b"")))])
    t("s18.44 LAYOUTRETURN of the recalled", res.status, NFS4_OK)
    t("s20.12 NOTIFY_DEVICEID4_DELETE once returned", wait(devnotes), True)
    if devnotes:
        n = devnotes[0].cnda_changes[0]
        t("s20.12.1 the mask", nfs4lib.bitmap2list(n.notify_mask),
          [[NOTIFY_DEVICEID4_DELETE]])
        t("s20.12.1 the device", n.notify_vals[4:], devid)
    res = s.compound([op.getdeviceinfo(devid, LAYOUT4_NFSV4_1_FILES, 4096,
        0)])
    t("s18.40.3 the old device ID once deleted", res.status, NFS4ERR_NOENT)

    # s12.5.5: REMOVE recalls
    res = lget(osid)
    t("s18.43 a layout before REMOVE", res.status, NFS4_OK)
    del recalls[:]
    res = s.compound(use_obj(export) + [op.remove(stamp + b"f")])
    t("s12.5.5 REMOVE", res.status, NFS4_OK)
    t("s12.5.5 REMOVE recalls the layout", wait(recalls), True)

    # s5.12.6, mdsthreshold
    res = create_file(s, stamp + b"g", path=export + [stamp + b"g"])
    check(res)
    gfh = res.resarray[-1].object
    gsid = res.resarray[-2].stateid
    res = s.compound([op.putfh(gfh), op.getattr(nfs4lib.list2bitmap(
        [FATTR4_MDSTHRESHOLD, FATTR4_SUPPORTED_ATTRS]))])
    t("s5.12.6 GETATTR mdsthreshold", res.status, NFS4_OK)
    if res.status == NFS4_OK:
        a = res.resarray[-1].obj_attributes
        t("s5.12.6 supported 68", 68 in nfs4lib.bitmap2list(
          a[FATTR4_SUPPORTED_ATTRS]), True)
        h = a.get(FATTR4_MDSTHRESHOLD)
        h = h.mth_hints if h is not None else []
        t("s5.12.6 one hint, of the file layout", [x.thi_layout_type
          for x in h], [[LAYOUT4_NFSV4_1_FILES]])
        if h:
            t("s3.3.22 read_size and write_size", nfs4lib.bitmap2list(
              h[0].thi_hintset), [[0, 1]])
            t("s3.3.22 both 0", h[0].thi_hintlist, b"\0" * 16)

    # s20.6, s20.7, s18.43.3: layout_max 2, with the REMOVEd file's
    # layout still out
    vm("sysctl -w vfs.nfsv4.layout_max=2")
    del rcas[:]
    del avails[:]
    res = s.compound([op.putfh(gfh), op.layoutget(False,
        LAYOUT4_NFSV4_1_FILES, LAYOUTIOMODE4_RW, 0, ANY, 0, gsid, 4096)])
    t("s18.43 LAYOUTGET to the bound", res.status, NFS4_OK)
    glsid = res.resarray[-1].logr_stateid if res.status == NFS4_OK else gsid
    t("s20.6 CB_RECALL_ANY near the bound", wait(rcas), True)
    if rcas:
        t("s20.6.1 keep half", rcas[0].craa_objects_to_keep, 1)
        t("s20.6.1 file layouts", nfs4lib.bitmap2list(
          rcas[0].craa_type_mask), [[RCA4_TYPE_MASK_FILE_LAYOUT]])
    res = create_file(s, stamp + b"h", path=export + [stamp + b"h"])
    check(res)
    hfh = res.resarray[-1].object
    hsid = res.resarray[-2].stateid
    res = s.compound([op.putfh(hfh), op.layoutget(True,
        LAYOUT4_NFSV4_1_FILES, LAYOUTIOMODE4_RW, 0, ANY, 0, hsid, 4096)])
    t("s18.43.3 past the bound", res.status, NFS4ERR_LAYOUTTRYLATER)
    t("s18.43.3 will signal", getattr(res.resarray[-1],
      "logr_will_signal_layout_avail", None), True)
    res = s.compound([op.putfh(gfh), op.layoutreturn(False,
        LAYOUT4_NFSV4_1_FILES, LAYOUTIOMODE4_ANY, layoutreturn4(
        LAYOUTRETURN4_FILE, layoutreturn_file4(0, ANY, glsid, b"")))])
    t("s18.44 LAYOUTRETURN under the bound", res.status, NFS4_OK)
    t("s20.7 CB_RECALLABLE_OBJ_AVAIL", wait(avails), True)
    if avails:
        t("s20.7.3 what it holds and the room", avails[0].
          craa_objects_to_keep, 2)
        t("s20.7.1 file layouts", nfs4lib.bitmap2list(
          avails[0].craa_type_mask), [[RCA4_TYPE_MASK_FILE_LAYOUT]])
    vm("sysctl -w vfs.nfsv4.layout_max=0")

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
