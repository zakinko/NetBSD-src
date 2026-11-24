#!/usr/bin/env python3
"""The data server under a server owner of its own (vfs.nfsv4.ds_owner),
RFC 8881 s13.6: a client of it is a client of a data server alone, and
gets NFS4ERR_NOTSUPP for what is not housekeeping or I/O; its I/O is of
a layout held at the metadata server (s12.5.1, NFS4ERR_PNFS_NO_LAYOUT)
with stateids of seqid 0 and none special (s13.9.1).  In version 4.2
IO_ADVISE, READ_PLUS, SEEK and WRITE_SAME are I/O too, RFC 7862 s3.3.1.  Run from pynfs's
nfs4.1 directory, with the second nfsv4d on 2051 that pnfs-linux.sh
starts: ds-role.py EXPORT.  Failures are the measurement."""
import subprocess, sys, time, traceback
import nfs_ops, nfs4client, nfs4lib
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
from server41tests.environment import create_file, check
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
export = sys.argv[1].strip('/').encode().split(b'/')
name = b"dsrole%d" % int(time.time())
print(vm("netstat -an -f inet | grep '\\.2051 .*LISTEN'; "
         "sysctl -w 'vfs.nfsv4.pnfs_ds=tcp 127.0.0.1.8.3'; "
         "sysctl -w vfs.nfsv4.ds_owner=1"))
try:
    mds = nfs4client.NFS4Client(b'127.0.0.1', 2049, 1)
    mds.homedir = export
    s = mds.new_pnfs_client_session(name)
    res = create_file(s, name + b"f", path=export + [name + b"f"])
    check(res)
    fh = res.resarray[-1].object
    osid = res.resarray[-2].stateid
    zsid = stateid4(0, osid.other)

    ds = nfs4client.NFS4Client(b'127.0.0.1', 2051, 1)
    cl = ds.new_client(name, flags=EXCHGID4_FLAG_USE_PNFS_DS)
    t("s13.1 the data server's roles", cl.flags & EXCHGID4_FLAG_MASK_PNFS,
      EXCHGID4_FLAG_USE_PNFS_DS)
    d = cl.create_session()
    res = d.compound([op.putrootfh()])
    t("s13.6 PUTROOTFH at the data server", res.status, NFS4ERR_NOTSUPP)
    res = d.compound([op.putfh(fh), op.getattr(nfs4lib.list2bitmap(
        [FATTR4_SIZE]))])
    t("s13.6 GETATTR at the data server", res.status, NFS4ERR_NOTSUPP)
    res = d.compound([op.putfh(fh), op.read(zsid, 0, 10)])
    t("s12.5.1 READ without a layout", res.status, NFS4ERR_PNFS_NO_LAYOUT)

    res = s.compound([op.putfh(fh), op.layoutget(False,
        LAYOUT4_NFSV4_1_FILES, LAYOUTIOMODE4_READ, 0, ANY, 0, osid, 4096)])
    t("LAYOUTGET for reading at the metadata server", res.status, NFS4_OK)
    lsid = res.resarray[-1].logr_stateid if res.status == NFS4_OK else None
    res = d.compound([op.putfh(fh), op.read(zsid, 0, 10)])
    t("s13.6 READ by a layout", res.status, NFS4_OK)
    res = d.compound([op.putfh(fh), op.read(osid, 0, 10)])
    t("s13.9.1 READ with a seqid", res.status, NFS4ERR_BAD_STATEID)
    res = d.compound([op.putfh(fh), op.read(stateid4(0, b"\0" * 12), 0, 10)])
    t("s13.9.1 READ with the anonymous stateid", res.status,
      NFS4ERR_BAD_STATEID)
    res = d.compound([op.putfh(fh), op.write(zsid, 0, UNSTABLE4, b"x")])
    t("s15.1.10.7 WRITE under a layout for reading", res.status,
      NFS4ERR_PNFS_NO_LAYOUT)
    res = d.compound([op.putfh(fh), op.commit(0, 0)])
    t("s13.6 COMMIT at the data server", res.status, NFS4_OK)

    # RFC 7862 s3.3.1: in version 4.2 the four operations are taken as
    # READ and WRITE are, under the same layouts and stateids.  A pair
    # of 4.2 clients of one co_ownerid (s2.4): the metadata server's
    # that opens and holds the layout, and the data server's that does
    # the I/O.  ds_peer() ties the two.
    n42 = name + b"42"
    mds42 = nfs4client.NFS4Client(b'127.0.0.1', 2049, 2)
    mds42.homedir = export
    s42 = mds42.new_pnfs_client_session(n42)
    res = create_file(s42, n42 + b"f", path=export + [n42 + b"f"])
    check(res)
    fh42 = res.resarray[-1].object
    osid42 = res.resarray[-2].stateid
    zsid42 = stateid4(0, osid42.other)
    res = s42.compound([op.putfh(fh42), op.layoutget(False,
        LAYOUT4_NFSV4_1_FILES, LAYOUTIOMODE4_RW, 0, ANY, 0, osid42, 4096)])
    t("LAYOUTGET for writing at the metadata server in 4.2", res.status,
      NFS4_OK)
    lsid42 = res.resarray[-1].logr_stateid if res.status == NFS4_OK else None

    ds42 = nfs4client.NFS4Client(b'127.0.0.1', 2051, 2)
    d42 = ds42.new_client(n42,
        flags=EXCHGID4_FLAG_USE_PNFS_DS).create_session()
    res = d42.compound([op.putfh(fh42), op.getattr(nfs4lib.list2bitmap(
        [FATTR4_SIZE]))])
    t("s13.6 GETATTR at the data server in 4.2", res.status,
      NFS4ERR_NOTSUPP)
    res = d42.compound([op.putfh(fh42), op.read_plus(osid42, 0, 10)])
    t("7862 s3.3.1 READ_PLUS with a seqid", res.status, NFS4ERR_BAD_STATEID)
    res = d42.compound([op.putfh(fh42), op.seek(stateid4(0, b"\0" * 12), 0,
        NFS4_CONTENT_DATA)])
    t("s13.9.1 SEEK with the anonymous stateid", res.status,
      NFS4ERR_BAD_STATEID)
    adb = app_data_block4(0, 512, 2, 0, 7, 8, b"\xfe\xed")
    res = d42.compound([op.putfh(fh42), op.write_same(zsid42, FILE_SYNC4,
        adb)])
    t("7862 s3.3.1 WRITE_SAME by a layout", res.status, NFS4_OK)
    res = d42.compound([op.putfh(fh42), op.read_plus(zsid42, 0, 1024)])
    t("7862 s3.3.1 READ_PLUS by a layout", res.status, NFS4_OK)
    res = d42.compound([op.putfh(fh42), op.seek(zsid42, 0,
        NFS4_CONTENT_DATA)])
    t("7862 s3.3.1 SEEK by a layout", res.status, NFS4_OK)
    res = d42.compound([op.putfh(fh42), op.io_advise(zsid42, 0, 0,
        1 << IO_ADVISE4_NORMAL)])
    t("7862 s3.3.1 IO_ADVISE by a layout", res.status, NFS4_OK)
    if lsid42 is not None:
        s42.compound([op.putfh(fh42), op.layoutreturn(False,
            LAYOUT4_NFSV4_1_FILES, LAYOUTIOMODE4_ANY, layoutreturn4(
            LAYOUTRETURN4_FILE, layoutreturn_file4(0, ANY, lsid42, b"")))])
    s42.compound([op.putfh(fh42), op.close(0, osid42)])
    # Returned and closed: a layout left held kept vfs.nfsv4.pnfs_ds from
    # being cleared (EBUSY), and the next step's client went on to a
    # data server that was no longer being served.
    if lsid is not None:
        s.compound([op.putfh(fh), op.layoutreturn(False,
            LAYOUT4_NFSV4_1_FILES, LAYOUTIOMODE4_ANY, layoutreturn4(
            LAYOUTRETURN4_FILE, layoutreturn_file4(0, ANY, lsid, b"")))])
    s.compound([op.putfh(fh), op.close(0, osid)])
except Exception:
    traceback.print_exc()
    t("exception", "exception", "none")
finally:
    print(vm("sysctl -w vfs.nfsv4.ds_owner=0"))
    for i in range(18):
        out = vm("sysctl -w vfs.nfsv4.pnfs_ds=")
        print(out)
        if "busy" not in out:
            break
        time.sleep(10)
print("failures:", fails)
sys.exit(0)
