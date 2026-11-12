#!/usr/bin/env python3
"""The pNFS block layout, RFC 5663, from the server's side: layout_hint
(s2.3.8), GETDEVICEINFO's volume (s2.2.1), the extents of LAYOUTGET
(s2.3.1), LAYOUTCOMMIT (s2.3.2) and the timed-lease fence (s2.3.8).
Then fsck_ffs of the file system after a layout for writing allocated
blocks past the end of a file, which is how FFS is preallocated here.
Run from pynfs's nfs4.1 directory, after pnfs-blk.sh has made
/export/blk: blk.py EXPORT.  Failures are the measurement."""
import struct, subprocess, sys, time, traceback
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
    try:
        p = subprocess.run(["ssh", "-o", "LogLevel=ERROR", "netbsd", cmd],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=180)
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    return p.stdout.decode().strip()

ANY = 0xffffffffffffffff
IMG = "/var/tmp/blkt/blk.img"	# under /dev/vnd3d, pnfs-blk.sh
BLK = LAYOUT4_BLOCK_VOLUME
RW_DATA, READ_DATA, INVALID, NONE = 0, 1, 2, 3	# s2.3
# Answer CB_LAYOUTRECALL without returning, so that the layout is let go
# at the end of its time and fenced.
recalls = []
def op_cb_layoutrecall(self, arg, env):
    recalls.append(arg)
    return nfs4client.encode_status(NFS4_OK)
nfs4client.NFS4Client.op_cb_layoutrecall = op_cb_layoutrecall

def extents(body):
    """pnfs_block_layout4, s2.3: (offset, length, storage, state)."""
    n, = struct.unpack(">I", body[:4])
    out, o = [], 4
    for i in range(n):
        off, ln, so, st = struct.unpack(">QQQI", body[o + 16:o + 44])
        out.append((off, ln, so, st))
        o += 44
    return out

def hint(s, fh, sid, io):
    return s.compound([op.putfh(fh), op.setattr(sid, {FATTR4_LAYOUT_HINT:
        layouthint4(BLK, struct.pack(">Q", io))})]).status

export = sys.argv[1].strip('/').encode().split(b'/')
stamp = b"%d" % int(time.time())
print(vm("sysctl -w vfs.nfsv4.pnfs_blk=/export/blk; "
         "sysctl -w vfs.nfsv4.blk_nohint=0"))
c = nfs4client.NFS4Client(b'127.0.0.1', 2049, 1)
c.homedir = export
def lget(s, fh, sid, iomode, off=0, length=ANY, minlen=0, maxcount=8192):
    return s.compound([op.putfh(fh), op.layoutget(False, BLK, iomode, off,
        length, minlen, sid, maxcount)])
def newfile(s, n):
    res = create_file(s, stamp + n, path=export + [stamp + n])
    check(res)
    return res.resarray[-1].object, res.resarray[-2].stateid
def size(s, fh):
    res = s.compound([op.putfh(fh), op.getattr(nfs4lib.list2bitmap(
        [FATTR4_SIZE]))])
    return res.resarray[-1].obj_attributes.get(FATTR4_SIZE)
opened = []
try:
    s = c.new_pnfs_client_session(stamp + b"a")
    time.sleep(2)
    res = s.compound(use_obj(export) + [op.getattr(nfs4lib.list2bitmap(
        [FATTR4_FS_LAYOUT_TYPES, FATTR4_LAYOUT_BLKSIZE]))])
    check(res)
    a = res.resarray[-1].obj_attributes
    t("s5.12.1 fs_layout_type", list(a.get(FATTR4_FS_LAYOUT_TYPES, [])),
      [[BLK]])
    t("RFC 5663 s2.3.2 layout_blksize, the block size", a.get(
      FATTR4_LAYOUT_BLKSIZE), 4096)
    fh, osid = newfile(s, b"h")
    opened = [(s, fh, osid)]
    # s2.3.8
    t("s2.3.8 no hint: LAYOUTUNAVAILABLE", lget(s, fh, osid,
      LAYOUTIOMODE4_READ).status, NFS4ERR_LAYOUTUNAVAILABLE)
    t("s2.3.8 unbounded hint: INVAL", hint(s, fh, osid, ANY), NFS4ERR_INVAL)
    t("s2.3.8 a bounded one after: refused still", hint(s, fh, osid, 30),
      NFS4_OK)
    t("s2.3.8 after INVAL: LAYOUTUNAVAILABLE", lget(s, fh, osid,
      LAYOUTIOMODE4_READ).status, NFS4ERR_LAYOUTUNAVAILABLE)

    s = c.new_pnfs_client_session(stamp + b"b")
    time.sleep(2)
    fh, osid = newfile(s, b"f")
    opened.append((s, fh, osid))
    t("s2.3.8 hint of 30 s", hint(s, fh, osid, 30), NFS4_OK)
    res = lget(s, fh, osid, LAYOUTIOMODE4_READ)
    t("s2.3.1 LAYOUTGET for reading an empty file", res.status, NFS4_OK)
    if res.status == NFS4_OK:
        lo = res.resarray[-1].logr_layout[0]
        ex = extents(lo.lo_content.loc_body)
        t("s2.3.1 one extent, a hole", [(e[0], e[3]) for e in ex],
          [[(0, NONE)]])
        devid = lo.lo_content.loc_body[4:20]
        lsid = res.resarray[-1].logr_stateid
        res = s.compound([op.getdeviceinfo(devid, BLK, 4096, 0)])
        t("s2.2 GETDEVICEINFO", res.status, NFS4_OK)
        if res.status == NFS4_OK:
            b = res.resarray[-1].da_addr_body
            nv, typ, nc, off, ln = struct.unpack(">IIIqI", b[:24])
            sig = b[24:24 + ln]
            t("s2.2.1 one simple volume of one component", (nv, typ, nc),
              [(1, 0, 1)])
            want = vm("dd if=%s bs=1 skip=%d count=%d 2>/dev/null"
                      " | od -A n -t x1 | tr -d ' \\n'" % (IMG, off, ln))
            t("s2.2.1 the signature is on the device at its offset",
              sig.hex(), want)
            print("signature offset %d, %s" % (off, sig.hex()))
        res = s.compound([op.putfh(fh), op.layoutreturn(False, BLK,
            LAYOUTIOMODE4_ANY, layoutreturn4(LAYOUTRETURN4_FILE,
            layoutreturn_file4(0, ANY, lsid, b"")))])
        t("s18.44 LAYOUTRETURN", res.status, NFS4_OK)

    # s2.3.1, for writing: holes allocated, the size kept.
    res = lget(s, fh, osid, LAYOUTIOMODE4_RW, 0, 1048576, 4096)
    t("s2.3.1 LAYOUTGET for writing", res.status, NFS4_OK)
    if res.status == NFS4_OK:
        lo = res.resarray[-1].logr_layout[0]
        lsid = res.resarray[-1].logr_stateid
        ex = extents(lo.lo_content.loc_body)
        t("s2.3.1 all READ_WRITE_DATA", set(e[3] for e in ex), [{RW_DATA}])
        t("s2.3.1 from 0, 1 MiB", (ex[0][0], sum(e[1] for e in ex)),
          [(0, 1048576)])
        t("the size has not moved", size(s, fh), 0)
        so = ex[0][2]
        # Write as the client would, to the volume, then commit 64 KiB.
        print(vm("printf 'written to the volume' | dd of=%s "
                 "bs=512 seek=%d conv=notrunc 2>&1 | tail -1" % (IMG, so // 512)))
        res = s.compound([op.putfh(fh), op.layoutcommit(0, 65536, False,
            lsid, newoffset4(True, 65535), newtime4(False),
            layoutupdate4(BLK, struct.pack(">I", 0)))])
        t("s2.3.2 LAYOUTCOMMIT", res.status, NFS4_OK)
        t("s2.3.2 the size is the client's", size(s, fh), 65536)
        res = s.compound([op.putfh(fh), op.read(stateid4(0, osid.other),
            0, 21)])
        t("s2.3.2 the server reads what is on the volume",
          res.resarray[-1].data if res.status == NFS4_OK else res.status,
          b"written to the volume")
        res = s.compound([op.putfh(fh), op.layoutreturn(False, BLK,
            LAYOUTIOMODE4_ANY, layoutreturn4(LAYOUTRETURN4_FILE,
            layoutreturn_file4(0, ANY, lsid, b"")))])
        t("s18.44 LAYOUTRETURN", res.status, NFS4_OK)

    # A layout for writing past the end, returned without LAYOUTCOMMIT:
    # the blocks stay allocated past the end.  What fsck_ffs makes of it.
    fh2, osid2 = newfile(s, b"past")
    res = lget(s, fh2, osid2, LAYOUTIOMODE4_RW, 0, 262144, 4096)
    t("LAYOUTGET for writing, 256 KiB of an empty file", res.status, NFS4_OK)
    if res.status == NFS4_OK:
        lsid = res.resarray[-1].logr_stateid
        s.compound([op.putfh(fh2), op.layoutreturn(False, BLK,
            LAYOUTIOMODE4_ANY, layoutreturn4(LAYOUTRETURN4_FILE,
            layoutreturn_file4(0, ANY, lsid, b"")))])
    opened.append((s, fh2, osid2))

    # s2.3.8: a layout recalled and not returned is let go after a lease
    # and fenced for a lease and the hint, 1 s here.
    s3 = c.new_pnfs_client_session(stamp + b"c")
    time.sleep(2)
    fh3, osid3 = newfile(s3, b"fence")
    opened.append((s3, fh3, osid3))
    t("s2.3.8 hint of 1 s", hint(s3, fh3, osid3, 1), NFS4_OK)
    res = lget(s3, fh3, osid3, LAYOUTIOMODE4_RW, 0, 65536, 4096)
    t("LAYOUTGET to be fenced", res.status, NFS4_OK)
    # A size, so that a SETATTR of a smaller one would free blocks.
    if res.status == NFS4_OK:
        res = s3.compound([op.putfh(fh3), op.layoutcommit(0, 65536, False,
            res.resarray[-1].logr_stateid, newoffset4(True, 65535),
            newtime4(False), layoutupdate4(BLK, struct.pack(">I", 0)))])
        t("LAYOUTCOMMIT of 64 KiB to be fenced", res.status, NFS4_OK)
    s4 = c.new_pnfs_client_session(stamp + b"d")
    time.sleep(2)
    res = s4.compound([op.putfh(fh3), op.open(0, OPEN4_SHARE_ACCESS_BOTH,
        OPEN4_SHARE_DENY_NONE, open_owner4(0, b"d"), openflag4(OPEN4_NOCREATE),
        open_claim4(CLAIM_FH))])
    check(res)
    osid4 = res.resarray[-1].stateid
    t("s2.3.8 hint of 30 s, the second client", hint(s4, fh3, osid4, 30),
      NFS4_OK)
    vm("sysctl -w vfs.nfsv4.layout_recall=1")
    # s12.5.5: let go a lease after the recall; the lease thread looks
    # every NFSV4_LEASE_SCAN.  The two clients renew meanwhile.
    t0 = time.time()
    fences = "0"
    while time.time() - t0 < 150 and fences == "0":
        time.sleep(5)
        s3.compound([])
        s4.compound([])
        fences = vm("sysctl -n vfs.nfsv4.blk_fences")
    print("let go after %d s" % (time.time() - t0))
    t("s2.3.8 fenced", fences, "1")
    t("s2.3.8 no layout of it to another client while fenced",
      lget(s4, fh3, osid4, LAYOUTIOMODE4_RW, 0, 65536, 4096).status,
      NFS4ERR_LAYOUTTRYLATER)
    res = s4.compound([op.putfh(fh3), op.setattr(osid4, {FATTR4_SIZE: 0})])
    t("s2.3.8 its blocks not freed while fenced (SETATTR of size 0)",
      res.status, NFS4ERR_DELAY)
    while time.time() - t0 < 330 and fences != "0":
        time.sleep(5)
        s4.compound([])
        fences = vm("sysctl -n vfs.nfsv4.blk_fences")
    print("fence ended after %d s" % (time.time() - t0))
    t("s2.3.8 the fence ends", fences, "0")
    res = lget(s4, fh3, osid4, LAYOUTIOMODE4_RW, 0, 65536, 4096)
    t("s2.3.8 a layout of it after", res.status, NFS4_OK)
    if res.status == NFS4_OK:
        lsid = res.resarray[-1].logr_stateid
        s4.compound([op.putfh(fh3), op.layoutreturn(False, BLK,
            LAYOUTIOMODE4_ANY, layoutreturn4(LAYOUTRETURN4_FILE,
            layoutreturn_file4(0, ANY, lsid, b"")))])
    opened.append((s4, fh3, osid4))

    # s2.3.8: a truncation that is not this server's, by a local process
    # (open with O_TRUNC) and by NFSv3 (SETATTR of the size to nfsd),
    # waits for the block layouts of the file as SETATTR does.
    def held(n):
        fh, sid = newfile(s4, n)
        opened.append((s4, fh, sid))
        g0 = vm("sysctl -n vfs.nfsv4.layouts_given")
        res = lget(s4, fh, sid, LAYOUTIOMODE4_RW, 0, 65536, 4096)
        t("LAYOUTGET to be held", res.status, NFS4_OK)
        lsid = res.resarray[-1].logr_stateid
        res = s4.compound([op.putfh(fh), op.layoutcommit(0, 65536, False,
            lsid, newoffset4(True, 65535), newtime4(False),
            layoutupdate4(BLK, struct.pack(">I", 0)))])
        t("LAYOUTCOMMIT of the held one", res.status, NFS4_OK)
        print("layouts given %s -> %s" % (g0,
              vm("sysctl -n vfs.nfsv4.layouts_given")))
        return fh, sid, lsid
    def outside(n, path, how):
        fh, sid, lsid = held(n)
        del recalls[:]
        vm("rm -f /var/tmp/blkt/tr.done; nohup sh -c ': > %s; "
           "touch /var/tmp/blkt/tr.done' >/dev/null 2>&1 &" % path)
        got = False
        for i in range(20):
            time.sleep(1)
            s4.compound([])
            if recalls:
                got = True
                break
        t("s2.3.8 %s: the layout is recalled" % how, got, True)
        time.sleep(3)
        t("s2.3.8 %s: not done while the layout is held" % how,
          vm("test -f /var/tmp/blkt/tr.done && echo done || echo waiting"),
          "waiting")
        s4.compound([op.putfh(fh), op.layoutreturn(False, BLK,
            LAYOUTIOMODE4_ANY, layoutreturn4(LAYOUTRETURN4_FILE,
            layoutreturn_file4(0, ANY, lsid, b"")))])
        for i in range(20):
            time.sleep(1)
            if "done" in vm("test -f /var/tmp/blkt/tr.done && echo done"):
                break
        t("s2.3.8 %s: done once the layout is back" % how,
          vm("test -f /var/tmp/blkt/tr.done && stat -f %%z %s" % path), "0")
    # newfile() puts the stamp in front; the paths are the same names.
    outside(b"trl", "/export/blk/" + (stamp + b"trl").decode(),
            "local O_TRUNC")
    print(vm("pgrep -x nfsd >/dev/null || /usr/sbin/nfsd -u -n 4; "
             "mkdir -p /mnt/blkv3; rpcinfo -p | grep -E 'nfs|mount'; "
             "timeout 60 mount_nfs -3 -u -i 127.0.0.1:/export/blk "
             "/mnt/blkv3; echo mount_nfs $?"))
    outside(b"trv3", "/mnt/blkv3/" + (stamp + b"trv3").decode(),
            "NFSv3 SETATTR")
    print(vm("umount /mnt/blkv3"))

    # OPEN with a size of 0 from another client: NFS4ERR_DELAY.
    fh6, osid6, lsid6 = held(b"tro")
    s5 = c.new_pnfs_client_session(stamp + b"e")
    res = s5.compound(use_obj(export) + [op.open(0, OPEN4_SHARE_ACCESS_BOTH,
        OPEN4_SHARE_DENY_NONE, open_owner4(0, b"e"), openflag4(OPEN4_CREATE,
        createhow4(UNCHECKED4, {FATTR4_SIZE: 0})),
        open_claim4(CLAIM_NULL, stamp + b"tro"))])
    t("s2.3.8 OPEN truncating, the layout held: DELAY", res.status,
      NFS4ERR_DELAY)
    s4.compound([op.putfh(fh6), op.layoutreturn(False, BLK,
        LAYOUTIOMODE4_ANY, layoutreturn4(LAYOUTRETURN4_FILE,
        layoutreturn_file4(0, ANY, lsid6, b"")))])

    # s2.3.8, RFC 8881 s8.4.3: a layout given after the client's lease ran
    # out and returned is not fenced; only what the lease took away is.
    s6 = c.new_pnfs_client_session(stamp + b"g")
    fh7, osid7 = newfile(s6, b"late0")
    t("s2.3.8 hint of 30 s, the late client", hint(s6, fh7, osid7, 30),
      NFS4_OK)
    print("waiting for the lease of the late client to run out")
    sys.stdout.flush()
    time.sleep(115)
    s6.compound([])
    fh8, osid8 = newfile(s6, b"late")
    res = lget(s6, fh8, osid8, LAYOUTIOMODE4_RW, 0, 65536, 4096)
    t("LAYOUTGET after the lease ran out", res.status, NFS4_OK)
    if res.status == NFS4_OK:
        lsid8 = res.resarray[-1].logr_stateid
        f0 = vm("sysctl -n vfs.nfsv4.blk_fences")
        res = s6.compound([op.putfh(fh8), op.layoutreturn(False, BLK,
            LAYOUTIOMODE4_ANY, layoutreturn4(LAYOUTRETURN4_FILE,
            layoutreturn_file4(0, ANY, lsid8, b"")))])
        t("its LAYOUTRETURN", res.status, NFS4_OK)
        t("s2.3.8 returned after the lease ran out: not fenced",
          vm("sysctl -n vfs.nfsv4.blk_fences"), f0)
        res = s6.compound([op.putfh(fh8), op.setattr(osid8,
            {FATTR4_SIZE: 0})])
        t("s2.3.8 its blocks free at once (SETATTR of size 0)",
          res.status, NFS4_OK)
        s7 = c.new_pnfs_client_session(stamp + b"h")
        res = s7.compound([op.putfh(fh8), op.open(0,
            OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_DENY_NONE,
            open_owner4(0, b"h"), openflag4(OPEN4_NOCREATE),
            open_claim4(CLAIM_FH))])
        if res.status == NFS4_OK:
            osid9 = res.resarray[-1].stateid
            hint(s7, fh8, osid9, 30)
            res = lget(s7, fh8, osid9, LAYOUTIOMODE4_RW, 0, 65536, 4096)
            t("s2.3.8 another client's layout of it at once", res.status,
              NFS4_OK)
            if res.status == NFS4_OK:
                s7.compound([op.putfh(fh8), op.layoutreturn(False, BLK,
                    LAYOUTIOMODE4_ANY, layoutreturn4(LAYOUTRETURN4_FILE,
                    layoutreturn_file4(0, ANY,
                    res.resarray[-1].logr_stateid, b"")))])
            opened.append((s7, fh8, osid9))

    # RFC 5661 errata 3379: DESTROY_CLIENTID of a client that holds only a
    # layout is not CLIENTID_BUSY; the layout goes as one the lease took,
    # fenced (1 s of hint, so a lease and 1 s).
    c8 = nfs4client.NFS4Client(b'127.0.0.1', 2049, 1)
    c8.homedir = export
    s8 = c8.new_pnfs_client_session(stamp + b"k")
    fh10, osid10 = newfile(s8, b"destroy")
    hint(s8, fh10, osid10, 1)
    res = lget(s8, fh10, osid10, LAYOUTIOMODE4_RW, 0, 65536, 4096)
    t("LAYOUTGET to be left", res.status, NFS4_OK)
    s8.compound([op.putfh(fh10), op.close(0, osid10)])
    f0 = int(vm("sysctl -n vfs.nfsv4.blk_fences"))
    res = c8.compound([op.destroy_session(s8.sessionid)])
    t("DESTROY_SESSION", res.status, NFS4_OK)
    res = c8.compound([op.destroy_clientid(s8.client.clientid)])
    t("errata 3379: DESTROY_CLIENTID with only a layout left", res.status,
      NFS4_OK)
    t("errata 3379: the layout left is fenced",
      int(vm("sysctl -n vfs.nfsv4.blk_fences")), f0 + 1)
    for i in range(30):
        if int(vm("sysctl -n vfs.nfsv4.blk_fences")) <= f0:
            break
        time.sleep(5)
    t("errata 3379: its fence ends", int(vm("sysctl -n vfs.nfsv4.blk_fences")),
      f0)
except Exception:
    traceback.print_exc()
    t("exception", "exception", "none")
finally:
    # Closed, so that the server holds none of the file system's vnodes.
    for ss, f, o in opened:
        try:
            print("CLOSE", ss.compound([op.putfh(f), op.close(0, o)]).status)
        except Exception:
            traceback.print_exc()
    print(vm("sysctl -w vfs.nfsv4.pnfs_blk=; sysctl -w vfs.nfsv4.blk_nohint=0"))

# fsck_ffs, read only, once the layouts for writing have ended: of the
# file system where stamp+"past" (size 0) had 64 blocks past its end and
# stamp+"f" 240, then after removing the first.
name = (stamp + b"past").decode()
def fsck(what):
    print("=== fsck_ffs -n, %s" % what)
    print(vm("ls -ls /export/blk; umount /export/blk || umount -f /export/blk"))
    out = vm("fsck_ffs -n -f /dev/rvnd3d; echo fsck exit $?")
    print(out)
    print(vm("mount /dev/vnd3d /export/blk; echo mount $?"))
    t("fsck_ffs finds nothing, " + what, out.endswith("fsck exit 0"), True)
# The layouts have ended, so what they allocated past the ends is freed.
fsck("the layouts for writing over")
print(vm("rm -f /export/blk/%s; echo rm $?" % name))
fsck("after removing %s" % name)
print("failures:", fails)
sys.exit(0)
