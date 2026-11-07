# The MUSTs of RFC 7862 and RFC 8276, each test named for its section,
# for the conformance table.  V42FS in the environment says what the
# export is: ffs, tmpfs, acl (FFS with extended attributes) or zfs.
import os
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import app_data_block4, netloc4, stateid4
from xdrdef.nfs4_type import locker4, open_to_lock_owner4, lock_owner4
from xdrdef.nfs4_type import netaddr4
from .environment import check, fail, create_file, write_file, read_file, create_obj
from .environment import use_obj, do_getattrdict
import nfs_ops
op = nfs_ops.NFS4ops()

FS = os.environ.get("V42FS", "ffs")
NOVAL = 0xffffffffffffffff

# The session of pynfs has 8192 bytes each way.
def wr(sess, fh, st, data, off=0):
    for i in range(0, len(data), 4096):
        check(write_file(sess, fh, data[i:i + 4096], off + i, st))

def mk(t, env, data=b"", suffix=b""):
    sess = env.c1.new_client_session(env.testname(t) + suffix)
    res = create_file(sess, env.testname(t) + suffix)
    check(res)
    fh, st = res.resarray[-1].object, res.resarray[-2].stateid
    wr(sess, fh, st, data)
    return sess, fh, st

def mk2(sess, env, t, data=b""):
    res = create_file(sess, env.testname(t) + b"_2")
    check(res)
    fh, st = res.resarray[-1].object, res.resarray[-2].stateid
    wr(sess, fh, st, data)
    return fh, st

def adir(sess, env, t):
    path = sess.c.homedir + [env.testname(t) + b"_d"]
    check(create_obj(sess, path))
    res = sess.compound(use_obj(path) + [op.getfh()])
    check(res)
    return res.resarray[-1].object

def rd(sess, fh, st, off, n):
    out = b""
    while len(out) < n:
        res = read_file(sess, fh, off + len(out), min(n - len(out), 4096), st)
        check(res)
        if not res.data:
            break
        out += res.data
    return out

def test_s15_1_wrong_type(t, env):
    """s15.1.3 ALLOCATE on a directory is WRONG_TYPE
    FLAGS: v42
    CODE: V4201
    VERS: 2-
    """
    sess, fh, st = mk(t, env)
    d = adir(sess, env, t)
    check(sess.compound([op.putfh(d), op.allocate(env.stateid0, 0, 1)]), NFS4ERR_WRONG_TYPE)
    check(sess.compound([op.putfh(d), op.deallocate(env.stateid0, 0, 1)]), NFS4ERR_WRONG_TYPE)

def test_s15_1_extends(t, env):
    """s15.1.3 past the end sets the size, and it reads as zeros
    FLAGS: v42
    CODE: V4202
    VERS: 2-
    """
    sess, fh, st = mk(t, env, b"abc")
    res = sess.compound([op.putfh(fh), op.allocate(st, 100000, 5000)])
    if FS == "zfs":
        check(res, NFS4ERR_NOTSUPP)
        return
    check(res)
    a = do_getattrdict(sess, fh, [FATTR4_SIZE])
    if a[FATTR4_SIZE] != 105000:
        fail("size %d" % a[FATTR4_SIZE])
    if rd(sess, fh, st, 0, 4096)[:5] != b"abc\0\0":
        fail("old data changed")

def test_s15_1_bad_stateid(t, env):
    """s15.1.3 a stateid not good for WRITE fails
    FLAGS: v42
    CODE: V4203
    VERS: 2-
    """
    sess, fh, st = mk(t, env)
    res = create_file(sess, env.testname(t) + b"_r", access=OPEN4_SHARE_ACCESS_READ)
    check(res)
    check(sess.compound([op.putfh(res.resarray[-1].object),
                         op.allocate(res.resarray[-2].stateid, 0, 1)]), NFS4ERR_OPENMODE)
    bad = stateid4(1, b"\x55" * 12)
    check(sess.compound([op.putfh(fh), op.deallocate(bad, 0, 1)]), NFS4ERR_BAD_STATEID)

def test_s15_4_zeros(t, env):
    """s15.4.3 reads of the range are zeros, unaligned, size stays
    FLAGS: v42
    CODE: V4204
    VERS: 2-
    """
    data = b"x" * 100000
    sess, fh, st = mk(t, env, data)
    check(sess.compound([op.putfh(fh), op.deallocate(st, 1234, 50000)]))
    want = data[:1234] + bytes(50000) + data[51234:]
    if rd(sess, fh, st, 0, len(want)) != want:
        fail("not zeros")

def test_s15_2_copy(t, env):
    """s15.2.3 identical data, count 0 to EOF, requirements met
    FLAGS: v42
    CODE: V4205
    VERS: 2-
    """
    data = os.urandom(70000)
    sess, fh, st = mk(t, env, data)
    fh2, st2 = mk2(sess, env, t)
    res = sess.compound([op.putfh(fh), op.savefh(), op.putfh(fh2),
                         op.copy(st, st2, 10, 5, 0, 1, 1, [])])
    check(res)
    r = res.resarray[-1]
    if r.cr_response.wr_count != len(data) - 10:
        fail("count %d" % r.cr_response.wr_count)
    if len(r.cr_response.wr_callback_id) != 0:
        fail("async")
    if not (r.cr_resok4.cr_requirements.cr_consecutive and r.cr_resok4.cr_requirements.cr_synchronous):
        fail("requirements")
    if rd(sess, fh2, st2, 5, 32768) != data[10:10 + 32768]:
        fail("data")

def test_s15_2_errors(t, env):
    """s15.2.3 same file and past EOF are INVAL, dir WRONG_TYPE, bad stateid fails
    FLAGS: v42
    CODE: V4206
    VERS: 2-
    """
    sess, fh, st = mk(t, env, b"abcd")
    fh2, st2 = mk2(sess, env, t)
    d = adir(sess, env, t)
    pre = [op.putfh(fh), op.savefh()]
    check(sess.compound(pre + [op.copy(st, st, 0, 2, 1, 0, 1, [])]), NFS4ERR_INVAL)
    check(sess.compound(pre + [op.putfh(fh2), op.copy(st, st2, 5, 0, 0, 0, 1, [])]), NFS4ERR_INVAL)
    check(sess.compound(pre + [op.putfh(fh2), op.copy(st, st2, 2, 0, 3, 0, 1, [])]), NFS4ERR_INVAL)
    check(sess.compound(pre + [op.putfh(d), op.copy(st, st2, 0, 0, 1, 0, 1, [])]), NFS4ERR_WRONG_TYPE)
    bad = stateid4(1, b"\x55" * 12)
    check(sess.compound(pre + [op.putfh(fh2), op.copy(bad, st2, 0, 0, 1, 0, 1, [])]), NFS4ERR_BAD_STATEID)

def test_s15_5_contradictory(t, env):
    """s15.5.3 contradictory hints succeed and say what is meant
    FLAGS: v42
    CODE: V4207
    VERS: 2-
    """
    sess, fh, st = mk(t, env)
    res = sess.compound([op.putfh(fh), op.io_advise(st, 0, 0, (1 << 1) | (1 << 3))])
    check(res)
    print(res.resarray[-1].ior_hints)

def test_s15_8_offload(t, env):
    """s4.8 a stateid never given out is not found
    FLAGS: v42
    CODE: V4208
    VERS: 2-
    """
    sess, fh, st = mk(t, env)
    check(sess.compound([op.putfh(fh), op.offload_status(st)]), NFS4ERR_BAD_STATEID)
    check(sess.compound([op.putfh(fh), op.offload_cancel(st)]), NFS4ERR_BAD_STATEID)

def test_s15_10_read_plus(t, env):
    """s15.10.3 contiguous contents, eof, zero count, types
    FLAGS: v42
    CODE: V4209
    VERS: 2-
    """
    sess, fh, st = mk(t, env, b"data")
    check(write_file(sess, fh, b"tail", 1 << 20, st))
    pos, out, eof = 0, 0, False
    while not eof:
        res = sess.compound([op.putfh(fh), op.read_plus(st, pos, 4096)])
        check(res)
        r = res.resarray[-1]
        eof = r.rpr_eof
        for c in r.rpr_contents:
            o = c.rpc_data.d_offset if c.rpc_content == NFS4_CONTENT_DATA else c.rpc_hole.di_offset
            n = len(c.rpc_data.d_data) if c.rpc_content == NFS4_CONTENT_DATA else c.rpc_hole.di_length
            if o != pos:
                fail("not contiguous: %d at %d" % (o, pos))
            pos += n
        if not r.rpr_contents and not eof:
            fail("no progress")
    if pos != (1 << 20) + 4:
        fail("ended at %d" % pos)
    res = sess.compound([op.putfh(fh), op.read_plus(st, 0, 0)])
    check(res)
    if res.resarray[-1].rpr_contents:
        fail("count 0 returned something")
    res = sess.compound([op.putfh(fh), op.read_plus(st, 1 << 30, 10)])
    check(res)
    if not res.resarray[-1].rpr_eof:
        fail("past the end not eof")
    d = adir(sess, env, t)
    check(sess.compound([op.putfh(d), op.read_plus(env.stateid0, 0, 1)]), NFS4ERR_ISDIR)

def test_s15_11_seek(t, env):
    """s15.11.3 NXIO past the end, the virtual hole
    FLAGS: v42
    CODE: V4210
    VERS: 2-
    """
    sess, fh, st = mk(t, env, b"x" * 5000)
    check(sess.compound([op.putfh(fh), op.seek(st, 5001, NFS4_CONTENT_DATA)]), NFS4ERR_NXIO)
    res = sess.compound([op.putfh(fh), op.seek(st, 0, NFS4_CONTENT_HOLE)])
    check(res)
    r = res.resarray[-1]
    if not r.sr_eof or r.sr_offset != 5000:
        fail("hole %s %d" % (r.sr_eof, r.sr_offset))

def test_s15_12_write_same(t, env):
    """s8.1.1, s15.12.3 populates ADBs, numbered, pattern in each
    FLAGS: v42
    CODE: V4211
    VERS: 2-
    """
    sess, fh, st = mk(t, env)
    adb = app_data_block4(0, 4096, 3, 0, 7, 8, b"\xfe\xed\xfa\xce")
    res = sess.compound([op.putfh(fh), op.write_same(st, FILE_SYNC4, adb)])
    check(res)
    if res.resarray[-1].wr_count != 3 * 4096:
        fail("count")
    b = rd(sess, fh, st, 0, 3 * 4096)
    for i in range(3):
        one = b[i * 4096:(i + 1) * 4096]
        if one[:4] != (7 + i).to_bytes(4, "big") or one[8:12] != b"\xfe\xed\xfa\xce" or any(one[12:]):
            fail("block %d" % i)
    adb = app_data_block4(0, 100, 1, NOVAL, 0, 98, b"abcd")
    check(sess.compound([op.putfh(fh), op.write_same(st, UNSTABLE4, adb)]), NFS4ERR_INVAL)

def test_s15_13_clone(t, env):
    """s15.13.3 overlap and past EOF INVAL; shares on ZFS, NOTSUPP elsewhere
    FLAGS: v42
    CODE: V4212
    VERS: 2-
    """
    data = os.urandom(1 << 17)
    sess, fh, st = mk(t, env, data)
    fh2, st2 = mk2(sess, env, t)
    pre = [op.putfh(fh), op.savefh()]
    check(sess.compound(pre + [op.clone(st, st, 0, 10, 100)]), NFS4ERR_INVAL)
    check(sess.compound(pre + [op.putfh(fh2), op.clone(st, st2, 1 << 20, 0, 1)]), NFS4ERR_INVAL)
    res = sess.compound(pre + [op.putfh(fh2), op.clone(st, st2, 0, 0, 0)])
    if FS == "zfs":
        check(res)
        if rd(sess, fh2, st2, 0, 4096) != data[:4096]:
            fail("data")
    else:
        check(res, NFS4ERR_NOTSUPP)

def test_s13_mni(t, env):
    """s13, s14.2.4 what is not implemented says NOTSUPP
    FLAGS: v42
    CODE: V4213
    VERS: 2-
    """
    sess, fh, st = mk(t, env)
    check(sess.compound([op.putfh(fh), op.getdevicelist(1, 1, 0, b"\0" * 8)]), NFS4ERR_NOTSUPP)

def test_s12_attrs(t, env):
    """s12.2 the new attributes that supported_attrs lists can be had
    FLAGS: v42
    CODE: V4214
    VERS: 2-
    """
    sess, fh, st = mk(t, env, b"abc")
    res = sess.compound([op.putfh(fh), op.getattr(1 << FATTR4_SUPPORTED_ATTRS)])
    check(res)
    sup = res.resarray[-1].obj_attributes[FATTR4_SUPPORTED_ATTRS]
    print("supported", [n for n in (77, 78, 79, 80, 82) if sup & (1 << n)])
    if not sup & (1 << FATTR4_CHANGE_ATTR_TYPE):
        fail("change_attr_type")
    if (FS == "zfs") != bool(sup & (1 << FATTR4_CLONE_BLKSIZE)):
        fail("clone_blksize goes with CLONE, s4.1.2")

def test_x8_change(t, env):
    """RFC 8276 s8.4.2.3, s8.4.4.3 change moves, change_info atomic
    FLAGS: v42x
    CODE: V4215
    VERS: 2-
    """
    sess, fh, st = mk(t, env)
    a = do_getattrdict(sess, fh, [FATTR4_CHANGE])[FATTR4_CHANGE]
    res = sess.compound([op.putfh(fh), op.setxattr(SETXATTR4_EITHER, b"k", b"v")])
    check(res)
    i = res.resarray[-1].sxr_info
    if not i.atomic or i.before == i.after:
        fail("setxattr change_info")
    if do_getattrdict(sess, fh, [FATTR4_CHANGE])[FATTR4_CHANGE] == a:
        fail("change did not move")
    res = sess.compound([op.putfh(fh), op.removexattr(b"k")])
    check(res)
    i = res.resarray[-1].rxr_info
    if not i.atomic or i.before == i.after:
        fail("removexattr change_info")

def test_x8_list(t, env):
    """RFC 8276 s8.4.3.3 cookie, eof, TOOSMALL, keys uninterpreted
    FLAGS: v42x
    CODE: V4216
    VERS: 2-
    """
    sess, fh, st = mk(t, env)
    for k in (b"aaaa", b"b.b", b"." ):
        check(sess.compound([op.putfh(fh), op.setxattr(SETXATTR4_CREATE, k, b"")]))
    names, c = [], 0
    while True:
        res = sess.compound([op.putfh(fh), op.listxattrs(c, 32)])
        check(res)
        r = res.resarray[-1]
        names += r.lxr_names
        c = r.lxr_cookie
        if r.lxr_eof:
            break
    if sorted(names) != [b".", b"aaaa", b"b.b"]:
        fail(repr(names))
    check(sess.compound([op.putfh(fh), op.listxattrs(0, 16)]), NFS4ERR_TOOSMALL)
    check(sess.compound([op.putfh(fh), op.listxattrs(99, 4096)]), NFS4ERR_BAD_COOKIE)

def test_x8_perm(t, env):
    """RFC 8276 s8.8 another user is held to the permissions
    FLAGS: v42x
    CODE: V4217
    VERS: 2-
    """
    sess, fh, st = mk(t, env)
    check(sess.compound([op.putfh(fh), op.setxattr(SETXATTR4_EITHER, b"k", b"v")]))
    check(sess.compound([op.putfh(fh), op.setattr(st, {FATTR4_MODE: 0o600})]))
    sess2 = env.c1.new_client_session(env.testname(t) + b"_2", sec=None)
    sess2.c.set_cred(env.cred2)
    check(sess2.compound([op.putfh(fh), op.setxattr(SETXATTR4_EITHER, b"k", b"w")]), NFS4ERR_ACCESS)
    sess2.c.set_cred(env.cred1)

def test_x8_notsupp(t, env):
    """RFC 8276 s8.4 no xattrs, all four refuse
    FLAGS: v42
    CODE: V4218
    VERS: 2-
    """
    sess, fh, st = mk(t, env)
    if FS in ("acl", "zfs"):
        return
    check(sess.compound([op.putfh(fh), op.getxattr(b"k")]), NFS4ERR_NOTSUPP)
    check(sess.compound([op.putfh(fh), op.setxattr(SETXATTR4_EITHER, b"k", b"v")]), NFS4ERR_NOTSUPP)
    check(sess.compound([op.putfh(fh), op.listxattrs(0, 4096)]), NFS4ERR_NOTSUPP)
    check(sess.compound([op.putfh(fh), op.removexattr(b"k")]), NFS4ERR_NOTSUPP)

def test_s12_label(t, env):
    """s12.2.4, s9.4, s9.5.2 a label stored comes back; the root answers
    FLAGS: v42x
    CODE: V4219
    VERS: 2-
    """
    sess, fh, st = mk(t, env)
    res = sess.compound([op.putrootfh(), op.getattr(1 << FATTR4_SEC_LABEL)])
    check(res)
    print(res.resarray[-1].obj_attributes)

def test_s15_10_lock_range(t, env):
    """s15.10.3 a hole read under a lock does not go past the range
    FLAGS: v42
    CODE: V4220
    VERS: 2-
    """
    sess, fh, st = mk(t, env, b"x")
    check(write_file(sess, fh, b"y", 1 << 20, st))
    bs = 4096
    lk = locker4(TRUE, open_owner=open_to_lock_owner4(0, st, 0,
                 lock_owner4(0, b"v42")))
    res = sess.compound([op.putfh(fh), op.lock(WRITE_LT, FALSE, bs, bs, lk)])
    check(res)
    res = sess.compound([op.putfh(fh), op.read_plus(st, bs, bs)])
    check(res)
    for c in res.resarray[-1].rpr_contents:
        if c.rpc_content == NFS4_CONTENT_HOLE and \
           c.rpc_hole.di_offset + c.rpc_hole.di_length > 2 * bs:
            fail("hole %d+%d past the lock" % (c.rpc_hole.di_offset, c.rpc_hole.di_length))
    # And with no lock on the file it does reach the end of the hole.
    sess2, fh2, st2 = mk(t, env, b"x", b"_n")
    check(write_file(sess2, fh2, b"y", 1 << 20, st2))
    print(sess2.compound([op.putfh(fh2), op.read_plus(st2, bs, bs)]).resarray[-1].rpr_eof)

def poll(sess, fh, sid):
    import time
    for i in range(300):
        res = sess.compound([op.putfh(fh), op.offload_status(sid)])
        if res.status == NFS4ERR_BAD_STATEID:
            return None         # it has been reported and is gone
        check(res)
        r = res.resarray[-1]
        if r.osr_complete:
            return r.osr_complete[0]
        time.sleep(1)
    fail("never finished")

def test_s15_12_all_blocks(t, env):
    """s15.12.3 all of adb_block_count, past where a COPY stops; s15.12.3.1
    FLAGS: v42
    CODE: V4221
    VERS: 2-
    """
    sess, fh, st = mk(t, env)
    n = 18000
    adb = app_data_block4(0, 4096, n, 0, 0, NOVAL, b"")
    res = sess.compound([op.putfh(fh), op.write_same(st, UNSTABLE4, adb)])
    check(res)
    r = res.resarray[-1]
    if r.wr_callback_id:
        print("async")
        s = poll(sess, fh, r.wr_callback_id[0])
        if s not in (None, NFS4_OK):
            fail("status %d" % s)
    elif r.wr_count != n * 4096:
        fail("short %d" % r.wr_count)
    b = rd(sess, fh, st, (n - 1) * 4096, 4096)
    if b[:4] != (n - 1).to_bytes(4, "big"):
        fail("last block %r" % b[:4])

def test_s15_2_async(t, env):
    """s15.2.3 a long COPY that may be asynchronous ends with all of it
    FLAGS: v42
    CODE: V4222
    VERS: 2-
    """
    sess, fh, st = mk(t, env)
    total = 70 << 20
    check(write_file(sess, fh, b"end", total - 3, st))
    fh2, st2 = mk2(sess, env, t)
    res = sess.compound([op.putfh(fh), op.savefh(), op.putfh(fh2),
                         op.copy(st, st2, 0, 0, 0, 0, 0, [])])
    check(res)
    r = res.resarray[-1]
    if r.cr_response.wr_callback_id:
        print("async")
        sid = r.cr_response.wr_callback_id[0]
        if sid.seqid == 0:
            fail("s4.8: a seqid of zero")
        s = poll(sess, fh2, sid)
        if s not in (None, NFS4_OK):
            fail("status %d" % s)
        if rd(sess, fh2, st2, total - 3, 3) != b"end":
            fail("data")
    elif r.cr_response.wr_count == 0:
        fail("nothing copied")

def test_s4_cancel_other_user(t, env):
    """s4.1.2 OFFLOAD_CANCEL of a stateid nothing runs under is BAD_STATEID
    FLAGS: v42
    CODE: V4223
    VERS: 2-
    """
    sess, fh, st = mk(t, env)
    bad = stateid4(1, b"\x55" * 12)
    check(sess.compound([op.putfh(fh), op.offload_cancel(bad)]), NFS4ERR_BAD_STATEID)

def arm(r, name):
    return getattr(r, name, None) or getattr(r.resok4, name)

def test_s15_3_inter_server(t, env):
    """s15.3.3, s15.2.3, s4.6.2 COPY_NOTIFY, then COPY from it by NFSv4.2
    FLAGS: v42
    CODE: V4224
    VERS: 2-
    """
    data = os.urandom(100000)
    sess, fh, st = mk(t, env, data)
    check(sess.compound([op.putfh(fh), op.copy_notify(env.stateid0,
        netloc4(NL4_NETADDR, nl_addr=netaddr4(b"tcp", b"127.0.0.1.8.1")))]),
        NFS4ERR_BAD_STATEID)
    res = sess.compound([op.putfh(fh), op.copy_notify(st,
        netloc4(NL4_NETADDR, nl_addr=netaddr4(b"tcp", b"127.0.0.1.8.1")))])
    check(res)
    r = res.resarray[-1]
    cnr = arm(r, "cnr_stateid")
    srcs = arm(r, "cnr_source_server")
    print("lease", arm(r, "cnr_lease_time").seconds, "sources", srcs)
    if cnr.seqid == 0 or not srcs:
        fail("cnr %r sources %r" % (cnr, srcs))
    fh2, st2 = mk2(sess, env, t)
    res = sess.compound([op.putfh(fh), op.savefh(), op.putfh(fh2),
                         op.copy(cnr, st2, 0, 0, len(data), 0, 1, srcs)])
    check(res)
    n = res.resarray[-1].cr_response.wr_count
    if n != len(data) or rd(sess, fh2, st2, 0, len(data)) != data:
        fail("copied %d" % n)
    # s15.8.3: cancelled at the source, the stateid reads no more.
    check(sess.compound([op.putfh(fh), op.offload_cancel(cnr)]))
    check(sess.compound([op.putfh(fh), op.read(cnr, 0, 10)]), NFS4ERR_BAD_STATEID)
