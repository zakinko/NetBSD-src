#!/usr/bin/env python3
"""What a line by line reading of RFC 8881 found, each as it was fixed.
Run from pynfs's nfs4.1 directory: t41b.py EXPORT SECEXPORT.  SECEXPORT
starts out open to any port; the script closes it with ssh to try the
rules of NFS4ERR_WRONGSEC.  Failures are the measurement."""
import re, subprocess, sys, time, traceback
import nfs_ops, nfs4client, nfs4lib
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
from server41tests.environment import (create_file, close_file, check,
                                       use_obj, open_file)
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

export = sys.argv[1].strip('/').encode().split(b'/')
sec = sys.argv[2].strip('/').encode().split(b'/')
stamp = b"%d" % int(time.time())
c = nfs4client.NFS4Client(b'127.0.0.1', 2049, 1)
c.homedir = export
refs = []
orig = nfs4client.NFS4Client.op_cb_sequence
def spy(self, arg, env):
    refs.append(arg.csa_referring_call_lists)
    return orig(self, arg, env)
nfs4client.NFS4Client.op_cb_sequence = spy
def sess_of(name):
    return c.new_client_session(stamp + name)
s = sess_of(b"a")
s2 = sess_of(b"b")
time.sleep(2)		# the probe of the backchannel
P = lambda n: export + [stamp + n]
def nofh(fh, *ops):
    return [op.putfh(fh)] + list(ops)
def mk(n, **kw):
    res = create_file(s, stamp + n, path=P(n), **kw)
    check(res)
    return res.resarray[-1].object, res.resarray[-2].stateid
def lockop(sid, owner, off, length):
    return op.lock(WRITE_LT, False, off, length, locker4(
        open_owner=open_to_lock_owner4(0, sid, 0, lock_owner4(0, owner)),
        new_lock_owner=True))
res = s.compound(use_obj(export) + [op.getfh()])
check(res)
dirfh = res.resarray[-1].object

# One section going wrong in python is not to hide the rest.
for part in re.split(r'(?m)^(?=# s)', open(__file__).read().split('\n#--' + 'BODY\n')[1]):
    try:
        exec(part, globals())
    except Exception:
        traceback.print_exc()
        t("section " + part.split('\n')[0], "exception", "none")
print("failures:", fails)
sys.exit(0)

#--BODY
# s14.5, s18.4.3 and the like
bad = b"\xff\xfe" + stamp
for name, o, want in (("LOOKUP", op.lookup(bad), NFS4ERR_INVAL),
                      ("CREATE", op.create(createtype4(NF4DIR), bad, {}), NFS4ERR_INVAL),
                      ("overlong", op.lookup(b"\xc0\xaf"), NFS4ERR_INVAL),
                      ("surrogate", op.lookup(b"\xed\xa0\x80"), NFS4ERR_INVAL),
                      ("cut short", op.lookup(b"a\xe3\x81"), NFS4ERR_INVAL),
                      ("U+10000", op.lookup(b"\xf0\x90\x80\x80"), NFS4ERR_NOENT),
                      ("kana", op.lookup("あ".encode()), NFS4ERR_NOENT)):
    t("s14.5 " + name, s.compound(nofh(dirfh, o)).status, want)

# rfc8881bis s36.25.4
fh, sid = mk(b"deny", deny=OPEN4_SHARE_DENY_WRITE)
t("bis REMOVE under DENY_WRITE", s.compound(nofh(dirfh, op.remove(stamp + b"deny"))).status,
  NFS4ERR_FILE_OPEN)
fh2, sid2 = mk(b"over")
close_file(s, fh2, sid2)
t("bis RENAME over DENY_WRITE", s.compound(nofh(dirfh, op.savefh(),
  op.rename(stamp + b"over", stamp + b"deny"))).status, NFS4ERR_FILE_OPEN)
close_file(s, fh, sid)
t("REMOVE after CLOSE", s.compound(nofh(dirfh, op.remove(stamp + b"deny"))).status, NFS4_OK)

# s9.5
fh, sid = mk(b"lk")
res = open_file(s, b"second", path=P(b"lk"), access=OPEN4_SHARE_ACCESS_BOTH)
check(res)
sid2 = res.resarray[-2].stateid
res = s.compound(nofh(fh, lockop(sid, b"lo", 0, 10)))
t("s9.5 LOCK by one", res.status, NFS4_OK)
res = s.compound(nofh(fh, lockop(sid2, b"lo", 5, 10)))
t("s9.5 LOCK by the other", res.status, NFS4_OK)
close_file(s, fh, sid)
res = open_file(s2, b"x", path=P(b"lk"), access=OPEN4_SHARE_ACCESS_BOTH)
check(res)
xs = res.resarray[-2].stateid
t("s9.5 bytes of the closed open", s2.compound(nofh(fh, lockop(xs, b"x", 0, 5))).status, NFS4_OK)
t("s9.5 bytes of the open left", s2.compound(nofh(fh, op.lockt(WRITE_LT, 5, 10,
  lock_owner4(0, b"y")))).status, NFS4ERR_DENIED)

# s8.2.6
fh, sid = mk(b"sa")
gone = stateid4(0, b'\x01' * 12)
t("s8.2.6 a stateid of nothing", s.compound(nofh(fh, op.setattr(gone,
  {FATTR4_MODE: 0o600}))).status, NFS4ERR_BAD_STATEID)
t("s8.2.6 open stateid", s.compound(nofh(fh, op.setattr(sid,
  {FATTR4_MODE: 0o600}))).status, NFS4_OK)
fx, _ = mk(b"sb")
t("s8.2.6 another file's", s.compound(nofh(fx, op.setattr(sid,
  {FATTR4_MODE: 0o600}))).status, NFS4ERR_BAD_STATEID)

# s18.16.3 the mask of what a truncating OPEN set
close_file(s, fh, sid)
res = s.compound(use_obj(export) + [op.open(0, OPEN4_SHARE_ACCESS_WRITE, 0,
    open_owner4(0, b"tr"), openflag4(OPEN4_CREATE, createhow4(UNCHECKED4,
    {FATTR4_SIZE: 0})), open_claim4(CLAIM_NULL, stamp + b"sa"))])
t("s18.16.3 OPEN truncates", res.status, NFS4_OK)
if res.status == NFS4_OK:
    t("s18.16.3 attrset", bool(nfs4lib.bitmap2list(res.resarray[-1].attrset).count(FATTR4_SIZE)), True)

# s6.2.4
t("s6.2.4 VERIFY of a bad mode", s.compound(nofh(fh, op.verify({FATTR4_MODE: 0o110000}))).status,
  NFS4ERR_INVAL)

# s6.2.5 mode_set_masked: only the masked bits change; W only; INVAL with
# mode, with bits mode has not, and in CREATE or OPEN.
fm, sm = mk(b"mm")
close_file(s, fm, sm)
def mode_of(fh):
    res = s.compound(nofh(fh, op.getattr(nfs4lib.list2bitmap([FATTR4_MODE]))))
    return res.resarray[-1].obj_attributes[FATTR4_MODE] if res.status == 0 else res.status
MM = lambda v, m: {FATTR4_MODE_SET_MASKED: mode_masked4(v, m)}
t("s6.2.5 set 0644", s.compound(nofh(fm, op.setattr(stateid4(0, b"\0" * 12),
  {FATTR4_MODE: 0o644}))).status, NFS4_OK)
res = s.compound(nofh(fm, op.setattr(stateid4(0, b"\0" * 12), MM(0o1070, 0o1050))))
t("s6.2.5 SETATTR", res.status, NFS4_OK)
t("s6.2.5 attrsset", res.status == 0 and nfs4lib.bitmap2list(res.resarray[-1].attrsset),
  [[FATTR4_MODE_SET_MASKED]])
# 0644 under value 1070, mask 1050: the sticky bit set, group r-- to r-x.
t("s6.2.5 the masked bits alone", mode_of(fm), 0o1654)
t("s6.2.5 with mode", s.compound(nofh(fm, op.setattr(stateid4(0, b"\0" * 12),
  {**MM(0, 0o7), FATTR4_MODE: 0o600}))).status, NFS4ERR_INVAL)
t("s6.2.5 an undefined bit", s.compound(nofh(fm, op.setattr(stateid4(0, b"\0" * 12),
  MM(0, 0o10000)))).status, NFS4ERR_INVAL)
t("s6.2.5 GETATTR", s.compound(nofh(fm, op.getattr(nfs4lib.list2bitmap(
  [FATTR4_MODE_SET_MASKED])))).status, NFS4ERR_INVAL)
res = s.compound(nofh(dirfh, op.getattr(nfs4lib.list2bitmap([FATTR4_SUPPORTED_ATTRS]))))
t("s6.2.5 supported", res.status == 0 and FATTR4_MODE_SET_MASKED in
  nfs4lib.bitmap2list(res.resarray[-1].obj_attributes[FATTR4_SUPPORTED_ATTRS]), True)
t("s6.2.5 CREATE", s.compound(nofh(dirfh, op.create(createtype4(NF4DIR),
  stamp + b"mmd", MM(0o755, 0o777)))).status, NFS4ERR_INVAL)
t("s6.2.5 OPEN", s.compound(nofh(dirfh, op.open(0, OPEN4_SHARE_ACCESS_READ, 0,
  open_owner4(0, b"mm"), openflag4(OPEN4_CREATE, createhow4(UNCHECKED4,
  MM(0o644, 0o777))), open_claim4(CLAIM_NULL, stamp + b"mmo")))).status, NFS4ERR_INVAL)

# s18.16.3
res = s.compound(nofh(fh, op.open(0, OPEN4_SHARE_ACCESS_READ, 0, open_owner4(0, b"p"),
    openflag4(OPEN4_NOCREATE), open_claim4(CLAIM_DELEG_PREV_FH))))
t("s18.16.3 CLAIM_DELEG_PREV_FH", res.status, NFS4ERR_NOTSUPP)

# s18.49
wd = lambda fh, w: s.compound(nofh(fh, op.want_delegation(w, deleg_claim4(CLAIM_FH))))
fh, sid = mk(b"wd")
close_file(s, fh, sid)
t("s18.49.3 want nothing", wd(fh, 0).status, NFS4ERR_INVAL)
t("s18.49.3 NO_DELEG", wd(fh, OPEN4_SHARE_ACCESS_WANT_NO_DELEG).status, NFS4ERR_INVAL)
res = wd(fh, OPEN4_SHARE_ACCESS_WANT_CANCEL)
t("s18.49.3 CANCEL", res.status, NFS4_OK)
t("s18.49.3 why", res.resarray[-1].wdr_resok4.od_whynone.ond_why if res.status == 0 else None,
  WND4_CANCELLED)
res = wd(fh, OPEN4_SHARE_ACCESS_WANT_READ_DELEG | OPEN4_SHARE_ACCESS_READ)
t("s18.49.3 READ ignored, read delegation", res.status, NFS4_OK)
d = res.resarray[-1].wdr_resok4 if res.status == 0 else None
t("s18.49 type", d and d.delegation_type, OPEN_DELEGATE_READ)
res = wd(fh, OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG)
t("s18.49 no upgrade", res.resarray[-1].wdr_resok4.od_whynone.ond_why if res.status == 0 else res.status,
  WND4_NOT_SUPP_UPGRADE)
res = wd(dirfh, OPEN4_SHARE_ACCESS_WANT_READ_DELEG)
t("s18.49 a directory", res.resarray[-1].wdr_resok4.od_whynone.ond_why if res.status == 0 else res.status,
  WND4_IS_DIR)
res = s.compound(nofh(dirfh, op.create(createtype4(NF4LNK, linkdata=b"x"), stamp + b"sl", {}),
    op.getfh()))
check(res)
res = wd(res.resarray[-1].object, OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG)
t("s18.49.3 a link", res.resarray[-1].wdr_resok4.od_whynone.ond_why if res.status == 0 else res.status,
  WND4_WRITE_DELEG_NOT_SUPP_FTYPE)

# s8.2.2 the seqid of a recall, s2.10.6.3 what it refers to, with s18.49.4
recalled = []
def hook(arg, env):
    recalled.append(arg.stateid.seqid)
s.client.cb_pre_hook(OP_CB_RECALL, hook)
if d is not None and d.delegation_type == OPEN_DELEGATE_READ:
    ow = open_owner4(0, b"w")
    o = op.open(0, OPEN4_SHARE_ACCESS_WRITE, 0, ow, openflag4(OPEN4_NOCREATE),
                open_claim4(CLAIM_FH))
    t("s10.4 recall by OPEN", s2.compound(nofh(fh, o)).status, NFS4ERR_DELAY)
    for i in range(20):
        if recalled:
            break
        time.sleep(0.5)
    t("s8.2.2 CB_RECALL seqid", recalled, [[0]])
    # s went on using its slot after WANT_DELEGATION, so the reply is
    # retired and there is nothing to refer to.
    print("  referring lists", refs)
    t("s2.10.6.3 retired, no list", refs[-1:], [[[]]])
    t("DELEGRETURN", s.compound(nofh(fh, op.delegreturn(d.read.stateid))).status, NFS4_OK)
    # Now with WANT_DELEGATION the last thing s sent: it MUST be referred to.
    fh3, sid3 = mk(b"wd2")
    close_file(s, fh3, sid3)
    res = wd(fh3, OPEN4_SHARE_ACCESS_WANT_READ_DELEG)
    d3 = res.resarray[-1].wdr_resok4 if res.status == 0 else None
    t("s18.49 second delegation", d3 and d3.delegation_type, OPEN_DELEGATE_READ)
    if d3 is not None and d3.delegation_type == OPEN_DELEGATE_READ:
        del recalled[:]
        del refs[:]
        o = op.open(0, OPEN4_SHARE_ACCESS_WRITE, 0, open_owner4(0, b"w3"),
                    openflag4(OPEN4_NOCREATE), open_claim4(CLAIM_FH))
        t("s10.4 recall by OPEN, again", s2.compound(nofh(fh3, o)).status, NFS4ERR_DELAY)
        for i in range(20):
            if recalled:
                break
            time.sleep(0.5)
        print("  referring lists", refs)
        t("s2.10.6.3 the unretired WANT_DELEGATION", any(l.rcl_sessionid == s.sessionid and
          len(l.rcl_referring_calls) > 0 for l in (refs[-1] if refs else [])), True)
        t("DELEGRETURN", s.compound(nofh(fh3, op.delegreturn(d3.read.stateid))).status, NFS4_OK)

# s18.16.3
res = s.compound(nofh(fh, op.openattr(True), op.open(0, OPEN4_SHARE_ACCESS_BOTH, 0,
    open_owner4(0, b"ea"), openflag4(OPEN4_CREATE, createhow4(EXCLUSIVE4_1,
    ch_createboth=creatverfattr(b"12345678", {}))), open_claim4(CLAIM_NULL, stamp))))
if res.resarray[-1].resop == OP_OPENATTR:
    print("  no named attributes here:", res.status)
else:
    t("s18.16.3 EXCLUSIVE4_1 of a named attribute", res.status, NFS4ERR_INVAL)

# s18.16.4, a resend
how = openflag4(OPEN4_CREATE, createhow4(EXCLUSIVE4_1, ch_createboth=creatverfattr(b"87654321", {})))
ops = use_obj(export) + [op.open(0, OPEN4_SHARE_ACCESS_READ, 0, open_owner4(0, b"ex"), how,
                         open_claim4(CLAIM_NULL, stamp + b"ex")), op.getfh()]
res = s.compound(ops)
t("s18.16.3 EXCLUSIVE4_1", res.status, NFS4_OK)
t("s18.16.4 the same verifier", s.compound(ops).status, NFS4_OK)

# s10.9, s18.39, with the attributes that came with it
rc = subprocess.call(["ssh", "netbsd", "sudo sysctl -w vfs.nfsv4.dirdeleg=1 || sysctl -w vfs.nfsv4.dirdeleg=1"])
res = s.compound(nofh(dirfh, op.create(createtype4(NF4DIR), stamp + b"dd", {}), op.getfh()))
check(res)
ddfh = res.resarray[-1].object
gdd = lambda fh: s.compound(nofh(fh, op.get_dir_delegation(False, 0, nfstime4(0, 0),
                                 nfstime4(0, 0), 0, 0)))
t("s18.39.3 not a directory", gdd(fh).status, NFS4ERR_NOTDIR)
res = gdd(ddfh)
t("s18.39 GET_DIR_DELEGATION", res.status, NFS4_OK)
if res.status == NFS4_OK:
    r = res.resarray[-1].gddr_res_non_fatal4
    t("s18.39 granted", r.gddrnf_status, GDD4_OK)
    t("s18.39.3 no notifications", r.gddrnf_resok4.gddr_notification, (0, []))
    dsid = r.gddrnf_resok4.gddr_stateid
    r = gdd(ddfh).resarray[-1].gddr_res_non_fatal4
    t("s18.39.3 held already", (r.gddrnf_status, r.gddrnf_will_signal_deleg_avail),
      [(GDD4_UNAVAIL, False)])
    n = op.create(createtype4(NF4DIR), stamp + b"in", {})
    t("s10.9 the holder may change it", s.compound(nofh(ddfh, n)).status, NFS4_OK)
    n = op.create(createtype4(NF4DIR), stamp + b"in2", {})
    del recalled[:]
    t("s10.9 another is held off", s2.compound(nofh(ddfh, n)).status, NFS4ERR_DELAY)
    for i in range(20):
        if recalled:
            break
        time.sleep(0.5)
    t("s10.9 recall", recalled, [[0]])
    t("s18.6 returned", s.compound(nofh(ddfh, op.delegreturn(dsid))).status, NFS4_OK)
    t("s10.9 then it goes", s2.compound(nofh(ddfh, n)).status, NFS4_OK)
sc = lambda v: subprocess.call(["ssh", "netbsd", "sudo sysctl -w %s || sysctl -w %s" % (v, v)])
sc("vfs.nfsv4.gdd_unavail_ok=0")
sc("vfs.nfsv4.deleg" + "ations=0")
t("s18.39.3 NFS4ERR_DIRDELEG_UNAVAIL", gdd(ddfh).status, NFS4ERR_DIRDELEG_UNAVAIL)
sc("vfs.nfsv4.gdd_unavail_ok=1")
r = gdd(ddfh)
t("option: GDD4_UNAVAIL", (r.status, r.status == 0 and r.resarray[-1].gddr_res_non_fatal4.gddrnf_status),
  [(NFS4_OK, GDD4_UNAVAIL)])
sc("vfs.nfsv4.deleg" + "ations=2")
rc = subprocess.call(["ssh", "netbsd", "sudo sysctl -w vfs.nfsv4.dirdeleg=0 || sysctl -w vfs.nfsv4.dirdeleg=0"])
t("s18.39 off", gdd(ddfh).status, NFS4ERR_NOTSUPP)
res = s.compound(nofh(dirfh, op.getattr(nfs4lib.list2bitmap([FATTR4_FS_STATUS,
      FATTR4_CHANGE_POLICY, FATTR4_FS_CHARSET_CAP]))))
t("s5.8.2 GETATTR", res.status, NFS4_OK)
print("  attrs", res.resarray[-1].obj_attributes if res.status == NFS4_OK else None)
if res.status == NFS4_OK:
    a = res.resarray[-1].obj_attributes
    t("s11.18 fs_status", a[FATTR4_FS_STATUS].fss_type, STATUS4_WRITABLE)
    t("s14.4 fs_charset_cap", a[FATTR4_FS_CHARSET_CAP], FSCHARSET_CAP4_ALLOWS_ONLY_UTF8)

# s18.36.3: callbacks of version 4, and the fallback to 1 of NFSV4_CB_VERS1.
# pynfs's callback server takes 1 only unless told otherwise.
sc = lambda v: subprocess.call(["ssh", "netbsd", "sudo sysctl -w %s || sysctl -w %s" % (v, v)])
def cbvers(name, fallback, vers):
    sc("vfs.nfsv4.cb_vers1=%d" % fallback)
    saved = c.versions
    c.versions = vers
    try:
        sx = sess_of(b"cbv" + name)
        time.sleep(3)		# the probe
        res = create_file(sx, stamp + b"cbv" + name, path=P(b"cbv" + name))
        check(res)
        fx, sidx = res.resarray[-1].object, res.resarray[-2].stateid
        close_file(sx, fx, sidx)
        res = sx.compound(nofh(fx, op.want_delegation(OPEN4_SHARE_ACCESS_WANT_READ_DELEG,
                                                       deleg_claim4(CLAIM_FH))))
        dx = res.resarray[-1].wdr_resok4 if res.status == 0 else None
        got = dx.delegation_type if dx is not None else res.status
        if got == OPEN_DELEGATE_READ:
            sx.compound(nofh(fx, op.delegreturn(dx.read.stateid)))
        return got
    finally:
        c.versions = saved
        sc("vfs.nfsv4.cb_vers1=1")
t("s18.36.3 version 4 taken", cbvers(b"a", 0, [4]), OPEN_DELEGATE_READ)
t("s18.36.3 a client of 1 only, no backchannel", cbvers(b"b", 0, [1]), OPEN_DELEGATE_NONE_EXT)
t("option: falls back to 1", cbvers(b"c", 1, [1]), OPEN_DELEGATE_READ)

# s10.2: a change through the server of NFSv3 recalls too.  nfsd(8) on UDP
# only, as the module has TCP 2049; the client is the VM's own.
# Soft, and bounded: a hard mount of a server that does not answer hung
# the whole script until its timeout (run 43022459488).  -u, NFS itself
# on UDP: -U is the mount protocol only, and NFS was asked for on TCP,
# which nfsd -u does not register (run 43026343439, "Program not
# registered" with 100003 on udp alone in rpcinfo).  Each ssh is held
# under the lease of 90 s and s, s2 renewed around it: a wait of 120 s
# let them expire, and s8.4.3 and s2.6.3.1.1 after it with them.
def alive():
    s.compound([])
    s2.compound([])
def vmcall(cmd, timeout=60):
    try:
        return subprocess.call(["ssh", "netbsd", cmd], timeout=timeout)
    except subprocess.TimeoutExpired:
        return "timed out"
    finally:
        alive()
alive()
v3 = vmcall("sh -c 'pgrep -x nfsd >/dev/null || /usr/sbin/nfsd -u -n 2; "
            "sleep 1; rpcinfo -p 127.0.0.1; pgrep -lx nfsd; "
            "mkdir -p /mnt/v3; mount | grep -q /mnt/v3 || "
            "mount_nfs -3 -u -U -s -x 2 -t 30 127.0.0.1:/%s /mnt/v3'" % b"/".join(export).decode())
print("  NFSv3 mount:", v3)
if v3 == 0:
    for name, cmd in ((b"v3t", "touch"), (b"v3r", "rm")):
        fv, sv = mk(name)
        close_file(s, fv, sv)
        res = wd(fv, OPEN4_SHARE_ACCESS_WANT_READ_DELEG)
        dv = res.resarray[-1].wdr_resok4 if res.status == 0 else None
        t("s10.2 delegation for " + cmd, dv and dv.delegation_type, OPEN_DELEGATE_READ)
        if dv is None or dv.delegation_type != OPEN_DELEGATE_READ:
            continue
        del recalled[:]
        p = subprocess.Popen(["ssh", "netbsd", "%s /mnt/v3/%s" % (cmd, (stamp + name).decode())])
        for i in range(30):
            if recalled:
                break
            time.sleep(0.5)
        t("s10.2 recall by NFSv3 " + cmd, recalled, [[0]])
        s.compound(nofh(fv, op.delegreturn(dv.read.stateid)))
        try:
            t("s10.2 the NFSv3 " + cmd + " then goes", p.wait(timeout=60), 0)
        except subprocess.TimeoutExpired:
            p.kill()
            t("s10.2 the NFSv3 " + cmd + " then goes", "timed out", 0)
        alive()
    vmcall("umount -f /mnt/v3")

# s11.17 fs_locations_info, here and at the referral in.vm.sh sets up
gli = lambda ops: s.compound(ops + [op.getattr(nfs4lib.list2bitmap([FATTR4_FS_LOCATIONS_INFO]))])
res = gli(nofh(dirfh))
t("s11.17 GETATTR fs_locations_info", res.status, NFS4_OK)
if res.status == NFS4_OK:
    li = res.resarray[-1].obj_attributes[FATTR4_FS_LOCATIONS_INFO]
    print("  ", li)
    t("s11.17.2 one item here", len(li.fli_items), 1)
    e = li.fli_items[0].fli_entries
    t("s11.17.1 this replica: CUR_REQ, WRITABLE", [(x.fls_info[0], len(x.fls_info), x.fls_server) for x in e],
      [[(FSLI4GF_CUR_REQ | FSLI4GF_WRITABLE, 12, b"")]])
res = gli(use_obj([b"export", b"ref", b"there"]))
t("s11.17 at a referral", res.status, NFS4_OK)
if res.status == NFS4_OK:
    li = res.resarray[-1].obj_attributes[FATTR4_FS_LOCATIONS_INFO]
    print("  ", li)
    t("s11.17.2 the referral's locations, no CUR_REQ",
      [([x.fls_server for x in i.fli_entries], [x.fls_info[0] for x in i.fli_entries])
       for i in li.fli_items],
      [[([b"srv1", b"srv2"], [0, 0]), ([b"srv3"], [0])]])

# s18.35.4 case 3: the same owner from another flavour, with state, is
# CLID_INUSE (ESXi counts on this when it mixes sec= on one server).
# The client's default credential is AUTH_NONE (rpc.py, CredInfo() with
# no sec), so the other flavour is AUTH_SYS: an AUTH_NONE here was the
# same principal, case 2, and OK was right (run 43026343439).
from rpc.security import AuthSys
sf = sess_of(b"flv")
res = create_file(sf, stamp + b"flv", path=P(b"flv"))
check(res)
# AUTH_NONE is uid (uid_t)-1 to the server (auth_none_verify(),
# nfsv4_client_principal()); AUTH_SYS with that uid differs in the
# flavour alone, which is what a8c5128aac0 added, and uid 0 in both.
print("  first flavour", c.default_cred.flavor)
for name, uid in (("the flavour alone", 0xffffffff), ("uid too", 0)):
    other = AuthSys().init_cred(uid=uid, gid=uid)
    res = c.compound([op.exchange_id(client_owner4(c.verifier, stamp + b"flv"), 0,
                                     state_protect4_a(SP4_NONE), [c.impl_id])],
                     other)
    t("s18.35.4 another flavour, CLID_INUSE, " + name, res.status, NFS4ERR_CLID_INUSE)

# s20.11 CB_NOTIFY_LOCK: OPEN says it may come (s20.11.3), and a LOCKU
# over a denied WRITEW_LT sends it to the waiter, with its lock_owner4.
res = create_file(s, stamp + b"nl", path=P(b"nl"), access=OPEN4_SHARE_ACCESS_BOTH)
check(res)
t("s20.11.3 OPEN4_RESULT_MAY_NOTIFY_LOCK",
  bool(res.resarray[-2].rflags & OPEN4_RESULT_MAY_NOTIFY_LOCK), True)
fn, sn = res.resarray[-1].object, res.resarray[-2].stateid
res = s.compound(nofh(fn, lockop(sn, b"nl1", 0, 10)))
t("s20.11 the first LOCK", res.status, NFS4_OK)
ls = res.resarray[-1].lock_stateid if res.status == 0 else None
res = open_file(s2, b"nl2", path=P(b"nl"), access=OPEN4_SHARE_ACCESS_BOTH)
check(res)
sn2 = res.resarray[-2].stateid
notified = []
def nhook(arg, env):
    notified.append((arg.cnla_fh, arg.cnla_lock_owner.owner))
s2.client.cb_pre_hook(OP_CB_NOTIFY_LOCK, nhook)
w = op.lock(WRITEW_LT, False, 0, 10, locker4(
    open_owner=open_to_lock_owner4(0, sn2, 0, lock_owner4(0, b"nl2")),
    new_lock_owner=True))
t("s20.11 WRITEW_LT denied", s2.compound(nofh(fn, w)).status, NFS4ERR_DENIED)
if ls is not None:
    t("s20.11 LOCKU", s.compound(nofh(fn, op.locku(WRITE_LT, 0, ls, 0, 10))).status, NFS4_OK)
    for i in range(20):
        if notified:
            break
        time.sleep(0.5)
    t("s20.11 CB_NOTIFY_LOCK to the waiter", notified, [[(fn, b"nl2")]])

# s8.4.3: a lock of an expired lease does not stand in the way
s3 = sess_of(b"gone")
res = create_file(s3, stamp + b"exp", path=P(b"exp"))
check(res)
fh, sid = res.resarray[-1].object, res.resarray[-2].stateid
t("s8.4.3 LOCK", s3.compound(nofh(fh, lockop(sid, b"z", 0, 10))).status, NFS4_OK)
sid4 = None
res = open_file(s2, b"late", path=P(b"exp"), access=OPEN4_SHARE_ACCESS_BOTH)
check(res)
sid4 = res.resarray[-2].stateid
print("  letting the lease run out"); sys.stdout.flush()
for i in range(47):		# s and s2 live on
    time.sleep(2)
    s.compound([])
    s2.compound([])
seen = []
for i in range(20):
    st = s2.compound(nofh(fh, lockop(sid4, b"late", 0, 10))).status
    seen.append(st)
    if st != NFS4ERR_DELAY:
        break
    time.sleep(1)
print("  statuses", seen)
t("s8.4.3 the conflicting LOCK", seen[-1], NFS4_OK)

# s2.6.3.1.1
res = s.compound(use_obj(sec) + [op.getfh()])
check(res)
secfh = res.resarray[-1].object
res = s.compound(nofh(secfh, op.create(createtype4(NF4DIR), stamp + b"d", {}), op.getfh()))
check(res)
subfh = res.resarray[-1].object
res = create_file(s, stamp + b"f", path=sec + [stamp + b"f"])
check(res)
secfile, sid = res.resarray[-1].object, res.resarray[-2].stateid
close_file(s, secfile, sid)
rc = subprocess.call(["ssh", "netbsd", "sh -c \"sed -i.bak '/^%s /s/ -noresvport//' "
                      "/etc/exports && kill -HUP \\$(cat /var/run/mountd.pid)\""
                      % sys.argv[2].replace('/', '\\/')])
print("  closing the export:", rc)
time.sleep(3)
def ws(name, ops, status, last):
    res = s.compound(ops)
    t("s2.6.3.1.1 " + name, (res.status, res.resarray[-1].resop), [(status, last)])
OK, WS = NFS4_OK, NFS4ERR_WRONGSEC
g = op.getattr(1 << FATTR4_TYPE)
ws("alone", [op.putfh(secfh)], OK, OP_PUTFH)
ws("then GETATTR", [op.putfh(secfh), g], WS, OP_PUTFH)
ws("then LOOKUP", [op.putfh(secfh), op.lookup(stamp + b"f")], WS, OP_LOOKUP)
ws("SAVEFH passes", [op.putfh(secfh), op.savefh(), op.lookup(stamp + b"f")], WS, OP_LOOKUP)
ws("SAVEFH then GETATTR", [op.putfh(secfh), op.savefh(), g], WS, OP_PUTFH)
ws("then LOOKUPP", [op.putfh(subfh), op.lookupp()], WS, OP_LOOKUPP)
ws("then SECINFO", [op.putfh(secfh), op.secinfo(stamp + b"f")], OK, OP_SECINFO)
ws("then SECINFO_NO_NAME", [op.putfh(secfh), op.secinfo_no_name(SECINFO_STYLE4_CURRENT_FH)],
   OK, OP_SECINFO_NO_NAME)
ws("two puts", [op.putfh(secfh), op.putfh(dirfh), g], OK, OP_GETATTR)
ws("RESTOREFH", [op.putfh(secfh), op.savefh(), op.putfh(dirfh), op.restorefh(), g], WS,
   OP_RESTOREFH)
ws("LINK of the saved", [op.putfh(secfile), op.savefh(), op.putfh(dirfh),
   op.link(stamp + b"ln")], WS, OP_LINK)
noc = op.open(0, OPEN4_SHARE_ACCESS_READ, 0, open_owner4(0, b"ws"), openflag4(OPEN4_NOCREATE),
              open_claim4(CLAIM_NULL, stamp + b"f"))
ws("OPEN of a name", [op.putfh(secfh), noc], WS, OP_OPEN)
cre = op.open(0, OPEN4_SHARE_ACCESS_READ, 0, open_owner4(0, b"ws"),
              openflag4(OPEN4_CREATE, createhow4(UNCHECKED4, {})),
              open_claim4(CLAIM_NULL, stamp + b"new"))
ws("OPEN to create", [op.putfh(secfh), cre], WS, OP_PUTFH)
byfh = op.open(0, OPEN4_SHARE_ACCESS_READ, 0, open_owner4(0, b"ws"), openflag4(OPEN4_NOCREATE),
               open_claim4(CLAIM_FH))
ws("OPEN by handle", [op.putfh(secfile), byfh], WS, OP_PUTFH)

# s4.2.2, the receiving end of a migration: vfs.nfsv4.arrived names the
# fsid of the old server's handles.  Here an fsid made up for it stands
# for the old server, and the file system is the export itself.
import struct
sc = lambda v: subprocess.call(["ssh", "netbsd", "sudo sysctl -w %s || sysctl -w %s" % (v, v)])
fh, sid = mk(b"arr")
fake = struct.pack("<II", 0x0badf00d, 0x0000beef)	# f_fsidx, amd64
old = fh[:4] + fake + fh[12:]
t("s4.2.2 an unknown fsid before", s.compound([op.putfh(old)]).status,
  NFS4ERR_STALE)
sc("'vfs.nfsv4.arrived=0badf00d:0000beef /%s'" % b"/".join(export).decode())
res = s.compound([op.putfh(old), op.getattr(nfs4lib.list2bitmap([FATTR4_FILEID])),
                  op.getfh()])
t("s4.2.2 the old server's handle", res.status, NFS4_OK)
if res.status == NFS4_OK:
    t("s4.2.2 and handles made here stay the old ones",
      res.resarray[-1].object, old)
res = s.compound([op.putfh(dirfh), op.lookup(stamp + b"arr"), op.getfh()])
t("s4.2.2 LOOKUP gives the old server's handle",
  res.resarray[-1].object if res.status == NFS4_OK else res.status, old)
sc("vfs.nfsv4.arrived=")
res = s.compound([op.putfh(dirfh), op.lookup(stamp + b"arr"), op.getfh()])
t("s4.2.2 forgotten, handles are this server's again",
  res.resarray[-1].object if res.status == NFS4_OK else res.status, fh)
