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

# s20.2.3 the seqid of a recall, that of the delegation as given (s8.2.2's
# 0 is for what a client sends), s2.10.6.3 what it refers to, s18.49.4
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
    t("s20.2.3 CB_RECALL seqid, the delegation's", recalled,
      [[d.read.stateid.seqid]])
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
    t("s10.9 recall, the delegation's seqid (s20.2.3)", recalled,
      [[dsid.seqid]])
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

# s18.36.3 and its errata 2291: callbacks of version 1 by default; 4, the
# text of RFC 8881, under vfs.nfsv4.cb_vers4, with the fallback to 1 of
# vfs.nfsv4.cb_vers1.  pynfs's callback server takes 1 only unless told
# otherwise.
sc = lambda v: subprocess.call(["ssh", "netbsd", "sudo sysctl -w %s || sysctl -w %s" % (v, v)])
def cbvers(name, v4, fallback, vers):
    sc("vfs.nfsv4.cb_vers4=%d" % v4)
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
        sc("vfs.nfsv4.cb_vers4=0")
        sc("vfs.nfsv4.cb_vers1=1")
t("errata 2291: version 1 by default", cbvers(b"d", 0, 1, [1]), OPEN_DELEGATE_READ)
t("errata 2291: a client of 4 only, no backchannel", cbvers(b"e", 0, 1, [4]), OPEN_DELEGATE_NONE_EXT)
t("cb_vers4: version 4 taken", cbvers(b"a", 1, 0, [4]), OPEN_DELEGATE_READ)
t("cb_vers4: a client of 1 only, no backchannel", cbvers(b"b", 1, 0, [1]), OPEN_DELEGATE_NONE_EXT)
t("cb_vers4 and cb_vers1: falls back to 1", cbvers(b"c", 1, 1, [1]), OPEN_DELEGATE_READ)

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
        t("s10.2 recall by NFSv3 " + cmd, recalled,
          [[dv.read.stateid.seqid]])
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

# s2.9.1: UDP by itself MUST NOT be a transport of 4.1, and s15.1.3.2 has
# a listener without the minor version say NFS4ERR_MINOR_VERS_MISMATCH,
# with no results.  4.0 is still served there.  In the VM, as the tunnel
# carries TCP only (udp41.c).
p = subprocess.run(["ssh", "netbsd", "/var/tmp/nfsv4/udp41"],
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
out = p.stdout.decode()
print("  udp41:", out.strip().replace("\n", "; "))
alive()
def udp(m):
    r = re.search(r"minor %d: (.*)" % m, out)
    return r.group(1) if r else out.strip()
t("s2.9.1 4.0 over UDP", udp(0), "status 0, results 0")
t("s2.9.1 4.1 over UDP, s15.1.3.2", udp(1), "status %d, results 0" % NFS4ERR_MINOR_VERS_MISMATCH)

# s5.8.2.5 change_policy MUST change with fs_locations, which a referral
# added changes, and when the file system goes read-only or back.  The
# latter on a mount of its own, exported for this and taken away after.
cpol = lambda ops: s.compound(ops + [op.getattr(nfs4lib.list2bitmap([FATTR4_CHANGE_POLICY]))])
def chp(ops):
    res = cpol(ops)
    if res.status != NFS4_OK:
        return res.status
    v = res.resarray[-1].obj_attributes[FATTR4_CHANGE_POLICY]
    return (v.cp_major, v.cp_minor)
before = chp(nofh(dirfh))
vmcall("sh -c 'mkdir -p /%s/%s && sysctl -w \"vfs.nfsv4.referral=/%s/%s srvcp:/cp\"'" % (
    b"/".join(export).decode(), (stamp + b"cpref").decode(),
    b"/".join(export).decode(), (stamp + b"cpref").decode()))
after = chp(nofh(dirfh))
print("  change_policy", before, after)
t("s5.8.2.5 a referral added changes it", isinstance(after, tuple) and after != before, True)
vmcall("sh -c 'mkdir -p /export/cpol && mount_tmpfs -s 1m tmpfs /export/cpol && "
       "echo \"/export/cpol -maproot=root -noresvport\" >>/etc/exports && "
       "kill -HUP $(cat /var/run/mountd.pid); sleep 2'")
cp = [b"export", b"cpol"]
rw = chp(use_obj(cp))
vmcall("sh -c 'mount -u -r /export/cpol; mount | grep cpol'")
ro = chp(use_obj(cp))
vmcall("sh -c 'mount -u -w /export/cpol; mount | grep cpol'")
rw2 = chp(use_obj(cp))
print("  change_policy rw, ro, rw", rw, ro, rw2)
t("s5.8.2.5 the mount made read-only changes it", isinstance(ro, tuple) and ro != rw, True)
t("s5.8.2.5 and writable again", isinstance(rw2, tuple) and rw2 != ro, True)
vmcall("sh -c 'sed -i.bak /cpol/d /etc/exports && kill -HUP $(cat /var/run/mountd.pid); "
       "sleep 2; umount /export/cpol'")

# s18.4.3: with FSCHARSET_CAP4_ALLOWS_ONLY_UTF8 the content of a symbolic
# link MUST be UTF-8; s14.5 makes what is not NFS4ERR_INVAL.
lnk = lambda n, data: s.compound(nofh(dirfh, op.create(createtype4(NF4LNK, linkdata=data),
                                                       stamp + n, {}))).status
t("s18.4.3 a link to bytes that are not UTF-8", lnk(b"sl8bad", b"\xff\xfe" + stamp), NFS4ERR_INVAL)
t("s18.4.3 an overlong form", lnk(b"sl8ovl", b"a\xc0\xafb"), NFS4ERR_INVAL)
t("s18.4.3 a link to UTF-8", lnk(b"sl8ok", "あ/い".encode()), NFS4_OK)

# s18.23.3: a cookie SHOULD NOT change when the directory is modified.
# Named attributes, on the export that has them (FFS with 2ea), set in
# the VM; the cookie of "c" before and after "a" goes, and READDIR from
# the cookie of "b" after that.
aexp = [b"export", b"acl"]
xf = "/export/acl/%s" % (stamp + b"xa").decode()
vmcall("sh -c 'touch %s && for n in a b c; do setextattr user $n v %s; done; lsextattr user %s'" %
       (xf, xf, xf))
res = s.compound(use_obj(aexp + [stamp + b"xa"]) + [op.openattr(False), op.getfh()])
t("s18.23.3 OPENATTR", res.status, NFS4_OK)
if res.status == NFS4_OK:
    adir = res.resarray[-1].object
    def ck(cookie=0):
        res = s.compound([op.putfh(adir), op.readdir(cookie, b"\0" * 8, 4096, 8192, 0)])
        if res.status != NFS4_OK:
            return res.status
        return dict((e.name, e.cookie) for e in res.resarray[-1].reply.entries)
    c1 = ck()
    vmcall("rmextattr user a %s" % xf)
    c2 = ck()
    print("  cookies", c1, c2)
    t("s18.23.3 the cookie of c stays", isinstance(c1, dict) and isinstance(c2, dict) and
      c1.get(b"c") is not None and c1.get(b"c") == c2.get(b"c"), True)
    t("s18.23.3 none of 0, 1, 2", isinstance(c2, dict) and all(v > 2 for v in c2.values()), True)
    t("s18.23.3 on from the cookie of b", sorted(ck(c1[b"b"]).keys()) if isinstance(c1, dict) and b"b" in c1 else c1,
      [sorted(k for k in c2 if c2[k] > c1[b"b"])] if isinstance(c1, dict) and b"b" in c1 and isinstance(c2, dict) else [None])
res = s.compound([op.putrootfh(), op.readdir(0, b"\0" * 8, 4096, 8192, 0)])
t("s18.23.3 the pseudo root still lists export",
  res.status == NFS4_OK and b"export" in [e.name for e in res.resarray[-1].reply.entries], True)

# s5.8.1.1 supported_attrs, with the set-only time_access_set (48) and
# time_modify_set (54), which SETATTR takes.
res = s.compound(nofh(dirfh, op.getattr(nfs4lib.list2bitmap([FATTR4_SUPPORTED_ATTRS]))))
sup = res.resarray[-1].obj_attributes[FATTR4_SUPPORTED_ATTRS] if res.status == NFS4_OK else res.status
t("s5.8.1.1 supported_attrs has 48 and 54",
  [bool(sup >> FATTR4_TIME_ACCESS_SET & 1), bool(sup >> FATTR4_TIME_MODIFY_SET & 1)]
  if isinstance(sup, int) else sup, [[True, True]])

# s6.2.1.3.1, s6.2.1.3.2, s6.4.3: what an ACL lets AUTH_SYS uid 1111 gid
# 37 do, who owns none of the objects.  On the export with ACLs.
from rpc.security import AuthSys
au = AuthSys().init_cred(uid=1111, gid=37, name=b"t41b")
anon = stateid4(0, b"\0" * 12)
A_, D_ = ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_ACCESS_DENIED_ACE_TYPE
RA = ACE4_READ_ATTRIBUTES | ACE4_READ_ACL | ACE4_SYNCHRONIZE
own = nfsace4(A_, 0, 0x1f01ff, b"OWNER@")
ev = lambda t_, m: nfsace4(t_, 0, m, b"EVERYONE@")
res = s.compound(use_obj(aexp) + [op.create(createtype4(NF4DIR), stamp + b"acl",
                 {FATTR4_MODE: 0o777}), op.getfh()])
check(res)
atop = res.resarray[-1].object
def amk(parent, n, acl, dir=False, data=b""):
    if dir:
        res = s.compound([op.putfh(parent), op.create(createtype4(NF4DIR), n,
                          {FATTR4_MODE: 0o755}), op.getfh()])
        check(res)
        fh = res.resarray[-1].object
    else:
        res = s.compound([op.putfh(parent), op.open(0, OPEN4_SHARE_ACCESS_WRITE |
            OPEN4_SHARE_ACCESS_WANT_NO_DELEG, OPEN4_SHARE_DENY_NONE,
            open_owner4(0, stamp + n), openflag4(OPEN4_CREATE, createhow4(GUARDED4,
            {FATTR4_MODE: 0o600})), open_claim4(CLAIM_NULL, n)), op.getfh()])
        check(res)
        fh, osid = res.resarray[-1].object, res.resarray[-2].stateid
        if data:
            check(s.compound([op.putfh(fh), op.write(osid, 0, FILE_SYNC4, data)]))
        s.compound([op.putfh(fh), op.close(0, osid)])
    if acl is not None:
        check(s.compound([op.putfh(fh), op.setattr(anon, {FATTR4_ACL: acl})]))
    return fh
# s6.2.1.3.1 ACE4_READ_DATA / ACE4_EXECUTE: READ with EXECUTE alone
fx = amk(atop, b"xonly", [own, ev(A_, ACE4_EXECUTE | RA)], data=b"hello")
res = s.compound([op.putfh(fx), op.read(anon, 0, 5)], credinfo=au)
t("s6.2.1.3.1 READ with only ACE4_EXECUTE allowed", res.status, NFS4_OK)
res = s.compound([op.putfh(fx), op.access(ACCESS4_READ | ACCESS4_EXECUTE)], credinfo=au)
t("s6.2.1.3.1 ACCESS tells EXECUTE from READ",
  (res.resarray[-1].supported, res.resarray[-1].access) if res.status == NFS4_OK else res.status,
  [(ACCESS4_READ | ACCESS4_EXECUTE, ACCESS4_EXECUTE)])
res = s.compound([op.putfh(fx), op.getattr(nfs4lib.list2bitmap([FATTR4_ACL]))])
evm = [a.access_mask for a in res.resarray[-1].obj_attributes[FATTR4_ACL]
       if a.who == b"EVERYONE@" and a.type == A_] if res.status == NFS4_OK else res.status
print("  EVERYONE@ allows", evm)
t("s6.2.1.3.1 EXECUTE set alone stays alone, no READ_DATA",
  isinstance(evm, list) and len(evm) > 0 and all(m & ACE4_EXECUTE and not m & ACE4_READ_DATA for m in evm), True)
# s6.2.1.3.1 ACE4_APPEND_DATA without ACE4_WRITE_DATA
fa = amk(atop, b"append", [own, ev(D_, ACE4_WRITE_DATA), ev(A_, ACE4_APPEND_DATA | ACE4_READ_DATA | RA)],
         data=b"hello")
res = s.compound([op.putfh(fa), op.write(anon, 0, FILE_SYNC4, b"X")], credinfo=au)
t("s6.2.1.3.1 WRITE not at EOF with APPEND_DATA only", res.status, NFS4ERR_ACCESS)
res = s.compound([op.putfh(fa), op.write(anon, 5, FILE_SYNC4, b"X")], credinfo=au)
print("  WRITE at EOF with APPEND_DATA only:", res.status)
# s6.2.1.3.2: neither DELETE nor DELETE_CHILD said, no MODE4_SVTX: allowed
# if and only if ACE4_ADD_FILE is.
for case, dacl, want in (("ADD_FILE", [own, ev(A_, ACE4_ADD_FILE | ACE4_EXECUTE | ACE4_READ_DATA | RA)], NFS4_OK),
                         ("no ADD_FILE", [own, ev(A_, ACE4_EXECUTE | ACE4_READ_DATA | RA)], NFS4ERR_ACCESS)):
    d = amk(atop, b"rm " + case.encode(), dacl, dir=True)
    amk(d, b"f", [own, ev(A_, ACE4_READ_DATA | RA)])
    res = s.compound([op.putfh(d), op.remove(b"f")], credinfo=au)
    t("s6.2.1.3.2 REMOVE, silent ACLs, " + case, res.status,
      want if want == NFS4_OK else [NFS4ERR_ACCESS, NFS4ERR_PERM])
# s6.4.3: after an EXCLUSIVE4 create, the owner's SETATTR SHOULD succeed
# whatever the object was made with.
d = amk(atop, b"excl", [own, ev(A_, ACE4_ADD_FILE | ACE4_EXECUTE | ACE4_READ_DATA | RA)], dir=True)
res = s.compound([op.putfh(d), op.open(0, OPEN4_SHARE_ACCESS_WRITE | OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
    OPEN4_SHARE_DENY_NONE, open_owner4(0, stamp + b"ex"),
    openflag4(OPEN4_CREATE, createhow4(EXCLUSIVE4, createverf=b"t41bexcl")),
    open_claim4(CLAIM_NULL, b"e")), op.getfh()], credinfo=au)
t("s6.4.3 OPEN EXCLUSIVE4 by uid 1111", res.status, NFS4_OK)
if res.status == NFS4_OK:
    efh, esid = res.resarray[-1].object, res.resarray[-2].stateid
    res = s.compound([op.putfh(efh), op.setattr(esid, {FATTR4_MODE: 0o640})], credinfo=au)
    t("s6.4.3 the owner's SETATTR of mode after it", res.status, NFS4_OK)
    res = s.compound([op.putfh(efh), op.setattr(esid, {FATTR4_ACL: [own, ev(A_, ACE4_READ_DATA | RA)]})],
                     credinfo=au)
    t("s6.4.3 the owner's SETATTR of acl after it", res.status, NFS4_OK)
    s.compound([op.putfh(efh), op.close(0, esid)], credinfo=au)

# s2.10.13.2.4, s2.10.6.2, s18.46.3: a callback left without a reply MUST
# be sent again, with its session, slot and sequence ID.  The first recall
# is held past the server's 5 s; the recall of another delegation that
# comes next must not go at that sequence ID, which the client would take
# for the retry and answer from its reply cache.
# pynfs's handle_1 answers a retry from its reply cache with env unset
# (UnboundLocalError, so no reply at all); this is that with env set.
import inspect, textwrap
h1 = nfs4client.NFS4Client.handle_1
src = textwrap.dedent(inspect.getsource(h1)).replace(
    "    try:\n        # SEQUENCE", "    env = None\n    try:\n        # SEQUENCE", 1).replace(
    "    unpacker.done()\n", "    unpacker.done()\n    _t41b_seen(args)\n", 1)
seen = []	# (seqid, the stateid's other of a CB_RECALL), each call as it came
def _t41b_seen(args):
    q = o = None
    for a in args.argarray:
        if a.argop == OP_CB_SEQUENCE:
            q = a.switch.csa_sequenceid
        elif a.argop == OP_CB_RECALL:
            o = a.switch.stateid.other
    seen.append((q, o))
nfs4client._t41b_seen = _t41b_seen
ns = {}
exec(src, nfs4client.__dict__, ns)
nfs4client.NFS4Client.handle_1 = ns["handle_1"]
seqs = []
orig2 = nfs4client.NFS4Client.op_cb_sequence
def spy2(self, arg, env):
    seqs.append(arg.csa_sequenceid)
    return orig2(self, arg, env)
nfs4client.NFS4Client.op_cb_sequence = spy2
got = []
def rhook(arg, env):
    got.append((seqs[-1] if seqs else None, arg.stateid.other))
    if len(got) == 1:
        time.sleep(7)
s.client.cb_pre_hook(OP_CB_RECALL, rhook)
dl = []
for n in (b"rtA", b"rtB"):
    f, sd = mk(n)
    close_file(s, f, sd)
    res = wd(f, OPEN4_SHARE_ACCESS_WANT_READ_DELEG)
    dd = res.resarray[-1].wdr_resok4 if res.status == 0 else None
    dl.append((f, dd.read.stateid if dd is not None and dd.delegation_type == OPEN_DELEGATE_READ else None))
t("s2.10.13.2.4 two read delegations", [x[1] is not None for x in dl], [[True, True]])
if dl[0][1] is not None and dl[1][1] is not None:
    wo = lambda n: op.open(0, OPEN4_SHARE_ACCESS_WRITE, 0, open_owner4(0, n),
                           openflag4(OPEN4_NOCREATE), open_claim4(CLAIM_FH))
    s2.compound(nofh(dl[0][0], wo(b"rtwa")))
    for i in range(20):
        if got:
            break
        time.sleep(0.5)
    time.sleep(8)
    s2.compound(nofh(dl[1][0], wo(b"rtwb")))
    for i in range(60):
        if any(o == dl[1][1].other for q, o in got):
            break
        time.sleep(0.5)
    print("  recalls (seqid, which)", [(q, "A" if o == dl[0][1].other else "B") for q, o in got])
    print("  CB_SEQUENCE seqids", seqs)
    qa = got[0][0] if got else None
    qb = [q for q, o in got if o == dl[1][1].other]
    t("s2.10.6.2 the next recall is not at the unanswered one's sequence ID",
      qa is not None and len(qb) > 0 and qb[0] > qa, True)
    print("  calls (seqid, which)", [(q, "A" if o == dl[0][1].other else "B" if o == dl[1][1].other else o)
                                     for q, o in seen])
    t("s2.10.13.2.4 the unanswered one went again at its sequence ID",
      qa is not None and seen.count((qa, dl[0][1].other)) >= 2, True)
    t("s2.10.6.2 nothing else went at that sequence ID",
      [o for q, o in seen if q == qa and o != dl[0][1].other], [[]])
    for f, d_ in dl:
        s.compound(nofh(f, op.delegreturn(d_)))
nfs4client.NFS4Client.op_cb_sequence = orig2
nfs4client.NFS4Client.handle_1 = h1
s.client.cb_pre_hook(OP_CB_RECALL, hook)
