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
for sec in re.split(r'(?m)^(?=# s)', open(__file__).read().split('\n#--' + 'BODY\n')[1]):
    try:
        exec(sec, globals())
    except Exception:
        traceback.print_exc()
        t("section " + sec.split('\n')[0], "exception", "none")
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
    t("s18.16.3 attrset", FATTR4_SIZE in res.resarray[-1].attrset, True)

# s6.2.4
t("s6.2.4 VERIFY of a bad mode", s.compound(nofh(fh, op.verify({FATTR4_MODE: 0o110000}))).status,
  NFS4ERR_INVAL)

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
c.cb_pre_hook(OP_CB_RECALL, hook)
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
    print("  referring lists", refs)
    t("s2.10.6.3 lists", bool(refs and refs[-1]), True)
    t("DELEGRETURN", s.compound(nofh(fh, op.delegreturn(d.read.stateid))).status, NFS4_OK)

# s18.16.3
res = s.compound(nofh(fh, op.openattr(True), op.open(0, OPEN4_SHARE_ACCESS_BOTH, 0,
    open_owner4(0, b"ea"), openflag4(OPEN4_CREATE, createhow4(EXCLUSIVE4_1,
    ch_createboth=creatverfattr(b"12345678", {}))), open_claim4(CLAIM_NULL, stamp))))
t("s18.16.3 EXCLUSIVE4_1 of a named attribute", res.status, NFS4ERR_INVAL)

# s18.16.4, a resend
how = openflag4(OPEN4_CREATE, createhow4(EXCLUSIVE4_1, ch_createboth=creatverfattr(b"87654321", {})))
ops = use_obj(export) + [op.open(0, OPEN4_SHARE_ACCESS_READ, 0, open_owner4(0, b"ex"), how,
                         open_claim4(CLAIM_NULL, stamp + b"ex")), op.getfh()]
res = s.compound(ops)
t("s18.16.3 EXCLUSIVE4_1", res.status, NFS4_OK)
t("s18.16.4 the same verifier", s.compound(ops).status, NFS4_OK)

# s10.9, s18.39, with the attributes that came with it
rc = subprocess.call(["ssh", "netbsd", "sudo sysctl -w vfs.nfsv4.dirdeleg=1"])
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
      (GDD4_UNAVAIL, False))
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
rc = subprocess.call(["ssh", "netbsd", "sudo sysctl -w vfs.nfsv4.dirdeleg=0"])
t("s18.39 off", gdd(ddfh).status, NFS4ERR_DIRDELEG_UNAVAIL)
res = s.compound(nofh(dirfh, op.getattr(nfs4lib.list2bitmap([FATTR4_FS_STATUS,
      FATTR4_CHANGE_POLICY, FATTR4_FS_CHARSET_CAP]))))
t("s5.8.2 GETATTR", res.status, NFS4_OK)
print("  attrs", res.resarray[-1].obj_attributes if res.status == NFS4_OK else None)
if res.status == NFS4_OK:
    a = res.resarray[-1].obj_attributes
    t("s11.18 fs_status", a[FATTR4_FS_STATUS].fss_type, STATUS4_WRITABLE)
    t("s14.4 fs_charset_cap", a[FATTR4_FS_CHARSET_CAP], FSCHARSET_CAP4_ALLOWS_ONLY_UTF8)

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
for i in range(47):		# s2 lives on
    time.sleep(2)
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
rc = subprocess.call(["ssh", "netbsd", "sudo sh -c \"sed -i.bak '/^%s /s/ -noresvport//' "
                      "/etc/exports && kill -HUP \\$(cat /var/run/mountd.pid)\""
                      % sys.argv[2].replace('/', '\\/')])
print("  closing the export:", rc)
time.sleep(3)
def ws(name, ops, status, last):
    res = s.compound(ops)
    t("s2.6.3.1.1 " + name, (res.status, res.resarray[-1].resop), (status, last))
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
