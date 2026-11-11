#!/usr/bin/env python3
"""The retention attributes, RFC 8881 s5.13.  Run from pynfs's nfs4.1
directory: retention.py EXPORT, on a file system with extended
attributes, where they are kept.  ssh to the VM tries UF_IMMUTABLE from
inside, locally and through NFSv3.  Failures are the measurement."""
import subprocess, sys, time, traceback
import nfs_ops, nfs4client, nfs4lib
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
from server41tests.environment import create_file, close_file, check, use_obj
op = nfs_ops.NFS4ops()
fails = 0
def t(name, got, want):
    global fails
    want = want if isinstance(want, list) else [want]
    ok = got in want
    print("%s %s: got %s, want %s" % ("ok  " if ok else "FAIL", name, got, want))
    sys.stdout.flush()
    if not ok:
        fails += 1

export = sys.argv[1].strip('/').encode().split(b'/')
stamp = b"%d" % int(time.time())
c = nfs4client.NFS4Client(b'127.0.0.1', 2049, 1)
c.homedir = export
s = c.new_client_session(stamp + b"r")
P = lambda n: export + [stamp + n]
res = s.compound(use_obj(export) + [op.getfh()])
check(res)
dirfh = res.resarray[-1].object
anon = stateid4(0, b'\0' * 12)

def mk(n):
    res = create_file(s, stamp + n, path=P(n),
                      access=OPEN4_SHARE_ACCESS_BOTH)
    check(res)
    return res.resarray[-1].object, res.resarray[-2].stateid
def setattr(fh, attrs, sid=anon):
    return s.compound([op.putfh(fh), op.setattr(sid, attrs)]).status
def getattr(fh, bits):
    res = s.compound([op.putfh(fh), op.getattr(nfs4lib.list2bitmap(bits))])
    return res.status, res.resarray[-1].obj_attributes if res.status == 0 else None
def remove(n):
    return s.compound([op.putfh(dirfh), op.remove(stamp + n)]).status
def rename(a, b):
    return s.compound([op.putfh(dirfh), op.savefh(),
                       op.rename(stamp + a, stamp + b)]).status
def write(fh, sid):
    return s.compound([op.putfh(fh), op.write(sid, 0, FILE_SYNC4, b"x")]).status
def trunc(n):
    return s.compound(use_obj(export) + [op.open(0, OPEN4_SHARE_ACCESS_WRITE, 0,
        open_owner4(0, b"tr" + n), openflag4(OPEN4_CREATE, createhow4(UNCHECKED4,
        {FATTR4_SIZE: 0})), open_claim4(CLAIM_NULL, stamp + n))]).status
def vm(cmd):
    try:
        # LogLevel: ssh says "Permanently added" on every connection,
        # which on stdout hid the "uchg" of stat from uchg().
        p = subprocess.run(["ssh", "-o", "LogLevel=ERROR", "netbsd",
                            "sh -c '%s'" % cmd],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=60)
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    return p.returncode, p.stdout.decode(errors="replace").strip()
V = lambda n: "/%s/%s" % (b"/".join(export).decode(), (stamp + n).decode())
def uchg(n):
    out = vm("stat -f %%Sf %s" % V(n))[1].splitlines()
    return bool(out) and "uchg" in out[-1].split(",")
# s10.2 of t41b: nfsd(8) on UDP only, as the module has TCP 2049;
# -u for NFS on UDP, -U for the mount protocol.
v3 = vm("pgrep -x nfsd >/dev/null || /usr/sbin/nfsd -u -n 2; "
        "sleep 1; rpcinfo -p 127.0.0.1; pgrep -lx nfsd; "
        "mkdir -p /mnt/v3r; mount | grep -q /mnt/v3r || "
        "mount_nfs -3 -u -U -s -x 2 -t 30 127.0.0.1:%s /mnt/v3r" % "/".join([""] + [e.decode() for e in export]))
print("  NFSv3 mount:", v3)
W = lambda n: "/mnt/v3r/%s" % (stamp + n).decode()
RS = lambda en, d=None: retention_set4(en, [] if d is None else [d])
RET = (FATTR4_RETENTION_GET, FATTR4_RETENTION_SET, FATTR4_RETENTEVT_GET,
       FATTR4_RETENTEVT_SET, FATTR4_RETENTION_HOLD)

def body():
    # s5.13: supported here, by number in the third word.
    st, a = getattr(dirfh, [FATTR4_SUPPORTED_ATTRS])
    sup = nfs4lib.bitmap2list(a[FATTR4_SUPPORTED_ATTRS]) if a else []
    for n in RET:
        t("s5.13 supported %d" % n, n in sup, True)
    fh, sid = mk(b"a")
    # s5.5: set-only is NFS4ERR_INVAL to GETATTR, get-only to SETATTR.
    t("s5.5 GETATTR retention_set", getattr(fh, [FATTR4_RETENTION_SET])[0],
      NFS4ERR_INVAL)
    t("s5.5 GETATTR retentevt_set", getattr(fh, [FATTR4_RETENTEVT_SET])[0],
      NFS4ERR_INVAL)
    t("s5.5 SETATTR retention_get", setattr(fh, {FATTR4_RETENTION_GET:
      retention_get4(0, [])}), NFS4ERR_INVAL)
    st, a = getattr(fh, [FATTR4_RETENTION_GET, FATTR4_RETENTEVT_GET,
                         FATTR4_RETENTION_HOLD])
    t("s5.13.1 not enabled", st == 0 and
      [a[FATTR4_RETENTION_GET].rg_begin_time, a[FATTR4_RETENTION_HOLD]],
      [[[], 0]])

    # s5.13.2: a duration not enabled may go down.
    t("s5.13.2 duration 100", setattr(fh, {FATTR4_RETENTION_SET: RS(False, 100)}),
      NFS4_OK)
    t("s5.13.2 down to 20", setattr(fh, {FATTR4_RETENTION_SET: RS(False, 20)}),
      NFS4_OK)
    t("s5.13.2 enable", setattr(fh, {FATTR4_RETENTION_SET: RS(True)}), NFS4_OK)
    st, a = getattr(fh, [FATTR4_RETENTION_GET])
    g = a[FATTR4_RETENTION_GET] if a else None
    t("s5.13.1 begin time", g is not None and len(g.rg_begin_time), 1)
    t("s5.13.2 counting down", g is not None and 1 <= g.rg_duration <= 20, True)
    t("s5.13.2 shorten while enabled", setattr(fh,
      {FATTR4_RETENTION_SET: RS(True, 1)}), NFS4ERR_INVAL)
    t("s5.13.2 disable while enabled", setattr(fh,
      {FATTR4_RETENTION_SET: RS(False)}), NFS4ERR_INVAL)
    # s5.13: the data and the name.
    t("s5.13 WRITE", write(fh, sid), NFS4ERR_ACCESS)
    t("s5.13 SETATTR size", setattr(fh, {FATTR4_SIZE: 0}, sid), NFS4ERR_ACCESS)
    # Not asked for by s5.13; UF_IMMUTABLE refuses it in ufs_setattr().
    t("s5.13 SETATTR mode", setattr(fh, {FATTR4_MODE: 0o644}), NFS4ERR_PERM)
    # UF_IMMUTABLE, so local processes and NFSv3 are refused too.
    t("uchg while retained", uchg(b"a"), True)
    t("local append refused", vm("echo x >> %s" % V(b"a"))[0] != 0, True)
    t("local rm refused", vm("rm -f %s" % V(b"a"))[0] != 0, True)
    if v3[0] == 0:
        t("NFSv3 append refused", vm("echo x >> %s" % W(b"a"))[0] != 0, True)
        t("NFSv3 rm refused", vm("rm -f %s" % W(b"a"))[0] != 0, True)
    # The owner may clear it (ufs_accessx); the server sets it again.
    vm("chflags nouchg %s" % V(b"a"))
    t("chflags nouchg, then REMOVE", [uchg(b"a"), remove(b"a"), uchg(b"a")],
      [[False, NFS4ERR_ACCESS, True]])
    close_file(s, fh, sid)
    t("s5.13 OPEN truncating", trunc(b"a"), NFS4ERR_ACCESS)
    t("s5.13 REMOVE", remove(b"a"), NFS4ERR_ACCESS)
    t("s5.13 RENAME from", rename(b"a", b"a2"), NFS4ERR_ACCESS)
    fo, so = mk(b"o")
    close_file(s, fo, so)
    t("s5.13 RENAME over", rename(b"o", b"a"), NFS4ERR_ACCESS)
    # Nothing over NFS now: lease_thread() is to clear it, 10 s after.
    for i in range(40):
        time.sleep(1)
        if not uchg(b"a"):
            break
    print("  uchg gone after", i + 1, "s")
    t("uchg gone with nobody looking", uchg(b"a"), False)
    st, a = getattr(fh, [FATTR4_RETENTION_GET])
    t("s5.13.1 ended", st == 0 and [a[FATTR4_RETENTION_GET].rg_duration,
      a[FATTR4_RETENTION_GET].rg_begin_time], [[0, []]])
    t("s5.13 RENAME after", rename(b"a", b"a2"), NFS4_OK)
    t("s5.13 REMOVE after", remove(b"a2"), NFS4_OK)
    t("REMOVE the other", remove(b"o"), NFS4_OK)

    # s5.13.4: event-based retention holds too.
    fh, sid = mk(b"e")
    close_file(s, fh, sid)
    t("s5.13.4 enable", setattr(fh, {FATTR4_RETENTEVT_SET: RS(True, 3)}),
      NFS4_OK)
    t("s5.13.4 REMOVE", remove(b"e"), NFS4ERR_ACCESS)
    t("s5.13.4 shorten", setattr(fh, {FATTR4_RETENTEVT_SET: RS(True, 1)}),
      NFS4ERR_INVAL)
    t("s5.13.2 the other kind meanwhile", setattr(fh,
      {FATTR4_RETENTION_SET: RS(True, 1)}), NFS4_OK)
    time.sleep(4)
    t("s5.13.4 REMOVE after", remove(b"e"), NFS4_OK)

    # A flag set before is not this one's, and stays.
    fh, sid = mk(b"u")
    close_file(s, fh, sid)
    t("chflags uchg", vm("chflags uchg %s" % V(b"u"))[0], 0)
    t("enable over uchg", setattr(fh, {FATTR4_RETENTION_SET: RS(True, 2)}), NFS4_OK)
    time.sleep(13)
    t("uchg kept after, scanned", uchg(b"u"), True)
    t("GETATTR after", getattr(fh, [FATTR4_RETENTION_GET])[0], NFS4_OK)
    t("uchg kept after, looked at", uchg(b"u"), True)
    t("REMOVE, the owner's uchg", remove(b"u"), [NFS4ERR_PERM, NFS4ERR_ACCESS])
    vm("chflags nouchg %s" % V(b"u"))
    t("REMOVE after nouchg", remove(b"u"), NFS4_OK)

    # s5.13.5
    fh, sid = mk(b"h")
    close_file(s, fh, sid)
    t("s5.13.5 hold", setattr(fh, {FATTR4_RETENTION_HOLD: 1 << 63}), NFS4_OK)
    st, a = getattr(fh, [FATTR4_RETENTION_HOLD])
    t("s5.13.5 read", st == 0 and a[FATTR4_RETENTION_HOLD], 1 << 63)
    t("s5.13.5 REMOVE", remove(b"h"), NFS4ERR_ACCESS)
    t("s5.13.5 RENAME", rename(b"h", b"h2"), NFS4ERR_ACCESS)
    t("s5.13.5 uchg", uchg(b"h"), True)
    t("s5.13.5 released", setattr(fh, {FATTR4_RETENTION_HOLD: 0}), NFS4_OK)
    t("s5.13.5 uchg gone at once", uchg(b"h"), False)
    t("s5.13.5 REMOVE after", remove(b"h"), NFS4_OK)

try:
    body()
except Exception:
    traceback.print_exc()
    t("exception", "exception", "none")
if v3[0] == 0:
    vm("umount -f /mnt/v3r")
print("failures:", fails)
sys.exit(0)
