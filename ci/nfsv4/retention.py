#!/usr/bin/env python3
"""The retention attributes, RFC 8881 s5.13.  Run from pynfs's nfs4.1
directory: retention.py EXPORT, on a file system with extended
attributes, where they are kept.  Failures are the measurement."""
import sys, time, traceback
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
    t("s5.13.2 down to 3", setattr(fh, {FATTR4_RETENTION_SET: RS(False, 3)}),
      NFS4_OK)
    t("s5.13.2 enable", setattr(fh, {FATTR4_RETENTION_SET: RS(True)}), NFS4_OK)
    st, a = getattr(fh, [FATTR4_RETENTION_GET])
    g = a[FATTR4_RETENTION_GET] if a else None
    t("s5.13.1 begin time", g is not None and len(g.rg_begin_time), 1)
    t("s5.13.2 counting down", g is not None and 1 <= g.rg_duration <= 3, True)
    t("s5.13.2 shorten while enabled", setattr(fh,
      {FATTR4_RETENTION_SET: RS(True, 1)}), NFS4ERR_INVAL)
    t("s5.13.2 disable while enabled", setattr(fh,
      {FATTR4_RETENTION_SET: RS(False)}), NFS4ERR_INVAL)
    # s5.13: the data and the name.
    t("s5.13 WRITE", write(fh, sid), NFS4ERR_ACCESS)
    t("s5.13 SETATTR size", setattr(fh, {FATTR4_SIZE: 0}, sid), NFS4ERR_ACCESS)
    t("s5.13 SETATTR mode, not retained", setattr(fh, {FATTR4_MODE: 0o644}),
      NFS4_OK)
    close_file(s, fh, sid)
    t("s5.13 OPEN truncating", trunc(b"a"), NFS4ERR_ACCESS)
    t("s5.13 REMOVE", remove(b"a"), NFS4ERR_ACCESS)
    t("s5.13 RENAME from", rename(b"a", b"a2"), NFS4ERR_ACCESS)
    fo, so = mk(b"o")
    close_file(s, fo, so)
    t("s5.13 RENAME over", rename(b"o", b"a"), NFS4ERR_ACCESS)
    time.sleep(4)
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

    # s5.13.5
    fh, sid = mk(b"h")
    close_file(s, fh, sid)
    t("s5.13.5 hold", setattr(fh, {FATTR4_RETENTION_HOLD: 1 << 63}), NFS4_OK)
    st, a = getattr(fh, [FATTR4_RETENTION_HOLD])
    t("s5.13.5 read", st == 0 and a[FATTR4_RETENTION_HOLD], 1 << 63)
    t("s5.13.5 REMOVE", remove(b"h"), NFS4ERR_ACCESS)
    t("s5.13.5 RENAME", rename(b"h", b"h2"), NFS4ERR_ACCESS)
    t("s5.13.5 released", setattr(fh, {FATTR4_RETENTION_HOLD: 0}), NFS4_OK)
    t("s5.13.5 REMOVE after", remove(b"h"), NFS4_OK)

try:
    body()
except Exception:
    traceback.print_exc()
    t("exception", "exception", "none")
print("failures:", fails)
sys.exit(0)
