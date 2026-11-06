#!/usr/bin/env python3
"""What pynfs's 4.1 suite does not run: FREE_STATEID, TEST_STATEID,
BIND_CONN_TO_SESSION, BACKCHANNEL_CTL, SET_SSV, leases that expire, the
connections a session forgets, a retry of a call in progress, trunking.
Each line says what RFC 8881 section it tries.  Run from pynfs's nfs4.1
directory: t41.py EXPORT.  Failures are the measurement."""
import sys, time
import nfs_ops, nfs4client, nfs4lib
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
from server41tests.environment import create_file, close_file, check
op = nfs_ops.NFS4ops()

fails = 0
def t(name, got, want):
    global fails
    want = want if isinstance(want, (list, tuple)) else [want]
    ok = got in want
    print("%s %s: got %s, want %s" % ("ok  " if ok else "FAIL", name,
          nfs4lib.nfsstat4.get(got, got) if hasattr(nfs4lib, 'nfsstat4') else got, want))
    if not ok:
        fails += 1

export = sys.argv[1].strip('/').encode().split(b'/')
c = nfs4client.NFS4Client(b'127.0.0.1', 2049, 1)
c.homedir = export
stamp = b"%d" % int(time.time())
def sess_of(name, **kw):
    s = c.new_client_session(stamp + name, **kw)
    return s
def lockop(type_, fh, open_sid, owner):
    l = locker4(open_owner=open_to_lock_owner4(0, open_sid, 0,
                lock_owner4(0, owner)), new_lock_owner=True)
    return [op.putfh(fh), op.lock(type_, False, 0, 100, l)]

# s18.38, s18.48
s = sess_of(b"st")
res = create_file(s, stamp + b"a", path=export + [stamp + b"a"])
check(res)
fh = res.resarray[-1].object
sid = res.resarray[-2].stateid
res = s.compound(lockop(WRITE_LT, fh, sid, b"lo"))
t("s18.10 LOCK", res.status, NFS4_OK)
lsid = res.resarray[-1].lock_stateid
t("s18.38.3 FREE_STATEID of an open", s.compound([op.free_stateid(sid)]).status,
  NFS4ERR_LOCKS_HELD)
t("s18.38.3 FREE_STATEID with locks", s.compound([op.free_stateid(lsid)]).status,
  NFS4ERR_LOCKS_HELD)
res = s.compound([op.test_stateid([sid, lsid, stateid4(0, b'\0' * 12),
                  stateid4(sid.seqid + 1, sid.other),
                  stateid4(0, sid.other)])])
t("s18.48 TEST_STATEID", res.status, NFS4_OK)
codes = res.resarray[-1].tsr_status_codes
print("  codes", codes)
t("s18.48.3 open", codes[0], NFS4_OK)
t("s18.48.3 lock", codes[1], NFS4_OK)
t("s18.48.3 special", codes[2], NFS4ERR_BAD_STATEID)
t("s8.2.4 seqid ahead", codes[3], NFS4ERR_BAD_STATEID)
t("s8.2.2 seqid 0", codes[4], NFS4_OK)
res = s.compound([op.putfh(fh), op.locku(WRITE_LT, 0, lsid, 0, 100)])
t("s18.12 LOCKU", res.status, NFS4_OK)
lsid2 = res.resarray[-1].lock_stateid
t("s18.38.3 FREE_STATEID old seqid", s.compound([op.free_stateid(lsid)]).status,
  NFS4ERR_OLD_STATEID)
t("s18.38.3 FREE_STATEID", s.compound([op.free_stateid(lsid2)]).status, NFS4_OK)
t("s18.38.3 then BAD_STATEID", s.compound([op.free_stateid(lsid2)]).status,
  NFS4ERR_BAD_STATEID)
res = s.compound([op.test_stateid([lsid2])])
t("s18.48.3 freed", res.resarray[-1].tsr_status_codes[0], NFS4ERR_BAD_STATEID)
s2 = sess_of(b"other")
res = s2.compound([op.test_stateid([sid])])
t("s18.48.3 another client's", res.resarray[-1].tsr_status_codes[0], NFS4ERR_BAD_STATEID)
t("s18.2 CLOSE", close_file(s, fh, sid).status, NFS4_OK)

# s18.47
t("s18.47.3 SET_SSV", s.compound([op.set_ssv(b"x", b"y")]).status, NFS4ERR_INVAL)
t("s18.46.3 SET_SSV first", c.compound([op.set_ssv(b"x", b"y")]).status,
  NFS4ERR_OP_NOT_IN_SESSION)

# s18.33
t("s18.33 BACKCHANNEL_CTL", s.compound([op.backchannel_ctl(0x40000000,
  [callback_sec_parms4(0)])]).status, NFS4_OK)
gss = callback_sec_parms4(RPCSEC_GSS, cbsp_gss_handles=gss_cb_handles4(
    RPC_GSS_SVC_NONE, b"x", b"y"))
t("s18.33.3 GSS handle unknown", s.compound([op.backchannel_ctl(0x40000000,
  [gss])]).status, NFS4ERR_NOENT)
t("s18.33.3 first", c.compound([op.backchannel_ctl(1, [])]).status,
  NFS4ERR_OP_NOT_IN_SESSION)

# s18.34, and session trunking by another connection, s2.10.5
sid4 = s.sessionid
p = c.connect(c.server_address)
def bind(d, sessid=sid4, pipe=p, more=[]):
    return c.compound([op.bind_conn_to_session(sessid, d, False)] + more, pipe=pipe)
res = bind(CDFC4_FORE_OR_BOTH)
t("s18.34 bind", res.status, NFS4_OK)
t("s18.34.3 dir", res.resarray[0].bctsr_dir, [CDFS4_FORE, CDFS4_BOTH])
d = res.resarray[0].bctsr_dir
t("s18.34.3 again", bind(CDFC4_FORE_OR_BOTH).status, NFS4_OK)
if d == CDFS4_BOTH:
    t("s18.34.3 change", bind(CDFC4_FORE).status, NFS4ERR_INVAL)
t("s18.34 bad session", bind(CDFC4_FORE, sessid=b'\0' * 16).status, NFS4ERR_BADSESSION)
t("s18.34.3 not only", bind(CDFC4_FORE, more=[op.putrootfh()]).status, NFS4ERR_NOT_ONLY_OP)
p2 = c.connect(c.server_address)
res = bind(CDFC4_BACK, pipe=p2)
t("s18.34.3 BACK", res.resarray[0].bctsr_dir if res.status == 0 else res.status, CDFS4_BACK)
class Raw:
    """A slot of the session driven by hand, away from pynfs's own."""
    def __init__(self, sess, slot):
        self.sid, self.slot, self.n = sess.sessionid, slot, 0
    def op(self, cache=False):
        self.n += 1
        return op.sequence(self.sid, self.n, self.slot, self.slot, cache)
raw = Raw(s, 1)
res = c.compound([raw.op()], pipe=p)
t("s2.10.3.1 SEQUENCE on the bound connection", res.status, NFS4_OK)

# s2.10.5.1: EXCHANGE_ID on two connections, the same server and client
e1 = c.compound([op.exchange_id(client_owner4(c.verifier, stamp + b"st"), 0,
                 state_protect4_a(SP4_NONE), [c.impl_id])])
e2 = c.compound([op.exchange_id(client_owner4(c.verifier, stamp + b"st"), 0,
                 state_protect4_a(SP4_NONE), [c.impl_id])], pipe=p)
r1, r2 = e1.resarray[0], e2.resarray[0]
t("s2.10.5 same clientid", r1.eir_clientid == r2.eir_clientid, True)
t("s2.10.5 same major id", r1.eir_server_owner.so_major_id ==
  r2.eir_server_owner.so_major_id, True)
t("s2.10.5 same scope", r1.eir_server_scope == r2.eir_server_scope, True)

# NFSV4_SES_CONNS, a choice of the server: the ninth pushes out the first.
s3 = sess_of(b"conns")
r3 = Raw(s3, 1)
first = c.connect(c.server_address)
t("s2.10.3.1 binds", c.compound([r3.op()], pipe=first).status, NFS4_OK)
keep = []
for i in range(9):
    q = c.connect(c.server_address)
    keep.append(q)
    c.compound([r3.op()], pipe=q)
t("oldest forgotten", c.compound([op.destroy_session(s3.sessionid)], pipe=first).status,
  NFS4ERR_CONN_NOT_BOUND_TO_SESSION)
t("and bound again", c.compound([r3.op()], pipe=first).status, NFS4_OK)
t("s18.37 destroyed", c.compound([op.destroy_session(s3.sessionid)], pipe=first).status,
  NFS4_OK)

# s2.10.6.2: a retry of a call still running.  Timing decides, so tries.
s4 = sess_of(b"delay")
res = create_file(s4, stamp + b"d", path=export + [stamp + b"d"])
check(res)
fh = res.resarray[-1].object
sid = res.resarray[-2].stateid
r4 = Raw(s4, 1)
q = c.connect(c.server_address)
data = b"x" * 131072
seen = {}
for i in range(30):
    seqop = r4.op(True)
    ops = [seqop, op.putfh(fh)] + [op.write(sid, 0, FILE_SYNC4, data)] * 8
    xid = c.compound_async(ops)
    res2 = c.compound([seqop, op.putfh(fh)], pipe=q)
    seen[res2.status] = seen.get(res2.status, 0) + 1
    res1 = c.listen(xid)
    if res1.status != NFS4_OK:
        print("  original", res1.status)
print("  retry answers", seen)
t("s2.10.6.2 DELAY seen", NFS4ERR_DELAY in seen, True)
close_file(s4, fh, sid)

# s8.3, s18.46.3: leases.  NFSV4_LEASE and its scan, a choice of 90 and 10.
s5 = sess_of(b"lease")
res = create_file(s5, stamp + b"l", path=export + [stamp + b"l"])
check(res)
fh = res.resarray[-1].object
sid = res.resarray[-2].stateid
res = s5.compound(lockop(WRITE_LT, fh, sid, b"lo"))
t("LOCK before the lease ends", res.status, NFS4_OK)
lsid = res.resarray[-1].lock_stateid
s6 = sess_of(b"idle")		# with no state to lose
print("  waiting out the lease"); sys.stdout.flush()
time.sleep(112)
res = s5.compound([])
t("s18.46.3 SEQUENCE", res.status, NFS4_OK)
flags = res.resarray[0].sr_status_flags if res.resarray else None
t("s18.46.2 EXPIRED_ALL_STATE_REVOKED", bool(flags & SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED), True)
res = s5.compound([op.test_stateid([sid, lsid])])
t("s18.48 EXPIRED", list(res.resarray[-1].tsr_status_codes),
  [[NFS4ERR_EXPIRED, NFS4ERR_EXPIRED]])
t("s8.2.4 READ", s5.compound([op.putfh(fh), op.read(sid, 0, 10)]).status, NFS4ERR_EXPIRED)
t("s18.38.3 free lock", s5.compound([op.free_stateid(lsid)]).status, NFS4_OK)
t("s18.38.3 free open", s5.compound([op.free_stateid(sid)]).status, NFS4_OK)
res = s5.compound([])
t("s18.46.2 flag gone", bool(res.resarray[0].sr_status_flags &
  SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED), False)
res = create_file(s5, stamp + b"l2", path=export + [stamp + b"l2"])
t("OPEN after", res.status, NFS4_OK)
res = s6.compound([])
t("no state, no flag", bool(res.resarray[0].sr_status_flags &
  SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED) if res.resarray else res.status, False)

print("failures:", fails)
sys.exit(0)
