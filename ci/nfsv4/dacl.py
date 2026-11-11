#!/usr/bin/env python3
"""The dacl attribute, RFC 8881 s6.2.2 and s6.4.3.2, and its aclflag4.
Run from pynfs's nfs4.1 directory: dacl.py EXPORT, on a file system with
NFSv4 ACLs and extended attributes.  Failures are the measurement."""
import sys, time
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
s = c.new_client_session(stamp + b"dacl")
anon = stateid4(0, b'\0' * 12)
def fh_of(path):
    res = s.compound(use_obj(path) + [op.getfh()])
    check(res)
    return res.resarray[-1].object
def setattr(fh, attrs):
    return s.compound([op.putfh(fh), op.setattr(anon, attrs)]).status
def dacl(fh):
    res = s.compound([op.putfh(fh), op.getattr(nfs4lib.list2bitmap([FATTR4_DACL]))])
    return res.resarray[-1].obj_attributes[FATTR4_DACL] if res.status == 0 else res.status
def acl(fh):
    res = s.compound([op.putfh(fh), op.getattr(nfs4lib.list2bitmap([FATTR4_ACL]))])
    return res.resarray[-1].obj_attributes[FATTR4_ACL] if res.status == 0 else res.status

root = fh_of(export)
res = s.compound([op.putfh(root), op.getattr(nfs4lib.list2bitmap([FATTR4_SUPPORTED_ATTRS]))])
sup = nfs4lib.bitmap2list(res.resarray[-1].obj_attributes[FATTR4_SUPPORTED_ATTRS])
t("s6.2.2 supported", FATTR4_DACL in sup, True)
t("s6.2.3 sacl not supported, no AUDIT or ALARM", FATTR4_SACL in sup, False)

res = s.compound([op.putfh(root), op.create(createtype4(NF4DIR), stamp + b"d",
                                           {FATTR4_MODE: 0o755}), op.getfh()])
check(res)
d = res.resarray[-1].object
INH = ACE4_FILE_INHERIT_ACE | ACE4_DIRECTORY_INHERIT_ACE
FULL = 0x1f01ff
aces = [nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, INH, ACE4_READ_DATA, b"1234"),
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0, FULL, b"OWNER@"),
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, ACE4_INHERITED_ACE, ACE4_READ_ACL,
                b"EVERYONE@")]
t("s6.2.2 SETATTR dacl", setattr(d, {FATTR4_DACL: nfsacl41(ACL4_AUTO_INHERIT, aces)}),
  NFS4_OK)
g = dacl(d)
t("s6.4.3.2 the flags kept", getattr(g, "na41_flag", g), ACL4_AUTO_INHERIT)
t("s6.4.3.2 ACE4_INHERITED_ACE kept in the dacl",
  [e.flag & ACE4_INHERITED_ACE for e in getattr(g, "na41_aces", []) if e.who == b"EVERYONE@"],
  [[ACE4_INHERITED_ACE]])
a = acl(d)
t("s6.4.3.2 and cleared in the acl",
  [e.flag & ACE4_INHERITED_ACE for e in a if e.who == b"EVERYONE@"] if isinstance(a, list) else a,
  [[0]])
t("s6.4.3.2 an undefined aclflag4 bit",
  setattr(d, {FATTR4_DACL: nfsacl41(0x8, aces)}), NFS4ERR_INVAL)
t("s6.4.1 acl and dacl together",
  setattr(d, {FATTR4_DACL: nfsacl41(0, aces), FATTR4_ACL: aces}), NFS4ERR_ATTRNOTSUPP)
t("s6.2.2 an AUDIT ACE in the dacl",
  setattr(d, {FATTR4_DACL: nfsacl41(0, [nfsace4(ACE4_SYSTEM_AUDIT_ACE_TYPE,
          ACE4_SUCCESSFUL_ACCESS_ACE_FLAG, ACE4_READ_DATA, b"OWNER@")])}),
  NFS4ERR_ATTRNOTSUPP)

# s6.4.3.2: a child made with no ACL gets AUTO_INHERIT from the parent,
# PROTECTED clear, and its inherited ACEs marked.
res = s.compound([op.putfh(d), op.create(createtype4(NF4DIR), stamp + b"c", {}),
                  op.getfh()])
check(res)
ch = res.resarray[-1].object
g = dacl(ch)
t("s6.4.3.2 child: AUTO_INHERIT from the parent, not PROTECTED",
  getattr(g, "na41_flag", g), ACL4_AUTO_INHERIT)
t("s6.4.3.2 child: inherited ACE marked",
  [e.flag & ACE4_INHERITED_ACE for e in getattr(g, "na41_aces", []) if e.who == b"1234"],
  [[ACE4_INHERITED_ACE]])

# s6.4.3.2: the same for one made with a mode, by CREATE and by OPEN;
# its ACL was inherited under the mode, not DEFAULTED.
res = s.compound([op.putfh(d), op.create(createtype4(NF4DIR), stamp + b"m",
                                         {FATTR4_MODE: 0o750}), op.getfh()])
check(res)
g = dacl(res.resarray[-1].object)
t("s6.4.3.2 CREATE with a mode: AUTO_INHERIT from the parent",
  getattr(g, "na41_flag", g), ACL4_AUTO_INHERIT)
res = create_file(s, stamp + b"mf", path=export + [stamp + b"d", stamp + b"mf"],
                  attrs={FATTR4_MODE: 0o640})
check(res)
g = dacl(res.resarray[-1].object)
t("s6.4.3.2 OPEN with a mode: AUTO_INHERIT from the parent",
  getattr(g, "na41_flag", g), ACL4_AUTO_INHERIT)
res = s.compound([op.putfh(root), op.create(createtype4(NF4DIR), stamp + b"n",
                                            {FATTR4_MODE: 0o750}), op.getfh()])
check(res)
g = dacl(res.resarray[-1].object)
t("s6.4.3.2 with a mode, parent without AUTO_INHERIT: no flags",
  getattr(g, "na41_flag", g), 0)

# s6.4.3.2 SHOULD: SETATTR of the acl sets ACL4_PROTECTED.
t("SETATTR acl", setattr(ch, {FATTR4_ACL: [aces[1]]}), NFS4_OK)
g = dacl(ch)
t("s6.4.3.2 acl sets PROTECTED",
  getattr(g, "na41_flag", g) & ACL4_PROTECTED if not isinstance(g, int) else g,
  ACL4_PROTECTED)

# s6.4.3.2 SHOULD: nothing to inherit, the server's ACL is DEFAULTED.
res = s.compound([op.putfh(root), op.create(createtype4(NF4DIR), stamp + b"e", {}),
                  op.getfh()])
check(res)
g = dacl(res.resarray[-1].object)
t("s6.4.3.2 nothing inherited: DEFAULTED",
  getattr(g, "na41_flag", g) & ACL4_DEFAULTED if not isinstance(g, int) else g,
  ACL4_DEFAULTED)
print("failures:", fails)
sys.exit(0)
