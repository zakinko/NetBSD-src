/*	$NetBSD$	*/

/*-
 * Copyright (c) 2026 Showta Ishizaki
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * owner and owner_group as strings, RFC 7530 s5.9.  The kernel has no
 * password file, so what translates is a table given from userland, a
 * line at a time, through vfs.nfsv4.idmap:
 *
 *	u 1000 alice		g 100 users		clear
 *
 * and vfs.nfsv4.domain says the dns_domain.  Without a domain, or for
 * an id not in the table, a number goes out, s5.9 having that mean no
 * translation.  A number coming in is refused when the id has a
 * translation, as s5.9 SHOULD, except under AUTH_SYS while
 * vfs.nfsv4.numeric_owner_sys is on (nfsv4_attr.c).  Only the one domain has valid translations, as s5.9
 * allows; another is NFS4ERR_BADOWNER, and one that is no domain is
 * NFS4ERR_INVAL, s12.6, whose first method compares them as U-labels.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/systm.h>

#include <lib/libkern/libkern.h>

#include <fs/nfsv4/nfsv4_var.h>

#define	IDMAP_HASH	256		/* chosen */
#define	IDMAP_NAMEMAX	64		/* chosen */
#define	IDMAP_DOMAINMAX	64		/* chosen */
#define	IDMAP_NORMMAX	(IDMAP_DOMAINMAX * 8)	/* a U-label is longer */

struct idmap_ent {
	LIST_ENTRY(idmap_ent) ie_byid;
	LIST_ENTRY(idmap_ent) ie_byname;
	bool		ie_group;
	uint32_t	ie_id;
	uint32_t	ie_len;
	char		ie_name[IDMAP_NAMEMAX];
};

static kmutex_t idmap_lock;
static LIST_HEAD(, idmap_ent) idmap_id[IDMAP_HASH], idmap_name[IDMAP_HASH];
static char idmap_domain[IDMAP_DOMAINMAX];
static u_int idmap_domlen;
static uint8_t idmap_ndomain[IDMAP_NORMMAX];	/* to compare with */
static u_int idmap_ndomlen;

static u_int
name_hash(const char *s, u_int len)
{
	uint32_t h = 0x811c9dc5U;

	while (len-- > 0)
		h = (h ^ (uint8_t)*s++) * 16777619U;
	return h % IDMAP_HASH;
}

static bool domain_norm(const uint8_t *, u_int, uint8_t *, u_int *);

void
nfsv4_idmap_init(void)
{
	u_int i;

	mutex_init(&idmap_lock, MUTEX_DEFAULT, IPL_NONE);
	for (i = 0; i < IDMAP_HASH; i++) {
		LIST_INIT(&idmap_id[i]);
		LIST_INIT(&idmap_name[i]);
	}
	idmap_domlen = 0;
}

static void
idmap_clear(void)
{
	struct idmap_ent *ie;
	u_int i;

	for (i = 0; i < IDMAP_HASH; i++) {
		while ((ie = LIST_FIRST(&idmap_id[i])) != NULL) {
			LIST_REMOVE(ie, ie_byid);
			LIST_REMOVE(ie, ie_byname);
			kmem_free(ie, sizeof(*ie));
		}
	}
}

void
nfsv4_idmap_fini(void)
{

	idmap_clear();
	mutex_destroy(&idmap_lock);
}

/* One line of vfs.nfsv4.idmap. */
int
nfsv4_idmap_line(const char *s)
{
	struct idmap_ent *ie;
	uint64_t id = 0;
	bool group;
	size_t len;

	if (strcmp(s, "clear") == 0) {
		mutex_enter(&idmap_lock);
		idmap_clear();
		mutex_exit(&idmap_lock);
		return 0;
	}
	if ((s[0] != 'u' && s[0] != 'g') || s[1] != ' ')
		return EINVAL;
	group = s[0] == 'g';
	s += 2;
	if (*s < '0' || *s > '9')
		return EINVAL;
	for (; *s >= '0' && *s <= '9'; s++) {
		id = id * 10 + (*s - '0');
		if (id > UINT32_MAX)
			return EINVAL;
	}
	if (*s++ != ' ')
		return EINVAL;
	len = strlen(s);
	if (len == 0 || len >= IDMAP_NAMEMAX || memchr(s, '@', len) != NULL)
		return EINVAL;
	ie = kmem_zalloc(sizeof(*ie), KM_SLEEP);
	ie->ie_group = group;
	ie->ie_id = (uint32_t)id;
	ie->ie_len = (uint32_t)len;
	memcpy(ie->ie_name, s, len);
	mutex_enter(&idmap_lock);
	LIST_INSERT_HEAD(&idmap_id[ie->ie_id % IDMAP_HASH], ie, ie_byid);
	LIST_INSERT_HEAD(&idmap_name[name_hash(s, len)], ie, ie_byname);
	mutex_exit(&idmap_lock);
	return 0;
}

int
nfsv4_idmap_setdomain(const char *s)
{
	uint8_t dom[IDMAP_NORMMAX];
	size_t len = strlen(s);
	u_int dlen = 0;

	if (len >= IDMAP_DOMAINMAX)
		return ENAMETOOLONG;
	if (len != 0 && !domain_norm((const uint8_t *)s, (u_int)len, dom,
	    &dlen))
		return EINVAL;
	mutex_enter(&idmap_lock);
	memcpy(idmap_domain, s, len);
	idmap_domlen = (u_int)len;
	memcpy(idmap_ndomain, dom, dlen);
	idmap_ndomlen = dlen;
	mutex_exit(&idmap_lock);
	return 0;
}

/* The string for an id; buf has NFSV4_IDSTR_MAX bytes.  Its length. */
u_int
nfsv4_idmap_out(bool group, uint32_t id, char *buf)
{
	struct idmap_ent *ie;
	u_int n = 0;

	mutex_enter(&idmap_lock);
	if (idmap_domlen != 0) {
		LIST_FOREACH(ie, &idmap_id[id % IDMAP_HASH], ie_byid) {
			if (ie->ie_id == id && ie->ie_group == group) {
				memcpy(buf, ie->ie_name, ie->ie_len);
				buf[ie->ie_len] = '@';
				memcpy(buf + ie->ie_len + 1, idmap_domain,
				    idmap_domlen);
				n = ie->ie_len + 1 + idmap_domlen;
				break;
			}
		}
	}
	mutex_exit(&idmap_lock);
	return n != 0 ? n : (u_int)snprintf(buf, NFSV4_IDSTR_MAX, "%u", id);
}

/* Whether nfsv4_idmap_out() would give name@domain for id, s5.9. */
bool
nfsv4_idmap_has(bool group, uint32_t id)
{
	struct idmap_ent *ie;
	bool has = false;

	mutex_enter(&idmap_lock);
	if (idmap_domlen != 0) {
		LIST_FOREACH(ie, &idmap_id[id % IDMAP_HASH], ie_byid) {
			if (ie->ie_id == id && ie->ie_group == group) {
				has = true;
				break;
			}
		}
	}
	mutex_exit(&idmap_lock);
	return has;
}

/* RFC 3492 s5 */
#define	PC_BASE		36
#define	PC_TMIN		1
#define	PC_TMAX		26
#define	PC_SKEW		38
#define	PC_DAMP		700
#define	PC_BIAS		72
#define	PC_N		128
#define	PC_MAXCP	64	/* chosen; a label has at most 63 octets */

static uint32_t
pc_adapt(uint32_t delta, uint32_t n, bool first)
{
	uint32_t k = 0;

	delta = first ? delta / PC_DAMP : delta / 2;
	delta += delta / n;
	while (delta > ((PC_BASE - PC_TMIN) * PC_TMAX) / 2) {
		delta /= PC_BASE - PC_TMIN;
		k += PC_BASE;
	}
	return k + ((PC_BASE - PC_TMIN + 1) * delta) / (delta + PC_SKEW);
}

static int
pc_digit(uint8_t c)
{

	if (c >= '0' && c <= '9')
		return c - '0' + 26;
	if (c >= 'a' && c <= 'z')
		return c - 'a';
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	return -1;
}

static u_int
utf8_put(uint32_t cp, uint8_t *o)
{

	if (cp < 0x80) {
		o[0] = (uint8_t)cp;
		return 1;
	}
	if (cp < 0x800) {
		o[0] = 0xc0 | (cp >> 6);
		o[1] = 0x80 | (cp & 0x3f);
		return 2;
	}
	if (cp < 0x10000) {
		o[0] = 0xe0 | (cp >> 12);
		o[1] = 0x80 | ((cp >> 6) & 0x3f);
		o[2] = 0x80 | (cp & 0x3f);
		return 3;
	}
	o[0] = 0xf0 | (cp >> 18);
	o[1] = 0x80 | ((cp >> 12) & 0x3f);
	o[2] = 0x80 | ((cp >> 6) & 0x3f);
	o[3] = 0x80 | (cp & 0x3f);
	return 4;
}

/*
 * RFC 3492 s6.2: the label after "xn--" to UTF-8 at out, which has
 * room.  Its length, or 0 if it is not valid Punycode.
 */
static u_int
pc_decode(const uint8_t *in, u_int len, uint8_t *out)
{
	uint32_t cp[PC_MAXCP], n = PC_N, i = 0, bias = PC_BIAS, ol = 0;
	uint32_t oldi, w, k, t;
	u_int pos = 0, b, j, olen = 0;
	int digit;

	for (b = len; b > 0 && in[b - 1] != '-'; b--)
		continue;
	if (b > 0) {
		b--;			/* the last delimiter */
		if (b > PC_MAXCP)
			return 0;
		for (j = 0; j < b; j++) {
			if (in[j] >= 0x80)
				return 0;
			cp[ol++] = in[j];
		}
		pos = b + 1;
	}
	while (pos < len) {
		oldi = i;
		w = 1;
		for (k = PC_BASE;; k += PC_BASE) {
			if (pos >= len)
				return 0;
			digit = pc_digit(in[pos++]);
			if (digit < 0 ||
			    (uint32_t)digit > (UINT32_MAX - i) / w)
				return 0;
			i += (uint32_t)digit * w;
			t = k <= bias ? PC_TMIN : k >= bias + PC_TMAX ?
			    PC_TMAX : k - bias;
			if ((uint32_t)digit < t)
				break;
			if (w > UINT32_MAX / (PC_BASE - t))
				return 0;
			w *= PC_BASE - t;
		}
		bias = pc_adapt(i - oldi, ol + 1, oldi == 0);
		if (i / (ol + 1) > 0x10ffff - n)
			return 0;
		n += i / (ol + 1);
		i %= ol + 1;
		if (ol == PC_MAXCP || (n >= 0xd800 && n <= 0xdfff))
			return 0;
		memmove(&cp[i + 1], &cp[i], (ol - i) * sizeof(cp[0]));
		cp[i++] = n;
		ol++;
	}
	for (j = 0; j < ol; j++)
		olen += utf8_put(cp[j], out + olen);
	return olen;
}

/*
 * s12.6, the first method: into the form of U-labels at out.  Fails on a
 * string that is not valid UTF-8, an ASCII label that is no LDH label, or
 * an XN-label that is not Punycode.  ASCII is folded, for comparing.
 */
static bool
domain_norm(const uint8_t *s, u_int len, uint8_t *out, u_int *olenp)
{
	u_int i, n, e, o = 0, l;
	bool ascii;

	if (len == 0)
		return false;
	for (i = 0; i <= len; i = e + 1) {
		ascii = true;
		for (e = i; e < len && s[e] != '.'; e++) {
			if (s[e] < 0x80) {
				if (!(s[e] == '-' ||
				    (s[e] >= '0' && s[e] <= '9') ||
				    (s[e] >= 'a' && s[e] <= 'z') ||
				    (s[e] >= 'A' && s[e] <= 'Z')))
					return false;
				continue;
			}
			ascii = false;
			n = s[e] >= 0xf0 ? 3 : s[e] >= 0xe0 ? 2 :
			    s[e] >= 0xc2 ? 1 : 0;
			if (n == 0 || s[e] > 0xf4 || e + n >= len)
				return false;
			for (; n > 0; n--) {
				if ((s[++e] & 0xc0) != 0x80)
					return false;
			}
		}
		if (e == i || e - i > 63)
			return false;
		if (ascii && (s[i] == '-' || s[e - 1] == '-'))
			return false;
		if (ascii && e - i > 4 && strncasecmp((const char *)s + i,
		    "xn--", 4) == 0) {
			l = pc_decode(s + i + 4, e - i - 4, out + o);
			if (l == 0)
				return false;
			o += l;
		} else {
			for (n = i; n < e; n++) {
				out[o++] = s[n] >= 'A' && s[n] <= 'Z' ?
				    s[n] + 'a' - 'A' : s[n];
			}
		}
		if (e < len)
			out[o++] = '.';
	}
	*olenp = o;
	return true;
}

/* name@domain for an id, s5.9; the caller has seen the "@" at at. */
uint32_t
nfsv4_idmap_in(bool group, const char *s, u_int len, u_int at, uint32_t *idp)
{
	struct idmap_ent *ie;
	uint8_t dom[IDMAP_NORMMAX];
	uint32_t st = NFS4ERR_BADOWNER;
	u_int dlen;

	if (len - at - 1 > IDMAP_DOMAINMAX * 2 ||
	    !domain_norm((const uint8_t *)s + at + 1, len - at - 1, dom,
	    &dlen))
		return NFS4ERR_INVAL;
	mutex_enter(&idmap_lock);
	if (dlen == idmap_ndomlen && memcmp(dom, idmap_ndomain, dlen) == 0) {
		LIST_FOREACH(ie, &idmap_name[name_hash(s, at)], ie_byname) {
			if (ie->ie_group == group && ie->ie_len == at &&
			    memcmp(ie->ie_name, s, at) == 0) {
				*idp = ie->ie_id;
				st = NFS4_OK;
				break;
			}
		}
	}
	mutex_exit(&idmap_lock);
	return st;
}
