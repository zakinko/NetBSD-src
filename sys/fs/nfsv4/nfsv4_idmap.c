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
 * translation.  Numbers are always taken, which s5.9 asks for outside
 * Kerberos.  Only the one domain has valid translations, as s5.9
 * allows; another is NFS4ERR_BADOWNER, and one that is no domain is
 * NFS4ERR_INVAL, s12.6.
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

static u_int
name_hash(const char *s, u_int len)
{
	uint32_t h = 0x811c9dc5U;

	while (len-- > 0)
		h = (h ^ (uint8_t)*s++) * 16777619U;
	return h % IDMAP_HASH;
}

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
	size_t len = strlen(s);

	if (len >= IDMAP_DOMAINMAX)
		return ENAMETOOLONG;
	mutex_enter(&idmap_lock);
	memcpy(idmap_domain, s, len);
	idmap_domlen = (u_int)len;
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

/* s12.6: valid UTF-8, and ASCII labels that are LDH labels. */
static bool
domain_ok(const uint8_t *s, u_int len)
{
	u_int i = 0, n, lab = 0;
	bool ascii = true;

	if (len == 0)
		return false;
	for (i = 0; i <= len; i++) {
		if (i == len || s[i] == '.') {
			if (i == lab)
				return false;
			if (ascii && (s[lab] == '-' || s[i - 1] == '-'))
				return false;
			lab = i + 1;
			ascii = true;
			continue;
		}
		if (s[i] < 0x80) {
			if (!(s[i] == '-' || (s[i] >= '0' && s[i] <= '9') ||
			    (s[i] >= 'a' && s[i] <= 'z') ||
			    (s[i] >= 'A' && s[i] <= 'Z')))
				return false;
			continue;
		}
		ascii = false;
		n = s[i] >= 0xf0 ? 3 : s[i] >= 0xe0 ? 2 : s[i] >= 0xc2 ? 1 : 0;
		if (n == 0 || s[i] > 0xf4 || i + n >= len)
			return false;
		for (; n > 0; n--) {
			if ((s[++i] & 0xc0) != 0x80)
				return false;
		}
	}
	return true;
}

/* name@domain for an id, s5.9; the caller has seen the "@" at at. */
uint32_t
nfsv4_idmap_in(bool group, const char *s, u_int len, u_int at, uint32_t *idp)
{
	struct idmap_ent *ie;
	uint32_t st = NFS4ERR_BADOWNER;

	if (!domain_ok((const uint8_t *)s + at + 1, len - at - 1))
		return NFS4ERR_INVAL;
	mutex_enter(&idmap_lock);
	if (len - at - 1 == idmap_domlen &&
	    strncasecmp(s + at + 1, idmap_domain, idmap_domlen) == 0) {
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
