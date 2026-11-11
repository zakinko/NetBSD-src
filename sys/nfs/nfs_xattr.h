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

#ifndef _NFS_NFS_XATTR_H_
#define _NFS_NFS_XATTR_H_

#include <sys/extattr.h>

/* Named attributes of the NFS servers: see nfs_xattr.c. */

#define	NFS_XATTR_NS		EXTATTR_NAMESPACE_USER

/* A choice: what is held in memory for one attribute. */
#define	NFS_XATTR_MAXSIZE	(64 * 1024)

/* The length byte of EXTATTR_LIST_LENPREFIX, sys/extattr.h. */
#define	NFS_XATTR_NAMEMAX	255

/* The most of a key, all of SHA-256. */
#define	NFS_XATTR_KEYMAX	32

/* What a node is, besides the file itself. */
#define	NFS_XATTR_DIR		1
#define	NFS_XATTR_FILE		2

struct vattr;

void	nfs_xattr_key(const char *, size_t, uint8_t *, size_t);
uint64_t nfs_xattr_fileid(uint64_t, int, const char *);
int	nfs_xattr_list(struct vnode *, kauth_cred_t, char **, size_t *,
	    size_t *);
int	nfs_xattr_byhash(struct vnode *, kauth_cred_t, const uint8_t *, size_t,
	    char *);
int	nfs_xattr_unique(struct vnode *, kauth_cred_t, const char *, size_t);
int	nfs_xattr_any(struct vnode *, kauth_cred_t, bool *);
int	nfs_xattr_size(struct vnode *, kauth_cred_t, const char *, uint64_t *);
int	nfs_xattr_read(struct vnode *, kauth_cred_t, const char *, uint64_t,
	    void *, size_t, size_t *, uint64_t *);
int	nfs_xattr_write(struct vnode *, kauth_cred_t, const char *, uint64_t,
	    const void *, size_t, bool);
int	nfs_xattr_create(struct vnode *, kauth_cred_t, const char *, bool,
	    bool);
int	nfs_xattr_remove(struct vnode *, kauth_cred_t, const char *);
int	nfs_xattr_rename(struct vnode *, kauth_cred_t, const char *,
	    const char *);
int	nfs_xattr_vattr(struct vnode *, kauth_cred_t, int, const char *,
	    struct vattr *);

#endif /* _NFS_NFS_XATTR_H_ */
