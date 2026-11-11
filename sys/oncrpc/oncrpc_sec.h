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

#ifndef _ONCRPC_ONCRPC_SEC_H_
#define _ONCRPC_ONCRPC_SEC_H_

/*
 * The flavors an NFS export accepts, in ex_flags of struct export_args,
 * as bits that no MNT_EX* uses, so that the structure stays as it is and
 * a mountd that knows nothing of them means what it always did.  None set
 * is the old behaviour: AUTH_SYS and AUTH_NONE.  Here and not in
 * <nfs/nfs.h>, which with NFSSERVER_ONCRPC off stays as before.
 */
#define	NFS_EXSEC_NONE	0x01
#define	NFS_EXSEC_SYS	0x02
#define	NFS_EXSEC_KRB5	0x04
#define	NFS_EXSEC_KRB5I	0x08
#define	NFS_EXSEC_KRB5P	0x10
#define	NFS_EXSEC_MASK	0x1f

#endif /* !_ONCRPC_ONCRPC_SEC_H_ */
