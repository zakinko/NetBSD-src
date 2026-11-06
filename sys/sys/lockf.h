/*	$NetBSD: lockf.h,v 1.20 2008/11/19 13:34:11 pooka Exp $	*/

/*
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Scooter Morris at Genentech Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)lockf.h	8.2 (Berkeley) 10/26/94
 */

#ifndef _SYS_LOCKF_H_
#define _SYS_LOCKF_H_

#ifdef _KERNEL

#include <sys/fcntl.h>
#include <sys/vnode.h>

struct lockf;

/*
 * Values of a_op for a VOP_ADVLOCK from inside the kernel, which fcntl(2)
 * cannot make.  They are for a server whose lock owners are not
 * processes, and a file system that hands its locks to lf_advlock() has
 * them; any other gives what it gives for an op it does not know.
 *
 * F_GETLKID is F_GETLK that also says whose the lock is, for which a_fl
 * must point to the lfq_fl of a struct lf_query, as struct flock is an
 * ABI with no room for it.  The range returned runs on over the owner's
 * locks of that type that touch the first one, which are one lock to an
 * owner though they sit apart in the list.  lfq_id is what the owner gave
 * as a_id, is only to be compared, and may belong to nothing the caller
 * knows: a process or an open file.
 *
 * F_HASLK says whether a_id holds a lock in the range: l_type is left as
 * the type of the first one found, or F_UNLCK.
 *
 * F_CANCELWAIT makes a thread asleep in F_SETLK with F_WAIT for a_id and
 * exactly this range return ECANCELED, for a thread that no signal can
 * reach.  l_type is left F_UNLCK if none was asleep, which may be because
 * the thread is between two sleeps, and the caller has to ask again.
 */
#define	F_GETLKID	100
#define	F_HASLK		101
#define	F_CANCELWAIT	102

struct lf_query {
	struct flock	lfq_fl;
	void		*lfq_id;
};

int lf_advlock(struct vop_advlock_args *, struct lockf **, off_t);
void lf_init(void);
#endif /* _KERNEL */

#endif /* !_SYS_LOCKF_H_ */
