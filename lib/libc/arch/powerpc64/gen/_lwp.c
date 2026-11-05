/*	$NetBSD: _lwp.c,v 1.3 2012/11/24 15:20:58 christos Exp $	*/

/*
 * Copyright (c) 2001 Wasabi Systems, Inc.
 * All rights reserved.
 *
 * Written by Allen Briggs for Wasabi Systems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed for the NetBSD Project by
 *      Wasabi Systems, Inc.
 * 4. The name of Wasabi Systems, Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY WASABI SYSTEMS, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL WASABI SYSTEMS, INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
__RCSID("$NetBSD: _lwp.c,v 1.3 2012/11/24 15:20:58 christos Exp $");
#endif /* LIBC_SCCS and not lint */

#include "namespace.h"
#include <sys/types.h>
#include <ucontext.h>
#include <lwp.h>
#include <stdlib.h>

#include <machine/lwp_private.h>

/*
 * A function pointer is the address of a descriptor, not of code: its
 * first doubleword is the entry point, the second the TOC the function
 * expects in r2, the third an environment pointer for r11 (64-bit PowerPC
 * ELF ABI Supplement 1.9, 3.2.5).  Putting the pointer itself in the PC
 * and LR started the new LWP in data.
 */
struct funcdesc {
	__greg_t	fd_entry;
	__greg_t	fd_toc;
	__greg_t	fd_env;
};

void
_lwp_makecontext(ucontext_t *u, void (*start)(void *), void *arg,
	void *tcb, caddr_t stack_base, size_t stack_size)
{
	const struct funcdesc *fstart = (const void *)start;
	const struct funcdesc *fexit = (const void *)_lwp_exit;
	void	**sp;

	getcontext(u);
	u->uc_link = NULL;

	u->uc_stack.ss_sp = stack_base;
	u->uc_stack.ss_size = stack_size;

	sp = (void *)(stack_base + stack_size);

	u->uc_mcontext.__gregs[3] = (__greg_t) arg;		/* arg1 */
	u->uc_mcontext.__gregs[1] = ((__greg_t) sp) - 112;	/* stack */
	u->uc_mcontext.__gregs[33] = fexit->fd_entry;		/* LR */
	u->uc_mcontext.__gregs[34] = fstart->fd_entry;		/* PC */
	u->uc_mcontext.__gregs[_REG_R2] = fstart->fd_toc;
	u->uc_mcontext.__gregs[_REG_R11] = fstart->fd_env;

	u->uc_mcontext.__gregs[_REG_R13] =
	    (__greg_t)tcb + TLS_TP_OFFSET + sizeof(struct tls_tcb);
	u->uc_flags |= _UC_TLSBASE;
}
