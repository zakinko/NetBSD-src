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
 * Calls out of the lock manager: to the local NSM, and to clients.  One
 * thread makes them all but the SM_MON that a LOCK waits for, as a client
 * that has gone away takes seconds to give up on.
 *
 * The NSM monitors an address, in text, and not caller_name.  caller_name
 * is whatever the client calls itself and very often cannot be resolved
 * here, and the NSM has to reach the host when this one reboots.  What
 * C702 asks of the name is only that the NSM can find the host.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/condvar.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/kthread.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <netinet6/in6.h>

#include <fs/nlm/nlm_var.h>

#define	NLM_GC_INTERVAL	5

/* An asynchronous result, C702 ch. 10: an RPC call of our own. */
struct nlm_rescall {
	TAILQ_ENTRY(nlm_rescall) rc_list;
	struct sockaddr_storage	 rc_to;
	uint32_t		 rc_vers;
	uint32_t		 rc_proc;
	void			*rc_buf;
	u_int			 rc_len;
};

static kcondvar_t nlm_nsm_cv;
static TAILQ_HEAD(, nlm_rescall) nlm_rescalls =
    TAILQ_HEAD_INITIALIZER(nlm_rescalls);
static u_int nlm_nrescalls;
static struct lwp *nlm_nsm_lwp;
static bool nlm_nsm_dying, nlm_nsm_starting;

bool
nlm_addr_string(const struct sockaddr *sa, char *buf, size_t len)
{

	switch (sa->sa_family) {
	case AF_INET:
		in_print(buf, len, &((const struct sockaddr_in *)sa)->sin_addr);
		return true;
	case AF_INET6:
		in6_print(buf, len,
		    &((const struct sockaddr_in6 *)sa)->sin6_addr);
		return true;
	default:
		return false;
	}
}

/* Call the NSM.  It is on this host, and one tells quickly if it is not. */
static int
nsm_call(uint32_t proc, xdrproc_t xargs, void *args, xdrproc_t xres, void *res)
{
	struct sockaddr_in to;
	uint16_t port;
	int error;

	memset(&to, 0, sizeof(to));
	to.sin_len = sizeof(to);
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = INADDR_LOOPBACK;
	error = oncrpc_clnt_getport((const struct sockaddr *)&to, SM_PROG,
	    SM_VERS, IPPROTO_UDP, &port);
	if (error == 0) {
		to.sin_port = htons(port);
		error = oncrpc_clnt_call((const struct sockaddr *)&to, SM_PROG,
		    SM_VERS, proc, xargs, args, xres, res, 2, 1, NULL);
	}
	return error;
}

struct nsm_monargs {
	char	ma_name[INET6_ADDRSTRLEN + 8];
	uint8_t	ma_priv[SM_PRIVLEN];
};

static bool_t
xdr_nsm_mon(XDR *x, const void *arg)
{
	const struct nsm_monargs *ma = arg;

	return nlm_xdr_mon(x, ma->ma_name, ma->ma_priv);
}

static bool_t
xdr_nsm_unmon(XDR *x, const void *arg)
{
	const struct nsm_monargs *ma = arg;

	return nlm_xdr_unmon(x, ma->ma_name);
}

static bool_t
xdr_nsm_name(XDR *x, const void *arg)
{

	return nlm_xdr_name(x, arg);
}

/* sm_stat_res, or sm_stat with res NULL */
static bool_t
xdr_nsm_statres(XDR *x, const void *arg)
{
	uint32_t *res = __UNCONST(arg);

	return xdr_u_int32_t(x, &res[0]) && xdr_u_int32_t(x, &res[1]);
}

static bool_t
xdr_nsm_stat(XDR *x, const void *arg)
{

	return xdr_u_int32_t(x, __UNCONST(arg));
}

/*
 * priv is the bare address: the name of a host may not survive the NSM
 * when it is given two, and nothing else need come back in SM_NOTIFY.
 */
void
nlm_nsm_priv(const struct sockaddr *sa, uint8_t *priv)
{

	memset(priv, 0, SM_PRIVLEN);
	if (sa->sa_family == AF_INET6)
		memcpy(priv, &((const struct sockaddr_in6 *)sa)->sin6_addr,
		    sizeof(struct in6_addr));
	else
		memcpy(priv, &((const struct sockaddr_in *)sa)->sin_addr,
		    sizeof(struct in_addr));
}

/* C702 SM_MON. */
int
nlm_nsm_mon(const struct sockaddr *sa, uint32_t *statep)
{
	struct nsm_monargs ma;
	uint32_t res[2];

	int error;

	if (!nlm_addr_string(sa, ma.ma_name, sizeof(ma.ma_name)))
		return EAFNOSUPPORT;
	nlm_nsm_priv(sa, ma.ma_priv);
	error = nsm_call(SM_MON, xdr_nsm_mon, &ma, xdr_nsm_statres, res);
	if (error != 0)
		return error;
	if (res[0] != SM_STAT_SUCC)
		return EPERM;	/* it was asked and said no */
	if (statep != NULL)
		*statep = res[1];
	return 0;
}

void
nlm_nsm_unmon(const struct sockaddr *sa)
{
	struct nsm_monargs ma;
	uint32_t state;

	if (nlm_addr_string(sa, ma.ma_name, sizeof(ma.ma_name)))
		(void)nsm_call(SM_UNMON, xdr_nsm_unmon, &ma, xdr_nsm_stat,
		    &state);
}

struct nlm_grant {
	uint32_t	 g_vers;
	const void	*g_cookie;
	uint32_t	 g_cookielen;
	bool		 g_exclusive;
	const char	*g_name;
	const void	*g_fh;
	uint32_t	 g_fhlen;
	const void	*g_oh;
	uint32_t	 g_ohlen;
	int32_t		 g_svid;
	uint64_t	 g_offset;
	uint64_t	 g_len;
};

static bool_t
xdr_grant(XDR *x, const void *arg)
{
	const struct nlm_grant *g = arg;

	return nlm_xdr_granted(x, g->g_vers, g->g_cookie, g->g_cookielen,
	    g->g_exclusive, g->g_name, g->g_fh, g->g_fhlen, g->g_oh,
	    g->g_ohlen, g->g_svid, g->g_offset, g->g_len);
}

/* nlm_res, the cookie being of no interest: C702 says not to rely on it. */
static bool_t
xdr_grantres(XDR *x, const void *arg)
{
	uint32_t *statp = __UNCONST(arg);
	uint32_t len;

	if (!xdr_u_int32_t(x, &len) || len > MAXNETOBJ_SZ ||
	    !xdr_setpos(x, xdr_getpos(x) + RNDUP(len)))
		return FALSE;
	return xdr_u_int32_t(x, statp);
}

static bool_t
xdr_raw(XDR *x, const void *arg)
{
	const struct nlm_rescall *rc = arg;

	return xdr_opaque(x, rc->rc_buf, rc->rc_len);
}

/*
 * NLM_GRANTED to a client, at the port its port mapper gives, C702
 * NLM_GRANTED and ch. 10 Port Number.  The answer goes in *statp.
 */
int
nlm_nsm_grant(const struct sockaddr *sa, uint32_t vers, const void *cookie,
    uint32_t cookielen, bool exclusive, const char *name, const void *fh,
    uint32_t fhlen, const void *oh, uint32_t ohlen, int32_t svid,
    uint64_t offset, uint64_t len, uint32_t *statp)
{
	struct sockaddr_storage to;
	struct nlm_grant g = {
		.g_vers = vers,
		.g_cookie = cookie,
		.g_cookielen = cookielen,
		.g_exclusive = exclusive,
		.g_name = name,
		.g_fh = fh,
		.g_fhlen = fhlen,
		.g_oh = oh,
		.g_ohlen = ohlen,
		.g_svid = svid,
		.g_offset = offset,
		.g_len = len,
	};
	uint16_t port;
	int error;

	memcpy(&to, sa, sa->sa_len);
	error = oncrpc_clnt_getport(sa, NLM_PROG, vers, IPPROTO_UDP, &port);
	if (error == 0) {
		((struct sockaddr_in *)&to)->sin_port = htons(port);
		error = oncrpc_clnt_call((const struct sockaddr *)&to, NLM_PROG,
		    vers, NLM_GRANTED, xdr_grant, &g, xdr_grantres, statp, 2, 2,
		    NULL);
		if (error == 0)
			return 0;
	}
	/* C702 ch. 10: a client may have only TCP, or UDP may not reach it. */
	error = oncrpc_clnt_getport(sa, NLM_PROG, vers, IPPROTO_TCP, &port);
	if (error != 0)
		return error;
	((struct sockaddr_in *)&to)->sin_port = htons(port);
	return oncrpc_clnt_call_tcp((const struct sockaddr *)&to, NLM_PROG, vers,
	    NLM_GRANTED, xdr_grant, &g, xdr_grantres, statp, 3, NULL);
}

/* Queue a result; buf is ours, from kmem_alloc(len). */
void
nlm_nsm_res(const struct sockaddr *sa, uint32_t vers, uint32_t proc, void *buf,
    u_int len)
{
	struct nlm_rescall *rc;

	rc = kmem_zalloc(sizeof(*rc), KM_SLEEP);
	memcpy(&rc->rc_to, sa, sa->sa_len);
	rc->rc_vers = vers;
	rc->rc_proc = proc;
	rc->rc_buf = buf;
	rc->rc_len = len;
	mutex_enter(&nlm_lock);
	if (nlm_nrescalls < NLM_MAXRESCALLS) {
		nlm_nrescalls++;
		TAILQ_INSERT_TAIL(&nlm_rescalls, rc, rc_list);
		cv_broadcast(&nlm_nsm_cv);
		rc = NULL;
	}
	mutex_exit(&nlm_lock);
	if (rc != NULL) {	/* a client that has lost the reply will retry */
		kmem_free(buf, len);
		kmem_free(rc, sizeof(*rc));
	}
}

static void
res_send(struct nlm_rescall *rc)
{
	const struct sockaddr *sa = (struct sockaddr *)&rc->rc_to;
	uint16_t port;

	if (oncrpc_clnt_getport(sa, NLM_PROG, rc->rc_vers, IPPROTO_UDP,
	    &port) != 0)
		return;
	((struct sockaddr_in *)&rc->rc_to)->sin_port = htons(port);
	/* C702 ch. 10: no RPC reply is to be expected to these. */
	(void)oncrpc_clnt_call(sa, NLM_PROG, rc->rc_vers, rc->rc_proc,
	    xdr_raw, rc, NULL, NULL, 0, 0, NULL);
}

/*
 * C702 ch. 9, Server NLM Initialisation has SM_UNMON_ALL here, for the
 * state and to forget what an earlier boot of the NLM asked for.  It is
 * not called: rpc.statd takes SIGSEGV on it with anything on its list,
 * which on a restart there will be.  SM_STAT gets the state, and what
 * stays on the list only costs a notification that finds no host here.
 */
static void
nsm_start(void)
{
	char name[] = "127.0.0.1";
	uint32_t res[2];

	if (nsm_call(SM_STAT, xdr_nsm_name, name, xdr_nsm_statres, res) == 0)
		printf("nlm: NSM state %u\n", res[1]);
}

static void
nlm_nsm_thread(void *arg)
{
	struct nlm_rescall *rc;
	time_t gc = 0;

	mutex_enter(&nlm_lock);
	while (!nlm_nsm_dying) {
		if (nlm_nsm_starting) {
			nlm_nsm_starting = false;
			mutex_exit(&nlm_lock);
			nsm_start();
			mutex_enter(&nlm_lock);
			continue;
		}
		if ((rc = TAILQ_FIRST(&nlm_rescalls)) != NULL) {
			TAILQ_REMOVE(&nlm_rescalls, rc, rc_list);
			nlm_nrescalls--;
			mutex_exit(&nlm_lock);
			res_send(rc);
			kmem_free(rc->rc_buf, rc->rc_len);
			kmem_free(rc, sizeof(*rc));
			mutex_enter(&nlm_lock);
			continue;
		}
		mutex_exit(&nlm_lock);
		nlm_grants_run();
		if (time_uptime >= gc) {
			nlm_hosts_gc();
			gc = time_uptime + NLM_GC_INTERVAL;
		}
		mutex_enter(&nlm_lock);
		if (!nlm_nsm_dying && !nlm_nsm_starting &&
		    TAILQ_EMPTY(&nlm_rescalls))
			(void)cv_timedwait(&nlm_nsm_cv, &nlm_lock, hz);
	}
	mutex_exit(&nlm_lock);
	kthread_exit(0);
}

/* A grant is due. */
void
nlm_nsm_kick(void)
{

	KASSERT(mutex_owned(&nlm_lock));
	cv_broadcast(&nlm_nsm_cv);
}

/* The first socket has arrived, so the NSM should be up. */
void
nlm_nsm_start(void)
{

	mutex_enter(&nlm_lock);
	nlm_nsm_starting = true;
	cv_broadcast(&nlm_nsm_cv);
	mutex_exit(&nlm_lock);
}

void
nlm_nsm_init(void)
{
	int error;

	cv_init(&nlm_nsm_cv, "nlmnsm");
	error = kthread_create(PRI_NONE, KTHREAD_MPSAFE | KTHREAD_MUSTJOIN,
	    NULL, nlm_nsm_thread, NULL, &nlm_nsm_lwp, "nlmnsm");
	if (error != 0)
		panic("nlm: kthread_create: %d", error);
}

void
nlm_nsm_fini(void)
{
	struct nlm_rescall *rc;

	mutex_enter(&nlm_lock);
	nlm_nsm_dying = true;
	cv_broadcast(&nlm_nsm_cv);
	mutex_exit(&nlm_lock);
	kthread_join(nlm_nsm_lwp);
	while ((rc = TAILQ_FIRST(&nlm_rescalls)) != NULL) {
		TAILQ_REMOVE(&nlm_rescalls, rc, rc_list);
		kmem_free(rc->rc_buf, rc->rc_len);
		kmem_free(rc, sizeof(*rc));
	}
	nlm_nrescalls = 0;
	nlm_nsm_dying = false;
	cv_destroy(&nlm_nsm_cv);
}
