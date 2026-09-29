/* $NetBSD: t_sched.c,v 1.6 2017/12/24 17:37:23 christos Exp $ */

/*-
 * Copyright (c) 2011 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jukka Ruohonen.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/cdefs.h>
__RCSID("$NetBSD: t_sched.c,v 1.6 2017/12/24 17:37:23 christos Exp $");

#include <sys/param.h>	/* PRI_NONE */
#include <sys/wait.h>
#include <sched.h>
#include <errno.h>
#include <lwp.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

static void	 sched_priority_set(int, int);

ATF_TC(sched_getparam);
ATF_TC_HEAD(sched_getparam, tc)
{
	atf_tc_set_md_var(tc, "descr", "A basic test of sched_getparam(3)");
}

ATF_TC_BODY(sched_getparam, tc)
{
	struct sched_param s1, s2;
	pid_t p = getpid();

	/*
	 * IEEE Std 1003.1-2008: if the supplied pid is zero,
	 * the parameters for the calling process are returned.
	 */
	ATF_REQUIRE(sched_getparam(0, &s1) == 0);
	ATF_REQUIRE(sched_getparam(p, &s2) == 0);

	ATF_CHECK_EQ(s1.sched_priority, s2.sched_priority);

	/*
	 * The behavior is undefined but should error
	 * out in case the supplied PID is negative.
	 */
	ATF_REQUIRE(sched_getparam(-1, &s1) != 0);
}

ATF_TC(sched_priority);
ATF_TC_HEAD(sched_priority, tc)
{
	atf_tc_set_md_var(tc, "descr", "Test sched(3) priority ranges");
}

ATF_TC_BODY(sched_priority, tc)
{
	static const int pol[3] = { SCHED_OTHER, SCHED_FIFO, SCHED_RR };
	int pmax, pmin;
	size_t i;

	/*
	 * Test that bogus values error out.
	 */
	if (INT_MAX > SCHED_RR)
		ATF_REQUIRE(sched_get_priority_max(INT_MAX) != 0);

	if (-INT_MAX < SCHED_OTHER)
		ATF_REQUIRE(sched_get_priority_max(-INT_MAX) != 0);

	/*
	 * Test that we have a valid range.
	 */
	for (i = 0; i < __arraycount(pol); i++) {

		pmax = sched_get_priority_max(pol[i]);
		pmin = sched_get_priority_min(pol[i]);
		if (pol[i] == SCHED_OTHER) {
			ATF_REQUIRE(pmax == PRI_NONE);
			ATF_REQUIRE(pmin == PRI_NONE);
		} else {
			ATF_REQUIRE(pmax != -1);
			ATF_REQUIRE(pmin != -1);
			ATF_REQUIRE(pmax > pmin);
		}
	}
}

static void
sched_priority_set(int pri, int pol)
{
	struct sched_param sched;

	sched.sched_priority = pri;

	ATF_REQUIRE(pri >= 0);
	ATF_REQUIRE(sched_setscheduler(0, pol, &sched) == 0);

	/*
	 * Test that the policy was changed.
	 */
	ATF_CHECK_EQ(sched_getscheduler(0), pol);

	/*
	 * And that sched_getparam(3) returns the new priority.
	 */
	sched.sched_priority = -1;

	ATF_REQUIRE(sched_getparam(0, &sched) == 0);
	ATF_CHECK_EQ(sched.sched_priority, pri);
}

ATF_TC(sched_setscheduler_1);
ATF_TC_HEAD(sched_setscheduler_1, tc)
{
	atf_tc_set_md_var(tc, "descr", "sched_setscheduler(3), max, RR");
	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC_BODY(sched_setscheduler_1, tc)
{
	int pri;

	pri = sched_get_priority_max(SCHED_RR);
	sched_priority_set(pri, SCHED_RR);
}

ATF_TC(sched_setscheduler_2);
ATF_TC_HEAD(sched_setscheduler_2, tc)
{
	atf_tc_set_md_var(tc, "descr", "sched_setscheduler(3), min, RR");
	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC_BODY(sched_setscheduler_2, tc)
{
	int pri;

	pri = sched_get_priority_min(SCHED_RR);
	sched_priority_set(pri, SCHED_RR);
}

ATF_TC(sched_setscheduler_3);
ATF_TC_HEAD(sched_setscheduler_3, tc)
{
	atf_tc_set_md_var(tc, "descr", "sched_setscheduler(3), max, FIFO");
	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC_BODY(sched_setscheduler_3, tc)
{
	int pri;

	pri = sched_get_priority_max(SCHED_FIFO);
	sched_priority_set(pri, SCHED_FIFO);
}

ATF_TC(sched_setscheduler_4);
ATF_TC_HEAD(sched_setscheduler_4, tc)
{
	atf_tc_set_md_var(tc, "descr", "sched_setscheduler(3), min, FIFO");
	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC_BODY(sched_setscheduler_4, tc)
{
	int pri;

	pri = sched_get_priority_min(SCHED_FIFO);
	sched_priority_set(pri, SCHED_FIFO);
}

ATF_TC(sched_rr_get_interval_1);
ATF_TC_HEAD(sched_rr_get_interval_1, tc)
{
	atf_tc_set_md_var(tc, "descr", "Test sched_rr_get_interval(3), #1"
	    " (PR lib/44768)");
	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC_BODY(sched_rr_get_interval_1, tc)
{
	struct timespec tv;
	int pri;

	pri = sched_get_priority_min(SCHED_RR);
	sched_priority_set(pri, SCHED_RR);

	/*
	 * This should fail with ESRCH for invalid PID.
	 */
	ATF_REQUIRE(sched_rr_get_interval(-INT_MAX, &tv) != 0);
}

ATF_TC(sched_rr_get_interval_2);
ATF_TC_HEAD(sched_rr_get_interval_2, tc)
{
	atf_tc_set_md_var(tc, "descr", "Test sched_rr_get_interval(3), #2");
	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC_BODY(sched_rr_get_interval_2, tc)
{
	struct timespec tv1, tv2;
	int pri;

	pri = sched_get_priority_min(SCHED_RR);
	sched_priority_set(pri, SCHED_RR);

	tv1.tv_sec = tv2.tv_sec = -1;
	tv1.tv_nsec = tv2.tv_nsec = -1;

	ATF_REQUIRE(sched_rr_get_interval(0, &tv1) == 0);
	ATF_REQUIRE(sched_rr_get_interval(getpid(), &tv2) == 0);

	ATF_REQUIRE(tv1.tv_sec != -1);
	ATF_REQUIRE(tv2.tv_sec != -1);

	ATF_REQUIRE(tv1.tv_nsec != -1);
	ATF_REQUIRE(tv2.tv_nsec != -1);

	ATF_REQUIRE(tv1.tv_sec == tv2.tv_sec);
	ATF_REQUIRE(tv1.tv_nsec == tv2.tv_nsec);
}

static struct sched_util
util(int min, int max)
{
	struct sched_util su;

	memset(&su, 0, sizeof(su));
	su.su_min = min;
	su.su_max = max;
	return su;
}

static void
util_expect(pid_t pid, int min, int max)
{
	struct sched_util su;

	ATF_REQUIRE(sched_getutil_np(pid, &su) == 0);
	ATF_CHECK_EQ_MSG(su.su_min, min, "su_min %d, want %d", su.su_min, min);
	ATF_CHECK_EQ_MSG(su.su_max, max, "su_max %d, want %d", su.su_max, max);
}

ATF_TC(sched_util_default);
ATF_TC_HEAD(sched_util_default, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Utilization bounds default to 0 and SCHED_UTIL_SCALE");
}

ATF_TC_BODY(sched_util_default, tc)
{

	util_expect(0, 0, SCHED_UTIL_SCALE);
	util_expect(getpid(), 0, SCHED_UTIL_SCALE);
}

ATF_TC(sched_util_set);
ATF_TC_HEAD(sched_util_set, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Bounds read back as set, and SCHED_UTIL_RESET restores them");
	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC_BODY(sched_util_set, tc)
{
	struct sched_util su;

	su = util(100, 800);
	ATF_REQUIRE(sched_setutil_np(0, &su) == 0);
	util_expect(0, 100, 800);

	su = util(SCHED_UTIL_RESET, 600);
	ATF_REQUIRE(sched_setutil_np(0, &su) == 0);
	util_expect(0, 0, 600);

	su = util(SCHED_UTIL_RESET, SCHED_UTIL_RESET);
	ATF_REQUIRE(sched_setutil_np(0, &su) == 0);
	util_expect(0, 0, SCHED_UTIL_SCALE);
}

ATF_TC(sched_util_einval);
ATF_TC_HEAD(sched_util_einval, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Out of range bounds, min above max and spare fields fail");
}

ATF_TC_BODY(sched_util_einval, tc)
{
	struct sched_util su;

	su = util(800, 100);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, sched_setutil_np(0, &su) == -1);

	su = util(0, SCHED_UTIL_SCALE + 1);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, sched_setutil_np(0, &su) == -1);

	su = util(-2, 100);
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, sched_setutil_np(0, &su) == -1);

	su = util(0, 100);
	su.su_spare[5] = 1;
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, sched_setutil_np(0, &su) == -1);

	/* Nothing of the failed calls took effect. */
	util_expect(0, 0, SCHED_UTIL_SCALE);
}

ATF_TC(sched_util_esrch);
ATF_TC_HEAD(sched_util_esrch, tc)
{
	atf_tc_set_md_var(tc, "descr", "A process that does not exist");
}

ATF_TC_BODY(sched_util_esrch, tc)
{
	struct sched_util su;
	pid_t pid;
	int status;

	/* A child that has been reaped leaves a pid nobody has. */
	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0)
		_exit(0);
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);

	su = util(0, 100);
	errno = 0;
	ATF_REQUIRE_ERRNO(ESRCH, sched_setutil_np(pid, &su) == -1);
	errno = 0;
	ATF_REQUIRE_ERRNO(ESRCH, sched_getutil_np(pid, &su) == -1);
}

ATF_TC(sched_util_eperm);
ATF_TC_HEAD(sched_util_eperm, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "An unprivileged process may lower its bounds but not raise them");
	atf_tc_set_md_var(tc, "require.user", "unprivileged");
}

ATF_TC_BODY(sched_util_eperm, tc)
{
	struct sched_util su;

	su = util(0, 500);
	ATF_REQUIRE(sched_setutil_np(0, &su) == 0);
	util_expect(0, 0, 500);

	su = util(0, 600);
	errno = 0;
	ATF_REQUIRE_ERRNO(EPERM, sched_setutil_np(0, &su) == -1);

	su = util(100, 500);
	errno = 0;
	ATF_REQUIRE_ERRNO(EPERM, sched_setutil_np(0, &su) == -1);

	util_expect(0, 0, 500);
}

static void *
util_thread(void *arg)
{
	struct sched_util *su = arg;

	if (_sched_getutil(0, _lwp_self(), su) != 0)
		su->su_min = -100;
	return NULL;
}

static pthread_mutex_t util_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t util_cv = PTHREAD_COND_INITIALIZER;
static int util_stage;
static lwpid_t util_lid;

static void *
util_waiter(void *arg)
{

	pthread_mutex_lock(&util_mtx);
	util_lid = _lwp_self();
	util_stage = 1;
	pthread_cond_broadcast(&util_cv);
	while (util_stage != 2)
		pthread_cond_wait(&util_cv, &util_mtx);
	pthread_mutex_unlock(&util_mtx);
	return NULL;
}

ATF_TC(sched_util_eperm_atomic);
ATF_TC_HEAD(sched_util_eperm_atomic, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A process-wide change refused for one thread changes none");
	atf_tc_set_md_var(tc, "require.user", "unprivileged");
}

ATF_TC_BODY(sched_util_eperm_atomic, tc)
{
	struct sched_util su;
	pthread_t t;

	ATF_REQUIRE(pthread_create(&t, NULL, util_waiter, NULL) == 0);
	pthread_mutex_lock(&util_mtx);
	while (util_stage != 1)
		pthread_cond_wait(&util_cv, &util_mtx);
	pthread_mutex_unlock(&util_mtx);

	/*
	 * Both orders: the thread that may be lowered is met first in one
	 * round and last in the other, whatever order the kernel walks
	 * the threads in.  Values only go down, as an unprivileged
	 * process may not raise them.
	 */
	static const struct {
		int self, other, req;
	} r[2] = {
		{ 500, 300, 400 },	/* lowers this thread, raises the other */
		{ 100, 300, 200 },	/* raises this thread, lowers the other */
	};
	for (int i = 0; i < 2; i++) {
		su = util(0, r[i].self);
		ATF_REQUIRE(_sched_setutil(0, _lwp_self(), &su) == 0);
		su = util(0, r[i].other);
		ATF_REQUIRE(_sched_setutil(0, util_lid, &su) == 0);

		su = util(0, r[i].req);
		errno = 0;
		ATF_CHECK_ERRNO(EPERM, sched_setutil_np(0, &su) == -1);
		ATF_REQUIRE(_sched_getutil(0, _lwp_self(), &su) == 0);
		ATF_CHECK_EQ_MSG(su.su_max, r[i].self, "round %d: this "
		    "thread's max %d", i, su.su_max);
		ATF_REQUIRE(_sched_getutil(0, util_lid, &su) == 0);
		ATF_CHECK_EQ_MSG(su.su_max, r[i].other, "round %d: other "
		    "thread's max %d", i, su.su_max);
	}

	pthread_mutex_lock(&util_mtx);
	util_stage = 2;
	pthread_cond_broadcast(&util_cv);
	pthread_mutex_unlock(&util_mtx);
	ATF_REQUIRE(pthread_join(t, NULL) == 0);
}

ATF_TC(sched_util_inherit);
ATF_TC_HEAD(sched_util_inherit, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "The child of fork(2) and new threads inherit the bounds");
	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC_BODY(sched_util_inherit, tc)
{
	struct sched_util su, tsu;
	pthread_t t;
	pid_t pid;
	int status;

	su = util(200, 700);
	ATF_REQUIRE(sched_setutil_np(0, &su) == 0);

	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		if (sched_getutil_np(0, &su) != 0 ||
		    su.su_min != 200 || su.su_max != 700)
			_exit(1);
		_exit(0);
	}
	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_CHECK_MSG(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	    "child did not inherit the bounds");

	memset(&tsu, 0, sizeof(tsu));
	ATF_REQUIRE(pthread_create(&t, NULL, util_thread, &tsu) == 0);
	ATF_REQUIRE(pthread_join(t, NULL) == 0);
	ATF_CHECK_EQ_MSG(tsu.su_min, 200, "thread su_min %d", tsu.su_min);
	ATF_CHECK_EQ_MSG(tsu.su_max, 700, "thread su_max %d", tsu.su_max);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, sched_getparam);
	ATF_TP_ADD_TC(tp, sched_priority);

	ATF_TP_ADD_TC(tp, sched_setscheduler_1);
	ATF_TP_ADD_TC(tp, sched_setscheduler_2);
	ATF_TP_ADD_TC(tp, sched_setscheduler_3);
	ATF_TP_ADD_TC(tp, sched_setscheduler_4);

	ATF_TP_ADD_TC(tp, sched_rr_get_interval_1);
	ATF_TP_ADD_TC(tp, sched_rr_get_interval_2);

	ATF_TP_ADD_TC(tp, sched_util_default);
	ATF_TP_ADD_TC(tp, sched_util_set);
	ATF_TP_ADD_TC(tp, sched_util_einval);
	ATF_TP_ADD_TC(tp, sched_util_esrch);
	ATF_TP_ADD_TC(tp, sched_util_eperm);
	ATF_TP_ADD_TC(tp, sched_util_eperm_atomic);
	ATF_TP_ADD_TC(tp, sched_util_inherit);

	return atf_no_error();
}
