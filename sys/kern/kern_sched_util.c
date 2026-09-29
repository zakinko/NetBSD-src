/*	$NetBSD$	*/

/*-
 * Copyright (c) 2026 Showta Ishizaki <zakinko@snowrabbit.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Utilization tracking and a frequency governor that honours the
 * utilization bounds of LWPs (struct sched_util).
 *
 * Off unless kern.sched.util_governor is set; until then nothing here
 * runs but a predicted branch in statclock and updatertime, and no
 * frequency is touched.
 *
 * Utilization is a decaying average of running time, in parts of
 * SCHED_UTIL_SCALE, with periods of 1024 us and a half-life of 32
 * periods, and scaled by the CPU's capacity and current frequency so
 * that it compares across CPUs.  This is the model Linux documents for
 * its PELT (Documentation/scheduler/schedutil.rst); the code is not
 * derived from Linux.  Two averages are kept:
 *
 *  - per CPU, of busy time, sampled by statclock;
 *  - per LWP, of its run time (l_rtime), brought up to date when it is
 *    switched out and at statclock while it runs.
 *
 * Every util_rate_ms the governor takes, for each frequency domain
 * (sys/cpufreq_domain.h), the highest demand among its CPUs: the CPU's
 * utilization or the sum of its runnable LWPs', whichever is greater,
 * held between the largest minimum and the largest maximum bound of
 * those LWPs (schedutil.rst; sched-util-clamp.rst 2.2, max
 * aggregation), and picks the lowest state that gives 1.25 times that
 * share of the top frequency.  The 25% headroom is also schedutil's.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/condvar.h>
#include <sys/cpu.h>
#include <sys/cpufreq_domain.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lwp.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/timetc.h>

/* 2^(-k/32) in 16.16 fixed point: the decay over k periods, k < 32. */
static const uint32_t sched_util_decay_tab[32] = {
	65536, 64132, 62757, 61413, 60097, 58809, 57549, 56316,
	55109, 53928, 52773, 51642, 50535, 49452, 48393, 47356,
	46341, 45348, 44376, 43425, 42495, 41584, 40693, 39821,
	38968, 38133, 37316, 36516, 35734, 34968, 34219, 33486,
};

#define	UTIL_PERIOD_SHIFT	10	/* 1024 us */
#define	UTIL_HALFLIFE		32	/* periods */
#define	UTIL_FP			16

bool	sched_util_on __read_mostly;
static int	sched_util_rate_ms = 10;

static kmutex_t		sched_util_lock;	/* domains, sched_util_on */
static kcondvar_t	sched_util_cv;
static LIST_HEAD(, cpufreq_domain) sched_util_domains =
    LIST_HEAD_INITIALIZER(sched_util_domains);
static struct lwp	*sched_util_kthread;

/* val decayed over us microseconds; whole periods only. */
static uint32_t
sched_util_decay(uint32_t val, uint64_t us)
{
	const uint64_t n = us >> UTIL_PERIOD_SHIFT;

	if (n >= (uint64_t)UTIL_HALFLIFE * 32)
		return 0;
	val >>= n / UTIL_HALFLIFE;
	/* Rounded: truncating in both places biases the average low. */
	return (uint32_t)(((uint64_t)val *
	    sched_util_decay_tab[n % UTIL_HALFLIFE] +
	    (1U << (UTIL_FP - 1))) >> UTIL_FP);
}

/*
 * Fold an interval of wall us, of which run us were running at a
 * speed of scale/SCHED_UTIL_SCALE, into the average util.
 */
static uint32_t
sched_util_fold(uint32_t util, uint64_t wall, uint64_t run, uint32_t scale)
{
	uint64_t share, gain;

	if (run > wall)
		run = wall;
	share = (run * SCHED_UTIL_SCALE * scale + wall * SCHED_UTIL_SCALE / 2) /
	    (wall * SCHED_UTIL_SCALE);
	gain = (1U << UTIL_FP) - sched_util_decay(1U << UTIL_FP, wall);
	util = sched_util_decay(util, wall) +
	    (uint32_t)((share * gain + (1U << (UTIL_FP - 1))) >> UTIL_FP);
	return MIN(util, SCHED_UTIL_SCALE);
}

static inline uint64_t
bintime_us(const struct bintime *bt)
{

	return (uint64_t)bt->sec * 1000000 +
	    (((uint64_t)1000000 * (uint32_t)(bt->frac >> 32)) >> 32);
}

/* Relative speed of ci now: capacity times frequency ratio. */
static inline uint32_t
sched_util_scale(struct cpu_info *ci)
{
	const uint32_t s = ci->ci_schedstate.spc_util_scale;

	return s != 0 ? s : SCHED_UTIL_SCALE;
}

static void
sched_util_lwp(struct lwp *l, uint64_t now, uint64_t rtime)
{
	uint64_t wall;

	if (__predict_false(l->l_util_stamp == 0)) {
		l->l_util_stamp = now;
		l->l_util_rtime = rtime;
		return;
	}
	wall = now - l->l_util_stamp;
	if (wall >> UTIL_PERIOD_SHIFT == 0 || now < l->l_util_stamp)
		return;		/* less than a period: wait for more */
	l->l_util = sched_util_fold(l->l_util, wall, rtime - l->l_util_rtime,
	    sched_util_scale(curcpu()));
	l->l_util_stamp = now;
	l->l_util_rtime = rtime;
}

/*
 * From updatertime(), with l_rtime just brought up to now.  Called in
 * mi_switch with the CPU's run queue lock held, which statclock cannot
 * interrupt (IPL_CLOCK is IPL_SCHED), so the LWP's fields have one
 * writer at a time.
 */
void
sched_util_switch(struct lwp *l, const struct bintime *now)
{

	sched_util_lwp(l, bintime_us(now), bintime_us(&l->l_rtime));
}

/*
 * The share of a fast CPU that l needs, for placement: its measured
 * utilization held between its bounds, which is what has to fit the
 * CPU's capacity (sched-capacity.rst 5.1.2).  No headroom is added
 * there; the governor's 25% is for choosing a frequency.  Before the
 * governor runs l_util is not kept, and the maximum bound stands in for
 * it, as it did before utilization was measured.  Read without locks;
 * placement takes it as a hint.
 */
u_int
sched_util_lwp_demand(const struct lwp *l)
{
	const u_int min = l->l_util_min, max = l->l_util_max;

	if (!sched_util_on)
		return max;
	return MIN(MAX(l->l_util, min), max);
}

/* From statclock: one sample of this CPU, busy or idle. */
void
sched_util_tick(struct cpu_info *ci, struct lwp *l, bool busy)
{
	struct schedstate_percpu * const spc = &ci->ci_schedstate;
	const uint64_t period = 1000000 / (stathz != 0 ? stathz : hz);
	struct bintime now, rt;

	spc->spc_util = sched_util_fold(spc->spc_util, period,
	    busy ? period : 0, sched_util_scale(ci));

	if ((l->l_flag & LW_IDLE) == 0) {
		/* l_rtime lacks the slice in progress; add it. */
		binuptime(&now);
		rt = l->l_rtime;
		bintime_add(&rt, &now);
		bintime_sub(&rt, &l->l_stime);
		sched_util_lwp(l, bintime_us(&now), bintime_us(&rt));
	}
}

/*
 * The demand of one CPU, with the bounds of what is on it.  Takes the
 * run queue lock to walk the queue.
 */
static uint32_t
sched_util_cpu_demand(struct cpu_info *ci)
{
	struct schedstate_percpu * const spc = &ci->ci_schedstate;
	uint32_t sum = 0, bmin = 0, bmax = 0, u;
	bool any = false;
	struct lwp *l;
	u_int i;

	spc_lock(ci);
	l = ci->ci_onproc;
	if (l != NULL && (l->l_flag & LW_IDLE) == 0) {
		sum += l->l_util;
		bmin = MAX(bmin, l->l_util_min);
		bmax = MAX(bmax, l->l_util_max);
		any = true;
	}
	for (i = 0; i < PRI_COUNT; i++) {
		__typeof__(spc->spc_queue) q;

		/* Bit layout as in kern_runq.c: MSB first, 32 per word. */
		if ((spc->spc_bitmap[i >> 5] & (0x80000000U >> (i & 31))) == 0)
			continue;
		q = &spc->spc_queue[i];
		TAILQ_FOREACH(l, q, l_runq) {
			sum += l->l_util;
			bmin = MAX(bmin, l->l_util_min);
			bmax = MAX(bmax, l->l_util_max);
			any = true;
		}
	}
	u = MAX(spc->spc_util, MIN(sum, SCHED_UTIL_SCALE));
	spc_unlock(ci);

	/* Nothing runnable: no bounds, and the idle average decays. */
	if (!any)
		return u;
	return MIN(MAX(u, bmin), bmax);
}

static void
sched_util_domain(struct cpufreq_domain *cd)
{
	CPU_INFO_ITERATOR cii;
	struct cpu_info *ci;
	uint32_t demand = 0;
	uint64_t want;
	u_int fmax, idx;

	for (CPU_INFO_FOREACH(cii, ci)) {
		if (kcpuset_isset(cd->cd_cpus, cpu_index(ci)))
			demand = MAX(demand, sched_util_cpu_demand(ci));
	}
	fmax = cd->cd_khz[cd->cd_nstates - 1];
	want = (uint64_t)fmax * demand * 5 / 4 / SCHED_UTIL_SCALE;
	for (idx = 0; idx + 1 < cd->cd_nstates; idx++) {
		if (cd->cd_khz[idx] >= want)
			break;
	}
	/* Someone else may have set the clock; believe the hardware. */
	if (cd->cd_get != NULL) {
		const int now = cd->cd_get(cd->cd_cookie);

		if (now >= 0 && (u_int)now < cd->cd_nstates)
			cd->cd_cur = now;
		else
			cd->cd_cur = cd->cd_nstates;	/* unknown: always set */
	}
	if (idx != cd->cd_cur && cd->cd_set(cd->cd_cookie, idx) == 0)
		cd->cd_cur = idx;
	if (cd->cd_cur >= cd->cd_nstates)
		return;		/* unknown and not set: leave the scale */

	/* What a unit of run time is worth on these CPUs now. */
	for (CPU_INFO_FOREACH(cii, ci)) {
		if (!kcpuset_isset(cd->cd_cpus, cpu_index(ci)))
			continue;
		ci->ci_schedstate.spc_util_scale =
		    (uint64_t)MAX(ci->ci_capacity, 1) *
		    cd->cd_khz[cd->cd_cur] / fmax;
	}
}

static void
sched_util_thread(void *arg)
{
	struct cpufreq_domain *cd;

	for (;;) {
		mutex_enter(&sched_util_lock);
		while (!sched_util_on)
			cv_wait(&sched_util_cv, &sched_util_lock);
		LIST_FOREACH(cd, &sched_util_domains, cd_list)
			sched_util_domain(cd);
		mutex_exit(&sched_util_lock);
		kpause("utilgov", false, MAX(mstohz(sched_util_rate_ms), 1),
		    NULL);
	}
}

int
cpufreq_domain_register(struct cpufreq_domain *cd)
{

	if (cd->cd_nstates == 0 || cd->cd_khz == NULL || cd->cd_set == NULL)
		return EINVAL;
	mutex_enter(&sched_util_lock);
	cd->cd_cur = cd->cd_nstates - 1;
	LIST_INSERT_HEAD(&sched_util_domains, cd, cd_list);
	mutex_exit(&sched_util_lock);
	return 0;
}

void
cpufreq_domain_deregister(struct cpufreq_domain *cd)
{

	mutex_enter(&sched_util_lock);
	LIST_REMOVE(cd, cd_list);
	mutex_exit(&sched_util_lock);
}

static int
sysctl_sched_util_governor(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	int val, error;

	val = sched_util_on;
	node.sysctl_data = &val;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || newp == NULL)
		return error;
	if (val != 0 && val != 1)
		return EINVAL;

	mutex_enter(&sched_util_lock);
	if (val && sched_util_kthread == NULL) {
		error = kthread_create(PRI_NONE, KTHREAD_MPSAFE, NULL,
		    sched_util_thread, NULL, &sched_util_kthread, "utilgov");
	}
	if (error == 0) {
		sched_util_on = val;
		cv_broadcast(&sched_util_cv);
	}
	mutex_exit(&sched_util_lock);
	return error;
}

SYSCTL_SETUP(sysctl_sched_util_setup, "sysctl sched util setup")
{
	const struct sysctlnode *node = NULL;

	mutex_init(&sched_util_lock, MUTEX_DEFAULT, IPL_NONE);
	cv_init(&sched_util_cv, "utilgov");

	sysctl_createv(clog, 0, NULL, &node, CTLFLAG_PERMANENT,
	    CTLTYPE_NODE, "sched", SYSCTL_DESCR("Scheduler options"),
	    NULL, 0, NULL, 0, CTL_KERN, CTL_CREATE, CTL_EOL);
	if (node == NULL)
		return;
	sysctl_createv(clog, 0, &node, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE, CTLTYPE_INT,
	    "util_governor",
	    SYSCTL_DESCR("Set CPU frequency from utilization and the "
		"utilization bounds of LWPs (0: off)"),
	    sysctl_sched_util_governor, 0, NULL, 0, CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, &node, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE, CTLTYPE_INT,
	    "util_rate_ms", SYSCTL_DESCR("Utilization governor period, ms"),
	    NULL, 0, &sched_util_rate_ms, 0, CTL_CREATE, CTL_EOL);
}
