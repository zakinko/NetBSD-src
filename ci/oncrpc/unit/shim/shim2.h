/* 2026-11-06: stand-ins needed only to compile oncrpc_svc.c.  Single-threaded. */
#ifndef SHIM2_H
#define SHIM2_H
#include "shim.h"
#include <sys/types.h>
typedef int kmutex_t, kcondvar_t, modcmd_t;
#define MUTEX_DRIVER 0
#define IPL_SOFTNET 0
#define mutex_init(a,b,c) ((void)0)
#define mutex_destroy(a) ((void)0)
#define mutex_enter(a) ((void)0)
#define mutex_exit(a) ((void)0)
#define mutex_owned(a) 1
#define cv_init(a,b) ((void)0)
#define cv_destroy(a) ((void)0)
#define cv_wait(a,b) abort()
#define cv_signal(a) ((void)0)
#define cv_broadcast(a) ((void)0)
#define atomic_inc_uint(p) (++*(p))
#define atomic_dec_uint(p) (--*(p))
#define atomic_load_relaxed(p) (*(p))
#define PRI_NONE 0
#define KTHREAD_MPSAFE 0
#define KTHREAD_MUSTJOIN 0
struct lwp; extern struct lwp *curlwp;
#define kthread_create(...) 0
#define kthread_join(l) ((void)0)
#define kthread_exit(x) return
#define MODULE(...)
#define MODULE_CMD_INIT 1
#define MODULE_CMD_FINI 2
#define DTYPE_SOCKET 1
#define SB_NOINTR 1
#define SB_UPCALL 2
#define SS_ISCONNECTED 1
struct sockbuf { int sb_flags, sb_timeo; };
struct dom { int dom_family; };
struct proto { struct dom *pr_domain; int pr_protocol; };
struct uio { int uio_resid; };
struct socket; 
struct socket { int so_type, so_state; struct proto *so_proto; void *so_upcallarg;
	void (*so_upcall)(struct socket *, void *, int, int); struct sockbuf so_rcv, so_snd;
	int (*so_receive)(struct socket *, struct mbuf **, struct uio *, struct mbuf **, struct mbuf **, int *);
	int (*so_send)(struct socket *, struct sockaddr *, struct uio *, struct mbuf *, struct mbuf *, int, struct lwp *); };
typedef struct file { int f_type, f_count, f_lock; struct socket *f_socket; } file_t;
#define closef(f) ((void)0)
#define solock(s) ((void)0)
#define sounlock(s) ((void)0)
#define soshutdown(s,h) ((void)0)
#define soreserve(s,a,b) 0
#define so_setsockopt(...) 0
#endif
