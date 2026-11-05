/* 2026-11-06: user-space stand-in for what sys/oncrpc takes from the kernel. */
#ifndef SHIM_H
#define SHIM_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#define __KERNEL_RCSID(a,b)
#define __RCSID(x)
#define _DIAGASSERT(x) assert(x)
#define KASSERT(x) assert(x)
#define CTASSERT(x) _Static_assert(x, #x)
#define __UNCONST(p) ((void *)(uintptr_t)(const void *)(p))
#define __arraycount(a) (sizeof(a)/sizeof((a)[0]))
#define __type_fit(t,v) 1
#ifndef NGROUPS
#define NGROUPS 16
#endif
#define warn(...) ((void)0)
#ifndef EMSGSIZE
#include <errno.h>
#endif
#include <errno.h>
#define KM_SLEEP 1
void *kmem_alloc(size_t, int); void *kmem_zalloc(size_t, int); void kmem_free(void *, size_t);
extern size_t kmem_last_alloc, kmem_badfree, kmem_live;
/* mbuf */
#define MLEN 224
#define MHLEN 200
#define MCLBYTES 2048
#define MINCLSIZE (MHLEN+1)
#define M_WAIT 1
#define MT_DATA 1
#define MT_SONAME 3
#define M_PKTHDR 2
struct mbuf { struct mbuf *m_next; int m_len; int m_flags; char *m_data; char *m_base; int m_cap;
	struct { int len; } m_pkthdr; };
#define mtod(m,t) ((t)((m)->m_data))
#define M_TRAILINGSPACE(m) ((m)->m_base + (m)->m_cap - ((m)->m_data + (m)->m_len))
struct mbuf *m_get(int,int); struct mbuf *m_gethdr(int,int); void m_clget(struct mbuf *,int);
void m_freem(struct mbuf *); void m_adj(struct mbuf *,int); struct mbuf *m_split(struct mbuf *,int,int);
void m_copydata(struct mbuf *,int,int,void *); void m_cat(struct mbuf *,struct mbuf *);
#define m_reset_rcvif(m) ((void)0)
#define m_remove_pkthdr(m) ((m)->m_flags &= ~M_PKTHDR)
#define M_PREPEND(m,n,w) do { struct mbuf *_p = m_gethdr(w,MT_DATA); _p->m_len=(n); _p->m_pkthdr.len=(m)->m_pkthdr.len+(n); m_remove_pkthdr(m); _p->m_next=(m); (m)=_p; } while (0)
/* kauth */
typedef struct kcred { uint32_t uid,euid,svuid,gid,egid,svgid; int ng; uint32_t g[32]; int refs; } *kauth_cred_t;
kauth_cred_t kauth_cred_alloc(void);
void kauth_cred_free(kauth_cred_t);
#define kauth_cred_setuid(c,v) ((c)->uid=(v))
#define kauth_cred_seteuid(c,v) ((c)->euid=(v))
#define kauth_cred_setsvuid(c,v) ((c)->svuid=(v))
#define kauth_cred_setgid(c,v) ((c)->gid=(v))
#define kauth_cred_setegid(c,v) ((c)->egid=(v))
#define kauth_cred_setsvgid(c,v) ((c)->svgid=(v))
int kauth_cred_setgroups(kauth_cred_t,const gid_t *,size_t,uid_t,int);
#define UIO_SYSSPACE 1
#endif
