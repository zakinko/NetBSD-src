/* 2026-11-06 mbuf and kmem stand-ins.  m_adj and m_split are written here,
 * so results through them say nothing about the real uipc_mbuf.c. */
#include "shim.h"
#include <sys/types.h>
size_t kmem_last_alloc, kmem_badfree, kmem_live;
void *kmem_alloc(size_t n, int f) { kmem_last_alloc = n; kmem_live += n; size_t *p = malloc(n + 16); *p = n; return (char *)p + 16; }
void *kmem_zalloc(size_t n, int f) { void *p = kmem_alloc(n, f); memset(p, 0, n); return p; }
void kmem_free(void *v, size_t n) { size_t *p = (size_t *)((char *)v - 16); if (*p != n) kmem_badfree++; kmem_live -= *p; free(p); }
static struct mbuf *mk(int cap, int fl) { struct mbuf *m = calloc(1, sizeof *m); m->m_base = m->m_data = malloc(cap); m->m_cap = cap; m->m_flags = fl; return m; }
struct mbuf *m_get(int w, int t) { return mk(MLEN, 0); }
struct mbuf *m_gethdr(int w, int t) { struct mbuf *m = mk(MHLEN, M_PKTHDR); return m; }
void m_clget(struct mbuf *m, int w) { free(m->m_base); m->m_base = m->m_data = malloc(MCLBYTES); m->m_cap = MCLBYTES; }
void m_freem(struct mbuf *m) { while (m) { struct mbuf *n = m->m_next; free(m->m_base); free(m); m = n; } }
void m_adj(struct mbuf *m, int n) { for (; m && n; m = m->m_next) { int k = n < m->m_len ? n : m->m_len; m->m_data += k; m->m_len -= k; n -= k; } }
struct mbuf *m_split(struct mbuf *m, int len, int w) {
	for (; len > m->m_len; m = m->m_next) len -= m->m_len;
	int rest = m->m_len - len; struct mbuf *n;
	if (rest == 0) { n = m->m_next; m->m_next = NULL; return n; }
	n = mk(rest > MLEN ? rest : MLEN, 0); memcpy(n->m_data, m->m_data + len, rest); n->m_len = rest;
	n->m_next = m->m_next; m->m_next = NULL; m->m_len = len; return n; }
void m_copydata(struct mbuf *m, int off, int len, void *p) { char *c = p; for (; len; m = m->m_next) { if (off >= m->m_len) { off -= m->m_len; continue; } int k = m->m_len - off; if (k > len) k = len; memcpy(c, m->m_data + off, k); c += k; len -= k; off = 0; } }
void m_cat(struct mbuf *m, struct mbuf *n) { while (m->m_next) m = m->m_next; m->m_next = n; }
kauth_cred_t kauth_cred_alloc(void) { kauth_cred_t c = calloc(1, sizeof *c); c->refs = 1; return c; }
void kauth_cred_free(kauth_cred_t c) { free(c); }
int kauth_cred_setgroups(kauth_cred_t c, const gid_t *g, size_t n, uid_t u, int s) { c->ng = n; for (size_t i = 0; i < n; i++) c->g[i] = g[i]; return 0; }
