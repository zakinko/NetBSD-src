/*	$NetBSD$	*/

/*
 * For LD_PRELOAD on rpc.gssd, which would give libgssapi the enctypes of
 * the kernel and so hide those of krb5.conf: only the strongest is ever
 * used, and the others cannot be measured through the Linux client.
 */

unsigned int
gss_set_allowable_enctypes(unsigned int *minor, void *cred, void *oid,
    unsigned int n, void *list)
{

	(void)cred; (void)oid; (void)n; (void)list;
	*minor = 0;
	return 0;
}

unsigned int
gss_krb5_set_allowable_enctypes(unsigned int *minor, void *cred,
    unsigned int n, void *list)
{

	(void)cred; (void)n; (void)list;
	*minor = 0;
	return 0;
}
