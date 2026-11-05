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
 * The Kerberos V5 GSS mechanism of sys/oncrpc.  The vectors are copied out
 * of RFC 3961, RFC 3962 and RFC 8009.  Neither RFC 4121 nor RFC 1964 has a
 * token vector: the tokens are checked against an independent construction
 * below, by OpenSSL directly where it matters, and interop is left to a
 * test against MIT krb5.  Every parse runs on a heap copy of exactly the
 * token's length.  Exit status 0 is success.
 *
 *	cc -g -fsanitize=address,undefined -I../../sys/oncrpc -Igss-shim \
 *	    t_gss_krb5.c ../../sys/oncrpc/gss_krb5*.c -lcrypto
 */

#include "gss_krb5_shim.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#define	GSS_KRB5_PRIVATE
#include "gss_krb5.h"

#define	N(a)	(sizeof(a) / sizeof((a)[0]))

/* RFC 3961 A.1 */
static const struct { int n; const char *in, *out; } v_nfold[] = {
	{ 64, "303132333435",
	  "be072631276b1955" },
	{ 56, "70617373776f7264",
	  "78a07b6caf85fa" },
	{ 64, "526f75676820436f6e73656e7375732c20616e642052756e6e696e6720436f6465",
	  "bb6ed30870b7f0e0" },
	{ 168, "70617373776f7264",
	  "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e" },
	{ 192, "4d41535341434856534554545320494e53544954565445204f4620544543484e4f4c4f4759",
	  "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b" },
	{ 168, "51",
	  "518a54a215a8452a518a54a215a8452a518a54a215" },
	{ 168, "6261",
	  "fb25d531ae8974499f52fd92ea9857c4ba24cf297e" },
	{ 64, "6b65726265726f73",
	  "6b65726265726f73" },
	{ 128, "6b65726265726f73",
	  "6b65726265726f737b9b5b2b93132b93" },
	{ 168, "6b65726265726f73",
	  "8372c236344e5f1550cd0747e15d62ca7a5a3bcea4" },
	{ 256, "6b65726265726f73",
	  "6b65726265726f737b9b5b2b93132b935c9bdcdad95c9899c4cae4dee6d6cae4" },
};

/* RFC 3961 A.3 */
static const struct { const char *key, *usage, *dr, *dk; } v_des3[] = {
	{ "dce06b1f64c857a11c3db57c51899b2cc1791008ce973b92", "0000000155",
	  "935079d14490a75c3093c4a6e8c3b049c71e6ee705",
	  "925179d04591a79b5d3192c4a7e9c289b049c71f6ee604cd" },
	{ "5e13d31c70ef765746578531cb51c15bf11ca82c97cee9f2", "00000001aa",
	  "9f58e5a047d894101c469845d67ae3c5249ed812f2",
	  "9e58e5a146d9942a101c469845d67a20e3c4259ed913f207" },
	{ "98e6fd8a04a4b6859b75a176540b9752bad3ecd610a252bc", "0000000155",
	  "12fff90c773f956d13fc2ca0d0840349dbd39908eb",
	  "13fef80d763e94ec6d13fd2ca1d085070249dad39808eabf" },
	{ "622aec25a2fe2cad7094680b7c64940280084c1a7cec92b5", "00000001aa",
	  "f8debf05b097e7dc0603686aca35d91fd9a5516a70",
	  "f8dfbf04b097e6d9dc0702686bcb3489d91fd9a4516b703e" },
	{ "d3f8298ccb166438dcb9b93ee5a7629286a491f838f802fb", "6b65726265726f73",
	  "2270db565d2a3d64cfbfdc5305d4f778a6de42d9da",
	  "2370da575d2a3da864cebfdc5204d56df779a7df43d9da43" },
	{ "c1081649ada74362e6a1459d01dfd30d67c2234c940704da", "0000000155",
	  "348056ec98fcc517171d2b4d7a9493af482d999175",
	  "348057ec98fdc48016161c2a4c7a943e92ae492c989175f7" },
	{ "5d154af238f46713155719d55e2f1f790dd661f279a7917c", "00000001aa",
	  "a8818bc367dadacbe9a6c84627fb60c294b01215e5",
	  "a8808ac267dada3dcbe9a7c84626fbc761c294b01315e5c1" },
	{ "798562e049852f57dc8c343ba17f2ca1d97394efc8adc443", "0000000155",
	  "c813f88b3be2b2f75424ce9175fbc8483b88c8713a",
	  "c813f88a3be3b334f75425ce9175fbe3c8493b89c8703b49" },
	{ "26dce334b545292f2feab9a8701a89a4b99eb9942cecd016", "00000001aa",
	  "f58efc6f83f93e55e695fd252cf8fe59f7d5ba37ec",
	  "f48ffd6e83f83e7354e694fd252cf83bfe58f7d5ba37ec5d" },
};

/* RFC 3962 App. B */
static const char v_cts_key[] = "636869636b656e207465726979616b69";
static const struct { const char *in, *out, *iv; } v_cts[] = {
	{ "4920776f756c64206c696b652074686520",
	  "c6353568f2bf8cb4d8a580362da7ff7f97",
	  "c6353568f2bf8cb4d8a580362da7ff7f" },
	{ "4920776f756c64206c696b65207468652047656e6572616c20476175277320",
	  "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5",
	  "fc00783e0efdb2c1d445d4c8eff7ed22" },
	{ "4920776f756c64206c696b65207468652047656e6572616c2047617527732043",
	  "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584",
	  "39312523a78662d5be7fcbcc98ebf5a8" },
	{ "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c",
	  "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5",
	  "b3fffd940c16a18c1b5549d2f838029e" },
	{ "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20",
	  "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8",
	  "9dad8bbb96c4cdc03bc103e1a194bbd8" },
	{ "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e",
	  "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8",
	  "4807efe836ee89a526730dbc2f7bc840" },
};

/* RFC 8009 App. A, key derivation; usage 2 */
static const struct { const char *base, *kc, *ke, *ki; } v_8009kd[] = {
	{ "3705d96080c17728a0e800eab6e0d23c",
	  "b31a018a48f54776f403e9a396325dc3",
	  "9b197dd1e8c5609d6e67c3e37c62c72e",
	  "9fda0e56ab2d85e1569a688696c26a6c" },
	{ "6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52",
	  "ef5718be86cc84963d8bbb5031e9f5c4ba41f28faf69e73d",
	  "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49",
	  "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f" },
};

/* RFC 8009 App. A, encryptions; et 0 aes128, 1 aes256 */
static const struct { int et; const char *pt, *conf, *ct; } v_8009enc[] = {
	{ 0, "",
	  "7e5895eaf2672435bad817f545a37148",
	  "ef85fb890bb8472f4dab20394dca781dad877eda39d50c870c0d5a0a8e48c718" },
	{ 0, "000102030405",
	  "7bca285e2fd4130fb55b1a5c83bc5b24",
	  "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6877ce99e247e52d16ed4421dfdf8976c" },
	{ 0, "000102030405060708090a0b0c0d0e0f",
	  "56ab21713ff62c0a1457200f6fa9948f",
	  "3517d640f50ddc8ad3628722b3569d2ae07493fa8263254080ea65c1008e8fc295fb4852e7d83e1e7c48c37eebe6b0d3" },
	{ 0, "000102030405060708090a0b0c0d0e0f1011121314",
	  "a7a4e29a4728ce10664fb64e49ad3fac",
	  "720f73b18d9859cd6ccb4346115cd336c70f58edc0c4437c5573544c31c813bce1e6d072c186b39a413c2f92ca9b8334a287ffcbfc" },
	{ 1, "",
	  "f764e9fa15c276478b2c7d0c4e5f58e4",
	  "41f53fa5bfe7026d91faf9be959195a058707273a96a40f0a01960621ac612748b9bbfbe7eb4ce3c" },
	{ 1, "000102030405",
	  "b80d3251c1f6471494256ffe712d0b9a",
	  "4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9f559c7f664f69eab7b6092237526ea0d1f61cb20d69d10f2" },
	{ 1, "000102030405060708090a0b0c0d0e0f",
	  "53bf8a0d105265d4e276428624ce5e63",
	  "bc47ffec7998eb91e8115cf8d19dac4bbbe2e163e87dd37f49beca92027764f68cf51f14d798c2273f35df574d1f932e40c4ff255b36a266" },
	{ 1, "000102030405060708090a0b0c0d0e0f1011121314",
	  "763e65367e864f02f55153c7e3b58af1",
	  "40013e2df58e8751957d2878bcd2d6fe101ccfd556cb1eae79db3c3ee86429f2b2a602ac86fef6ecb647d6295fae077a1feb517508d2c16b4192e01f62" },
};

/* RFC 8009 App. A, checksums */
static const struct { const char *kc, *pt, *ck; } v_8009ck[] = {
	{ "b31a018a48f54776f403e9a396325dc3",
	  "000102030405060708090a0b0c0d0e0f1011121314",
	  "d78367186643d67b411cba9139fc1dee" },
	{ "ef5718be86cc84963d8bbb5031e9f5c4ba41f28faf69e73d",
	  "000102030405060708090a0b0c0d0e0f1011121314",
	  "45ee791567eefca37f4ac1e0222de80d43c3bfa06699672a" },
};

/* RFC 8009 App. A, PRF of "test" */
static const struct { const char *key, *out; } v_8009prf[] = {
	{ "3705d96080c17728a0e800eab6e0d23c",
	  "9d188616f63852fe86915bb840b4a886ff3e6bb0f819b49b893393d393854295" },
	{ "6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52",
	  "9801f69a368c2bf675e59521e177d9a07f67efe1cfde8d3c8d6f6a0256e3b17db3c1b62ad1b8553360d17367eb1514d2" },
};

static const struct {
	uint32_t	enctype;
	const char	*name;
	bool		cfx;
} etypes[] = {
	{ GSS_KRB5_ENC_DES_CBC_CRC, "des-cbc-crc", false },
	{ GSS_KRB5_ENC_DES_CBC_MD5, "des-cbc-md5", false },
	{ GSS_KRB5_ENC_DES3_CBC_SHA1, "des3-cbc-sha1", false },
	{ GSS_KRB5_ENC_AES128_SHA1, "aes128-sha1", true },
	{ GSS_KRB5_ENC_AES256_SHA1, "aes256-sha1", true },
	{ GSS_KRB5_ENC_AES128_SHA256, "aes128-sha256", true },
	{ GSS_KRB5_ENC_AES256_SHA384, "aes256-sha384", true },
};

static unsigned int npass, nfail;

static void
report(bool ok, const char *group, const char *name)
{

	if (ok)
		npass++;
	else
		nfail++;
	printf("%s %s %s\n", ok ? "PASS" : "FAIL", group, name);
}

/* For the many: one line each for the group, every failure named. */
static unsigned int gpass, gfail;

static void
sub(bool ok, const char *what, int a, int b)
{

	if (ok)
		gpass++;
	else {
		if (++gfail < 20)
			printf("  bad: %s %d %d\n", what, a, b);
	}
}

static void
group_end(const char *group, const char *name)
{
	char s[64];

	snprintf(s, sizeof(s), "%s (%u checks)", name, gpass + gfail);
	report(gfail == 0, group, s);
	gpass = gfail = 0;
}

static size_t
unhex(const char *s, uint8_t *out)
{
	size_t i, n = strlen(s) / 2;
	unsigned int v;

	for (i = 0; i < n; i++) {
		sscanf(s + i * 2, "%2x", &v);
		out[i] = (uint8_t)v;
	}
	return n;
}

static void
t_nfold(void)
{
	uint8_t in[128], want[64], out[64];
	char name[32];
	size_t i, n, m;

	for (i = 0; i < N(v_nfold); i++) {
		n = unhex(v_nfold[i].in, in);
		m = unhex(v_nfold[i].out, want);
		if ((size_t)v_nfold[i].n != m * 8)
			abort();
		gk_nfold(in, n, out, m);
		snprintf(name, sizeof(name), "%d-fold #%zu", v_nfold[i].n, i);
		report(memcmp(out, want, m) == 0, "3961-A.1", name);
	}
}

static void
t_des3(void)
{
	const struct gk_etype *et =
	    gk_etype_lookup(GSS_KRB5_ENC_DES3_CBC_SHA1);
	uint8_t key[24], usage[16], dr[21], dk[24], o[32], k[24];
	char name[32];
	size_t i, n;

	for (i = 0; i < N(v_des3); i++) {
		unhex(v_des3[i].key, key);
		n = unhex(v_des3[i].usage, usage);
		unhex(v_des3[i].dr, dr);
		unhex(v_des3[i].dk, dk);
		gk_dr(et, key, usage, n, o);
		snprintf(name, sizeof(name), "DR #%zu", i);
		report(memcmp(o, dr, 21) == 0, "3961-A.3", name);
		gk_des3_random_to_key(o, k);
		snprintf(name, sizeof(name), "DK #%zu", i);
		report(memcmp(k, dk, 24) == 0, "3961-A.3", name);
	}
}

static void
t_cts(void)
{
	struct aesenc enc;
	struct aesdec dec;
	uint8_t key[16], in[64], want[64], iv[16], buf[64];
	uint32_t nr;
	char name[32];
	size_t i, n, nextiv;

	unhex(v_cts_key, key);
	nr = aes_setenckey128(&enc, key);
	(void)aes_setdeckey128(&dec, key);
	for (i = 0; i < N(v_cts); i++) {
		n = unhex(v_cts[i].in, in);
		unhex(v_cts[i].out, want);
		unhex(v_cts[i].iv, iv);
		memcpy(buf, in, n);
		gk_cts_encrypt(&enc, nr, buf, n);
		snprintf(name, sizeof(name), "encrypt %zu", n);
		report(memcmp(buf, want, n) == 0, "3962-B", name);
		/* s5: the next-to-last block, the last if only one. */
		nextiv = n <= 16 ? 0 : ((n - 1) / 16 - 1) * 16;
		snprintf(name, sizeof(name), "next IV %zu", n);
		report(memcmp(buf + nextiv, iv, 16) == 0, "3962-B", name);
		gk_cts_decrypt(&dec, nr, buf, n);
		snprintf(name, sizeof(name), "decrypt %zu", n);
		report(memcmp(buf, in, n) == 0, "3962-B", name);
	}
}

static const uint32_t et8009[2] = {
	GSS_KRB5_ENC_AES128_SHA256, GSS_KRB5_ENC_AES256_SHA384,
};

static void
t_8009(void)
{
	const struct gk_etype *et;
	uint8_t base[32], want[32], o[32], kc[32], pt[64], conf[16], ct[128];
	uint8_t buf[128];
	struct gk_dk dk;
	char name[40];
	size_t i, n, m;

	for (i = 0; i < N(v_8009kd); i++) {
		et = gk_etype_lookup(et8009[i]);
		unhex(v_8009kd[i].base, base);
		n = unhex(v_8009kd[i].kc, want);
		gk_derive(et, base, 2, 0x99, o);
		snprintf(name, sizeof(name), "%s Kc", i ? "aes256" : "aes128");
		report(n == et->ge_kclen && memcmp(o, want, n) == 0,
		    "8009-A-kd", name);
		n = unhex(v_8009kd[i].ke, want);
		gk_derive(et, base, 2, 0xaa, o);
		snprintf(name, sizeof(name), "%s Ke", i ? "aes256" : "aes128");
		report(n == et->ge_kelen && memcmp(o, want, n) == 0,
		    "8009-A-kd", name);
		n = unhex(v_8009kd[i].ki, want);
		gk_derive(et, base, 2, 0x55, o);
		snprintf(name, sizeof(name), "%s Ki", i ? "aes256" : "aes128");
		report(n == et->ge_kilen && memcmp(o, want, n) == 0,
		    "8009-A-kd", name);
	}
	for (i = 0; i < N(v_8009enc); i++) {
		et = gk_etype_lookup(et8009[v_8009enc[i].et]);
		unhex(v_8009kd[v_8009enc[i].et].base, base);
		gk_dk_init(et, base, 2, &dk);
		n = unhex(v_8009enc[i].pt, pt);
		unhex(v_8009enc[i].conf, conf);
		m = unhex(v_8009enc[i].ct, ct);
		memcpy(buf, conf, 16);
		if (n != 0)
			memcpy(buf + 16, pt, n);
		gk_encrypt(et, &dk, buf, n);
		snprintf(name, sizeof(name), "%s %zu encrypt",
		    v_8009enc[i].et ? "aes256" : "aes128", n);
		report(m == 16 + n + et->ge_maclen &&
		    memcmp(buf, ct, m) == 0, "8009-A-enc", name);
		snprintf(name, sizeof(name), "%s %zu decrypt",
		    v_8009enc[i].et ? "aes256" : "aes128", n);
		report(gk_decrypt(et, &dk, buf, m) &&
		    (n == 0 || memcmp(buf + 16, pt, n) == 0), "8009-A-enc",
		    name);
	}
	for (i = 0; i < N(v_8009ck); i++) {
		et = gk_etype_lookup(et8009[i]);
		unhex(v_8009ck[i].kc, kc);
		n = unhex(v_8009ck[i].pt, pt);
		m = unhex(v_8009ck[i].ck, want);
		gk_checksum(et, kc, pt, n, NULL, 0, o);
		report(m == et->ge_maclen && memcmp(o, want, m) == 0,
		    "8009-A-ck", i ? "sha384" : "sha256");
	}
	for (i = 0; i < N(v_8009prf); i++) {
		uint8_t want2[48], o2[48];

		et = gk_etype_lookup(et8009[i]);
		unhex(v_8009prf[i].key, base);
		m = unhex(v_8009prf[i].out, want2);
		gk_kdf2(et->ge_hash, base, et->ge_keylen, "prf", 3, "test", 4,
		    (uint32_t)m * 8, o2);
		report(memcmp(o2, want2, m) == 0, "8009-A-prf",
		    i ? "sha384" : "sha256");
	}
}

static void
mkkey(struct gss_krb5_import *gi, size_t e, bool initiator, bool subkey)
{
	unsigned int i;

	memset(gi, 0, sizeof(*gi));
	gi->gi_enctype = etypes[e].enctype;
	gi->gi_keylen = gk_etype_lookup(gi->gi_enctype)->ge_keylen;
	gi->gi_cfx = etypes[e].cfx;
	for (i = 0; i < gi->gi_keylen; i++)
		gi->gi_key[i] = (uint8_t)(0xa1 + 7 * i);
	gi->gi_initiator = initiator;
	gi->gi_acceptor_subkey = subkey;
}

static void
mkctx(size_t e, bool subkey, struct gss_krb5_ctx **ini,
    struct gss_krb5_ctx **acc)
{
	struct gss_krb5_import gi;

	mkkey(&gi, e, true, subkey);
	if (gss_krb5_ctx_create(&gi, ini) != 0)
		abort();
	mkkey(&gi, e, false, subkey);
	if (gss_krb5_ctx_create(&gi, acc) != 0)
		abort();
}

/* The call on a heap copy of exactly len, so that ASan sees any overrun. */
static uint32_t
xverify(struct gss_krb5_ctx *c, const void *m, size_t mlen, const void *tok,
    size_t len)
{
	uint8_t *p = malloc(len ? len : 1);
	uint32_t r;

	if (len != 0)
		memcpy(p, tok, len);
	r = gss_krb5_verify_mic(c, m, mlen, p, len);
	free(p);
	return r;
}

static uint32_t
xunwrap(struct gss_krb5_ctx *c, const void *tok, size_t len, const void *want,
    size_t wantlen, bool wantconf)
{
	uint8_t *p = malloc(len ? len : 1);
	void *m = NULL;
	size_t mlen = 0;
	bool conf = false;
	uint32_t r;

	if (len != 0)
		memcpy(p, tok, len);
	r = gss_krb5_unwrap(c, p, len, NULL, &m, &mlen, &conf);
	if (r == GSS_S_COMPLETE && want != NULL &&
	    (mlen != wantlen || conf != wantconf ||
	    (mlen != 0 && memcmp(m, want, mlen) != 0)))
		r = GSS_S_FAILURE;
	free(p);
	return r;
}

static void
t_roundtrip(void)
{
	static const size_t sizes[] = {
		0, 1, 15, 16, 17, 31, 32, 33, 4095, 65536
	};
	struct gss_krb5_ctx *c[2];
	uint8_t *msg, *tok, mic[GSS_KRB5_MAXMIC];
	size_t e, i, len, cap;
	int sk, dir;

	msg = malloc(65536);
	for (i = 0; i < 65536; i++)
		msg[i] = (uint8_t)(i * 31 + 7);
	for (e = 0; e < N(etypes); e++) {
		for (sk = 0; sk <= (etypes[e].cfx ? 1 : 0); sk++) {
			mkctx(e, sk != 0, &c[0], &c[1]);
			for (dir = 0; dir < 2; dir++) {
				for (i = 0; i < N(sizes); i++) {
					sub(gss_krb5_get_mic(c[dir], msg,
					    sizes[i], mic, sizeof(mic), &len)
					    == GSS_S_COMPLETE, "getmic", dir,
					    (int)i);
					sub(xverify(c[!dir], msg, sizes[i],
					    mic, len) == GSS_S_COMPLETE,
					    "verify", dir, (int)i);
					cap = gss_krb5_wrap_size(c[dir],
					    sizes[i]);
					tok = malloc(cap);
					sub(gss_krb5_wrap(c[dir], msg,
					    sizes[i], tok, cap, &len) ==
					    GSS_S_COMPLETE && len == cap,
					    "wrap", dir, (int)i);
					sub(xunwrap(c[!dir], tok, len, msg,
					    sizes[i], true) ==
					    GSS_S_COMPLETE, "unwrap", dir,
					    (int)i);
					free(tok);
				}
			}
			gss_krb5_ctx_destroy(c[0]);
			gss_krb5_ctx_destroy(c[1]);
		}
		group_end("roundtrip", etypes[e].name);
	}
	free(msg);
}

/*
 * A CFX Wrap token built outside the code under test.  ec goes in both
 * headers but only fill octets of filler go in; a sender is free to lie.
 */
static size_t
fab_cfx(size_t e, bool byacceptor, bool subkey, bool sealed, unsigned int ec,
    size_t fill, unsigned int rrc, unsigned int innerrrc, uint64_t seq,
    const uint8_t *msg, size_t mlen, uint8_t *tok)
{
	struct gss_krb5_import gi;
	const struct gk_etype *et = gk_etype_lookup(etypes[e].enctype);
	struct gk_dk dk;
	uint8_t *body = tok + 16, hdr[16], *q, *rot;
	size_t n, r, i;

	mkkey(&gi, e, !byacceptor, subkey);
	gk_dk_init(et, gi.gi_key, byacceptor ? 22 : 24, &dk);
	tok[0] = 0x05;
	tok[1] = 0x04;
	tok[2] = (byacceptor ? 1 : 0) | (sealed ? 2 : 0) | (subkey ? 4 : 0);
	tok[3] = 0xff;
	tok[4] = (uint8_t)(ec >> 8);
	tok[5] = (uint8_t)ec;
	tok[6] = (uint8_t)(rrc >> 8);
	tok[7] = (uint8_t)rrc;
	for (i = 0; i < 8; i++)
		tok[8 + i] = (uint8_t)(seq >> (56 - 8 * i));
	if (sealed) {
		memset(body, 0x5a, et->ge_block);
		q = body + et->ge_block;
		if (mlen != 0)
			memcpy(q, msg, mlen);
		memset(q + mlen, 0xee, fill);
		memcpy(hdr, tok, 16);
		hdr[6] = (uint8_t)(innerrrc >> 8);
		hdr[7] = (uint8_t)innerrrc;
		memcpy(q + mlen + fill, hdr, 16);
		gk_encrypt(et, &dk, body, mlen + fill + 16);
		n = et->ge_block + mlen + fill + 16 + et->ge_maclen;
	} else {
		if (mlen != 0)
			memcpy(body, msg, mlen);
		memcpy(hdr, tok, 16);
		memset(hdr + 4, 0, 4);
		gk_checksum(et, dk.gd_kc, body, mlen, hdr, 16, body + mlen);
		n = mlen + et->ge_maclen;
	}
	r = n != 0 ? rrc % n : 0;
	rot = malloc(n);
	memcpy(rot, body + n - r, r);
	memcpy(rot + r, body, n - r);
	memcpy(body, rot, n);
	free(rot);
	return 16 + n;
}

static const uint8_t oid[] = {
	0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02
};

/*
 * A 1964 token built outside the code under test, with OpenSSL for the
 * checksum.  badpad, if not 0, overrides the last octet of the padding.
 */
static size_t
fab_1964(size_t e, bool byacceptor, bool sealed, int badpad, const uint8_t *msg,
    size_t mlen, uint8_t *tok)
{
	struct gss_krb5_import gi;
	const struct gk_etype *et = gk_etype_lookup(etypes[e].enctype);
	bool des = et->ge_keylen == 8;
	size_t mac = des ? 8 : 20, pad = 8 - mlen % 8, body = 8 + mlen + pad;
	size_t inner = 16 + mac + body, hl;
	uint8_t *p, *q, cksum[20], md[16], ck[16], kc[24];
	unsigned int ml;
	des_key_schedule a, b, c;
	des_cblock k, iv;
	HMAC_CTX *h;
	EVP_MD_CTX *m;
	size_t i;

	mkkey(&gi, e, !byacceptor, false);
	memcpy(k, gi.gi_key, 8);
	des_set_key_unchecked(&k, a);
	if (!des) {
		memcpy(k, gi.gi_key + 8, 8);
		des_set_key_unchecked(&k, b);
		memcpy(k, gi.gi_key + 16, 8);
		des_set_key_unchecked(&k, c);
	}
	tok[0] = 0x60;
	if (11 + inner < 0x80) {
		tok[1] = (uint8_t)(11 + inner);
		hl = 2;
	} else {
		tok[1] = 0x82;
		tok[2] = (uint8_t)((11 + inner) >> 8);
		tok[3] = (uint8_t)(11 + inner);
		hl = 4;
	}
	memcpy(tok + hl, oid, 11);
	p = tok + hl + 11;
	p[0] = 2;
	p[1] = 1;
	p[2] = des ? 0 : 4;
	p[3] = 0;
	p[4] = !sealed ? 0xff : des ? 0 : 2;
	p[5] = !sealed ? 0xff : 0;
	p[6] = p[7] = 0xff;
	q = p + 16 + mac;
	memset(q, 0x33, 8);
	if (mlen != 0)
		memcpy(q + 8, msg, mlen);
	memset(q + 8 + mlen, (int)pad, pad);
	if (badpad != 0)
		q[body - 1] = (uint8_t)badpad;
	if (des) {
		m = EVP_MD_CTX_new();
		EVP_DigestInit_ex(m, EVP_md5(), NULL);
		EVP_DigestUpdate(m, p, 8);
		EVP_DigestUpdate(m, q, body);
		EVP_DigestFinal_ex(m, md, &ml);
		EVP_MD_CTX_free(m);
		memset(iv, 0, 8);
		des_ncbc_encrypt(md, ck, 16, a, &iv, DES_ENCRYPT);
		memcpy(cksum, ck + 8, 8);
	} else {
		gk_derive(et, gi.gi_key, 23, 0x99, kc);
		h = HMAC_CTX_new();
		HMAC_Init_ex(h, kc, 24, EVP_sha1(), NULL);
		HMAC_Update(h, p, 8);
		HMAC_Update(h, q, body);
		HMAC_Final(h, cksum, &ml);
		HMAC_CTX_free(h);
	}
	memcpy(p + 16, cksum, mac);
	memset(p + 8, 0, 4);
	p[8] = 9;
	memset(p + 12, byacceptor ? 0xff : 0, 4);
	memcpy(iv, cksum, 8);
	if (des)
		des_ncbc_encrypt(p + 8, p + 8, 8, a, &iv, DES_ENCRYPT);
	else
		des_ede3_cbc_encrypt(p + 8, p + 8, 8, a, b, c, &iv,
		    DES_ENCRYPT);
	if (sealed) {
		memset(iv, 0, 8);
		if (des) {
			for (i = 0; i < 8; i++)
				k[i] = gi.gi_key[i] ^ 0xf0;
			des_set_key_unchecked(&k, a);
			des_ncbc_encrypt(q, q, (long)body, a, &iv,
			    DES_ENCRYPT);
		} else
			des_ede3_cbc_encrypt(q, q, (long)body, a, b, c, &iv,
			    DES_ENCRYPT);
	}
	return hl + 11 + inner;
}

static void
t_flip(void)
{
	static const uint8_t msg[6] = "hello";
	struct gss_krb5_ctx *c[2];
	uint8_t tok[256], t[256];
	size_t e, len, i;
	int b;

	for (e = 0; e < N(etypes); e++) {
		mkctx(e, false, &c[0], &c[1]);

		gss_krb5_get_mic(c[0], msg, 5, tok, sizeof(tok), &len);
		for (i = 0; i < len; i++) {
			for (b = 0; b < 8; b++) {
				memcpy(t, tok, len);
				t[i] ^= 1 << b;
				sub(xverify(c[1], msg, 5, t, len) !=
				    GSS_S_COMPLETE, "mic flip", (int)i, b);
			}
		}
		for (i = 0; i < len; i++)
			sub(xverify(c[1], msg, 5, tok, i) != GSS_S_COMPLETE,
			    "mic trunc", (int)i, 0);
		sub(xverify(c[1], msg, 5, tok, len + 1) != GSS_S_COMPLETE,
		    "mic long", 0, 0);
		sub(xverify(c[0], msg, 5, tok, len) != GSS_S_COMPLETE,
		    "mic reflected", 0, 0);
		sub(xunwrap(c[1], tok, len, NULL, 0, false) != GSS_S_COMPLETE,
		    "mic as wrap", 0, 0);
		sub(xverify(c[1], "hellp", 5, tok, len) == GSS_S_BAD_SIG,
		    "mic other message", 0, 0);

		gss_krb5_wrap(c[0], msg, 5, tok, sizeof(tok), &len);
		for (i = 0; i < len; i++) {
			for (b = 0; b < 8; b++) {
				memcpy(t, tok, len);
				t[i] ^= 1 << b;
				sub(xunwrap(c[1], t, len, NULL, 0, false) !=
				    GSS_S_COMPLETE, "wrap flip", (int)i, b);
			}
		}
		for (i = 0; i < len; i++)
			sub(xunwrap(c[1], tok, i, NULL, 0, false) !=
			    GSS_S_COMPLETE, "wrap trunc", (int)i, 0);
		sub(xunwrap(c[0], tok, len, NULL, 0, false) != GSS_S_COMPLETE,
		    "wrap reflected", 0, 0);
		sub(xverify(c[1], msg, 5, tok, len) != GSS_S_COMPLETE,
		    "wrap as mic", 0, 0);
		sub(xunwrap(c[1], tok, len, msg, 5, true) == GSS_S_COMPLETE,
		    "wrap intact", 0, 0);

		gss_krb5_ctx_destroy(c[0]);
		gss_krb5_ctx_destroy(c[1]);
		group_end("reject", etypes[e].name);
	}
}

static void
rotate_tok(uint8_t *tok, size_t len, unsigned int rrc)
{
	size_t n = len - 16, r = rrc % n;
	uint8_t *t = malloc(n);

	memcpy(t, tok + 16 + n - r, r);
	memcpy(t + r, tok + 16, n - r);
	memcpy(tok + 16, t, n);
	tok[6] = (uint8_t)(rrc >> 8);
	tok[7] = (uint8_t)rrc;
	free(t);
}

static void
t_cfx(void)
{
	static const unsigned int rrcs[] = { 0, 1, 16, 28, 44, 1000, 65535 };
	static const uint8_t msg[33] = "0123456789abcdef0123456789abcdef";
	struct gss_krb5_ctx *c[2], *s[2];
	const struct gk_etype *et;
	uint8_t tok[1024], t[1024], m[GSS_KRB5_MAXMIC];
	uint8_t want[EVP_MAX_MD_SIZE], kc[32], d[128];
	struct gss_krb5_import gi;
	unsigned int ml;
	size_t e, i, len;
	const EVP_MD *md;
	int sk;

	for (e = 0; e < N(etypes); e++) {
		if (!etypes[e].cfx)
			continue;
		et = gk_etype_lookup(etypes[e].enctype);
		mkctx(e, false, &c[0], &c[1]);
		mkctx(e, true, &s[0], &s[1]);

		/* The sender's RRC is ours; these are any other. */
		for (i = 0; i < N(rrcs); i++) {
			gss_krb5_wrap(c[0], msg, sizeof(msg), tok,
			    sizeof(tok), &len);
			rotate_tok(tok, len, rrcs[i]);
			sub(xunwrap(c[1], tok, len, msg, sizeof(msg), true)
			    == GSS_S_COMPLETE, "rrc conf", (int)i, 0);
			len = fab_cfx(e, false, false, false, et->ge_maclen, 0,
			    rrcs[i], 0, 7, msg, sizeof(msg), tok);
			sub(xunwrap(c[1], tok, len, msg, sizeof(msg), false)
			    == GSS_S_COMPLETE, "rrc noconf", (int)i, 0);
			len = fab_cfx(e, true, true, true, 0, 0, rrcs[i], 0, 7,
			    msg, sizeof(msg), tok);
			sub(xunwrap(s[0], tok, len, msg, sizeof(msg), true)
			    == GSS_S_COMPLETE, "rrc fab", (int)i, 0);
		}
		len = fab_cfx(e, false, false, false, et->ge_maclen, 0, 65535,
		    0, 7, NULL, 0, tok);
		sub(xunwrap(c[1], tok, len, NULL, 0, false) == GSS_S_COMPLETE,
		    "noconf empty", 0, 0);

		/* EC: filler is honoured, and a false count stays inside. */
		len = fab_cfx(e, false, false, true, 100, 100, 0, 0, 7, msg,
		    sizeof(msg), tok);
		sub(xunwrap(c[1], tok, len, msg, sizeof(msg), true) ==
		    GSS_S_COMPLETE, "ec 100", 0, 0);
		len = fab_cfx(e, false, false, true, 35, 1, 0, 0, 7, msg,
		    sizeof(msg), tok);
		sub(xunwrap(c[1], tok, len, NULL, 0, false) ==
		    GSS_S_DEFECTIVE_TOKEN, "ec past start", 0, 0);
		len = fab_cfx(e, false, false, true, 65535, 0, 0, 0, 7, msg,
		    sizeof(msg), tok);
		sub(xunwrap(c[1], tok, len, NULL, 0, false) ==
		    GSS_S_DEFECTIVE_TOKEN, "ec 65535", 0, 0);
		len = fab_cfx(e, false, false, false, 65535, 0, 0, 0, 7, msg,
		    sizeof(msg), tok);
		sub(xunwrap(c[1], tok, len, NULL, 0, false) ==
		    GSS_S_DEFECTIVE_TOKEN, "noconf ec 65535", 0, 0);
		len = fab_cfx(e, false, false, false, 0, 0, 0, 0, 7, msg,
		    sizeof(msg), tok);
		sub(xunwrap(c[1], tok, len, NULL, 0, false) ==
		    GSS_S_DEFECTIVE_TOKEN, "noconf ec 0", 0, 0);
		len = fab_cfx(e, false, false, false, et->ge_maclen, 0, 0, 0,
		    7, msg, sizeof(msg), tok);
		tok[16] ^= 1;
		sub(xunwrap(c[1], tok, len, NULL, 0, false) == GSS_S_BAD_SIG,
		    "noconf flipped", 0, 0);

		/* The copy agrees with the outside, RRC apart. */
		len = fab_cfx(e, false, false, true, 0, 0, 0, 5, 7, msg,
		    sizeof(msg), tok);
		sub(xunwrap(c[1], tok, len, msg, sizeof(msg), true) ==
		    GSS_S_COMPLETE, "inner rrc", 0, 0);
		len = fab_cfx(e, false, false, true, 0, 0, 0, 0, 7, msg,
		    sizeof(msg), tok);
		tok[15] ^= 1;		/* the outer SND_SEQ */
		sub(xunwrap(c[1], tok, len, NULL, 0, false) ==
		    GSS_S_DEFECTIVE_TOKEN, "outer seq", 0, 0);

		/* The direction and the subkey flag, properly protected. */
		len = fab_cfx(e, true, false, true, 0, 0, 0, 0, 7, msg,
		    sizeof(msg), tok);
		sub(xunwrap(c[1], tok, len, NULL, 0, false) ==
		    GSS_S_DEFECTIVE_TOKEN, "wrong direction", 0, 0);
		sub(xunwrap(c[0], tok, len, msg, sizeof(msg), true) ==
		    GSS_S_COMPLETE, "right direction", 0, 0);
		for (sk = 0; sk < 2; sk++) {
			gss_krb5_get_mic(sk ? s[0] : c[0], msg, 5, m, sizeof(m),
			    &len);
			sub(xverify(sk ? c[1] : s[1], msg, 5, m, len) ==
			    GSS_S_DEFECTIVE_TOKEN, "subkey mic", sk, 0);
			gss_krb5_wrap(sk ? s[0] : c[0], msg, 5, tok,
			    sizeof(tok), &len);
			sub(xunwrap(sk ? c[1] : s[1], tok, len, NULL, 0, false)
			    == GSS_S_DEFECTIVE_TOKEN, "subkey wrap", sk, 0);
		}

		/*
		 * The MIC, from the outside: format of s4.2.6.1, checksum
		 * of s4.2.4 by OpenSSL's HMAC, usage of s2, sequence.
		 */
		md = et->ge_hash == GK_HASH_SHA1 ? EVP_sha1() :
		    et->ge_hash == GK_HASH_SHA256 ? EVP_sha256() : EVP_sha384();
		mkkey(&gi, e, true, true);
		gi.gi_send_seq = 0x0102030405060708ULL;
		gss_krb5_ctx_destroy(s[0]);
		gss_krb5_ctx_create(&gi, &s[0]);
		gss_krb5_get_mic(s[0], msg, sizeof(msg), m, sizeof(m), &len);
		gk_derive(et, gi.gi_key, 25, 0x99, kc);
		memcpy(d, msg, sizeof(msg));
		memcpy(d + sizeof(msg), m, 16);
		HMAC(md, kc, (int)et->ge_kclen, d, sizeof(msg) + 16, want, &ml);
		sub(len == 16 + et->ge_maclen, "mic len", 0, 0);
		sub(memcmp(m, "\x04\x04\x04\xff\xff\xff\xff\xff"
		    "\x01\x02\x03\x04\x05\x06\x07\x08", 16) == 0, "mic hdr",
		    0, 0);
		sub(memcmp(m + 16, want, et->ge_maclen) == 0, "mic sum", 0, 0);
		gss_krb5_get_mic(s[0], msg, sizeof(msg), m, sizeof(m), &len);
		sub(m[15] == 9, "mic seq+1", 0, 0);
		/* Sealed in a MIC, with a good checksum: s4.2.2. */
		mkkey(&gi, e, false, false);
		gk_derive(et, gi.gi_key, 25, 0x99, kc);
		memset(m, 0xff, 16);
		m[0] = m[1] = 4;
		m[2] = 2;
		memset(m + 8, 0, 8);
		memcpy(d, msg, 5);
		memcpy(d + 5, m, 16);
		HMAC(md, kc, (int)et->ge_kclen, d, 5 + 16, m + 16, &ml);
		sub(xverify(c[1], msg, 5, m, 16 + et->ge_maclen) ==
		    GSS_S_DEFECTIVE_TOKEN, "mic sealed", 0, 0);
		/* An unknown flag is ignored: it reaches the checksum. */
		m[2] = 0x80;
		memcpy(d + 5, m, 16);
		HMAC(md, kc, (int)et->ge_kclen, d, 5 + 16, m + 16, &ml);
		sub(xverify(c[1], msg, 5, m, 16 + et->ge_maclen) ==
		    GSS_S_COMPLETE, "mic unknown flag", 0, 0);

		/* Wrap's format, and that Ke, Ki of s2 opened it. */
		gss_krb5_wrap(c[0], msg, sizeof(msg), tok, sizeof(tok), &len);
		sub(tok[0] == 5 && tok[1] == 4 && tok[2] == 2 &&
		    tok[3] == 0xff && tok[4] == 0 && tok[5] == 0 &&
		    tok[6] == 0 && tok[7] == 0, "wrap hdr", 0, 0);
		{
			struct gk_dk dk;

			gk_dk_init(et, gi.gi_key, 24, &dk);
			memcpy(t, tok, len);
			sub(gk_decrypt(et, &dk, t + 16, len - 16) &&
			    memcmp(t + 32, msg, sizeof(msg)) == 0 &&
			    memcmp(t + 32 + sizeof(msg), tok, 16) == 0,
			    "wrap body", 0, 0);
		}

		gss_krb5_ctx_destroy(c[0]);
		gss_krb5_ctx_destroy(c[1]);
		gss_krb5_ctx_destroy(s[0]);
		gss_krb5_ctx_destroy(s[1]);
		group_end("cfx", etypes[e].name);
	}
}

static void
t_1964(void)
{
	static const uint8_t msg[21] = "a message of twenty.";
	struct gss_krb5_ctx *c[2];
	uint8_t tok[512], t[512], *big;
	size_t e, len, i, off;
	int sealed, dir;
	void *m;
	size_t ml;
	bool conf;

	for (e = 0; e < N(etypes); e++) {
		if (etypes[e].cfx)
			continue;
		mkctx(e, false, &c[0], &c[1]);

		for (dir = 0; dir < 2; dir++) {
			for (sealed = 0; sealed < 2; sealed++) {
				len = fab_1964(e, dir != 0, sealed != 0, 0,
				    msg, sizeof(msg), tok);
				sub(xunwrap(c[!dir], tok, len, msg,
				    sizeof(msg), sealed != 0) ==
				    GSS_S_COMPLETE, "fab opens", dir, sealed);
				sub(xunwrap(c[dir], tok, len, NULL, 0, false)
				    != GSS_S_COMPLETE, "fab reflected", dir,
				    sealed);
				len = fab_1964(e, dir != 0, sealed != 0, 0,
				    msg, 16, tok);
				sub(xunwrap(c[!dir], tok, len, msg, 16,
				    sealed != 0) == GSS_S_COMPLETE,
				    "fab 8 of pad", dir, sealed);
				len = fab_1964(e, dir != 0, sealed != 0, 0,
				    NULL, 0, tok);
				sub(xunwrap(c[!dir], tok, len, NULL, 0, false)
				    == GSS_S_COMPLETE, "fab empty", dir,
				    sealed);
				/* Good checksum over bad padding. */
				len = fab_1964(e, dir != 0, sealed != 0, 9,
				    msg, 16, tok);
				sub(xunwrap(c[!dir], tok, len, NULL, 0, false)
				    == GSS_S_DEFECTIVE_TOKEN, "pad 9", dir,
				    sealed);
				len = fab_1964(e, dir != 0, sealed != 0, 3,
				    msg, 16, tok);
				sub(xunwrap(c[!dir], tok, len, NULL, 0, false)
				    == GSS_S_DEFECTIVE_TOKEN, "pad false", dir,
				    sealed);
				len = fab_1964(e, dir != 0, sealed != 0, 0x100,
				    msg, 16, tok);
				sub(xunwrap(c[!dir], tok, len, NULL, 0, false)
				    == GSS_S_DEFECTIVE_TOKEN, "pad 0", dir,
				    sealed);
			}
		}

		/* The framing: not the shortest DER is not a token. */
		gss_krb5_wrap(c[0], msg, sizeof(msg), tok, sizeof(tok), &len);
		sub(tok[0] == 0x60 && memcmp(tok + 2, oid, 11) == 0 &&
		    tok[1] == len - 2, "frame", 0, 0);
		sub(tok[13] == 2 && tok[14] == 1 && tok[17] != 0xff &&
		    tok[19] == 0xff, "wrap hdr", 0, 0);
		t[0] = 0x60;
		t[1] = 0x81;
		t[2] = tok[1];
		memcpy(t + 3, tok + 2, len - 2);
		sub(xunwrap(c[1], t, len + 1, NULL, 0, false) ==
		    GSS_S_DEFECTIVE_TOKEN, "long-form length", 0, 0);
		t[1] = 0x85;
		sub(xunwrap(c[1], t, len + 1, NULL, 0, false) ==
		    GSS_S_DEFECTIVE_TOKEN, "length of length", 0, 0);
		/* Lengths at the framing's steps, written and read. */
		big = malloc(0x12000);
		for (i = 0; i < 3; i++) {
			static const size_t bigs[3] = { 80, 200, 0x10000 };

			off = bigs[i];
			sub(gss_krb5_wrap(c[0], (uint8_t[0x10000]){ 0 }, off,
			    big, 0x12000, &len) == GSS_S_COMPLETE, "big wrap",
			    (int)i, 0);
			sub(gss_krb5_unwrap(c[1], big, len, NULL, &m, &ml,
			    &conf) == GSS_S_COMPLETE && ml == off && conf,
			    "big unwrap", (int)i, 0);
		}
		free(big);

		gss_krb5_ctx_destroy(c[0]);
		gss_krb5_ctx_destroy(c[1]);
		group_end("1964", etypes[e].name);
	}
}

static void
t_api(void)
{
	struct gss_krb5_import gi;
	struct gss_krb5_ctx *c;
	uint8_t tok[128];
	size_t e, len;

	for (e = 0; e < N(etypes); e++) {
		mkkey(&gi, e, true, false);
		gi.gi_keylen--;
		sub(gss_krb5_ctx_create(&gi, &c) == EINVAL, "keylen", 0, 0);
		mkkey(&gi, e, true, false);
		gi.gi_cfx = !gi.gi_cfx;
		sub(gss_krb5_ctx_create(&gi, &c) == EINVAL, "cfx", 0, 0);
		mkkey(&gi, e, true, false);
		sub(gss_krb5_ctx_create(&gi, &c) == 0, "create", 0, 0);
		sub(gss_krb5_get_mic(c, "x", 1, tok, 8, &len) == GSS_S_FAILURE,
		    "mic room", 0, 0);
		sub(gss_krb5_wrap(c, "x", 1, tok,
		    gss_krb5_wrap_size(c, 1) - 1, &len) == GSS_S_FAILURE,
		    "wrap room", 0, 0);
		sub(gss_krb5_wrap_size(c, SIZE_MAX) == SIZE_MAX, "wrap_size",
		    0, 0);
		gss_krb5_ctx_destroy(c);
	}
	gi.gi_enctype = 23;
	sub(gss_krb5_ctx_create(&gi, &c) == EINVAL, "rc4", 0, 0);
	group_end("api", "create and limits");
	report(gss_krb5_selftest() == 0, "selftest", "gss_krb5_selftest()");
}

int
main(void)
{

	t_nfold();
	t_des3();
	t_cts();
	t_8009();
	t_roundtrip();
	t_flip();
	t_cfx();
	t_1964();
	t_api();
	printf("%u passed, %u failed\n", npass, nfail);
	return nfail != 0;
}
