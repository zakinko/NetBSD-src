/*
 * Run the algorithms whose assembler the NetBSD build glue fix turns on,
 * through the EVP API of whichever libcrypto the dynamic linker finds, and
 * print one line per result:
 *
 *   evpcheck kat            known answers, prints ok/FAIL lines
 *   evpcheck out <seed>     hex of every result for a fixed pseudo-random
 *                           input; diff the output of two libraries
 *   evpcheck speed <alg>    MB/s over 16 KiB buffers for ~2 s
 *   evpcheck sm2sign <keyfile> <sigfile> / sm2verify <pubfile> <sigfile>
 *   evpcheck one <alg>      run one operation, for a debugger breakpoint
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

static unsigned char key[64], iv[16];

static void
hex(const char *name, const unsigned char *p, size_t n)
{
	size_t i;

	printf("%s ", name);
	for (i = 0; i < n; i++)
		printf("%02x", p[i]);
	printf("\n");
}

static void
die(const char *what)
{
	fprintf(stderr, "%s failed\n", what);
	ERR_print_errors_fp(stderr);
	exit(2);
}

static size_t
digest(const char *alg, const unsigned char *in, size_t n, unsigned char *out)
{
	unsigned int len;

	if (!EVP_Digest(in, n, out, &len, EVP_get_digestbyname(alg), NULL))
		die(alg);
	return len;
}

static size_t
poly1305(const unsigned char *k, const unsigned char *in, size_t n,
    unsigned char *out)
{
	EVP_MAC *mac = EVP_MAC_fetch(NULL, "POLY1305", NULL);
	EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
	size_t len;

	if (ctx == NULL || !EVP_MAC_init(ctx, k, 32, NULL) ||
	    !EVP_MAC_update(ctx, in, n) || !EVP_MAC_final(ctx, out, &len, 16))
		die("poly1305");
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(mac);
	return len;
}

/* Encrypt or decrypt n bytes; for AEAD the 16-byte tag follows the output. */
static size_t
cipher(const char *alg, int enc, const unsigned char *in, size_t n,
    unsigned char *out)
{
	EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, alg, NULL);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int aead, l1 = 0, l2 = 0;

	if (c == NULL)
		die(alg);
	aead = (EVP_CIPHER_get_flags(c) & EVP_CIPH_FLAG_AEAD_CIPHER) != 0;
	if (!EVP_CipherInit_ex2(ctx, c, key, iv, enc, NULL))
		die(alg);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	if (aead && !enc &&
	    !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
	    (void *)(in + n)))
		die("set tag");
	if (aead && !EVP_CipherUpdate(ctx, NULL, &l1, key, 13))	/* AAD */
		die("aad");
	if (!EVP_CipherUpdate(ctx, out, &l1, in, (int)n) ||
	    !EVP_CipherFinal_ex(ctx, out + l1, &l2))
		die(alg);
	if (aead && enc) {
		if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16,
		    out + l1 + l2))
			die("get tag");
		l2 += 16;
	}
	EVP_CIPHER_CTX_free(ctx);
	EVP_CIPHER_free(c);
	return (size_t)(l1 + l2);
}

static const char *digests[] = {
	"SHA256", "SHA384", "SHA512", "SHA512-256", "MD5", "SM3", NULL
};
static const char *ciphers[] = {
	"AES-128-CBC", "AES-256-CBC", "AES-128-CTR", "AES-256-CTR",
	"AES-128-ECB", "AES-128-XTS", "AES-256-XTS", "AES-128-GCM",
	"SM4-CBC", "SM4-CTR", "SM4-ECB", "SM4-XTS", "SM4-GCM",
	"ChaCha20-Poly1305", NULL
};

static int
check(const char *name, const char *want, const unsigned char *p, size_t n)
{
	char got[256];
	size_t i;

	for (i = 0; i < n; i++)
		snprintf(got + 2 * i, 3, "%02x", p[i]);
	if (strcmp(got, want) == 0) {
		printf("ok   %s\n", name);
		return 0;
	}
	printf("FAIL %s: want %s got %s\n", name, want, got);
	return 1;
}

static int
kat(void)
{
	static const unsigned char rk[32] = {
		0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,0x7f,0x44,0x52,0xfe,
		0x42,0xd5,0x06,0xa8,0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
		0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b };
	static const char rm[] = "Cryptographic Forum Research Group";
	unsigned char out[64];
	int f = 0;

	f |= check("sha512(abc)", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
	    out, digest("SHA512", (const unsigned char *)"abc", 3, out));
	f |= check("sha384(abc)", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
	    out, digest("SHA384", (const unsigned char *)"abc", 3, out));
	f |= check("sha256(abc)", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	    out, digest("SHA256", (const unsigned char *)"abc", 3, out));
	f |= check("md5(abc)", "900150983cd24fb0d6963f7d28e17f72",
	    out, digest("MD5", (const unsigned char *)"abc", 3, out));
	f |= check("sm3(abc)", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
	    out, digest("SM3", (const unsigned char *)"abc", 3, out));
	/* RFC 8439 2.5.2 */
	f |= check("poly1305(rfc8439)", "a8061dc1305136c6c22b8baf0c0127a9",
	    out, poly1305(rk, (const unsigned char *)rm, sizeof(rm) - 1, out));
	return f;
}

/* Deterministic bytes, so two runs need not share a file. */
static void
fill(unsigned char *p, size_t n, unsigned long s)
{
	while (n--) {
		s = s * 6364136223846793005UL + 1442695040888963407UL;
		*p++ = (unsigned char)(s >> 56);
	}
}

static void
out(unsigned long seed)
{
	/* lengths around block and bulk boundaries */
	static const size_t lens[] = { 16, 64, 1008, 4096, 65536 + 16 * 3, 1048576 };
	size_t li, n;
	unsigned char *in, *ct, *pt, md[64];
	const char **a;
	char name[64];

	in = malloc(1048576 + 64);
	ct = malloc(1048576 + 64);
	pt = malloc(1048576 + 64);
	fill(key, sizeof(key), seed);
	fill(iv, sizeof(iv), seed + 1);
	for (li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
		n = lens[li];
		fill(in, n + 13, seed + 2 + li);
		for (a = digests; *a; a++) {
			snprintf(name, sizeof(name), "%s/%zu", *a, n + 13);
			hex(name, md, digest(*a, in, n + 13, md));
		}
		snprintf(name, sizeof(name), "POLY1305/%zu", n + 13);
		hex(name, md, poly1305(key, in, n + 13, md));
		for (a = ciphers; *a; a++) {
			size_t m = cipher(*a, 1, in, n, ct);

			snprintf(name, sizeof(name), "%s/%zu", *a, n);
			digest("SHA256", ct, m, md);	/* the ciphertext, hashed */
			hex(name, md, 32);
			/* and it must decrypt back */
			cipher(*a, 0, ct, n, pt);
			if (memcmp(in, pt, n) != 0)
				printf("FAIL decrypt %s\n", name);
		}
	}
}

static void
speed(const char *alg)
{
	static unsigned char buf[16384 + 16], o[16384 + 64];
	struct timespec t0, t1;
	double s;
	long i = 0;
	int isd = EVP_get_digestbyname(alg) != NULL;
	int ism = strcmp(alg, "POLY1305") == 0;

	fill(key, sizeof(key), 1);
	fill(iv, sizeof(iv), 2);
	fill(buf, sizeof(buf), 3);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	do {
		if (isd)
			digest(alg, buf, 16384, o);
		else if (ism)
			poly1305(key, buf, 16384, o);
		else
			cipher(alg, 1, buf, 16384, o);
		i++;
		clock_gettime(CLOCK_MONOTONIC, &t1);
		s = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
	} while (s < 2.0);
	printf("%s %.1f MB/s\n", alg, i * 16384.0 / s / 1e6);
}

static int
sm2(int sign, const char *kf, const char *sf)
{
	static unsigned char msg[4096];
	unsigned char sig[256];
	size_t sl = sizeof(sig);
	FILE *f;
	EVP_PKEY *k;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	int ok;

	fill(msg, sizeof(msg), 7);
	if ((f = fopen(kf, "r")) == NULL)
		die(kf);
	k = sign ? PEM_read_PrivateKey(f, NULL, NULL, NULL) :
	    PEM_read_PUBKEY(f, NULL, NULL, NULL);
	fclose(f);
	if (k == NULL)
		die("read key");
	if (sign) {
		if (!EVP_DigestSignInit(ctx, NULL, EVP_sm3(), NULL, k) ||
		    !EVP_DigestSign(ctx, sig, &sl, msg, sizeof(msg)))
			die("sm2 sign");
		f = fopen(sf, "w");
		fwrite(sig, 1, sl, f);
		fclose(f);
		return 0;
	}
	f = fopen(sf, "r");
	sl = fread(sig, 1, sizeof(sig), f);
	fclose(f);
	ok = EVP_DigestVerifyInit(ctx, NULL, EVP_sm3(), NULL, k) &&
	    EVP_DigestVerify(ctx, sig, sl, msg, sizeof(msg)) == 1;
	return ok ? 0 : 1;
}

int
main(int argc, char **argv)
{
	if (argc >= 2 && strcmp(argv[1], "kat") == 0)
		return kat();
	if (argc == 3 && strcmp(argv[1], "out") == 0) {
		out(strtoul(argv[2], NULL, 0));
		return 0;
	}
	if (argc == 3 && strcmp(argv[1], "speed") == 0) {
		speed(argv[2]);
		return 0;
	}
	if (argc == 4 && strcmp(argv[1], "sm2sign") == 0)
		return sm2(1, argv[2], argv[3]);
	if (argc == 4 && strcmp(argv[1], "sm2verify") == 0)
		return sm2(0, argv[2], argv[3]);
	if (argc == 3 && strcmp(argv[1], "one") == 0) {
		static unsigned char b[65536], o[65536 + 64];

		fill(key, sizeof(key), 1);
		fill(iv, sizeof(iv), 2);
		if (strcmp(argv[2], "SM2") == 0) {
			EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
			EVP_MD_CTX *ctx = EVP_MD_CTX_new();
			size_t sl = sizeof(o);

			if (k == NULL ||
			    !EVP_DigestSignInit(ctx, NULL, EVP_sm3(), NULL, k) ||
			    !EVP_DigestSign(ctx, o, &sl, b, 64))
				die("sm2");
		} else if (EVP_get_digestbyname(argv[2]) != NULL)
			digest(argv[2], b, sizeof(b), o);
		else if (strcmp(argv[2], "POLY1305") == 0)
			poly1305(key, b, sizeof(b), o);
		else {
			cipher(argv[2], 1, b, sizeof(b), o);
			cipher(argv[2], 0, o, sizeof(b), b);
		}
		return 0;
	}
	fprintf(stderr, "usage: see the comment at the top\n");
	return 2;
}
