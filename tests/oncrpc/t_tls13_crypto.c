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
 * The AES-GCM and TLS 1.3 record code of sys/oncrpc/tls13_crypto.c in
 * userland, against published vectors: NIST CAVP for GCM, and the
 * simple 1-RTT trace of RFC 8448 s3 for the traffic keys and records.
 * cc -Isys/oncrpc -Itests/oncrpc/gss-shim tests/oncrpc/t_tls13_crypto.c \
 *     sys/oncrpc/tls13_crypto.c -lcrypto
 */

#include "gss_krb5_shim.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "tls13_crypto.h"

#ifndef __arraycount
#define	__arraycount(a)	(sizeof(a) / sizeof((a)[0]))
#endif

struct gcmv {
	const char *file, *key, *iv, *pt, *aad, *ct, *tag;
	int fail;
};

static const struct gcmv gcmv[] = {
	{ "gcmEncryptExtIV128", "11754cd72aec309bf52f7687212e8957", "3c819d9a9bed087615030b65", "", "", "", "250327c674aaf477aef2675748cf6971", 0 },
	{ "gcmEncryptExtIV128", "77be63708971c4e240d1cb79e8d77feb", "e0e00f19fed7ba0136a797f3", "", "7a43ec1d9c0a5a78a0b16533a6213cab", "", "209fcc8d3675ed938e9c7166709dd946", 0 },
	{ "gcmEncryptExtIV128", "20b5b6b854e187b058a84d57bc1538b6", "94c1935afc061cbf254b936f", "", "ca418e71dbf810038174eaa3719b3fcb80531c7110ad9192d105eeaafa15b819ac005668752b344ed1b22faf77048baf03dbddb3b47d6b00e95c4f005e0cc9b7627ccafd3f21b3312aa8d91d3fa0893fe5bff7d44ca46f23afe0", "", "b37286ebaf4a54e0ffc2a1deafc9f6db", 0 },
	{ "gcmEncryptExtIV128", "7fddb57453c241d03efbed3ac44e371c", "ee283a3fc75575e33efd4887", "d5de42b461646c255c87bd2962d3b9a2", "", "2ccda4a5415cb91e135c2a0f78c9b2fd", "b36d1df9b9d5e596f83e8b7f52971cb3", 0 },
	{ "gcmEncryptExtIV128", "c939cc13397c1d37de6ae0e1cb7c423c", "b3d8cc017cbb89b39e0f67e2", "c3b3c41f113a31b73d9a5cd432103069", "24825602bd12a984e0092d3e448eda5f", "93fe7d9e9bfd10348a5606e5cafa7354", "0032a1dc85f1c9786925a2e71d8272dd", 0 },
	{ "gcmEncryptExtIV128", "bd7c5c63b7542b56a00ebe71336a1588", "87721f23ba9c3c8ea5571abc", "de15ddbb1e202161e8a79af6a55ac6f3", "a6ec8075a0d3370eb7598918f3b93e48444751624997b899a87fa6a9939f844e008aa8b70e9f4c3b1a19d3286bf543e7127bfecba1ad17a5ec53fccc26faecacc4c75369498eaa7d706aef634d0009279b11e4ba6c993e5e9ed9", "41eb28c0fee4d762de972361c863bc80", "9cb567220d0b252eb97bff46e4b00ff8", 0 },
	{ "gcmEncryptExtIV128", "594157ec4693202b030f33798b07176d", "49b12054082660803a1df3df", "3feef98a976a1bd634f364ac428bb59cd51fb159ec1789946918dbd50ea6c9d594a3a31a5269b0da6936c29d063a5fa2cc8a1c", "", "c1b7a46a335f23d65b8db4008a49796906e225474f4fe7d39e55bf2efd97fd82d4167de082ae30fa01e465a601235d8d68bc69", "ba92d3661ce8b04687e8788d55417dc2", 0 },
	{ "gcmEncryptExtIV128", "b61553bb854895b929751cd0c5f80384", "8863f999ae64e55d0bbd7457", "9b1b113217d0c4ea7943cf123c69c6ad2e3c97368c51c9754145d155dde1ee8640c8cafff17a5c9737d26a137eee4bf369096d", "d914b5f2d1b08ce53ea59cb310587245", "acfab4632b8a25805112f13d85e082bc89dc49bd92164fa8a2dad242c3a1b2f2696f2fdff579025f3f146ea97da3e47dc34b65", "5d9b5f4a9868c1c69cbd6fd851f01340", 0 },
	{ "gcmEncryptExtIV128", "2c1f21cf0f6fb3661943155c3e3d8492", "23cb5ff362e22426984d1907", "42f758836986954db44bf37c6ef5e4ac0adaf38f27252a1b82d02ea949c8a1a2dbc0d68b5615ba7c1220ff6510e259f06655d8", "5d3624879d35e46849953e45a32a624d6a6c536ed9857c613b572b0333e701557a713e3f010ecdf9a6bd6c9e3e44b065208645aff4aabee611b391528514170084ccf587177f4488f33cfb5e979e42b6e1cfc0a60238982a7aec", "81824f0e0d523db30d3da369fdc0d60894c7a0a20646dd015073ad2732bd989b14a222b6ad57af43e1895df9dca2a5344a62cc", "57a3ee28136e94c74838997ae9823f3a", 0 },
	{ "gcmDecrypt128", "cf063a34d4a9a76c2c86787d3f96db71", "113b9785971864c83b01c787", "", "", "", "72ac8493e3a5228b5d130a69d2510e42", 0 },
	{ "gcmDecrypt128", "a49a5e26a2f8cb63d05546c2a62f5343", "907763b19b9b4ab6bd4f0281", "", "", "", "a2be08210d8c470a8df6e8fbd79ec5cf", 1 },
	{ "gcmDecrypt128", "d1f6af919cde85661208bdce0c27cb22", "898c6929b435017bf031c3c5", "", "7c5faa40e636bbc91107e68010c92b9f", "", "ae45f11777540a2caeb128be8092468a", 1 },
	{ "gcmDecrypt128", "2370e320d4344208e0ff5683f243b213", "04dbb82f044d30831c441228", "", "d43a8e5089eea0d026c03a85178b27da", "", "2a049c049d25aa95969b451d93c31c6e", 0 },
	{ "gcmDecrypt128", "c1e007d318d0e5c87d28fd890dfb04ba", "d7bc58d494491ff57639b60b", "", "10c68681c6d700ffc72ea9a790cdc9ddc1904c7e886e23ca166dbfa364a4c5f95205bdd1f22eeebefbbb9375f1a416ec7faed6cfdf706085f8fd2632c7a261a78875811f17fba19baf905f0aa623e67175f2158cda313a5047e3", "", "2f1ede16f025bc8c5421854b5f0109d1", 1 },
	{ "gcmDecrypt128", "8dc7a59a71cd76499de67feac53c786a", "beb45b75ea5b7750e69a409d", "", "8bade18807ac5fe59cfd34d7eed8ae33dfeeb960d2a15693837f22dd98f68715079d358a49a04a7b231d486ae45f4cd6c0fe3cde6c0d967ce8d84bbf2e4be2db793afb72ea83c7b21a73f65742c214768f7e6133e3814059efb6", "", "46e8457d8d409f2a0690e6502f8b7a87", 0 },
	{ "gcmDecrypt128", "e98b72a9881a84ca6b76e0f43e68647a", "8b23299fde174053f3d652ba", "28286a321293253c3e0aa2704a278032", "", "5a3c1cf1985dbb8bed818036fdd5ab42", "23c7ab0f952b7091cd324835043b5eb5", 0 },
	{ "gcmDecrypt128", "5164df856f1e9cac04a79b808dc5be39", "e76925d5355e0584ce871b2b", "", "", "0216c899c88d6e32c958c7e553daa5bc", "a145319896329c96df291f64efbe0e3a", 1 },
	{ "gcmDecrypt128", "816e39070410cf2184904da03ea5075a", "32c367a3362613b27fc3e67e", "ecafe96c67a1646744f1c891f5e69427", "f2a30728ed874ee02983c294435d3c16", "552ebe012e7bcf90fcef712f8344e8f1", "ecaae9fc68276a45ab0ca3cb9dd9539f", 0 },
	{ "gcmDecrypt128", "867fc5d5476d5008f0703d81e3622255", "22945529dff947c3c9264df7", "", "261a9efd4f32bc3d07c115b4edcf8adf", "1c785025e5a2678e4b29b29276e395bb", "87fdf1261846164a950c37a3f2eea17d", 1 },
	{ "gcmDecrypt128", "99a9bddbb68be243759bc01c882c4ce7", "6d78e303d165a42082abf5a2", "", "80a8d9fdefb4b114f12208b0a79299ab5e2c8524d2991617f29b23b31cedef24226fadc72b3475c0f201ea0648aa4936ffff9c80f08a329e042cc23728e0b1569357bfd08e9af1b77369bce491b995f7393903c3eceb3fe0c0e4", "1e3a3fdb540717afe12651d3a51b4340", "66dbb3bd4b766df31d37a0282876276c", 1 },
	{ "gcmDecrypt128", "300b8ffab4368cc90f6d4063e4279f2a", "8e69fa64e871d0e98a183a49", "4953b54859870631e818da71fc69c981", "5166309e153447b27c67051453abf441de3f4a7f6b633ec6122ff82dc132cfb422d36c5ec6e7cc90a9ad55caa1ccdcb82dc5022a20062a9c6e9238f34d085b1f554b5eac05eff25b5a5cb6e18e7827d70175dc0662d77033d118", "2d2292da61c280aff86767d25b75e814", "633ee657a8981a7682f87505594c95ad", 0 },
	{ "gcmDecrypt128", "f3c4c058c7f0965a0328f0f011a128e0", "e96098c39d9aa83522119355", "", "", "b42c25155820564b41c525c6aa8ff4363c7c511917772b9bcd574b0be1f6b4ca2153869ddf0c4f76dfad3aef0a76ce056582f9", "44331e39b8a66a81591ed155d7d32372", 1 },
	{ "gcmDecrypt128", "93ae114052b7985d409a39a40df8c7ee", "8ad733a4a9b8330690238c42", "3f3bb0644eac878b97d990d257f5b36e1793490dbc13fea4efe9822cebba7444cce4dee5a7f5dfdf285f96785792812200c279", "", "bbb5b672a479afca2b11adb0a4c762b698dd565908fee1d101f6a01d63332c91b85d7f03ac48a477897d512b4572f9042cb7ea", "4d78bdcb1366fcba02fdccee57e1ff44", 0 },
	{ "gcmDecrypt128", "bc22f3f05cc40db9311e4192966fee92", "134988e662343c06d3ab83db", "337c1bc992386cf0f957617fe4d5ec1218ae1cc40369305518eb177e9b15c1646b142ff71237efaa58790080cd82e8848b295c", "10087e6ed81049b509c31d12fee88c64", "4c0168ab95d3a10ef25e5924108389365c67d97778995892d9fd46897384af61fc559212b3267e90fe4df7bfd1fbed46f4b9ee", "771357958a316f166bd0dacc98ea801a", 0 },
	{ "gcmDecrypt128", "4384629e9b1686927e8508243be1d01a", "84ff7f4feddde7d89d370e7d", "", "a51cebf08d0f293e3a83bea5a9f1cc6d", "8f385490e9622a6c1009900052385c23442890d2af667b210d012781e62d0de311f2149cc377a490afcc686cd92e7c35dc7e5c", "00097982ccc985671477cb1f1a250bd4", 1 },
	{ "gcmDecrypt128", "da2bb7d581493d692380c77105590201", "44aa3e7856ca279d2eb020c6", "9bbf4c1a2742f6ac80cb4e8a052e4a8f4f07c43602361355b717381edf9fabd4cb7e3ad65dbd1378b196ac270588dd0621f642", "4cd171b23bddb3a53cdf959d5c1710b481eb3785a90eb20a2345ee00d0bb7868c367ab12e6f4dd1dee72af4eee1d197777d1d6499cc541f34edbf45cda6ef90b3c024f9272d72ec1909fb8fba7db88a4d6f7d3d925980f9f9f72", "9290d430c9e89c37f0446dbd620c9a6b34b1274aeb6f911f75867efcf95b6feda69f1af4ee16c761b3c9aeac3da03aa9889c88", "9e3ac938d3eb0cadd6f5c9e35d22ba38", 0 },
	{ "gcmDecrypt128", "1986310c725ac94ecfe6422e75fc3ee7", "93ec4214fa8e6dc4e3afc775", "", "e80b88e62c49c958b5e0b8b54f532d9ff6aa84c8a40132e93e55b59fc24e8decf28463139f155d1e8ce4ee76aaeefcd245baa0fc519f83a5fb9ad9aa40c4b21126013f576c4272c2cb136c8fd091cc4539877a5d1e72d607f960", "b178ec72f85a311ac4168f42a4b2c23113fbea4b85f4b9dabb74e143eb1b8b0a361e0243edfd365b90d5b325950df0ada058f9", "8b347853f11d75e81e8a95010be81f17", 1 },
};

static int passed, failed;

static size_t
unhex(uint8_t *out, const char *s)
{
	size_t n = 0;
	unsigned v;

	for (; *s != '\0'; s++) {
		if (*s == ' ')
			continue;
		sscanf(s, "%2x", &v);
		out[n++] = (uint8_t)v;
		s++;
	}
	return n;
}

static void
check(int cond, const char *what)
{

	if (cond)
		passed++;
	else {
		failed++;
		printf("FAIL %s\n", what);
	}
}

static void
test_gcm(void)
{
	uint8_t key[16], iv[12], pt[64], aad[128], ct[64], tag[16], buf[64],
	    t[16];
	size_t i, ptlen, aadlen, ctlen;
	struct tls13_gcm g;
	char what[128];

	for (i = 0; i < __arraycount(gcmv); i++) {
		const struct gcmv *v = &gcmv[i];

		unhex(key, v->key);
		unhex(iv, v->iv);
		ptlen = unhex(pt, v->pt);
		aadlen = unhex(aad, v->aad);
		ctlen = unhex(ct, v->ct);
		unhex(tag, v->tag);
		tls13_gcm_init(&g, key);
		snprintf(what, sizeof(what), "%s #%zu (ct %zu, aad %zu%s)",
		    v->file, i, ctlen, aadlen, v->fail ? ", FAIL" : "");
		memcpy(buf, ct, ctlen);
		if (v->fail) {
			check(tls13_gcm_open(&g, iv, aad, aadlen, buf, ctlen,
			    tag) == EBADMSG, what);
			check(memcmp(buf, ct, ctlen) == 0, "untouched on FAIL");
			continue;
		}
		check(tls13_gcm_open(&g, iv, aad, aadlen, buf, ctlen, tag) == 0 &&
		    memcmp(buf, pt, ptlen) == 0, what);
		memcpy(buf, pt, ptlen);
		tls13_gcm_seal(&g, iv, aad, aadlen, buf, ptlen, t);
		check(memcmp(buf, ct, ctlen) == 0 && memcmp(t, tag, 16) == 0,
		    what);
		/* One bit off in the tag, the data and the AAD. */
		tag[15] ^= 1;
		memcpy(buf, ct, ctlen);
		check(tls13_gcm_open(&g, iv, aad, aadlen, buf, ctlen, tag) ==
		    EBADMSG, "tag bit");
		tag[15] ^= 1;
		if (ctlen > 0) {
			buf[0] ^= 0x80;
			check(tls13_gcm_open(&g, iv, aad, aadlen, buf, ctlen,
			    tag) == EBADMSG, "data bit");
		}
		if (aadlen > 0) {
			memcpy(buf, ct, ctlen);
			aad[aadlen - 1] ^= 1;
			check(tls13_gcm_open(&g, iv, aad, aadlen, buf, ctlen,
			    tag) == EBADMSG, "aad bit");
		}
	}
}

/* RFC 8448 s3 */
static const char c_secret[] =
    "9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52"
    "87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5";
static const char c_key[] = "17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6 3f 50 51";
static const char c_iv[] = "5b 78 92 3d ee 08 57 90 33 e5 23 d9";
static const char s_secret[] =
    "a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32"
    "82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43";
static const char s_key[] = "9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac 92 e3 56";
static const char s_iv[] = "cf 78 2b 88 dd 83 54 9a ad f1 e9 84";
static const char c_app[] =
    "17 03 03 00 43 a2 3f 70 54 b6 2c 94"
    "d0 af fa fe 82 28 ba 55 cb ef ac ea 42 f9 14 aa 66 bc ab 3f 2b"
    "98 19 a8 a5 b4 6b 39 5b d5 4a 9a 20 44 1e 2b 62 97 4e 1f 5a 62"
    "92 a2 97 70 14 bd 1e 3d ea e6 3a ee bb 21 69 49 15 e4";
static const char s_app[] =
    "17 03 03 00 43 2e 93 7e 11 ef 4a c7"
    "40 e5 38 ad 36 00 5f c4 a4 69 32 fc 32 25 d0 5f 82 aa 1b 36 e3"
    "0e fa f9 7d 90 e6 df fc 60 2d cb 50 1a 59 a8 fc c4 9c 4b f2 e5"
    "f0 a2 1c 00 47 c2 ab f3 32 54 0d d0 32 e1 67 c2 95 5d";
static const char c_alert[] =
    "17 03 03 00 13 c9 87 27 60 65 56 66 b7 4d 7f f1 15 3e fd 6d b6 d0 b0 e3";
static const char s_alert[] =
    "17 03 03 00 13 b5 8f d6 71 66 eb f5 99 d2 47 20 cf be 7e fa 7a 88 64 a9";

static void
test_record(const char *who, const char *secret, const char *key,
    const char *iv, const char *app, uint64_t appseq, const char *alert)
{
	uint8_t sec[32], k[16], v[12], want[128], rec[128], type;
	size_t n, len, i;
	struct tls13_dir d;
	char what[64];

	unhex(sec, secret);
	unhex(k, key);
	unhex(v, iv);
	tls13_expand_label(sec, "key", NULL, 0, want, 16);
	snprintf(what, sizeof(what), "%s write key, s7.3", who);
	check(memcmp(want, k, 16) == 0, what);
	tls13_dir_init(&d, sec, appseq);
	snprintf(what, sizeof(what), "%s write iv, s7.3", who);
	check(memcmp(d.d_iv, v, 12) == 0, what);

	/* The payload of both application_data records: 00 01 .. 31 */
	n = unhex(want, app);
	for (i = 0; i < 50; i++)
		rec[TLS13_HDRLEN + i] = (uint8_t)i;
	check(tls13_seal(&d, TLS13_CT_APPDATA, rec, 50) == 0, "seal");
	snprintf(what, sizeof(what), "%s application_data record, seq %ju",
	    who, (uintmax_t)appseq);
	check(n == TLS13_HDRLEN + 50 + 1 + 16 && memcmp(rec, want, n) == 0,
	    what);
	/* The alert of RFC 8448: warning(1), close_notify(0), s6. */
	rec[TLS13_HDRLEN] = 0x01;
	rec[TLS13_HDRLEN + 1] = 0x00;
	check(tls13_seal(&d, TLS13_CT_ALERT, rec, 2) == 0, "seal alert");
	n = unhex(want, alert);
	snprintf(what, sizeof(what), "%s alert record", who);
	check(memcmp(rec, want, n) == 0, what);

	/* And back. */
	tls13_dir_init(&d, sec, appseq);
	n = unhex(rec, app);
	check(tls13_open(&d, rec, n, &type, &len) == 0 &&
	    type == TLS13_CT_APPDATA && len == 50 && rec[TLS13_HDRLEN + 49] == 49,
	    "open application_data");
	n = unhex(rec, alert);
	check(tls13_open(&d, rec, n, &type, &len) == 0 &&
	    type == TLS13_CT_ALERT && len == 2, "open alert");
	/* Replayed: the sequence number has moved on. */
	n = unhex(rec, alert);
	check(tls13_open(&d, rec, n, &type, &len) == EBADMSG, "replay");
	/* The outer type is not application_data. */
	tls13_dir_init(&d, sec, appseq);
	n = unhex(rec, app);
	rec[0] = TLS13_CT_HANDSHAKE;
	check(tls13_open(&d, rec, n, &type, &len) == EPROTO,
	    "outer type, unexpected_message");
	/* Longer than 2^14 + 256. */
	rec[0] = TLS13_CT_APPDATA;
	rec[3] = 0x41;
	rec[4] = 0x01;
	check(tls13_open(&d, rec, n, &type, &len) == EMSGSIZE,
	    "record_overflow");
	tls13_dir_fini(&d);
}

/* Padding, s5.4, and a record of zeros only. */
static void
test_padding(void)
{
	uint8_t sec[32], rec[TLS13_HDRLEN + 64 + 16], type;
	struct tls13_dir w, r;
	size_t len;

	memset(sec, 0x42, sizeof(sec));
	tls13_dir_init(&w, sec, 0);
	tls13_dir_init(&r, sec, 0);
	memset(rec, 0, sizeof(rec));
	rec[TLS13_HDRLEN] = 'x';
	check(tls13_seal(&w, TLS13_CT_APPDATA, rec, 1) == 0, "seal 1");
	check(tls13_open(&r, rec, TLS13_HDRLEN + 2 + 16, &type, &len) == 0 &&
	    len == 1 && type == TLS13_CT_APPDATA, "open 1");
	/* A record whose inner plaintext is a single zero byte. */
	memset(rec, 0, sizeof(rec));
	check(tls13_seal(&w, 0, rec, 0) == 0, "seal type 0");
	check(tls13_open(&r, rec, TLS13_HDRLEN + 1 + 16, &type, &len) ==
	    EPROTO, "no non-zero byte, unexpected_message");
	/* KeyUpdate on both sides keeps them talking; s7.2. */
	tls13_dir_update(&w);
	tls13_dir_update(&r);
	rec[TLS13_HDRLEN] = 'y';
	check(tls13_seal(&w, TLS13_CT_APPDATA, rec, 1) == 0 &&
	    tls13_open(&r, rec, TLS13_HDRLEN + 2 + 16, &type, &len) == 0 &&
	    rec[TLS13_HDRLEN] == 'y', "after KeyUpdate");
	check(w.d_seq == 1 && r.d_seq == 1, "sequence restarted at 0");
}

/*
 * RFC 8446 s7.2 has no published trace; OpenSSL's HKDF in expand-only
 * mode, given the HkdfLabel of s7.1 built here, is the reference.
 */
static void
test_keyupdate(void)
{
	static const char label[] = "tls13 traffic upd";
	uint8_t sec[32], info[64], want[32];
	struct tls13_dir d;
	EVP_PKEY_CTX *pc;
	size_t n = 0, wl = sizeof(want);

	unhex(sec, c_secret);
	info[n++] = 0;
	info[n++] = 32;
	info[n++] = sizeof(label) - 1;
	memcpy(info + n, label, sizeof(label) - 1);
	n += sizeof(label) - 1;
	info[n++] = 0;
	pc = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (pc == NULL || EVP_PKEY_derive_init(pc) <= 0 ||
	    EVP_PKEY_CTX_hkdf_mode(pc, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0 ||
	    EVP_PKEY_CTX_set_hkdf_md(pc, EVP_sha256()) <= 0 ||
	    EVP_PKEY_CTX_set1_hkdf_key(pc, sec, 32) <= 0 ||
	    EVP_PKEY_CTX_add1_hkdf_info(pc, info, (int)n) <= 0 ||
	    EVP_PKEY_derive(pc, want, &wl) <= 0) {
		check(0, "OpenSSL HKDF");
		return;
	}
	EVP_PKEY_CTX_free(pc);
	tls13_dir_init(&d, sec, 7);
	tls13_dir_update(&d);
	check(memcmp(d.d_secret, want, 32) == 0 && d.d_seq == 0,
	    "application_traffic_secret_1, s7.2");
}

int
main(void)
{

	test_gcm();
	/*
	 * RFC 8448 s3: the client's first record under its application
	 * keys is the data; the server sent a NewSessionTicket first.
	 */
	test_record("client", c_secret, c_key, c_iv, c_app, 0, c_alert);
	test_record("server", s_secret, s_key, s_iv, s_app, 1, s_alert);
	test_padding();
	test_keyupdate();
	check(tls13_selftest() == 0, "tls13_selftest");
	printf("%d passed, %d failed\n", passed, failed);
	return failed != 0;
}
