/**
 *	@file    eccperf.c
 *	@version $Format:%h%d$
 *
 *	ECC performance testing	.
 */
/*
 *	Copyright (c) 2013-2016 INSIDE Secure Corporation
 *	Copyright (c) PeerSec Networks, 2002-2011
 *	All Rights Reserved
 *
 *	The latest version of this code is available at http://www.matrixssl.org
 *
 *	This software is open source; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This General Public License does NOT permit incorporating this software
 *	into proprietary programs.  If you are unable to comply with the GPL, a
 *	commercial license for this software may be purchased from INSIDE at
 *	http://www.insidesecure.com/
 *
 *	This program is distributed in WITHOUT ANY WARRANTY; without even the
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *	See the GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *	http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

#include "crypto/cryptoApi.h"

#ifdef USE_ECC

/* OPERATIONS TO TEST */
#define SIGN_OP		/* Private encrypt operations */
#define VERIFY_OP	/* Public decrypt operations */
#define MAKE_KEY_OP	/* DH key gen operations */
#define SHARED_SECRET_OP	/* DH shared secret computation */

/* CURVES TO TEST */
#ifdef USE_SECP192R1
 #define DO_SECP192R1
#endif
#ifdef USE_SECP224R1
 #define DO_SECP224R1
#endif
#ifdef USE_SECP256R1
 #define DO_SECP256R1
#endif
#ifdef USE_SECP384R1
 #define DO_SECP384R1
#endif
#ifdef USE_SECP521R1
 #define DO_SECP521R1
#endif

#ifdef USE_BRAIN224R1
 #define DO_BRAIN224R1
#endif
#ifdef USE_BRAIN256R1
 #define DO_BRAIN256R1
#endif
#ifdef USE_BRAIN384R1
 #define DO_BRAIN384R1
#endif
#ifdef USE_BRAIN512R1
//TODO not currently working
// #define DO_BRAIN512R1
#endif

/* NUMBER OF OPERATIONS */
#define ITER 1

#define PS_OH sizeof(psPool_t)

/**/
#define POOL_SIGN_192		(8 * 1024) + PS_OH
#define POOL_VERIFY_192		(8 * 1024) + PS_OH
#define POOL_MAKE_KEY_192	(8 * 1024) + PS_OH
#define POOL_MISC_192		(8 * 1024) + PS_OH

#define POOL_SIGN_224		(8 * 1024) + PS_OH
#define POOL_VERIFY_224		(8 * 1024) + PS_OH
#define POOL_MAKE_KEY_224	(8 * 1024) + PS_OH
#define POOL_MISC_224		(8 * 1024) + PS_OH

#define POOL_SIGN_256		(8 * 1024) + PS_OH
#define POOL_VERIFY_256		(8 * 1024) + PS_OH
#define POOL_MAKE_KEY_256	(8 * 1024) + PS_OH
#define POOL_MISC_256		(8 * 1024) + PS_OH

#define POOL_SIGN_384		(12 * 1024) + PS_OH
#define POOL_VERIFY_384		(12 * 1024) + PS_OH
#define POOL_MAKE_KEY_384	(12 * 1024) + PS_OH
#define POOL_MISC_384		(12 * 1024) + PS_OH

#define POOL_SIGN_521		(12 * 1024) + PS_OH
#define POOL_VERIFY_521		(12 * 1024) + PS_OH
#define POOL_MAKE_KEY_521	(12 * 1024) + PS_OH
#define POOL_MISC_521		(12 * 1024) + PS_OH

#ifdef DO_SECP192R1
#include "testkeys/EC/192_EC_KEY.h"		/* EC192KEY[] */
#endif
#ifdef DO_SECP224R1
#include "testkeys/EC/224_EC_KEY.h"		/* EC224KEY[] */
#endif
#ifdef DO_SECP256R1
#include "testkeys/EC/256_EC_KEY.h"		/* EC256KEY[] */
#endif
#ifdef DO_SECP384R1
#include "testkeys/EC/384_EC_KEY.h"		/* EC384KEY[] */
#endif
#ifdef DO_SECP521R1
#include "testkeys/EC/521_EC_KEY.h"		/* EC521KEY[] */
#endif
#ifdef DO_BRAIN224R1
#include "brainpoolp224r1.h"
#endif
#ifdef DO_BRAIN256R1
#include "brainpoolp256r1.h"
#endif
#ifdef DO_BRAIN384R1
#include "brainpoolp384r1.h"
#endif
#ifdef DO_BRAIN512R1
#include "brainpoolp512r1.h"
#endif

typedef struct {
	char				*name;
	const unsigned char	*key;
	uint32				len;
	int32				iter;
	int32				poolSign;
	int32				poolVerify;
	int32				poolMakeKey;
	int32				poolMisc;
} keyList_t;

#ifdef USE_HIGHRES_TIME
  #define psDiffMsecs(A, B, C) psDiffUsecs(A, B)
  #define TIME_UNITS "    %lld usecs"
  #define PER_SEC(A) ((A) ? (1000000 / (A)) : 0)
#else
  #define TIME_UNITS "    %d msecs"
  #define PER_SEC(A) ((A) ? (1000 / (A)) : 0)
#endif

const static keyList_t keys[] = {
#ifdef DO_SECP192R1
	{"secp192r1", EC192KEY, EC192KEY_SIZE, ITER, POOL_SIGN_192,
		POOL_VERIFY_192, POOL_MAKE_KEY_192, POOL_MISC_192},
#endif
#ifdef DO_SECP224R1
	{"secp224r1", EC224KEY, EC224KEY_SIZE, ITER, POOL_SIGN_224,
		POOL_VERIFY_224, POOL_MAKE_KEY_224, POOL_MISC_224},
#endif
#ifdef DO_SECP256R1
	{"secp256r1", EC256KEY, EC256KEY_SIZE, ITER, POOL_SIGN_256,
		POOL_VERIFY_256, POOL_MAKE_KEY_256, POOL_MISC_256},
#endif
#ifdef DO_SECP384R1
	{"secp384r1", EC384KEY, EC384KEY_SIZE, ITER, POOL_SIGN_384,
		POOL_VERIFY_384, POOL_MAKE_KEY_384, POOL_MISC_384},
#endif
#ifdef DO_SECP521R1
	{"secp521r1", EC521KEY, EC521KEY_SIZE, ITER, POOL_SIGN_521,
		POOL_VERIFY_521, POOL_MAKE_KEY_521, POOL_MISC_521},
#endif
#ifdef DO_BRAIN224R1
	{"brainpoolp224r1", brainpoolp224r1, sizeof(brainpoolp224r1),
		ITER, POOL_SIGN_224, POOL_VERIFY_224, POOL_MAKE_KEY_224, POOL_MISC_224},
#endif
#ifdef DO_BRAIN256R1
	{"brainpoolp256r1", brainpoolp256r1, sizeof(brainpoolp256r1),
		ITER, POOL_SIGN_256, POOL_VERIFY_256, POOL_MAKE_KEY_256, POOL_MISC_256},
#endif
#ifdef DO_BRAIN384R1
	{"brainpoolp384r1", brainpoolp384r1, sizeof(brainpoolp384r1),
		ITER, POOL_SIGN_384, POOL_VERIFY_384, POOL_MAKE_KEY_384, POOL_MISC_384},
#endif
#ifdef DO_BRAIN512R1
	{"brainpoolp512r1", brainpoolp512r1, sizeof(brainpoolp512r1),
		ITER, POOL_SIGN_521, POOL_VERIFY_521, POOL_MAKE_KEY_521, POOL_MISC_521},
#endif
	{NULL}
};

/******************************************************************************/
/*
	Main
*/

#ifdef STATS
	#include <unistd.h>
	#include <fcntl.h>
#ifdef USE_HIGHRES_TIME
	#define TIME_STRING "\t%lld"
#else
	#define TIME_STRING "\t%d"
#endif
#endif

int main(int argc, char **argv)
{
	psPool_t		*pool, *misc;
	psEccKey_t		privkey;
	psEccKey_t		eccKey;
	unsigned char	in[SHA256_HASHLEN];
	unsigned char	*out;
	psTime_t		start, end;
	uint32			iter, i = 0;
	int32			t, validateStatus;
	uint16_t		signLen;
#ifdef STATS
	FILE			*sfd;
#endif

	pool = misc = NULL;
	if (psCryptoOpen(PSCRYPTO_CONFIG) < PS_SUCCESS) {
		_psTrace("Failed to initialize library:  psCryptoOpen failed\n");
		return -1;
	}
	_psTraceStr("STARTING ECCPERF\n", NULL);
#ifdef STATS
	if ((sfd = fopen("perfstat.txt", "w")) == NULL) {
		return PS_FAILURE;
	}
#ifdef USE_HIGHRES_TIME
	fprintf(sfd, "Key\tSign(usec)\tVerify\tEncrypt\tDecrypt\n");
#else
	fprintf(sfd, "Key\tSign(msec)\tVerify\tEncrypt\tDecrypt\n");
#endif
#endif /* STATS */

	while (keys[i].key != NULL) {
		_psTraceStr("Testing %s...\n", keys[i].name);
#ifdef STATS
		fprintf(sfd, "%s", keys[i].name);
#endif
		if (psEccParsePrivKey(misc, (unsigned char*)keys[i].key, keys[i].len,
				&privkey, NULL) < 0) {
			_psTrace("	FAILED OPERATION:ParsePriv\n");
			exit(0);
		}

		/* Get random data to sign */
		psGetEntropy(in, sizeof(in), NULL);

		/* A signature is twice as long as the privKey, plus some overhead
		for ASN.1 encoding. The definitive output size is not known until
		the value is generated because of leading zero padding required for
		ASN.1 for numbers with the high bit set */
		signLen = 2 * privkey.curve->size + 10;
		out = psMalloc(misc, signLen);

#ifdef MAKE_KEY_OP
		psGetTime(&start, NULL);
		for (iter = 0; iter < keys[i].iter; iter++) {
			if (psEccGenKey(pool, &eccKey, privkey.curve, NULL) < 0) {
				_psTrace("	FAILED OPERATION:GenKey\n");
			} else {
				psEccClearKey(&eccKey);
			}
		}
		psGetTime(&end, NULL);
		t = psDiffMsecs(start, end, NULL) / keys[i].iter;
		_psTraceInt(TIME_UNITS "/genkey ", t);
		_psTraceInt("(%d per sec)\n", PER_SEC(t));
#ifdef STATS
		fprintf(sfd, TIME_STRING, t);
#endif
#endif /* MAKE_KEY_OP */

#ifdef SHARED_SECRET_OP
		if (psEccGenKey(pool, &eccKey, privkey.curve, NULL) < 0) {
			_psTrace("	FAILED OPERATION:GenKeySharedSecret\n");
		}
		psGetTime(&start, NULL);
		for (iter = 0; iter < keys[i].iter; iter++) {
			signLen = privkey.curve->size;
			if (psEccGenSharedSecret(pool, &privkey, &eccKey,
					out, &signLen, NULL) < 0 || signLen != privkey.curve->size) {
				_psTrace("	FAILED OPERATION:SharedSecret\n");
			}
		}
		psGetTime(&end, NULL);
		psEccClearKey(&eccKey);
		t = psDiffMsecs(start, end, NULL) / keys[i].iter;
		_psTraceInt(TIME_UNITS "/sharedsecret ", t);
		_psTraceInt("(%d per sec)\n", PER_SEC(t));
#ifdef STATS
		fprintf(sfd, TIME_STRING, t);
#endif
#endif /* SHARED_SECRET_OP */

#ifdef SIGN_OP
		psGetTime(&start, NULL);
		for (iter = 0; iter < keys[i].iter; iter++) {
			signLen = 2 * privkey.curve->size + 10;
			if (psEccDsaSign(pool, &privkey,
					in, sizeof(in), out, &signLen, 1, NULL) < 0) {
				_psTrace("	FAILED OPERATION: SignHash\n");
			}
		}
		psGetTime(&end, NULL);
		t = psDiffMsecs(start, end, NULL) / keys[i].iter;
		_psTraceInt(TIME_UNITS "/sign ", t);
		_psTraceInt("(%d per sec)\n", PER_SEC(t));
#ifdef STATS
		fprintf(sfd, TIME_STRING, t);
#endif
#endif /* SIGN_OP */

#ifdef VERIFY_OP
		psGetTime(&start, NULL);
		for (iter = 0; iter < keys[i].iter; iter++) {
			signLen = 2 * privkey.curve->size + 10;
			if (psEccDsaVerify(pool, &privkey,
					in, sizeof(in),
					out + 2, signLen - 2,
					&validateStatus, NULL) < 0 || validateStatus != 1) {
				_psTrace("	FAILED OPERATION:VerifySignature\n");
			}
		}
		psGetTime(&end, NULL);
		t = psDiffMsecs(start, end, NULL) / keys[i].iter;
		_psTraceInt(TIME_UNITS "/verify ", t);
		_psTraceInt("(%d per sec)\n", PER_SEC(t));
#ifdef STATS
		fprintf(sfd, TIME_STRING, t);
#endif
#endif /* VERIFY_OP */

		memzero_s(in, sizeof(in));
		psFree(out, misc);
		psEccClearKey(&privkey);
		i++;
	}

#ifdef STATS
	fclose(sfd);
#endif
#ifdef WIN32
	_psTrace("Press any key to close");
	getchar();
#endif
	_psTraceStr("FINISHED ECCPERF\n", NULL);
	psCryptoClose();
	return 0;
}

#else
int main(int argc, char **argv) {
	printf("USE_ECC not defined.\n");
	return 0;
}
#endif /* USE_ECC */

