/**
 *      @file    eccTest.c
 *      @version $Format:%h%d$
 *
 *      ECC test.
 */

#include <stdio.h>
#include <stdlib.h>
#include "crypto/cryptoApi.h"

#ifdef USE_ECC

/* Allow two 256-bits values (r,s) and additional space for ASN.1 encoding. */
#define BUFFER_SIZE (32 * 2 + 10)

int sign_verify_test1(psEccKey_t *privKey,
                      psEccKey_t *pubKey,
                      unsigned char (*buffer_p)[BUFFER_SIZE],
                      psSize_t *buffer_size_result_p)
{
    /* SHA-256("abc") */
    psPool_t *pool = NULL;
    int32 validateStatus;
    unsigned char in[SHA256_HASHLEN] =
    {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
        0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
        0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    unsigned char *buffer = *buffer_p;
    *buffer_size_result_p = BUFFER_SIZE;
    if (psEccDsaSign(pool, privKey,
                     in, sizeof(in), buffer, buffer_size_result_p, 1, NULL) < 0)
    {
        printf("Operation failed: Ecc Sign\n");
        return 1;
    }

    if (psEccDsaVerify(pool, pubKey,
                       in, sizeof(in),
                       buffer + 2, *buffer_size_result_p - 2,
                       &validateStatus, NULL) < 0)
    {
        printf("Operation failed: Ecc Verify\n");
        return 2;
    }
    if (validateStatus != 1)
    {
        printf("Signature failure: Ecc Verify\n");
        return 3;
    }
    return 0;
}

#define EC256KEY_SIZE   121
const static unsigned char EC256KEY[EC256KEY_SIZE] =
    "\x30\x77\x02\x01\x01\x04\x20\x5c\xe9\x89\xc5\xb1\x53\xa0\x02\x3c"
    "\x90\xbe\x3a\x2a\x73\xb2\x08\x16\xc3\xed\xbc\xd5\xd6\x67\x26\x10"
    "\x4e\xec\x79\x28\x0f\xbf\xcb\xa0\x0a\x06\x08\x2a\x86\x48\xce\x3d"
    "\x03\x01\x07\xa1\x44\x03\x42\x00\x04\x5f\xad\x62\x02\x42\x48\xba"
    "\xfb\xe2\x88\xd8\x7f\xb9\x72\xcb\x28\xae\xc3\x8a\x1e\xc3\x0e\x9c"
    "\x7d\x7a\xa4\xb5\x7f\xda\xbd\x46\x5a\xb9\x95\x39\xe0\x44\x51\x71"
    "\xba\xe3\xb3\x40\xf2\x54\xfd\x23\x84\xb2\xea\x2a\x84\xa3\x4f\xd7"
    "\xb0\x08\xba\x6e\x80\xc3\xeb\xdf\x2f";

extern int psEccDsaSignBlinding;

int main(void)
{
    psEccKey_t privkey;
    unsigned char buffer[BUFFER_SIZE];
    psSize_t sz = 0;
    psPool_t *misc = NULL;
    int res;

    if (psCryptoOpen(PSCRYPTO_CONFIG) < PS_SUCCESS)
    {
        printf("Failed to initialize library: psCryptoOpen failed\n");
        return 4;
    }

    if (psEccParsePrivKey(misc, (unsigned char *) EC256KEY, EC256KEY_SIZE,
                          &privkey, NULL) < 0)
    {
        printf("FAILED OPERATION: ParsePriv\n");
        return 5;
    }

    /* private key also includes public key. */
    res = sign_verify_test1(&privkey, &privkey, &buffer, &sz);
    if (res != 0)
    {
        printf("Sign-verify test failed: %d!\n", res);
        return res;
    }
    printf("Result: encoded bytes=%d (max=%d)\n",
           (int) sz, (int) BUFFER_SIZE);
    {
        psSize_t i;
        /* Result will be something like
           00483046022100RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR022100SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS,
           where R and S are replaced by nibbles appearing random.

           This is maximum length output, resulting with approximately 25%
           probability. Often the result will be somewhat shorter. When output
           is shorter, then 00 byte(s) will typically disappear and
           48, 46 and one of 21 will change.

           The first two bytes are for TLS (length of ASN.1 encoding), the
           remaining bytes are standard ASN.1 DER encoding of ECDSA signature.
        */
        for(i = 0; i < sz; i++)
        {
            printf("%02x", buffer[i]);
        }
        printf("\n");
    }
    psEccClearKey(&privkey);
    psCryptoClose();
    return 0;
}

#else

int main(void)
{
    printf("Skipped ECC test: USE_ECC is not enabled.\n");
    return 0;
}

#endif /* USE_ECC */
