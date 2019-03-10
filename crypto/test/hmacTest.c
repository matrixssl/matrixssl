/**
 *      @file    hmacTest.c
 *      @version $Format:%h%d$
 *
 *      HMAC test. (Only tests HMAC-SHA-1 currently.)
 */

#include <stdio.h>
#include <stdlib.h>
#include "crypto/cryptoApi.h"

#ifdef USE_HMAC_SHA1

/* A single basic test case. */
static int32 hmac_test_simple(void)
{
    unsigned char res[20];
    unsigned char res2[20];
    psHmacSha1_t ctx;
    int32_t rv;
    const char *data1 = "Hi There";

    unsigned char key1[] = {
        0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b
    };
    const unsigned char res1[] = {
        0xb6, 0x17, 0x31, 0x86,
        0x55, 0x05, 0x72, 0x64,
        0xe2, 0x8b, 0xc0, 0xb6,
        0xfb, 0x37, 0x8c, 0x8e,
        0xf1, 0x46, 0xbe, 0x00
    };
    psSize_t keyLen = (uint16_t) sizeof(key1);

    /* Try single-call */
    rv = psHmacSha1(key1, keyLen, (unsigned char *) data1,
        (uint32_t) Strlen(data1), res2,
        key1, &keyLen);
    if (rv != PS_SUCCESS)
    {
        printf("FAILED: Single-part HMAC KAT execution failure (rv=%d)\n",
            (int) rv);
        return PS_FAILURE;
    }
    if (Memcmp(res1, res2, 20) != 0)
    {
        printf("FAILED: Single-part HMAC KAT mismatch\n");
        return PS_FAILURE;
    }

    /* Try init-update-finish */
    rv = psHmacSha1Init(&ctx, key1, keyLen);
    if (rv != PS_SUCCESS)
    {
        printf("FAILED: Init state of Init-Update-Finish HMAC\n");
        return PS_FAILURE;
    }
    psHmacSha1Update(&ctx, (unsigned char *) data1, (uint32_t) Strlen(data1));
    (void) psHmacSha1Final(&ctx, res);
    if (Memcmp(res, res1, 20) != 0)
    {
        printf("FAILED: Init-Update-Finish HMAC KAT mismatch\n");
    }
    return PS_SUCCESS;
}

/* Get SHA-1 digest in hex. */
static void hexify(unsigned char (*res_p)[20], char (*res_hex_p)[43])
{
    int i;

    (*res_hex_p)[0] = '0';
    (*res_hex_p)[1] = 'x';
    for(i = 0; i < 20; i++)
    {
        sprintf((*res_hex_p) + i * 2 + 2, "%02x", (*res_p)[i]);
    }
}

/* A single basic test case. */
static int32 hmac_test_vector(const unsigned char *key, size_t keylen,
                              const unsigned char *data, size_t datalen,
                              const char *mac)
{
    unsigned char res[20];
    unsigned char res2[20];
    char res_hex[43];
    char res2_hex[43];
    psHmacSha1_t ctx;
    int32_t rv;
    unsigned char key1[64];
    psSize_t keyLen = (uint16_t) keylen;

    /* Try single-call */
    rv = psHmacSha1(key, keylen, data, datalen, res, key1, &keyLen);
    if (rv != PS_SUCCESS)
    {
        printf("FAILED: Single-part HMAC KAT execution failure (rv=%d)\n",
            (int) rv);
        return PS_FAILURE;
    }
    hexify(&res, &res_hex);
    if (strcmp(mac, res_hex))
    {
        printf("FAILED: Single-part HMAC KAT mismatch\n");
        printf("%s expected, got %s\n", mac, res_hex);
        return PS_FAILURE;
    }

    /* Try init-update-finish */
    rv = psHmacSha1Init(&ctx, key1, keyLen);
    if (rv != PS_SUCCESS)
    {
        printf("FAILED: Init state of Init-Update-Finish HMAC\n");
        return PS_FAILURE;
    }
    psHmacSha1Update(&ctx, data, datalen / 2);
    psHmacSha1Update(&ctx, data + datalen / 2, datalen - (datalen / 2));
    (void) psHmacSha1Final(&ctx, res2);
    hexify(&res2, &res2_hex);
    if (strcmp(mac, res2_hex))
    {
        printf("FAILED: Multipart HMAC KAT mismatch\n");
        printf("%s expected, got %s\n", mac, res2_hex);
        return PS_FAILURE;
    }
    return PS_SUCCESS;
}

/* A two vector test case with common prefix: use copying. */
static int32 hmac_test_vector2_copy(const unsigned char *key, size_t keylen,
                                    const unsigned char *data_base, size_t data_baselen,
                                    const unsigned char *data_post1, size_t data_post1len,
                                    const unsigned char *data_post2, size_t data_post2len,
                                    const char *mac1,
                                    const char *mac2)
{
    unsigned char res1[20];
    unsigned char res2[20];
    char res1_hex[43];
    char res2_hex[43];
    psHmacSha1_t ctx1;
    psHmacSha1_t ctx2;
    psRes_t rv;

    rv = psHmacSha1Init(&ctx1, key, keylen);
    if (rv != PS_SUCCESS)
    {
        printf("FAILED: Init state of Init-Update-Finish HMAC\n");
        return PS_FAILURE;
    }

    psHmacSha1Update(&ctx1, data_base, data_baselen);

    /* Copy state. */
    memcpy(&ctx2, &ctx1, sizeof(ctx2));

    /* Update. */
    psHmacSha1Update(&ctx1, data_post1, data_post1len);
    psHmacSha1Update(&ctx2, data_post2, data_post2len);

    /* Finish. */
    (void) psHmacSha1Final(&ctx2, res2);
    hexify(&res2, &res2_hex);
    if (strcmp(mac2, res2_hex))
    {
        printf("FAILED: Multipart HMAC KAT mismatch (branch 1)\n");
        printf("%s expected, got %s\n", mac2, res2_hex);
        return PS_FAILURE;
    }

    (void) psHmacSha1Final(&ctx1, res1);
    hexify(&res1, &res1_hex);
    if (strcmp(mac1, res1_hex))
    {
        printf("FAILED: Multipart HMAC KAT mismatch (branch 2)\n");
        printf("%s expected, got %s\n", mac1, res1_hex);
        return PS_FAILURE;
    }

    return PS_SUCCESS;
}

/* A two vector test case with common prefix. */
static int32 hmac_test_vector2(const unsigned char *key, size_t keylen,
                               const unsigned char *data_base, size_t data_baselen,
                               const unsigned char *data_post1, size_t data_post1len,
                               const unsigned char *data_post2, size_t data_post2len,
                               const char *mac1,
                               const char *mac2)
{
    unsigned char res[20];
    unsigned char res2[20];
    char res_hex[43];
    char res2_hex[43];
    int32_t rv;
    unsigned char key1[64];
    psSize_t keyLen = (uint16_t) keylen;
    unsigned char data[2048];
    psSize_t datalen;

    if (data_baselen > 1024 || data_post1len > 1024 || data_post2len > 1024)
    {
        /* Possible buffer overflow. */
        printf("FAILED: Multi-part HMAC KAT execution failure (invalid test vector).\n");
        return PS_FAILURE;
    }

    /* Try single-call interfaces for concatenated vector. */
    memcpy(data, data_base, data_baselen);
    memcpy(data + data_baselen, data_post1, data_post1len);
    datalen = data_baselen + data_post1len;
    rv = psHmacSha1(key, keylen, data, datalen, res, key1, &keyLen);
    if (rv != PS_SUCCESS)
    {
        printf("FAILED: Multi-part combined HMAC KAT execution failure (rv=%d)\n",
            (int) rv);
        return PS_FAILURE;
    }
    hexify(&res, &res_hex);
    if (strcmp(mac1, res_hex))
    {
        printf("FAILED: Single-part HMAC KAT (1) mismatch\n");
        printf("%s expected, got %s\n", mac1, res_hex);
        return PS_FAILURE;
    }

    memcpy(data, data_base, data_baselen);
    memcpy(data + data_baselen, data_post2, data_post2len);
    datalen = data_baselen + data_post2len;
    rv = psHmacSha1(key, keylen, data, datalen, res2, key1, &keyLen);
    if (rv != PS_SUCCESS)
    {
        printf("FAILED: Multi-part combined HMAC KAT execution failure (rv=%d)\n",
            (int) rv);
        return PS_FAILURE;
    }
    hexify(&res2, &res2_hex);
    if (strcmp(mac2, res2_hex))
    {
        printf("FAILED: Single-part HMAC KAT (2) mismatch\n");
        printf("%s expected, got %s\n", mac2, res2_hex);
        return PS_FAILURE;
    }

    /* Continue with tests involving Init-Update-Update-Finish and copy. */
    /* Use truncated key here. */
    return hmac_test_vector2_copy(key1, keyLen, data_base, data_baselen, data_post1, data_post1len, data_post2, data_post2len, mac1, mac2);
}

const static unsigned char HMACKEY[] =
    "The quick brown fox jumps over a lazy dog. "
    "The quick brown fox jumps over another dog. "
    "The quick brown fox jumps over the lazy dog again.";

#define HMACKEY_LEN (sizeof(HMACKEY) - 1)
extern int psHmacDsaSignBlinding;

int main(void)
{
    psRes_t res;

    if (psCryptoOpen(PSCRYPTO_CONFIG) < PS_SUCCESS)
    {
        printf("Failed to initialize library: psCryptoOpen failed\n");
        return 4;
    }

    res = hmac_test_simple();
    if (res != 0)
    {
        printf("hmac test failed: %d!\n", res);
        return 1;
    }

    res = hmac_test_vector(HMACKEY, HMACKEY_LEN, (unsigned char *)"abc", 3,
                           "0xee251a5cb1c09d8b0978aaac1885a4c5faf5b5f5");
    if (res != 0)
    {
        printf("hmac test failed: %d!\n", res);
        return 1;
    }

    res = hmac_test_vector(HMACKEY, HMACKEY_LEN, HMACKEY, HMACKEY_LEN,
                           "0xac11e301b5426191f7bf05fb5b9db144f9bcd8c8");
    if (res != 0)
    {
        printf("hmac test failed: %d!\n", res);
        return 1;
    }

    res = hmac_test_vector2(HMACKEY, HMACKEY_LEN,
                            HMACKEY, 124,
                            HMACKEY + 124, HMACKEY_LEN - 124,
                            (unsigned char *) "zy cog again.", HMACKEY_LEN - 124,
                            "0xac11e301b5426191f7bf05fb5b9db144f9bcd8c8",
                            "0x2c9ccb6518efee19472ca7cabf9f5b4a99817c41");
    if (res != 0)
    {
        printf("hmac test failed: %d!\n", res);
        return 1;
    }

    res = hmac_test_vector2(HMACKEY, HMACKEY_LEN,
                            HMACKEY, 124,
                            HMACKEY + 124, HMACKEY_LEN - 124,
                            (unsigned char *) "", 0,
                            "0xac11e301b5426191f7bf05fb5b9db144f9bcd8c8",
                            "0x5122e938ae8ac9fa15751b9e9829a8de40a5bbe6");
    if (res != 0)
    {
        printf("hmac test failed: %d!\n", res);
        return 1;
    }

    psCryptoClose();
    printf("Test executed successfully.\n");
    return 0;
}

#else

int main(void)
{
    printf("Skipped HMAC test: USE_HMAC is not enabled.\n");
    return 0;
}

#endif /* USE_HMAC_SHA1 */
