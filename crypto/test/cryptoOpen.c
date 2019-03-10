#include "osdep_stdio.h"
#include "crypto/cryptoApi.h"

int main(void)
{
    psSha256_t md;
    int i;
    unsigned char out[32 + 2];
    unsigned char txt[3] = { 'a', 'b', 'c' };
    const unsigned char expect[32 + 2] =
    {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
        0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        0xfe, 0xfe /* bytes unmodified. */
    };
    unsigned char sum;
    psRes_t res;
    
    Memset(out, 0xfe, 32 + 2);

    /* Try opening cryptographic library. */
    res = psCryptoOpen(PSCRYPTO_CONFIG);
    if (res == PS_SELFTEST_FAILED)
    {
        Fprintf(stdout, "Library initialization failed: Self-test failure\n");
        return 2;
    }
    else if (res < PS_SUCCESS)
    {
        Fprintf(stdout, "Library initialization failed\n");
        return 2;
    }

    /* Things appear ok. Ensure they are: */
    psSha256PreInit(&md); /* Pre-init before first use. */
    psSha256Init(&md);
    psSha256Update(&md, txt, 3);
    psSha256Final(&md, out);

    sum = 0;
    for(i = 0; i < 32 + 2; i++)
    {
        sum |= out[i] ^ expect[i];
    }

    if (sum != 0)
    {
        Fprintf(stderr, "Library is broken.\n");
        return 3;
    }
    
    Fprintf(stderr, "Successful init.\n");
    return 0;
}
