
#include "crypto_scalarmult.h"

const char *
psSodium_crypto_scalarmult_primitive(void)
{
    return psSodium_crypto_scalarmult_PRIMITIVE;
}

int
psSodium_crypto_scalarmult_base(unsigned char *q, const unsigned char *n)
{
    return psSodium_crypto_scalarmult_curve25519_base(q, n);
}

int
psSodium_crypto_scalarmult(unsigned char *q, const unsigned char *n,
                  const unsigned char *p)
{
    return psSodium_crypto_scalarmult_curve25519(q, n, p);
}

size_t
psSodium_crypto_scalarmult_bytes(void)
{
    return psSodium_crypto_scalarmult_BYTES;
}

size_t
psSodium_crypto_scalarmult_scalarbytes(void)
{
    return psSodium_crypto_scalarmult_SCALARBYTES;
}
