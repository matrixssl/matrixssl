
#include <string.h>

#include "crypto_sign_ed25519.h"
#include "ref10/sign_ed25519_ref10.h"

size_t
psSodium_crypto_sign_ed25519_bytes(void)
{
    return crypto_sign_ed25519_BYTES;
}

size_t
psSodium_crypto_sign_ed25519_seedbytes(void)
{
    return crypto_sign_ed25519_SEEDBYTES;
}

size_t
psSodium_crypto_sign_ed25519_publickeybytes(void)
{
    return crypto_sign_ed25519_PUBLICKEYBYTES;
}

size_t
psSodium_crypto_sign_ed25519_secretkeybytes(void)
{
    return psSodium_crypto_sign_ed25519_SECRETKEYBYTES;
}

size_t
psSodium_crypto_sign_ed25519_messagebytes_max(void)
{
    return psSodium_crypto_sign_ed25519_MESSAGEBYTES_MAX;
}

int
psSodium_crypto_sign_ed25519_sk_to_seed(unsigned char *seed, const unsigned char *sk)
{
    memmove(seed, sk, crypto_sign_ed25519_SEEDBYTES);

    return 0;
}

int
psSodium_crypto_sign_ed25519_sk_to_pk(unsigned char *pk, const unsigned char *sk)
{
    memmove(pk, sk + crypto_sign_ed25519_SEEDBYTES,
            crypto_sign_ed25519_PUBLICKEYBYTES);
    return 0;
}
