
#include "crypto_sign.h"

size_t
psSodium_crypto_sign_bytes(void)
{
    return crypto_sign_BYTES;
}

size_t
psSodium_crypto_sign_seedbytes(void)
{
    return crypto_sign_SEEDBYTES;
}

size_t
psSodium_crypto_sign_publickeybytes(void)
{
    return crypto_sign_PUBLICKEYBYTES;
}

size_t
psSodium_crypto_sign_secretkeybytes(void)
{
    return crypto_sign_SECRETKEYBYTES;
}

size_t
psSodium_crypto_sign_messagebytes_max(void)
{
    return crypto_sign_MESSAGEBYTES_MAX;
}

const char *
psSodium_crypto_sign_primitive(void)
{
    return crypto_sign_PRIMITIVE;
}

int
psSodium_crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                         const unsigned char *seed)
{
    return psSodium_crypto_sign_ed25519_seed_keypair(pk, sk, seed);
}

int
psSodium_crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    return psSodium_crypto_sign_ed25519_keypair(pk, sk);
}

int
psSodium_crypto_sign(unsigned char *sm, unsigned long long *smlen_p,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk)
{
    return psSodium_crypto_sign_ed25519(sm, smlen_p, m, mlen, sk);
}

int
psSodium_crypto_sign_open(unsigned char *m, unsigned long long *mlen_p,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk)
{
    return psSodium_crypto_sign_ed25519_open(m, mlen_p, sm, smlen, pk);
}

int
psSodium_crypto_sign_detached(unsigned char *sig, unsigned long long *siglen_p,
                     const unsigned char *m, unsigned long long mlen,
                     const unsigned char *sk)
{
    return psSodium_crypto_sign_ed25519_detached(sig, siglen_p, m, mlen, sk);
}

int
psSodium_crypto_sign_verify_detached(const unsigned char *sig, const unsigned char *m,
                            unsigned long long mlen, const unsigned char *pk)
{
    return psSodium_crypto_sign_ed25519_verify_detached(sig, m, mlen, pk);
}
