
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "crypto_sign_ed25519.h"
#include "crypto_verify_32.h"
#include "sign_ed25519_ref10.h"
#include "private/ed25519_ref10.h"
#include "crypto_verify_32.h"
#include "cryptoApi.h"

#ifndef NO_ED25519_COMPAT
# define ED25519_COMPAT
#endif

# ifdef USE_ED25519
int
_psSodium_crypto_sign_ed25519_verify_detached(const unsigned char *sig,
                                     const unsigned char *m,
                                     unsigned long long   mlen,
                                     const unsigned char *pk,
                                     int prehashed)
{
    unsigned char            h[64];
    unsigned char            rcheck[32];
    psSodium_ge25519_p3      A;
    psSodium_ge25519_p2      R;
    static const unsigned char DOM2PREFIX[32 + 2] = {
        'S', 'i', 'g', 'E', 'd', '2', '5', '5', '1', '9', ' ',
        'n', 'o', ' ',
        'E', 'd', '2', '5', '5', '1', '9', ' ',
        'c', 'o', 'l', 'l', 'i', 's', 'i', 'o', 'n', 's', 1, 0
    };
    psSha512_t md;

#ifndef ED25519_COMPAT
    if (psSodium_sc25519_is_canonical(sig + 32) == 0 ||
        psSodium_ge25519_has_small_order(sig) != 0) {
        return -1;
    }
    if (psSodium_sc25519_is_canonical(pk) == 0) {
        return -1;
    }
#else
    if (sig[63] & 224) {
        return -1;
    }
#endif
    if (psSodium_ge25519_has_small_order(pk) != 0 ||
        psSodium_ge25519_frombytes_negate_vartime(&A, pk) != 0) {
        return -1;
    }

    psSha512PreInit(&md);
    (void)psSha512Init(&md);
    if (prehashed) {
        psSha512Update(&md, DOM2PREFIX, sizeof(DOM2PREFIX));
    }
    psSha512Update(&md, sig, 32);
    psSha512Update(&md, pk, 32);
    psSha512Update(&md, m, mlen);
    psSha512Final(&md, h);
    psSodium_sc25519_reduce(h);

    psSodium_ge25519_double_scalarmult_vartime(&R, h, &A, sig + 32);
    psSodium_ge25519_tobytes(rcheck, &R);

    return psCrypto_verify_32(rcheck, sig) | (-(rcheck == sig)) |
           psSodium_memcmp(sig, rcheck, 32);
}

int
psSodium_crypto_sign_ed25519_verify_detached(const unsigned char *sig,
                                    const unsigned char *m,
                                    unsigned long long   mlen,
                                    const unsigned char *pk)
{
    return _psSodium_crypto_sign_ed25519_verify_detached(sig, m, mlen, pk, 0);
}

int
psSodium_crypto_sign_ed25519_open(unsigned char *m, unsigned long long *mlen_p,
                         const unsigned char *sm, unsigned long long smlen,
                         const unsigned char *pk)
{
    unsigned long long mlen;

    if (smlen < 64 || smlen - 64 > psSodium_crypto_sign_ed25519_MESSAGEBYTES_MAX) {
        goto badsig;
    }
    mlen = smlen - 64;
    if (psSodium_crypto_sign_ed25519_verify_detached(sm, sm + 64, mlen, pk) != 0) {
        memset(m, 0, mlen);
        goto badsig;
    }
    if (mlen_p != NULL) {
        *mlen_p = mlen;
    }
    memmove(m, sm + 64, mlen);

    return 0;

badsig:
    if (mlen_p != NULL) {
        *mlen_p = 0;
    }
    return -1;
}
#endif /* USE_ED25519 */
