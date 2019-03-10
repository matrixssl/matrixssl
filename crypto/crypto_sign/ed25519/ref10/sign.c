
#include <string.h>

#include "crypto_sign_ed25519.h"
#include "sign_ed25519_ref10.h"
#include "private/ed25519_ref10.h"
#include "utils.h"
#include "cryptoApi.h"

# ifdef USE_ED25519

static inline void
_psSodium_crypto_sign_ed25519_clamp(unsigned char k[32])
{
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

int
_psSodium_crypto_sign_ed25519_detached(unsigned char *sig, unsigned long long *siglen_p,
                              const unsigned char *m, unsigned long long mlen,
                              const unsigned char *sk, int prehashed)
{
    unsigned char            az[64];
    unsigned char            nonce[64];
    unsigned char            hram[64];
    psSodium_ge25519_p3      R;
    static const unsigned char DOM2PREFIX[32 + 2] = {
        'S', 'i', 'g', 'E', 'd', '2', '5', '5', '1', '9', ' ',
        'n', 'o', ' ',
        'E', 'd', '2', '5', '5', '1', '9', ' ',
        'c', 'o', 'l', 'l', 'i', 's', 'i', 'o', 'n', 's', 1, 0
    };
    psSha512_t md, md2;

    Memset(&md, 0, sizeof(md));
    Memset(&md2, 0, sizeof(md));

    psSha512PreInit(&md);
    (void)psSha512Init(&md);
    if (prehashed) {
        psSha512Update(&md, DOM2PREFIX, sizeof(DOM2PREFIX));
    }

    /* az = Hash ( sk ).
       First half of az is s, the second half is prefix. */
    psSha512Single(sk, 32, az);

    /* r = nonce = Hash( prefix || m ) */
    psSha512Update(&md, az + 32, 32);
    psSha512Update(&md, m, mlen);
    psSha512Final(&md, nonce);

    /* sig = (32 bytes of garbage) || public key. */
    memmove(sig + 32, sk + 32, 32);

    psSodium_sc25519_reduce(nonce);
    psSodium_ge25519_scalarmult_base(&R, nonce);
    psSodium_ge25519_p3_tobytes(sig, &R);

    psSha512PreInit(&md2);
    (void)psSha512Init(&md2);
    if (prehashed) {
        psSha512Update(&md2, DOM2PREFIX, sizeof(DOM2PREFIX));
    }
    psSha512Update(&md2, sig, 64);
    psSha512Update(&md2, m, mlen);
    psSha512Final(&md2, hram);

    psSodium_sc25519_reduce(hram);
    _psSodium_crypto_sign_ed25519_clamp(az);
    psSodium_sc25519_muladd(sig + 32, hram, az, nonce);

    psSodium_memzero(az, sizeof az);
    psSodium_memzero(nonce, sizeof nonce);

    if (siglen_p != NULL) {
        *siglen_p = 64U;
    }
    return 0;
}

int
psSodium_crypto_sign_ed25519_detached(unsigned char *sig, unsigned long long *siglen_p,
                             const unsigned char *m, unsigned long long mlen,
                             const unsigned char *sk)
{
    return _psSodium_crypto_sign_ed25519_detached(sig, siglen_p, m, mlen, sk, 0);
}

int
psSodium_crypto_sign_ed25519(unsigned char *sm, unsigned long long *smlen_p,
                    const unsigned char *m, unsigned long long mlen,
                    const unsigned char *sk)
{
    unsigned long long siglen;

    memmove(sm + crypto_sign_ed25519_BYTES, m, mlen);
    /* LCOV_EXCL_START */
    if (psSodium_crypto_sign_ed25519_detached(
            sm, &siglen, sm + crypto_sign_ed25519_BYTES, mlen, sk) != 0 ||
        siglen != crypto_sign_ed25519_BYTES) {
        if (smlen_p != NULL) {
            *smlen_p = 0;
        }
        memset(sm, 0, mlen + crypto_sign_ed25519_BYTES);
        return -1;
    }
    /* LCOV_EXCL_STOP */

    if (smlen_p != NULL) {
        *smlen_p = mlen + siglen;
    }
    return 0;
}

# endif /* USE_ED25519 */
