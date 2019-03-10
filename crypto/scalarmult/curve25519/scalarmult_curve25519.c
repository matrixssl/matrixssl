
#include "crypto_scalarmult_curve25519.h"
#include "private/implementations.h"
#include "scalarmult_curve25519.h"
#include "runtime.h"

#ifdef HAVE_AVX_ASM
# include "sandy2x/curve25519_sandy2x.h"
#endif
#include "ref10/x25519_ref10.h"
static const psSodium_crypto_scalarmult_curve25519_implementation *implementation =
    &psSodium_crypto_scalarmult_curve25519_ref10_implementation;

int
psSodium_crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n,
                             const unsigned char *p)
{
    size_t                 i;
    volatile unsigned char d = 0;

    if (implementation->mult(q, n, p) != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    for (i = 0; i < psSodium_crypto_scalarmult_curve25519_BYTES; i++) {
        d |= q[i];
    }
    return -(1 & ((d - 1) >> 8));
}

int
psSodium_crypto_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n)
{
    return implementation->mult_base(q, n);
}

size_t
psSodium_crypto_scalarmult_curve25519_bytes(void)
{
    return psSodium_crypto_scalarmult_curve25519_BYTES;
}

size_t
psSodium_crypto_scalarmult_curve25519_scalarbytes(void)
{
    return psSodium_crypto_scalarmult_curve25519_SCALARBYTES;
}

int
_psSodium_crypto_scalarmult_curve25519_pick_best_implementation(void)
{
    implementation = &psSodium_crypto_scalarmult_curve25519_ref10_implementation;

#ifdef HAVE_AVX_ASM
    if (sodium_runtime_has_avx()) {
        implementation = &psSodium_crypto_scalarmult_curve25519_sandy2x_implementation;
    }
#endif
    return 0;
}
