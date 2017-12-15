#include "ps_chacha20poly1305ietf_config.h"
#ifdef USE_MATRIX_CHACHA20_POLY1305_IETF
# include "crypto_stream_chacha20.h"
# include "private/common.h"
# ifdef USE_MATRIX_CHACHA20_POLY1305_IETF_KEYGEN
#  include "randombytes.h"
# endif /* USE_MATRIX_CHACHA20_POLY1305_IETF_KEYGEN */
# include "runtime.h"
# include "stream_chacha20.h"

# include "ref/chacha20_ref.h"
# if defined(HAVE_AVX2INTRIN_H) && defined(HAVE_EMMINTRIN_H) && \
    defined(HAVE_TMMINTRIN_H) && defined(HAVE_SMMINTRIN_H) && \
    !defined(CL_DISABLE_AVX2)
#  include "dolbeau/chacha20_dolbeau-avx2.h"
# endif
# if defined(HAVE_EMMINTRIN_H) && defined(HAVE_TMMINTRIN_H)
#  include "dolbeau/chacha20_dolbeau-ssse3.h"
# endif

static const crypto_stream_chacha20_implementation *implementation =
    &psCrypto_stream_chacha20_ref_implementation;

size_t
psCrypto_stream_chacha20_keybytes(void) {
    return crypto_stream_chacha20_KEYBYTES;
}

size_t
psCrypto_stream_chacha20_noncebytes(void) {
    return crypto_stream_chacha20_NONCEBYTES;
}

size_t
psCrypto_stream_chacha20_ietf_keybytes(void) {
    return crypto_stream_chacha20_ietf_KEYBYTES;
}

size_t
psCrypto_stream_chacha20_ietf_noncebytes(void) {
    return crypto_stream_chacha20_ietf_NONCEBYTES;
}

int
psCrypto_stream_chacha20(unsigned char *c, unsigned long long clen,
                       const unsigned char *n, const unsigned char *k)
{
    return implementation->stream(c, clen, n, k);
}

int
psCrypto_stream_chacha20_ietf(unsigned char *c, unsigned long long clen,
                            const unsigned char *n, const unsigned char *k)
{
    return implementation->stream_ietf(c, clen, n, k);
}

int
psCrypto_stream_chacha20_xor_ic(unsigned char *c, const unsigned char *m,
                              unsigned long long mlen,
                              const unsigned char *n, uint64_t ic,
                              const unsigned char *k)
{
    return implementation->stream_xor_ic(c, m, mlen, n, ic, k);
}

int
psCrypto_stream_chacha20_ietf_xor_ic(unsigned char *c, const unsigned char *m,
                                   unsigned long long mlen,
                                   const unsigned char *n, uint32_t ic,
                                   const unsigned char *k)
{
    return implementation->stream_ietf_xor_ic(c, m, mlen, n, ic, k);
}

int
psCrypto_stream_chacha20_xor(unsigned char *c, const unsigned char *m,
                           unsigned long long mlen, const unsigned char *n,
                           const unsigned char *k)
{
    return implementation->stream_xor_ic(c, m, mlen, n, 0U, k);
}

int
psCrypto_stream_chacha20_ietf_xor(unsigned char *c, const unsigned char *m,
                                unsigned long long mlen, const unsigned char *n,
                                const unsigned char *k)
{
    return implementation->stream_ietf_xor_ic(c, m, mlen, n, 0U, k);
}

# ifdef USE_MATRIX_CHACHA20_POLY1305_IETF_KEYGEN
void
psCrypto_stream_chacha20_ietf_keygen(unsigned char k[crypto_stream_chacha20_ietf_KEYBYTES])
{
    randombytes_buf(k, crypto_stream_chacha20_ietf_KEYBYTES);
}

void
psCrypto_stream_chacha20_keygen(unsigned char k[crypto_stream_chacha20_KEYBYTES])
{
    randombytes_buf(k, crypto_stream_chacha20_KEYBYTES);
}
# endif /* USE_MATRIX_CHACHA20_POLY1305_IETF_KEYGEN */

int
psCrypto_stream_chacha20_pick_best_implementation(void)
{
    implementation = &psCrypto_stream_chacha20_ref_implementation;
# if defined(HAVE_AVX2INTRIN_H) && defined(HAVE_EMMINTRIN_H) && \
    defined(HAVE_TMMINTRIN_H) && defined(HAVE_SMMINTRIN_H) && \
    !defined(CL_DISABLE_AVX2)
    if (psSodium_runtime_has_avx2()) {
        implementation = &psCrypto_stream_chacha20_dolbeau_avx2_implementation;
        return 0;
    }
# endif
# if defined(HAVE_EMMINTRIN_H) && defined(HAVE_TMMINTRIN_H)
    if (psSodium_runtime_has_ssse3()) {
        implementation = &psCrypto_stream_chacha20_dolbeau_ssse3_implementation;
        return 0;
    }
# endif
    return 0;
}

#endif /* USE_MATRIX_CHACHA20_POLY1305_IETF */
