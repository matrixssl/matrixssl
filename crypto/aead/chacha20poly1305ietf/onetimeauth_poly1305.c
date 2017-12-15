#include "ps_chacha20poly1305ietf_config.h"
#ifdef USE_MATRIX_CHACHA20_POLY1305_IETF
# include "onetimeauth_poly1305.h"
# include "crypto_onetimeauth_poly1305.h"
# include "private/common.h"
# ifdef USE_MATRIX_CHACHA20_POLY1305_IETF_KEYGEN
#  include "randombytes.h"
# endif /* USE_MATRIX_CHACHA20_POLY1305_IETF_KEYGEN */
# include "runtime.h"

# include "donna/poly1305_donna.h"
# if defined(HAVE_TI_MODE) && defined(HAVE_EMMINTRIN_H)
#  include "sse2/poly1305_sse2.h"
# endif

static const crypto_onetimeauth_poly1305_implementation *implementation =
    &psCrypto_onetimeauth_poly1305_donna_implementation;

int
psCrypto_onetimeauth_poly1305(unsigned char *out, const unsigned char *in,
                            unsigned long long inlen, const unsigned char *k)
{
    return implementation->onetimeauth(out, in, inlen, k);
}

int
psCrypto_onetimeauth_poly1305_verify(const unsigned char *h,
                                   const unsigned char *in,
                                   unsigned long long   inlen,
                                   const unsigned char *k)
{
    return implementation->onetimeauth_verify(h, in, inlen, k);
}

int
psCrypto_onetimeauth_poly1305_init(crypto_onetimeauth_poly1305_state *state,
                                 const unsigned char *              key)
{
    return implementation->onetimeauth_init(state, key);
}

int
psCrypto_onetimeauth_poly1305_update(crypto_onetimeauth_poly1305_state *state,
                                   const unsigned char *              in,
                                   unsigned long long                 inlen)
{
    return implementation->onetimeauth_update(state, in, inlen);
}

int
psCrypto_onetimeauth_poly1305_final(crypto_onetimeauth_poly1305_state *state,
                                  unsigned char *                    out)
{
    return implementation->onetimeauth_final(state, out);
}

size_t
psCrypto_onetimeauth_poly1305_bytes(void)
{
    return crypto_onetimeauth_poly1305_BYTES;
}

size_t
psCrypto_onetimeauth_poly1305_keybytes(void)
{
    return crypto_onetimeauth_poly1305_KEYBYTES;
}

size_t
psCrypto_onetimeauth_poly1305_statebytes(void)
{
    return sizeof(crypto_onetimeauth_poly1305_state);
}

# ifdef USE_MATRIX_CHACHA20_POLY1305_IETF_KEYGEN
void
psCrypto_onetimeauth_poly1305_keygen(
    unsigned char k[crypto_onetimeauth_poly1305_KEYBYTES])
{
    randombytes_buf(k, crypto_onetimeauth_poly1305_KEYBYTES);
}
# endif /* USE_MATRIX_CHACHA20_POLY1305_IETF_KEYGEN */

int
psCrypto_onetimeauth_poly1305_pick_best_implementation(void)
{
    implementation = &psCrypto_onetimeauth_poly1305_donna_implementation;
#if defined(HAVE_TI_MODE) && defined(HAVE_EMMINTRIN_H)
    if (psSodium_runtime_has_sse2()) {
        implementation = &psCrypto_onetimeauth_poly1305_sse2_implementation;
    }
#endif
    return 0;
}

#endif /* USE_MATRIX_CHACHA20_POLY1305_IETF */
