#include "../ps_chacha20poly1305ietf_config.h"
#ifdef USE_MATRIX_CHACHA20_POLY1305_IETF
# include "poly1305_donna.h"
# include "crypto_verify_16.h"
# include "private/common.h"
# include "utils.h"

# ifdef HAVE_TI_MODE
# include "poly1305_donna64.h"
# else
# include "poly1305_donna32.h"
# endif
# include "../onetimeauth_poly1305.h"

static void
poly1305_update(poly1305_state_internal_t *st, const unsigned char *m,
                unsigned long long bytes)
{
    unsigned long long i;

    /* handle leftover */
    if (st->leftover) {
        unsigned long long want = (poly1305_block_size - st->leftover);

        if (want > bytes) {
            want = bytes;
        }
        for (i = 0; i < want; i++) {
            st->buffer[st->leftover + i] = m[i];
        }
        bytes -= want;
        m += want;
        st->leftover += want;
        if (st->leftover < poly1305_block_size) {
            return;
        }
        poly1305_blocks(st, st->buffer, poly1305_block_size);
        st->leftover = 0;
    }

    /* process full blocks */
    if (bytes >= poly1305_block_size) {
        unsigned long long want = (bytes & ~(poly1305_block_size - 1));

        poly1305_blocks(st, m, want);
        m += want;
        bytes -= want;
    }

    /* store leftover */
    if (bytes) {
        for (i = 0; i < bytes; i++) {
            st->buffer[st->leftover + i] = m[i];
        }
        st->leftover += bytes;
    }
}

static int
psCrypto_onetimeauth_poly1305_donna(unsigned char *out, const unsigned char *m,
                                  unsigned long long   inlen,
                                  const unsigned char *key)
{
    CRYPTO_ALIGN(64) poly1305_state_internal_t state;

    poly1305_init(&state, key);
    poly1305_update(&state, m, inlen);
    poly1305_finish(&state, out);

    return 0;
}

static int
psCrypto_onetimeauth_poly1305_donna_init(crypto_onetimeauth_poly1305_state *state,
                                       const unsigned char *              key)
{
    COMPILER_ASSERT(sizeof(crypto_onetimeauth_poly1305_state) >=
        sizeof(poly1305_state_internal_t));
    poly1305_init((poly1305_state_internal_t *) (void *) state, key);

    return 0;
}

static int
psCrypto_onetimeauth_poly1305_donna_update(
    crypto_onetimeauth_poly1305_state *state, const unsigned char *in,
    unsigned long long inlen)
{
    poly1305_update((poly1305_state_internal_t *) (void *) state, in, inlen);

    return 0;
}

static int
psCrypto_onetimeauth_poly1305_donna_final(
    crypto_onetimeauth_poly1305_state *state, unsigned char *out)
{
    poly1305_finish((poly1305_state_internal_t *) (void *) state, out);

    return 0;
}

static int
psCrypto_onetimeauth_poly1305_donna_verify(const unsigned char *h,
                                         const unsigned char *in,
                                         unsigned long long   inlen,
                                         const unsigned char *k)
{
    unsigned char correct[16];

    psCrypto_onetimeauth_poly1305_donna(correct, in, inlen, k);

    return psCrypto_verify_16(h, correct);
}

struct crypto_onetimeauth_poly1305_implementation
    psCrypto_onetimeauth_poly1305_donna_implementation = {
        SODIUM_C99(.onetimeauth =) psCrypto_onetimeauth_poly1305_donna,
        SODIUM_C99(.onetimeauth_verify =)
            psCrypto_onetimeauth_poly1305_donna_verify,
        SODIUM_C99(.onetimeauth_init =) psCrypto_onetimeauth_poly1305_donna_init,
        SODIUM_C99(.onetimeauth_update =)
            psCrypto_onetimeauth_poly1305_donna_update,
        SODIUM_C99(.onetimeauth_final =) psCrypto_onetimeauth_poly1305_donna_final
    };

#endif /* USE_MATRIX_CHACHA20_POLY1305_IETF */
