
#include "osdep_string.h"
#include "pscompilerdep.h"
#include "crypto_scalarmult_ed25519.h"
#include "private/ed25519_ref10.h"
#include "utils.h"

static int
_psSodium_crypto_scalarmult_ed25519_is_inf(const unsigned char s[32])
{
    unsigned char c;
    unsigned int  i;

    c = s[0] ^ 0x01;
    for (i = 1; i < 31; i++) {
        c |= s[i];
    }
    c |= s[31] & 0x7f;

    return ((((unsigned int) c) - 1U) >> 8) & 1;
}

static inline void
_psSodium_crypto_scalarmult_ed25519_clamp(unsigned char k[32])
{
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

int
psSodium_crypto_scalarmult_ed25519(unsigned char *q, const unsigned char *n,
                          const unsigned char *p)
{
    unsigned char *t = q;
    psSodium_ge25519_p3     Q;
    psSodium_ge25519_p3     P;
    unsigned int   i;

    if (psSodium_ge25519_is_canonical(p) == 0 || psSodium_ge25519_has_small_order(p) != 0 ||
        psSodium_ge25519_frombytes(&P, p) != 0 || psSodium_ge25519_is_on_main_subgroup(&P) == 0) {
        return -1;
    }
    for (i = 0; i < 32; ++i) {
        t[i] = n[i];
    }
    _psSodium_crypto_scalarmult_ed25519_clamp(t);
    psSodium_ge25519_scalarmult(&Q, t, &P);
    psSodium_ge25519_p3_tobytes(q, &Q);
    if (_psSodium_crypto_scalarmult_ed25519_is_inf(q) != 0 || psSodium_is_zero(n, 32)) {
        return -1;
    }
    return 0;
}

int
psSodium_crypto_scalarmult_ed25519_base(unsigned char *q,
                               const unsigned char *n)
{
    unsigned char *t = q;
    psSodium_ge25519_p3     Q;
    unsigned int   i;

    for (i = 0; i < 32; ++i) {
        t[i] = n[i];
    }
    _psSodium_crypto_scalarmult_ed25519_clamp(t);
    psSodium_ge25519_scalarmult_base(&Q, t);
    psSodium_ge25519_p3_tobytes(q, &Q);
    if (psSodium_is_zero(n, 32) != 0) {
        return -1;
    }
    return 0;
}

size_t
psSodium_crypto_scalarmult_ed25519_bytes(void)
{
    return psSodium_crypto_scalarmult_ed25519_BYTES;
}

size_t
psSodium_crypto_scalarmult_ed25519_scalarbytes(void)
{
    return psSodium_crypto_scalarmult_ed25519_SCALARBYTES;
}
