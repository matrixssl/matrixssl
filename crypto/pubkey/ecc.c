/**
 *      @file    ecc.c
 *      @version $Format:%h%d$
 *
 *      Implements ECC over Z/pZ for curve y^2 = x^3 + ax + b.
 */
/*
 *      Copyright (c) 2013-2017 INSIDE Secure Corporation
 *      Copyright (c) PeerSec Networks, 2002-2011
 *      All Rights Reserved
 *
 *      The latest version of this code is available at http://www.matrixssl.org
 *
 *      This software is open source; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This General Public License does NOT permit incorporating this software
 *      into proprietary programs.  If you are unable to comply with the GPL, a
 *      commercial license for this software may be purchased from INSIDE at
 *      http://www.insidesecure.com/
 *
 *      This program is distributed in WITHOUT ANY WARRANTY; without even the
 *      implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *      See the GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *      http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

#include "../cryptoImpl.h"

#ifdef USE_MATRIX_ECC

/******************************************************************************/

# define ECC_BUF_SIZE    256

static psEccPoint_t *eccNewPoint(psPool_t *pool, short size);
static void eccFreePoint(psEccPoint_t *p);

static int32_t eccMulmod(psPool_t *pool, const pstm_int *k, const psEccPoint_t *G,
                         psEccPoint_t *R, pstm_int *modulus, uint8_t map, pstm_int *tmp_int);
static int32_t eccProjectiveAddPoint(psPool_t *pool, const psEccPoint_t *P,
                                     const psEccPoint_t *Q, psEccPoint_t *R, const pstm_int *modulus,
                                     const pstm_digit *mp, pstm_int *tmp_int);
static int32_t eccProjectiveDblPoint(psPool_t *pool, const psEccPoint_t *P,
                                     psEccPoint_t *R, const pstm_int *modulus, const pstm_digit *mp,
                                     const pstm_int *A);
static int32_t eccMap(psPool_t *pool, psEccPoint_t *P, const pstm_int *modulus,
                      const pstm_digit *mp);

/*
    This array holds the ecc curve settings.

    The recommended elliptic curve domain parameters over p have been given
    nicknames to enable them to be easily identified. The nicknames were
    chosen as follows. Each name begins with sec to denote ‘Standards for
    Efficient Cryptography’, followed by a p to denote parameters over p,
    followed by a number denoting the length in bits of the field size p,
    followed by a k to denote parameters associated with a Koblitz curve or an
    r to denote verifiably random parameters, followed by a sequence number.

    typedef struct {
        uint8_t     size; // The size of the curve in octets
        psCurve16_t    curveId; // IANA named curve id for TLS use
        uint8_t     isOptimized; // 1 if optimized with field parameter A=-3
        uint32_t    OIDsum; // Internal Matrix OID
        //Domain parameters
        const char *name;  // name of curve
        const char *prime; // prime defining the field the curve is in (hex)
        const char *A; // The fields A param (hex)
        const char *B; // The fields B param (hex)
        const char *order; // The order of the curve (hex)
        const char *Gx; // The x co-ordinate of the base point on the curve (hex)
        const char *Gy; // The y co-ordinate of the base point on the curve (hex)
    } psEccCurve_t;
 */
const static psEccCurve_t eccCurves[] = {
# ifdef USE_SECP521R1
    {
        66,
        IANA_SECP521R1,
        1,   /* isOptimized */
        211, /* 43.129.4.0.35 */
        "secp521r1",
        "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
        "51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
        "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
        "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
        "11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
    },
# endif
# ifdef USE_BRAIN512R1
    {
        64,  /* size in octets */
        IANA_BRAIN512R1,
        0,   /* isOptimized */
        110, /* 1.3.36.3.3.2.8.1.1.13 */
        "brainpoolP512r1",
        "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
        "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
        "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
        "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069",
        "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
        "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
    },
# endif
# ifdef USE_SECP384R1
    {
        48,
        IANA_SECP384R1,
        1,   /* isOptimized */
        210, /* 43.129.4.0.34 */
        "secp384r1",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
    },
# endif
# ifdef USE_BRAIN384R1
    {
        48,  /* size in octets */
        IANA_BRAIN384R1,
        0,   /* isOptimized */
        108, /* 1.3.36.3.3.2.8.1.1.11 */
        "brainpoolP384r1",
        "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
        "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
        "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
        "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565",
        "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
        "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
    },
# endif
# ifdef USE_SECP256R1
    {
        32,
        IANA_SECP256R1,
        1,   /* isOptimized */
        526, /* 42.134.72.206.61.3.1.7 */
        "secp256r1",
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
    },
# endif
# ifdef USE_BRAIN256R1
    {
        32,  /* size in octets */
        IANA_BRAIN256R1,
        0,   /* isOptimized */
        104, /* 1.3.36.3.3.2.8.1.1.7 */
        "brainpoolP256r1",
        "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
        "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
        "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
        "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",
        "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
        "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
    },
# endif
# ifdef USE_SECP224R1
    {
        28,
        IANA_SECP224R1,
        1,   /* isOptimized */
        209, /* 43.129.4.0.33 */
        "secp224r1",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
        "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
        "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
        "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
    },
# endif
# ifdef USE_BRAIN224R1
    {
        28,  /* size in octets */
        IANA_BRAIN224R1,
        0,   /* isOptimized */
        102, /* 1.3.36.3.3.2.8.1.1.5 */
        "brainpoolP224r1",
        "D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",
        "68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43",
        "2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B",
        "D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F",
        "0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D",
        "58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD"
    },
# endif
# ifdef USE_SECP192R1
    {
        24,                                                 /* size in octets */
        IANA_SECP192R1,                                     /* IANA named curve ID */
        1,                                                  /* isOptimized */
        520,                                                /* 42.134.72.206.61.3.1.1 */
        "secp192r1",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", /* prime */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC", /* A = -3 */
        "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", /* B */
        "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", /* order */
        "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", /* Gx */
        "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", /* Gy */
    },
# endif
    {
        0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL
    }
};

/*****************************************************************************/
/**
    Initialize an ecc key, and assign the curve, if provided.
    @param[in] pool Memory pool
    @param[out] key Pointer to allocated ECC key to initialize
    @param[in] curve Curve to assign, or NULL.
    @return < 0 on failure, 0 on success.
    @note To allocate and initialize a key, use psEccNewKey().
 */
int32_t psEccInitKey(psPool_t *pool, psEccKey_t *key, const psEccCurve_t *curve)
{
    if (!key)
    {
        return PS_MEM_FAIL;
    }
    memset(key, 0x0, sizeof(psEccKey_t));
    key->pool = pool;
    key->pubkey.pool = pool;
    key->curve = curve; /* Curve can be NULL */
    /* key->type will be set by one of the key generate/import/read functions */
    return PS_SUCCESS;
}

/**
    Clear an ECC key.
    @param[out] key Pointer to allocated ECC key to clear.
    @note Caller is responsible for freeing memory associated with key structure,
        if appropriate.
 */
void psEccClearKey(psEccKey_t *key)
{
    psAssert(key);
    /* Clear private k separately, since it may not be present */
    pstm_clear(&key->k);
    pstm_clear_multi(
        &key->pubkey.x,
        &key->pubkey.y,
        &key->pubkey.z,
        NULL, NULL, NULL, NULL, NULL);
    key->curve = NULL;
    key->pool = NULL;
    key->pubkey.pool = NULL;
    key->type = 0;
}

/**
    Allocate memory for an ECC key and initialize it.
    @param[in] pool Memory pool
    @param[out] key Pointer to unallocated ECC key to initialize. Will
    point to allocated and initialized key on successful return.
    @param[in] curve Curve to assign, or NULL.
    @return < 0 on failure, 0 on success.
 */
int32_t psEccNewKey(psPool_t *pool, psEccKey_t **key, const psEccCurve_t *curve)
{
    psEccKey_t *k;
    int32_t rc;

    if ((k = psMalloc(pool, sizeof(psEccKey_t))) == NULL)
    {
        return PS_MEM_FAIL;
    }
    k->type = 0;
    if ((rc = psEccInitKey(pool, k, curve)) < 0)
    {
        psFree(k, pool);
        return rc;
    }
    *key = k;
    return PS_SUCCESS;
}

/* 'to' digits will be allocated here */
int32 psEccCopyKey(psEccKey_t *to, psEccKey_t *from)
{
    int32 rc;

    if (to->pool == NULL)
    {
        to->pool = from->pool;
        to->pubkey.pool = from->pubkey.pool;
    }
    else
    {
        to->pubkey.pool = to->pool;
    }
    to->curve = from->curve;
    to->type = from->type;

    /* pubkey */
    if ((rc = pstm_init_copy(to->pool, &to->pubkey.x, &from->pubkey.x, 0))
        != PSTM_OKAY)
    {
        goto error;
    }
    if ((rc = pstm_init_copy(to->pool, &to->pubkey.y, &from->pubkey.y, 0))
        != PSTM_OKAY)
    {
        goto error;
    }
    if ((rc = pstm_init_copy(to->pool, &to->pubkey.z, &from->pubkey.z, 0))
        != PSTM_OKAY)
    {
        goto error;
    }

    /* privkey */
    if (to->type == PS_PRIVKEY)
    {
        if ((rc = pstm_init_copy(to->pool, &to->k, &from->k, 0))
            != PSTM_OKAY)
        {
            goto error;
        }
    }

error:
    if (rc < 0)
    {
        psEccClearKey(from);
    }
    return rc;
}

/**
    Free memory for an ECC key and clear it.
    @param[out] key Pointer to dynamically allocated ECC key to free. Pointer
    will be cleared, freed and set to NULL on return.
 */
void psEccDeleteKey(psEccKey_t **key)
{
    psEccKey_t *k = *key;

    psEccClearKey(k);
    psFree(k, NULL);
    *key = NULL;
}

/**
    ECC key size in bytes.
    @return Public key size in bytes if key->type is public, otherwise private size.
    @note ECC public keys are twice as many bytes as private keys.
 */
uint8_t psEccSize(const psEccKey_t *key)
{
    if (key && key->curve)
    {
        return key->curve->size * 2;
    }
    return 0;
}

/*****************************************************************************/
/*
    Called from the cert parse.  The initial bytes in this stream are
    technically the EcpkParameters from the ECDSA pub key OBJECT IDENTIFIER
    that name the curve.  The asnGetAlgorithmIdentifier call right before
    this just stripped out the OID
 */
int32_t getEcPubKey(psPool_t *pool, const unsigned char **pp, psSize_t len,
    psEccKey_t *pubKey, unsigned char sha1KeyHash[SHA1_HASH_SIZE])
{
# ifdef USE_SHA1
    psDigestContext_t dc;
# endif
    const psEccCurve_t *eccCurve;
    const unsigned char *p = *pp, *end;
    int32_t oid;
    psSize_t arcLen;
    uint8_t ignore_bits;

    end = p + len;
    if (len < 1 ||
        *(p++) != ASN_OID ||
        getAsnLength(&p, (uint16_t) (end - p), &arcLen) < 0 ||
        (uint16_t) (end - p) < arcLen)
    {

        psTraceCrypto("Only namedCurve types are supported in EC certs\n");
        return PS_PARSE_FAIL;
    }
/*
    NamedCurve OIDs

    ansi-x9-62 OBJECT IDENTIFER ::= {
        iso(1) member-body(2) us(840) 10045
    }

    secp192r1 OBJECT IDENTIFIER ::= { ansi-x9-62 curves(3) prime(1) 1 }
        2a8648ce3d030101 -> sum = 520

    secp256r1 OBJECT IDENTIFIER ::= { ansi-x9-62 curves(3) prime(1) 7 }
        2a8648ce3d030107 -> sum = 526
 */
    /* Note arcLen could be zero here */
    oid = 0;
    while (arcLen > 0)
    {
        oid += *p++;
        arcLen--;
    }
    /* Match the sum against our list of curves to make sure we got it */
    if (getEccParamByOid(oid, &eccCurve) < 0)
    {
        psTraceCrypto("Cert named curve not found in eccCurve list\n");
        return PS_UNSUPPORTED_FAIL;
    }

    if ((uint16_t) (end - p) < 1 || (*(p++) != ASN_BIT_STRING) ||
        getAsnLength(&p, len - 1, &arcLen) < 0 ||
        (uint16_t) (end - p) < arcLen ||
        arcLen < 1)
    {

        psTraceCrypto("Unexpected ECC pubkey format\n");
        return PS_PARSE_FAIL;
    }
    ignore_bits = *p++;
    arcLen--;
    if (ignore_bits != 0)
    {
        psTraceCrypto("Unexpected ECC ignore_bits\n");
    }

# ifdef USE_SHA1
    /* A public key hash is used in PKI tools (OCSP, Trusted CA indication).
        Standard form - SHA-1 hash of the value of the BIT STRING
        subjectPublicKey [excluding the tag, length, and number of unused
        bits] */
    psSha1PreInit(&dc.sha1);
    psSha1Init(&dc.sha1);
    psSha1Update(&dc.sha1, p, arcLen);
    psSha1Final(&dc.sha1, sha1KeyHash);
# endif

    /* Note arcLen could again be zero here */
    if (psEccX963ImportKey(pool, p, arcLen, pubKey, eccCurve) < 0)
    {
        psTraceCrypto("Unable to parse ECC pubkey from cert\n");
        return PS_PARSE_FAIL;
    }
    p += arcLen;

    *pp = p;

    return PS_SUCCESS;
}

/**
    Initialize an ECC key and generate a public/private keypair for the given
    curve.
    @param pool Memory pool
    @param[out] key Uninitialized ECC key. This API will call psEccInitKey() on this key.
    @param[in] curve ECC named curve to use for key.
    @param[in] usrData User data pointer to pass to hardware implementations that use it.
    @return < 0 on failure.
 */
int32_t psEccGenKey(psPool_t *pool, psEccKey_t *key, const psEccCurve_t *curve,
    void *usrData)
{
    int32_t err;
    psSize_t keysize, slen;
    psEccPoint_t *base;
    pstm_int *A = NULL;
    pstm_int prime, order, rand;
    unsigned char *buf;

    if (!key || !curve)
    {
        psTraceCrypto("Only named curves supported in psEccGenKey\n");
        return PS_UNSUPPORTED_FAIL;
    }

    psEccInitKey(pool, key, curve);
    keysize  = curve->size; /* Note, curve is non-null */
    slen = keysize * 2;

    /* allocate ram */
    base = NULL;
    buf  = psMalloc(pool, ECC_MAXSIZE);
    if (buf == NULL)
    {
        psError("Memory allocation error in psEccGenKey\n");
        err = PS_MEM_FAIL;
        goto ERR_KEY;
    }

    /* Make sure random number is less than "order" */
    if (pstm_init_for_read_unsigned_bin(pool, &order, keysize) < 0)
    {
        err = PS_MEM_FAIL;
        goto ERR_BUF;
    }

    if ((err = pstm_read_radix(pool, &order, key->curve->order, slen, 16))
        != PS_SUCCESS)
    {
        pstm_clear(&order);
        goto ERR_BUF;
    }

    /* make up random string */
RETRY_RAND:
    if (psGetPrngLocked(buf, keysize, usrData) != keysize)
    {
        err = PS_PLATFORM_FAIL;
        pstm_clear(&order);
        goto ERR_BUF;
    }

    if (pstm_init_for_read_unsigned_bin(pool, &rand, keysize) < 0)
    {
        err = PS_MEM_FAIL;
        pstm_clear(&order);
        goto ERR_BUF;
    }

    if ((err = pstm_read_unsigned_bin(&rand, buf, keysize)) != PS_SUCCESS)
    {
        pstm_clear(&order);
        pstm_clear(&rand);
        goto ERR_BUF;
    }

    /* Make sure random number is less than "order" */
    if (pstm_cmp(&rand, &order) == PSTM_GT)
    {
        pstm_clear(&rand);
        goto RETRY_RAND;
    }
    pstm_clear(&rand);
    pstm_clear(&order);

    if (key->curve->isOptimized == 0)
    {
        if ((A = psMalloc(pool, sizeof(pstm_int))) == NULL)
        {
            err = PS_MEM_FAIL;
            goto ERR_BUF;
        }
        if (pstm_init_for_read_unsigned_bin(pool, A, keysize) < 0)
        {
            err = PS_MEM_FAIL;
            psFree(A, pool);
            goto ERR_BUF;
        }
        if ((err = pstm_read_radix(pool, A, key->curve->A, slen, 16))
            != PS_SUCCESS)
        {
            goto ERR_A;
        }
    }

    if (pstm_init_for_read_unsigned_bin(pool, &prime, keysize) < 0)
    {
        err = PS_MEM_FAIL;
        goto ERR_A;
    }

    base = eccNewPoint(pool, prime.alloc);
    if (base == NULL)
    {
        err = PS_MEM_FAIL;
        goto ERR_PRIME;
    }

    /* read in the specs for this key */
    if ((err = pstm_read_radix(pool, &prime, key->curve->prime, slen, 16))
        != PS_SUCCESS)
    {
        goto ERR_BASE;
    }
    if ((err = pstm_read_radix(pool, &base->x, key->curve->Gx, slen, 16))
        != PS_SUCCESS)
    {
        goto ERR_BASE;
    }
    if ((err = pstm_read_radix(pool, &base->y, key->curve->Gy, slen, 16))
        != PS_SUCCESS)
    {
        goto ERR_BASE;
    }
    pstm_set(&base->z, 1);

    if (pstm_init_for_read_unsigned_bin(pool, &key->k, keysize) < 0)
    {
        err = PS_MEM_FAIL;
        goto ERR_BASE;
    }
    if ((err = pstm_read_unsigned_bin(&key->k, buf, keysize))
        != PS_SUCCESS)
    {
        goto ERR_BASE;
    }

    /* make the public key */
    if (pstm_init_size(pool, &key->pubkey.x, (key->k.used * 2) + 1) < 0)
    {
        err = PS_MEM_FAIL;
        goto ERR_BASE;
    }
    if (pstm_init_size(pool, &key->pubkey.y, (key->k.used * 2) + 1) < 0)
    {
        err = PS_MEM_FAIL;
        goto ERR_BASE;
    }
    if (pstm_init_size(pool, &key->pubkey.z, (key->k.used * 2) + 1) < 0)
    {
        err = PS_MEM_FAIL;
        goto ERR_BASE;
    }
    if ((err = eccMulmod(pool, &key->k, base, &key->pubkey, &prime, 1, A)) !=
        PS_SUCCESS)
    {
        goto ERR_BASE;
    }

    key->type = PS_PRIVKEY;

    /* frees for success */
    eccFreePoint(base);
    pstm_clear(&prime);
    if (A)
    {
        pstm_clear(A);
        psFree(A, pool);
    }
    psFree(buf, pool);
    return PS_SUCCESS;

ERR_BASE:
    eccFreePoint(base);
ERR_PRIME:
    pstm_clear(&prime);
ERR_A:
    if (A)
    {
        pstm_clear(A);
        psFree(A, pool);
    }
ERR_BUF:
    psFree(buf, pool);
ERR_KEY:
    psEccClearKey(key);
    return err;
}

# if defined(MATRIX_USE_FILE_SYSTEM) && defined(USE_PRIVATE_KEY_PARSING)
/******************************************************************************/
/*
    ECPrivateKey{CURVES:IOSet} ::= SEQUENCE {
        version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
        privateKey OCTET STRING,
        parameters [0] Parameters{{IOSet}} OPTIONAL,
        publicKey [1] BIT STRING OPTIONAL
    }

 */
int32_t psEccParsePrivFile(psPool_t *pool, const char *fileName,
    const char *password, psEccKey_t *key)
{
    unsigned char *DERout;
    int32_t rc;
    psSize_t DERlen;

#  ifdef USE_PKCS8
    psPubKey_t pubkey;
#  endif

    if ((rc = psPkcs1DecodePrivFile(pool, fileName, password, &DERout, &DERlen)) < 0)
    {
        return rc;
    }

    if ((rc = psEccParsePrivKey(pool, DERout, DERlen, key, NULL)) < 0)
    {
#  ifdef USE_PKCS8
        /* This logic works for processing PKCS#8 files becuase the above file
            and bin decodes will always leave the unprocessed buffer intact and
            the password protection is done in the internal ASN.1 encoding */
        if ((rc = psPkcs8ParsePrivBin(pool, DERout, DERlen, (char *) password,
                 &pubkey)) < 0)
        {
            psFree(DERout, pool);
            return rc;
        }
        rc = psEccCopyKey(key, &pubkey.key.ecc);
        psClearPubKey(&pubkey);
#  else
        psFree(DERout, pool);
        return rc;
#  endif
    }
    psFree(DERout, pool);
    return PS_SUCCESS;
}
# endif /* MATRIX_USE_FILE_SYSTEM && USE_PRIVATE_KEY_PARSING */

int32_t psEccParsePrivKey(psPool_t *pool,
    const unsigned char *keyBuf, psSize_t keyBufLen,
    psEccKey_t *key, const psEccCurve_t *curve)
{
    const psEccCurve_t *eccCurve;
    const unsigned char *buf, *end;
    uint8_t ignore_bits;
    uint32_t oid;
    int32_t asnInt;
    psSize_t len;
    size_t privkey_len;

    buf = keyBuf;
    end = buf + keyBufLen;

    if (getAsnSequence(&buf, (uint16_t) (end - buf), &len) < 0)
    {
        psTraceCrypto("ECDSA subject signature parse failure 1\n");
        return PS_FAILURE;
    }
    if (getAsnInteger(&buf, (uint16_t) (end - buf), &asnInt) < 0 ||
        asnInt != 1)
    {
        psTraceCrypto("Expecting private key flag\n");
        return PS_FAILURE;
    }
    /* Initial curve check */
    if ((*buf++ != ASN_OCTET_STRING) ||
        getAsnLength(&buf, (uint16_t) (end - buf), &len) < 0 ||
        (uint16_t) (end - buf) < len ||
        len < (MIN_ECC_BITS / 8))
    {
        psTraceCrypto("Expecting private key octet string\n");
        return PS_FAILURE;
    }
    privkey_len = len;

    psEccInitKey(pool, key, curve);
    if (pstm_init_for_read_unsigned_bin(pool, &key->k, len) != PS_SUCCESS)
    {
        goto L_FAIL;
    }
    /* Key material */
    if (pstm_read_unsigned_bin(&key->k, buf, len) != PS_SUCCESS)
    {
        psTraceCrypto("Unable to read private key octet string\n");
        goto L_FAIL;
    }
    key->type = PS_PRIVKEY;
    buf += len;

    if (*buf == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED))
    {

        /* optional parameters are present */
        buf++;
        if (getAsnLength(&buf, (uint16_t) (end - buf), &len) < 0 ||
            (uint16_t) (end - buf) < len ||
            len < 1)
        {

            psTraceCrypto("Bad private key format\n");
            goto L_FAIL;
        }
        if (*(buf++) != ASN_OID ||
            getAsnLength(&buf, (uint16_t) (end - buf), &len) < 0 ||
            (uint16_t) (end - buf) < len)
        {

            psTraceCrypto("Only namedCurves are supported in EC keys\n");
            goto L_FAIL;
        }
        /* Note len can be 0 here */
        oid = 0;
        while (len > 0)
        {
            oid += *buf++;
            len--;
        }
        if (getEccParamByOid(oid, &eccCurve) < 0)
        {
            psTraceCrypto("Cert named curve not found in eccCurve list\n");
            goto L_FAIL;
        }
        if (curve != NULL && curve != eccCurve)
        {
            psTraceCrypto("PrivKey named curve doesn't match desired\n");
            goto L_FAIL;
        }
        key->curve = eccCurve;

    }
    else if (curve != NULL)
    {
        key->curve = curve;
    }
    else
    {
        psTraceCrypto("No curve found in EC private key\n");
        goto L_FAIL;
    }

    if (*buf == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1))
    {
        /* optional public key is present */
        buf++;
        if (getAsnLength(&buf, (uint16_t) (end - buf), &len) < 0 ||
            (uint16_t) (end - buf) < len ||
            len < 1)
        {

            psTraceCrypto("Bad private key format\n");
            goto L_FAIL;
        }
        if (*(buf++) != ASN_BIT_STRING ||
            getAsnLength(&buf, (uint16_t) (end - buf), &len) < 0 ||
            (uint16_t) (end - buf) < len ||
            len < 1)
        {

            goto L_FAIL;
        }
        ignore_bits = *buf++;
        len--;
        if (ignore_bits != 0)
        {
            psTraceCrypto("Unexpected ECC pubkey format\n");
            goto L_FAIL;
        }

        /* Note len can be 0 here */
        if (psEccX963ImportKey(pool, buf, len, key, key->curve) < 0)
        {
            psTraceCrypto("Unable to parse ECC pubkey from cert\n");
            goto L_FAIL;
        }
        buf += len;
    }
    /* Try to parse 'implicitly' encoded optional public key with no
       DER header, i.e. assume that all the remaining bytes are public
       key bytes. This is not valid ASN.1, but sometimes appears in
       practice and parsing it is a requirement for some users. */
    if (buf < end &&
        *buf == ANSI_UNCOMPRESSED &&                  /* Uncompressed is the only format we support. */
        ((end - (buf + 1)) == privkey_len * 2))       /* Pubkey must be 2x privkey size. */
    {
        if (psEccX963ImportKey(pool, buf, (end - buf), key, key->curve) < 0)
        {
            psTraceCrypto("Unable to parse ECC pubkey from cert\n");
            goto L_FAIL;
        }
        buf += (end - buf);
    }

    /* Should be at the end */
    if (end != buf)
    {
        /* If this stream came from an encrypted file, there could be
            padding bytes on the end */
        len = (uint16_t) (end - buf);
        while (buf < end)
        {
            if (*buf != len)
            {
                psTraceCrypto("Problem at end of private key parse\n");
                goto L_FAIL;
            }
            buf++;
        }
    }
    return PS_SUCCESS;

L_FAIL:
    psEccClearKey(key);
    return PS_FAIL;
}

int32_t getEccParamById(psCurve16_t curveId, const psEccCurve_t **curve)
{
    int i = 0;

    /* A curveId of zero is asking for a default curver */
    if (curveId == 0)
    {
        *curve = &eccCurves[0];
        return 0;
    }

    *curve = NULL;
    while (eccCurves[i].size > 0)
    {
        if (curveId == eccCurves[i].curveId)
        {
            *curve = &eccCurves[i];
            return 0;
        }
        i++;
    }
    return PS_FAIL;
}

int32_t getEccParamByOid(uint32_t oid, const psEccCurve_t **curve)
{
    int i = 0;

    *curve = NULL;
    while (eccCurves[i].size > 0)
    {
        if (oid == eccCurves[i].OIDsum)
        {
            *curve = &eccCurves[i];
            return 0;
        }
        i++;
    }
    return PS_FAIL;
}

int32_t getEccParamByName(const char *curveName,
    const psEccCurve_t **curve)
{
    int i = 0;

    *curve = NULL;
    while (eccCurves[i].size > 0)
    {
        if (strcmp(curveName, eccCurves[i].name) == 0)
        {
            *curve = &eccCurves[i];
            return 0;
        }
        i++;
    }
    return PS_FAIL;
}

/**
    Return a list of all supported curves.
    This method will put the largest bit strength first in the list, because
    of their order in the eccCurves[] array.
 */
void psGetEccCurveIdList(unsigned char *curveList, uint8_t *len)
{
    psSize_t listLen = 0, i = 0;

    while (eccCurves[i].size > 0)
    {
        if (listLen < (*len - 2))
        {
            curveList[listLen++] = (eccCurves[i].curveId & 0xFF00) >> 8;
            curveList[listLen++] = eccCurves[i].curveId & 0xFF;
        }
        i++;
    }
    *len = listLen;
}

/**
    User set list of curves they want to support.
    This method will put the largest bit strength first in the list.
    @param[in] curves Flags indicating which curves to use.
 */
void userSuppliedEccList(unsigned char *curveList, uint8_t *len, uint32_t curves)
{
    const psEccCurve_t *curve;
    uint8_t listLen = 0;

    if (curves & IS_SECP521R1)
    {
        if (getEccParamById(IANA_SECP521R1, &curve) == 0)
        {
            if (listLen < (*len - 2))
            {
                curveList[listLen++] = (curve->curveId & 0xFF00) >> 8;
                curveList[listLen++] = curve->curveId & 0xFF;
            }
        }
    }
    if (curves & IS_BRAIN512R1)
    {
        if (getEccParamById(IANA_BRAIN512R1, &curve) == 0)
        {
            if (listLen < (*len - 2))
            {
                curveList[listLen++] = (curve->curveId & 0xFF00) >> 8;
                curveList[listLen++] = curve->curveId & 0xFF;
            }
        }
    }
    if (curves & IS_SECP384R1)
    {
        if (getEccParamById(IANA_SECP384R1, &curve) == 0)
        {
            if (listLen < (*len - 2))
            {
                curveList[listLen++] = (curve->curveId & 0xFF00) >> 8;
                curveList[listLen++] = curve->curveId & 0xFF;
            }
        }
    }
    if (curves & IS_BRAIN384R1)
    {
        if (getEccParamById(IANA_BRAIN384R1, &curve) == 0)
        {
            if (listLen < (*len - 2))
            {
                curveList[listLen++] = (curve->curveId & 0xFF00) >> 8;
                curveList[listLen++] = curve->curveId & 0xFF;
            }
        }
    }
    if (curves & IS_SECP256R1)
    {
        if (getEccParamById(IANA_SECP256R1, &curve) == 0)
        {
            if (listLen < (*len - 2))
            {
                curveList[listLen++] = (curve->curveId & 0xFF00) >> 8;
                curveList[listLen++] = curve->curveId & 0xFF;
            }
        }
    }
    if (curves & IS_BRAIN256R1)
    {
        if (getEccParamById(IANA_BRAIN256R1, &curve) == 0)
        {
            if (listLen < (*len - 2))
            {
                curveList[listLen++] = (curve->curveId & 0xFF00) >> 8;
                curveList[listLen++] = curve->curveId & 0xFF;
            }
        }
    }
    if (curves & IS_SECP224R1)
    {
        if (getEccParamById(IANA_SECP224R1, &curve) == 0)
        {
            if (listLen < (*len - 2))
            {
                curveList[listLen++] = (curve->curveId & 0xFF00) >> 8;
                curveList[listLen++] = curve->curveId & 0xFF;
            }
        }
    }
    if (curves & IS_BRAIN224R1)
    {
        if (getEccParamById(IANA_BRAIN224R1, &curve) == 0)
        {
            if (listLen < (*len - 2))
            {
                curveList[listLen++] = (curve->curveId & 0xFF00) >> 8;
                curveList[listLen++] = curve->curveId & 0xFF;
            }
        }
    }
    if (curves & IS_SECP192R1)
    {
        if (getEccParamById(IANA_SECP192R1, &curve) == 0)
        {
            if (listLen < (*len - 2))
            {
                curveList[listLen++] = (curve->curveId & 0xFF00) >> 8;
                curveList[listLen++] = curve->curveId & 0xFF;
            }
        }
    }

    *len = listLen;
}

uint32_t compiledInEcFlags(void)
{
    uint32_t ecFlags = 0;

# ifdef USE_SECP192R1
    ecFlags |= IS_SECP192R1;
# endif
# ifdef USE_SECP224R1
    ecFlags |= IS_SECP224R1;
# endif
# ifdef USE_SECP256R1
    ecFlags |= IS_SECP256R1;
# endif
# ifdef USE_SECP384R1
    ecFlags |= IS_SECP384R1;
# endif
# ifdef USE_SECP521R1
    ecFlags |= IS_SECP521R1;
# endif
# ifdef USE_BRAIN224R1
    ecFlags |= IS_BRAIN224R1;
# endif
# ifdef USE_BRAIN256R1
    ecFlags |= IS_BRAIN256R1;
# endif
# ifdef USE_BRAIN384R1
    ecFlags |= IS_BRAIN384R1;
# endif
# ifdef USE_BRAIN512R1
    ecFlags |= IS_BRAIN512R1;
# endif

    return ecFlags;
}

/******************************************************************************/

static uint8_t get_digit_count(const pstm_int *a)
{
    return a->used;
}

static pstm_digit get_digit(const pstm_int *a, uint8_t n)
{
    return (n >= a->used) ? (pstm_digit) 0 : a->dp[n];
}

/******************************************************************************/
/**
    Perform a point multiplication
    @param[in] pool Memory pool
    @param[in] k The scalar to multiply by
    @param[in] G The base point
    @param[out] R Destination for kG
    @param modulus The modulus of the field the ECC curve is in
    @param map Boolean whether to map back to affine or not (1==map)
    @param[in,out] tmp_int Temporary scratch big integer (memory optimization)
    @return PS_SUCCESS on success, < 0 on error
 */
/* size of sliding window, don't change this! */
# define ECC_MULMOD_WINSIZE 4

static int32_t eccMulmod(psPool_t *pool, const pstm_int *k, const psEccPoint_t *G,
    psEccPoint_t *R, pstm_int *modulus, uint8_t map, pstm_int *tmp_int)
{
    psEccPoint_t *tG, *M[8];      /* @note large on stack */
    int32 i, j, err;
    pstm_int mu;
    pstm_digit mp;
    unsigned long buf;
    int32 first, bitbuf, bitcpy, bitcnt, mode, digidx;

    /* init montgomery reduction */
    if ((err = pstm_montgomery_setup(modulus, &mp)) != PS_SUCCESS)
    {
        return err;
    }
    if ((err = pstm_init_size(pool, &mu, modulus->alloc)) != PS_SUCCESS)
    {
        return err;
    }
    if ((err = pstm_montgomery_calc_normalization(&mu, modulus)) != PS_SUCCESS)
    {
        pstm_clear(&mu);
        return err;
    }

    /* alloc ram for window temps */
    for (i = 0; i < 8; i++)
    {
        M[i] = eccNewPoint(pool, (G->x.used * 2) + 1);
        if (M[i] == NULL)
        {
            for (j = 0; j < i; j++)
            {
                eccFreePoint(M[j]);
            }
            pstm_clear(&mu);
            return PS_MEM_FAIL;
        }
    }

    /* make a copy of G incase R==G */
    tG = eccNewPoint(pool, G->x.alloc);
    if (tG == NULL)
    {
        err = PS_MEM_FAIL;
        goto done;
    }

    /* tG = G  and convert to montgomery */
    if (pstm_cmp_d(&mu, 1) == PSTM_EQ)
    {
        if ((err = pstm_copy(&G->x, &tG->x)) != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_copy(&G->y, &tG->y)) != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_copy(&G->z, &tG->z)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    else
    {
        if ((err = pstm_mulmod(pool, &G->x, &mu, modulus, &tG->x)) != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_mulmod(pool, &G->y, &mu, modulus, &tG->y)) != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_mulmod(pool, &G->z, &mu, modulus, &tG->z)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    pstm_clear(&mu);

    /* calc the M tab, which holds kG for k==8..15 */
    /* M[0] == 8G */
    if ((err = eccProjectiveDblPoint(pool, tG, M[0], modulus, &mp, tmp_int)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = eccProjectiveDblPoint(pool, M[0], M[0], modulus, &mp, tmp_int)) !=
        PS_SUCCESS)
    {
        goto done;
    }
    if ((err = eccProjectiveDblPoint(pool, M[0], M[0], modulus, &mp, tmp_int)) !=
        PS_SUCCESS)
    {
        goto done;
    }

    /* now find (8+k)G for k=1..7 */
    for (j = 9; j < 16; j++)
    {
        if ((err = eccProjectiveAddPoint(pool, M[j - 9], tG, M[j - 8], modulus,
                 &mp, tmp_int)) != PS_SUCCESS)
        {
            goto done;
        }
    }

    /* setup sliding window */
    mode   = 0;
    bitcnt = 1;
    buf    = 0;
    digidx = get_digit_count(k) - 1;
    bitcpy = bitbuf = 0;
    first  = 1;

    /* perform ops */
    for (;; )
    {
        /* grab next digit as required */
        if (--bitcnt == 0)
        {
            if (digidx == -1)
            {
                break;
            }
            buf = get_digit(k, digidx);
            bitcnt = DIGIT_BIT;
            --digidx;
        }

        /* grab the next msb from the ltiplicand */
        i = (buf >> (DIGIT_BIT - 1)) & 1;
        buf <<= 1;

        /* skip leading zero bits */
        if (mode == 0 && i == 0)
        {
            continue;
        }

        /* if the bit is zero and mode == 1 then we double */
        if (mode == 1 && i == 0)
        {
            if ((err = eccProjectiveDblPoint(pool, R, R, modulus, &mp, tmp_int)) !=
                PS_SUCCESS)
            {
                goto done;
            }
            continue;
        }

        /* else we add it to the window */
        bitbuf |= (i << (ECC_MULMOD_WINSIZE - ++bitcpy));
        mode = 2;

        if (bitcpy == ECC_MULMOD_WINSIZE)
        {
            /* if this is the first window we do a simple copy */
            if (first == 1)
            {
                /* R = kG [k = first window] */
                if ((err = pstm_copy(&M[bitbuf - 8]->x, &R->x)) != PS_SUCCESS)
                {
                    goto done;
                }
                if ((err = pstm_copy(&M[bitbuf - 8]->y, &R->y)) != PS_SUCCESS)
                {
                    goto done;
                }
                if ((err = pstm_copy(&M[bitbuf - 8]->z, &R->z)) != PS_SUCCESS)
                {
                    goto done;
                }
                first = 0;
            }
            else
            {
                /* normal window */
                /* ok window is filled so double as required and add  */
                /* double first */
                for (j = 0; j < ECC_MULMOD_WINSIZE; j++)
                {
                    if ((err = eccProjectiveDblPoint(pool, R, R, modulus, &mp, tmp_int))
                        != PS_SUCCESS)
                    {
                        goto done;
                    }
                }

                /* then add, bitbuf will be 8..15 [8..2^WINSIZE] guaranteed */
                if ((err = eccProjectiveAddPoint(pool, R, M[bitbuf - 8], R,
                         modulus, &mp, tmp_int)) != PS_SUCCESS)
                {
                    goto done;
                }
            }
            /* empty window and reset */
            bitcpy = bitbuf = 0;
            mode = 1;
        }
    }

    /* if bits remain then double/add */
    if (mode == 2 && bitcpy > 0)
    {
        /* double then add */
        for (j = 0; j < bitcpy; j++)
        {
            /* only double if we have had at least one add first */
            if (first == 0)
            {
                if ((err = eccProjectiveDblPoint(pool, R, R, modulus, &mp, tmp_int)) !=
                    PS_SUCCESS)
                {
                    goto done;
                }
            }

            bitbuf <<= 1;
            if ((bitbuf & (1 << ECC_MULMOD_WINSIZE)) != 0)
            {
                if (first == 1)
                {
                    /* first add, so copy */
                    if ((err = pstm_copy(&tG->x, &R->x)) != PS_SUCCESS)
                    {
                        goto done;
                    }
                    if ((err = pstm_copy(&tG->y, &R->y)) != PS_SUCCESS)
                    {
                        goto done;
                    }
                    if ((err = pstm_copy(&tG->z, &R->z)) != PS_SUCCESS)
                    {
                        goto done;
                    }
                    first = 0;
                }
                else
                {
                    /* then add */
                    if ((err = eccProjectiveAddPoint(pool, R, tG, R, modulus,
                             &mp, tmp_int)) !=  PS_SUCCESS)
                    {
                        goto done;
                    }
                }
            }
        }
    }

    /* map R back from projective space */
    if (map)
    {
        err = eccMap(pool, R, modulus, &mp);
    }
    else
    {
        err = PS_SUCCESS;
    }
done:

    pstm_clear(&mu);
    eccFreePoint(tG);
    for (i = 0; i < 8; i++)
    {
        eccFreePoint(M[i]);
    }
    return err;
}

static int32 eccTestPoint(psPool_t *pool, psEccPoint_t *P, pstm_int *prime,
    pstm_int *b)
{
    pstm_int t1, t2;
    uint32 paDlen;
    pstm_digit *paD;
    int32 err;

    if ((err = pstm_init(pool, &t1)) < 0)
    {
        return err;
    }
    if ((err = pstm_init(pool, &t2)) < 0)
    {
        pstm_clear(&t1);
        return err;
    }
    /*  Pre-allocated digit. TODO: haven't fully explored max paDlen */
    paDlen = (prime->used * 2 + 1) * sizeof(pstm_digit);
    if ((paD = psMalloc(pool, paDlen)) == NULL)
    {
        pstm_clear(&t1);
        pstm_clear(&t2);
        return PS_MEM_FAIL;
    }

    /* compute y^2 */
    if ((err = pstm_sqr_comba(pool, &P->y, &t1, paD, paDlen)) < 0)
    {
        goto error;
    }

    /* compute x^3 */
    if ((err = pstm_sqr_comba(pool, &P->x, &t2, paD, paDlen)) < 0)
    {
        goto error;
    }
    if ((err = pstm_mod(pool, &t2, prime, &t2)) < 0)
    {
        goto error;
    }

    if ((err = pstm_mul_comba(pool, &P->x, &t2, &t2, paD, paDlen)) < 0)
    {
        goto error;
    }

    /* compute y^2 - x^3 */
    if ((err = pstm_sub(&t1, &t2, &t1)) < 0)
    {
        goto error;
    }

    /* compute y^2 - x^3 + 3x */
    if ((err = pstm_add(&t1, &P->x, &t1)) < 0)
    {
        goto error;
    }
    if ((err = pstm_add(&t1, &P->x, &t1)) < 0)
    {
        goto error;
    }
    if ((err = pstm_add(&t1, &P->x, &t1)) < 0)
    {
        goto error;
    }
    if ((err = pstm_mod(pool, &t1, prime, &t1)) < 0)
    {
        goto error;
    }
    while (pstm_cmp_d(&t1, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&t1, prime, &t1)) < 0)
        {
            goto error;
        }
    }
    while (pstm_cmp(&t1, prime) != PSTM_LT)
    {
        if ((err = pstm_sub(&t1, prime, &t1)) < 0)
        {
            goto error;
        }
    }

    /* compare to b */
    if (pstm_cmp(&t1, b) != PSTM_EQ)
    {
        psTraceCrypto("Supplied EC public point not on curve\n");
        err = PS_LIMIT_FAIL;
    }
    else
    {
        err = PS_SUCCESS;
    }

error:
    psFree(paD, pool);
    pstm_clear(&t1);
    pstm_clear(&t2);
    return err;
}

/******************************************************************************/
/**
    ANSI X9.62 or X9.63 (Section 4.3.7) uncompressed import.
    This function imports the public ECC key elements (the x, y and z values).
    If a private 'k' value is defined, the public elements are added to the
        key. Otherwise, only the public elements are loaded and the key
        marked public.
    The format of import is ASN.1, and is used both within certificate
    parsing and when parsing public keys passed on the wire in TLS.

    @param[in] pool Memory pool
    @param[in] in ECC key data in uncompressed form
    @param[in] inlen Length of destination and final output size
    @param[in, out] key Key to import. Private keys types will not be
    initialized, all others will.
    @param[in] curve Curve parameters, may be NULL
    @return PS_SUCCESS on success, < 0 on failure
 */
int32_t psEccX963ImportKey(psPool_t *pool,
    const unsigned char *in, psSize_t inlen,
    psEccKey_t *key, const psEccCurve_t *curve)
{
    int32_t err;
    pstm_int prime, b;

    /* Must be odd and minimal size */
    if (inlen < ((2 * (MIN_ECC_BITS / 8)) + 1) || (inlen & 1) == 0)
    {
        return PS_ARG_FAIL;
    }

    /* The key passed in may be a private key that is already initialized
       and the 'k' parameter set. */
    if (key->type != PS_PRIVKEY)
    {
        if (psEccInitKey(pool, key, curve) < 0)
        {
            return PS_MEM_FAIL;
        }
        key->type = PS_PUBKEY;
    }
    if (pstm_init_for_read_unsigned_bin(pool, &key->pubkey.x,
            (inlen - 1) >> 1) < 0)
    {
        return PS_MEM_FAIL;
    }
    if (pstm_init_for_read_unsigned_bin(pool, &key->pubkey.y,
            (inlen - 1) >> 1) < 0)
    {
        pstm_clear(&key->pubkey.x);
        return PS_MEM_FAIL;
    }
    if (pstm_init_size(pool, &key->pubkey.z, 1) < 0)
    {
        pstm_clear(&key->pubkey.x);
        pstm_clear(&key->pubkey.y);
        return PS_MEM_FAIL;
    }

    switch (*in)
    {
    /* Standard, supported format */
    case ANSI_UNCOMPRESSED:
        break;
    /* Unsupported formats */
    case ANSI_COMPRESSED0:
    case ANSI_COMPRESSED1:
    case ANSI_HYBRID0:
    case ANSI_HYBRID1:
    default:
        psTraceCrypto("ERROR: ECC compressed/hybrid formats unsupported\n");
        err = PS_UNSUPPORTED_FAIL;
        goto error;
    }
    if ((err = pstm_read_unsigned_bin(&key->pubkey.x, (unsigned char *) in + 1,
             (inlen - 1) >> 1)) != PS_SUCCESS)
    {
        goto error;
    }
    if ((err = pstm_read_unsigned_bin(&key->pubkey.y,
             (unsigned char *) in + 1 + ((inlen - 1) >> 1),
             (inlen - 1) >> 1)) != PS_SUCCESS)
    {
        goto error;
    }
    pstm_set(&key->pubkey.z, 1);

    /* Validate the point is on the curve */
    if (curve != NULL && curve->isOptimized)
    {
        if ((err = pstm_init_for_read_unsigned_bin(pool, &prime, curve->size)) < 0)
        {
            goto error;
        }
        if ((err = pstm_init_for_read_unsigned_bin(pool, &b, curve->size)) < 0)
        {
            pstm_clear(&prime);
            goto error;
        }
        if ((err = pstm_read_radix(pool, &prime, curve->prime,
                 curve->size * 2, 16)) < 0)
        {
            pstm_clear(&prime);
            pstm_clear(&b);
            goto error;
        }

        if ((err = pstm_read_radix(pool, &b, curve->B, curve->size * 2, 16)) < 0)
        {
            pstm_clear(&prime);
            pstm_clear(&b);
            goto error;
        }
        if ((err = eccTestPoint(pool, &key->pubkey, &prime, &b)) < 0)
        {
            pstm_clear(&prime);
            pstm_clear(&b);
            goto error;
        }
        pstm_clear(&prime);
        pstm_clear(&b);
    }
    else
    {
        psTraceCrypto("WARNING: ECC public key not validated\n");
    }

    return PS_SUCCESS;

error:
    psEccClearKey(key);
    return err;
}

/******************************************************************************/
/**
   ANSI X9.62 or X9.63 (Sec. 4.3.6) uncompressed export.
   @param[in] pool Memory pool
   @param[in] key Key to export
   @param[out] out [out] destination of export
   @param[in, out] outlen Length of destination and final output size
   @return PS_SUCCESS on success, < 0 on failure
 */
int32_t psEccX963ExportKey(psPool_t *pool, const psEccKey_t *key,
    unsigned char *out, psSize_t *outlen)
{
    unsigned char buf[ECC_BUF_SIZE];
    unsigned long numlen;
    int32_t res;

    numlen = key->curve->size;
    if (*outlen < (1 + 2 * numlen))
    {
        *outlen = 1 + 2 * numlen;
        return PS_LIMIT_FAIL;
    }

    out[0] = (unsigned char) ANSI_UNCOMPRESSED;

    /* pad and store x */
    memset(buf, 0, sizeof(buf));
    if ((res = pstm_to_unsigned_bin(pool, &key->pubkey.x, buf +
             (numlen - pstm_unsigned_bin_size(&key->pubkey.x)))) != PSTM_OKAY)
    {
        return res;
    }
    memcpy(out + 1, buf, numlen);

    /* pad and store y */
    memset(buf, 0, sizeof(buf));
    if ((res = pstm_to_unsigned_bin(pool, &key->pubkey.y, buf +
             (numlen - pstm_unsigned_bin_size(&key->pubkey.y)))) != PSTM_OKAY)
    {
        return res;
    }
    memcpy(out + 1 + numlen, buf, numlen);

    *outlen = 1 + 2 * numlen;
    return PS_SUCCESS;
}

/******************************************************************************/
/**
    Create an ECC shared secret between two keys.
    @param[in] pool Memory pool
    @param[in] private_key The private ECC key
    @param[in] public_key The public key
    @param[out] out Destination of the shared secret (Conforms to EC-DH from ANSI X9.63)
    @param[in,out] outlen The max size and resulting size of the shared secret
    @param[in,out] usrData Opaque usrData for hardware offload.
    @return PS_SUCCESS if successful
 */
int32_t psEccGenSharedSecret(psPool_t *pool,
    const psEccKey_t *private_key, const psEccKey_t *public_key,
    unsigned char *out, psSize_t *outlen,
    void *usrData)
{
    uint16_t x;
    psEccPoint_t *result;
    pstm_int *A = NULL;
    pstm_int prime;
    int32_t err;

    /* type valid? */
    if (private_key->type != PS_PRIVKEY)
    {
        return PS_ARG_FAIL;
    }
    if (public_key->curve != NULL)
    {
        if (private_key->curve != public_key->curve)
        {
            return PS_ARG_FAIL;
        }
    }

    /* make new point */
    result = eccNewPoint(pool, (private_key->k.used * 2) + 1);
    if (result == NULL)
    {
        return PS_MEM_FAIL;
    }

    if (private_key->curve->isOptimized == 0)
    {
        if ((A = psMalloc(pool, sizeof(pstm_int))) == NULL)
        {
            eccFreePoint(result);
            return PS_MEM_FAIL;
        }

        if (pstm_init_for_read_unsigned_bin(pool, A, private_key->curve->size) < 0)
        {
            psFree(A, pool);
            eccFreePoint(result);
            return PS_MEM_FAIL;
        }

        if ((err = pstm_read_radix(pool, A, private_key->curve->A,
                 private_key->curve->size * 2, 16))
            != PS_SUCCESS)
        {
            pstm_clear(A);
            psFree(A, pool);
            eccFreePoint(result);
            return err;
        }
    }

    if ((err = pstm_init_for_read_unsigned_bin(pool, &prime,
             private_key->curve->size))  != PS_SUCCESS)
    {
        if (A)
        {
            pstm_clear(A);
            psFree(A, pool);
        }
        eccFreePoint(result);
        return err;
    }

    if ((err = pstm_read_radix(pool, &prime, private_key->curve->prime,
             private_key->curve->size * 2, 16)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = eccMulmod(pool, &private_key->k, &public_key->pubkey, result,
             &prime, 1, A)) != PS_SUCCESS)
    {
        goto done;
    }

    x = pstm_unsigned_bin_size(&prime);
    if (*outlen < x)
    {
        *outlen = x;
        err = PS_LIMIT_FAIL;
        goto done;
    }
    memset(out, 0, x);
    if ((err = pstm_to_unsigned_bin(pool, &result->x,
             out + (x - pstm_unsigned_bin_size(&result->x)))) != PS_SUCCESS)
    {
        goto done;
    }

    err = PS_SUCCESS;
    *outlen = x;
done:
    if (A)
    {
        pstm_clear(A);
        psFree(A, pool);
    }
    pstm_clear(&prime);
    eccFreePoint(result);
    return err;
}

/******************************************************************************/
/**
    Add two ECC points
    @param P The point to add
    @param Q The point to add
    @param[out] R The destination of the double
    @param modulus The modulus of the field the ECC curve is in
    @param mp The "b" value from montgomery_setup()
    @return PS_SUCCESS on success
 */
static int32_t eccProjectiveAddPoint(psPool_t *pool, const psEccPoint_t *P,
    const psEccPoint_t *Q, psEccPoint_t *R,
    const pstm_int *modulus, const pstm_digit *mp, pstm_int *tmp_int)
{
    pstm_int t1, t2, x, y, z;
    pstm_digit *paD;
    int32 err;
    uint32 paDlen;

    paD = NULL;
    if (pstm_init_size(pool, &t1, P->x.alloc) < 0)
    {
        return PS_MEM_FAIL;
    }
    err = PS_MEM_FAIL;
    if (pstm_init_size(pool, &t2, P->x.alloc) < 0)
    {
        goto ERR_T1;
    }
    if (pstm_init_size(pool, &x, P->x.alloc) < 0)
    {
        goto ERR_T2;
    }
    if (pstm_init_size(pool, &y, P->y.alloc) < 0)
    {
        goto ERR_X;
    }
    if (pstm_init_size(pool, &z, P->z.alloc) < 0)
    {
        goto ERR_Y;
    }

    /* should we dbl instead? */
    if ((err = pstm_sub(modulus, &Q->y, &t1)) != PS_SUCCESS)
    {
        goto done;
    }

    if ((pstm_cmp(&P->x, &Q->x) == PSTM_EQ) &&
        /* (&Q->z != NULL && pstm_cmp(&P->z, &Q->z) == PSTM_EQ) && */
        (pstm_cmp(&P->z, &Q->z) == PSTM_EQ) &&
        (pstm_cmp(&P->y, &Q->y) == PSTM_EQ ||
         pstm_cmp(&P->y, &t1) == PSTM_EQ))
    {
        pstm_clear_multi(&t1, &t2, &x, &y, &z, NULL, NULL, NULL);
        return eccProjectiveDblPoint(pool, P, R, modulus, mp, tmp_int);
    }

    if ((err = pstm_copy(&P->x, &x)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_copy(&P->y, &y)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_copy(&P->z, &z)) != PS_SUCCESS)
    {
        goto done;
    }

/*
    Pre-allocated digit.  Used for mul, sqr, AND reduce*/
    paDlen = (modulus->used * 2 + 1) * sizeof(pstm_digit);
    if ((paD = psMalloc(pool, paDlen)) == NULL)
    {
        err = PS_MEM_FAIL;
        goto done;
    }

    /* if Z is one then these are no-operations */
    if (pstm_cmp_d(&Q->z, 1) != PSTM_EQ)
    {
        /* T1 = Z' * Z' */
        if ((err = pstm_sqr_comba(pool, &Q->z, &t1, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
        /* X = X * T1 */
        if ((err = pstm_mul_comba(pool, &t1, &x, &x, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_montgomery_reduce(pool, &x, modulus, *mp, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
        /* T1 = Z' * T1 */
        if ((err = pstm_mul_comba(pool, &Q->z, &t1, &t1, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
        /* Y = Y * T1 */
        if ((err = pstm_mul_comba(pool, &t1, &y, &y, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_montgomery_reduce(pool, &y, modulus, *mp, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
    }

    /* T1 = Z*Z */
    if ((err = pstm_sqr_comba(pool, &z, &t1, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* T2 = X' * T1 */
    if ((err = pstm_mul_comba(pool, &Q->x, &t1, &t2, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t2, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* T1 = Z * T1 */
    if ((err = pstm_mul_comba(pool, &z, &t1, &t1, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* T1 = Y' * T1 */
    if ((err = pstm_mul_comba(pool, &Q->y, &t1, &t1, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }

    /* Y = Y - T1 */
    if ((err = pstm_sub(&y, &t1, &y)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&y, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&y, modulus, &y)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* T1 = 2T1 */
    if ((err = pstm_add(&t1, &t1, &t1)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp(&t1, modulus) != PSTM_LT)
    {
        if ((err = pstm_sub(&t1, modulus, &t1)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* T1 = Y + T1 */
    if ((err = pstm_add(&t1, &y, &t1)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp(&t1, modulus) != PSTM_LT)
    {
        if ((err = pstm_sub(&t1, modulus, &t1)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* X = X - T2 */
    if ((err = pstm_sub(&x, &t2, &x)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&x, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&x, modulus, &x)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* T2 = 2T2 */
    if ((err = pstm_add(&t2, &t2, &t2)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp(&t2, modulus) != PSTM_LT)
    {
        if ((err = pstm_sub(&t2, modulus, &t2)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* T2 = X + T2 */
    if ((err = pstm_add(&t2, &x, &t2)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp(&t2, modulus) != PSTM_LT)
    {
        if ((err = pstm_sub(&t2, modulus, &t2)) != PS_SUCCESS)
        {
            goto done;
        }
    }

    /* if Z' != 1 */
    if (pstm_cmp_d(&Q->z, 1) != PSTM_EQ)
    {
        /* Z = Z * Z' */
        if ((err = pstm_mul_comba(pool, &z, &Q->z, &z, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_montgomery_reduce(pool, &z, modulus, *mp, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
    }

    /* Z = Z * X */
    if ((err = pstm_mul_comba(pool, &z, &x, &z, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &z, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }

    /* T1 = T1 * X  */
    if ((err = pstm_mul_comba(pool, &t1, &x, &t1, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* X = X * X */
    if ((err = pstm_sqr_comba(pool, &x, &x, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &x, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* T2 = T2 * x */
    if ((err = pstm_mul_comba(pool, &t2, &x, &t2, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t2, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* T1 = T1 * X  */
    if ((err = pstm_mul_comba(pool, &t1, &x, &t1, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }

    /* X = Y*Y */
    if ((err = pstm_sqr_comba(pool, &y, &x, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &x, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* X = X - T2 */
    if ((err = pstm_sub(&x, &t2, &x)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&x, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&x, modulus, &x)) != PS_SUCCESS)
        {
            goto done;
        }
    }

    /* T2 = T2 - X */
    if ((err = pstm_sub(&t2, &x, &t2)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&t2, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&t2, modulus, &t2)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* T2 = T2 - X */
    if ((err = pstm_sub(&t2, &x, &t2)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&t2, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&t2, modulus, &t2)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* T2 = T2 * Y */
    if ((err = pstm_mul_comba(pool, &t2, &y, &t2, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t2, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* Y = T2 - T1 */
    if ((err = pstm_sub(&t2, &t1, &y)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&y, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&y, modulus, &y)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* Y = Y/2 */
    if (pstm_isodd(&y))
    {
        if ((err = pstm_add(&y, modulus, &y)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    if ((err = pstm_div_2(&y, &y)) != PS_SUCCESS)
    {
        goto done;
    }

    if ((err = pstm_copy(&x, &R->x)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_copy(&y, &R->y)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_copy(&z, &R->z)) != PS_SUCCESS)
    {
        goto done;
    }

    err = PS_SUCCESS;

done:
    pstm_clear(&z);
ERR_Y:
    pstm_clear(&y);
ERR_X:
    pstm_clear(&x);
ERR_T2:
    pstm_clear(&t2);
ERR_T1:
    pstm_clear(&t1);
    if (paD)
    {
        psFree(paD, pool);
    }
    return err;
}


/******************************************************************************/
/**
    Double an ECC point
    @param[in] P The point to double
    @param[out] R The destination of the double
    @param[in] modulus The modulus of the field the ECC curve is in
    @param[in] mp The "b" value from montgomery_setup()
    @param[in] A The "A" of the field the ECC curve is in
    @return PS_SUCCESS on success
 */
static int32_t eccProjectiveDblPoint(psPool_t *pool, const psEccPoint_t *P,
    psEccPoint_t *R, const pstm_int *modulus, const pstm_digit *mp,
    const pstm_int *A)
{
    pstm_int t1, t2;
    pstm_digit *paD;
    uint32 paDlen;
    int32 err, initSize;


    if (P != R)
    {
        if (pstm_copy(&P->x, &R->x) < 0)
        {
            return PS_MEM_FAIL;
        }
        if (pstm_copy(&P->y, &R->y) < 0)
        {
            return PS_MEM_FAIL;
        }
        if (pstm_copy(&P->z, &R->z) < 0)
        {
            return PS_MEM_FAIL;
        }
    }

    initSize = R->x.used;
    if (R->y.used > initSize)
    {
        initSize = R->y.used;
    }
    if (R->z.used > initSize)
    {
        initSize = R->z.used;
    }

    if (pstm_init_size(pool, &t1, (initSize * 2) + 1) < 0)
    {
        return PS_MEM_FAIL;
    }
    if (pstm_init_size(pool, &t2, (initSize * 2) + 1) < 0)
    {
        pstm_clear(&t1);
        return PS_MEM_FAIL;
    }

/*
    Pre-allocated digit.  Used for mul, sqr, AND reduce*/
    paDlen = (modulus->used * 2 + 1) * sizeof(pstm_digit);
    if ((paD = psMalloc(pool, paDlen)) == NULL)
    {
        err = PS_MEM_FAIL;
        goto done;
    }

    /* t1 = Z * Z */
    if ((err = pstm_sqr_comba(pool, &R->z, &t1, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* Z = Y * Z */
    if ((err = pstm_mul_comba(pool, &R->z, &R->y, &R->z, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &R->z, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* Z = 2Z */
    if ((err = pstm_add(&R->z, &R->z, &R->z)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp(&R->z, modulus) != PSTM_LT)
    {
        if ((err = pstm_sub(&R->z, modulus, &R->z)) != PS_SUCCESS)
        {
            goto done;
        }
    }

    /* compute into T1  M=3(X+Z^2)(X-Z^2) */
    if (A == NULL)
    {
        /* T2 = X - T1 */
        if ((err = pstm_sub(&R->x, &t1, &t2)) != PS_SUCCESS)
        {
            goto done;
        }
        if (pstm_cmp_d(&t2, 0) == PSTM_LT)
        {
            if ((err = pstm_add(&t2, modulus, &t2)) != PS_SUCCESS)
            {
                goto done;
            }
        }
        /* T1 = X + T1 */
        if ((err = pstm_add(&t1, &R->x, &t1)) != PS_SUCCESS)
        {
            goto done;
        }
        if (pstm_cmp(&t1, modulus) != PSTM_LT)
        {
            if ((err = pstm_sub(&t1, modulus, &t1)) != PS_SUCCESS)
            {
                goto done;
            }
        }
        /* T2 = T1 * T2 */
        if ((err = pstm_mul_comba(pool, &t1, &t2, &t2, paD, paDlen)) != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_montgomery_reduce(pool, &t2, modulus, *mp, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }
        /* T1 = 2T2 */
        if ((err = pstm_add(&t2, &t2, &t1)) != PS_SUCCESS)
        {
            goto done;
        }
        if (pstm_cmp(&t1, modulus) != PSTM_LT)
        {
            if ((err = pstm_sub(&t1, modulus, &t1)) != PS_SUCCESS)
            {
                goto done;
            }
        }
        /* T1 = T1 + T2 */
        if ((err = pstm_add(&t1, &t2, &t1)) != PS_SUCCESS)
        {
            goto done;
        }
        if (pstm_cmp(&t1, modulus) != PSTM_LT)
        {
            if ((err = pstm_sub(&t1, modulus, &t1)) != PS_SUCCESS)
            {
                goto done;
            }
        }
    }
    else
    {
        /* compute into T1  M=3X^2 + A Z^4 */
        pstm_int t3, t4;

        if (pstm_init_size(pool, &t3, (initSize * 2) + 1) < 0)
        {
            return PS_MEM_FAIL;
        }
        if (pstm_init_size(pool, &t4, (initSize * 2) + 1) < 0)
        {
            pstm_clear(&t3);
            return PS_MEM_FAIL;
        }

        /* T3 = X * X */
        if ((err = pstm_sqr_comba(pool, &R->x, &t3, paD, paDlen)) != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_montgomery_reduce(pool, &t3, modulus, *mp, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }

        /* T4 = 2T3 */
        if ((err = pstm_add(&t3, &t3, &t4)) != PS_SUCCESS)
        {
            goto done;
        }
        if (pstm_cmp(&t4, modulus) != PSTM_LT)
        {
            if ((err = pstm_sub(&t4, modulus, &t4)) != PS_SUCCESS)
            {
                goto done;
            }
        }

        /* T3 = T3 + T4 */
        if ((err = pstm_add(&t3, &t4, &t3)) != PS_SUCCESS)
        {
            goto done;
        }
        if (pstm_cmp(&t3, modulus) != PSTM_LT)
        {
            if ((err = pstm_sub(&t3, modulus, &t3)) != PS_SUCCESS)
            {
                goto done;
            }
        }

        /* T4 = T1 * T1 */
        if ((err = pstm_sqr_comba(pool, &t1, &t4, paD, paDlen)) != PS_SUCCESS)
        {
            goto done;
        }
        if ((err = pstm_mod(pool, &t4, modulus, &t4)) != PS_SUCCESS)
        {
            goto done;
        }

        /* T4 = T4 * A */
        if ((err = pstm_mul_comba(pool, &t4, A, &t4, paD, paDlen)) != PS_SUCCESS)
        {
            goto done;
        }

        if ((err = pstm_montgomery_reduce(pool, &t4, modulus, *mp, paD, paDlen))
            != PS_SUCCESS)
        {
            goto done;
        }

        /* T1 = T3 + T4 */
        if ((err = pstm_add(&t3, &t4, &t1)) != PS_SUCCESS)
        {
            goto done;
        }
        if (pstm_cmp(&t1, modulus) != PSTM_LT)
        {
            if ((err = pstm_sub(&t1, modulus, &t1)) != PS_SUCCESS)
            {
                goto done;
            }
        }

        pstm_clear_multi(&t3, &t4, NULL, NULL, NULL, NULL, NULL, NULL);
    }

    /* Y = 2Y */
    if ((err = pstm_add(&R->y, &R->y, &R->y)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp(&R->y, modulus) != PSTM_LT)
    {
        if ((err = pstm_sub(&R->y, modulus, &R->y)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* Y = Y * Y */
    if ((err = pstm_sqr_comba(pool, &R->y, &R->y, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &R->y, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* T2 = Y * Y */
    if ((err = pstm_sqr_comba(pool, &R->y, &t2, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &t2, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* T2 = T2/2 */
    if (pstm_isodd(&t2))
    {
        if ((err = pstm_add(&t2, modulus, &t2)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    if ((err = pstm_div_2(&t2, &t2)) != PS_SUCCESS)
    {
        goto done;
    }
    /* Y = Y * X */
    if ((err = pstm_mul_comba(pool, &R->y, &R->x, &R->y, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &R->y, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }

    /* X  = T1 * T1 */
    if ((err = pstm_sqr_comba(pool, &t1, &R->x, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &R->x, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* X = X - Y */
    if ((err = pstm_sub(&R->x, &R->y, &R->x)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&R->x, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&R->x, modulus, &R->x)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* X = X - Y */
    if ((err = pstm_sub(&R->x, &R->y, &R->x)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&R->x, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&R->x, modulus, &R->x)) != PS_SUCCESS)
        {
            goto done;
        }
    }

    /* Y = Y - X */
    if ((err = pstm_sub(&R->y, &R->x, &R->y)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&R->y, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&R->y, modulus, &R->y)) != PS_SUCCESS)
        {
            goto done;
        }
    }
    /* Y = Y * T1 */
    if ((err = pstm_mul_comba(pool, &R->y, &t1, &R->y, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &R->y, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    /* Y = Y - T2 */
    if ((err = pstm_sub(&R->y, &t2, &R->y)) != PS_SUCCESS)
    {
        goto done;
    }
    if (pstm_cmp_d(&R->y, 0) == PSTM_LT)
    {
        if ((err = pstm_add(&R->y, modulus, &R->y)) != PS_SUCCESS)
        {
            goto done;
        }
    }

    err = PS_SUCCESS;
done:
    pstm_clear_multi(&t1, &t2, NULL, NULL, NULL, NULL, NULL, NULL);
    if (paD)
    {
        psFree(paD, pool);
    }
    return err;
}

/******************************************************************************/
/**
    Allocate a new ECC point.
    @return A newly allocated point or NULL on error
 */
static psEccPoint_t *eccNewPoint(psPool_t *pool, short size)
{
    psEccPoint_t *p = NULL;

    p = psMalloc(pool, sizeof(psEccPoint_t));
    if (p == NULL)
    {
        return NULL;
    }
    p->pool = pool;
    if (size == 0)
    {
        if (pstm_init(pool, &p->x) != PSTM_OKAY)
        {
            goto ERR;
        }
        if (pstm_init(pool, &p->y) != PSTM_OKAY)
        {
            goto ERR_X;
        }
        if (pstm_init(pool, &p->z) != PSTM_OKAY)
        {
            goto ERR_Y;
        }
    }
    else
    {
        if (pstm_init_size(pool, &p->x, size) != PSTM_OKAY)
        {
            goto ERR;
        }
        if (pstm_init_size(pool, &p->y, size) != PSTM_OKAY)
        {
            goto ERR_X;
        }
        if (pstm_init_size(pool, &p->z, size) != PSTM_OKAY)
        {
            goto ERR_Y;
        }
    }
    return p;
ERR_Y:
    pstm_clear(&p->y);
ERR_X:
    pstm_clear(&p->x);
ERR:
    psFree(p, pool);
    return NULL;
}

/**
    Free an ECC point from memory.
    @param p   The point to free
 */
static void eccFreePoint(psEccPoint_t *p)
{
    if (p != NULL)
    {
        pstm_clear(&p->x);
        pstm_clear(&p->y);
        pstm_clear(&p->z);
        psFree(p, p->pool);
    }
}

/**
   Map a projective jacbobian point back to affine space
   @param[in,out] P [in/out] The point to map
   @param[in] modulus  The modulus of the field the ECC curve is in
   @param[in] mp       The "b" value from montgomery_setup()
   @return PS_SUCCESS on success
 */
static int32_t eccMap(psPool_t *pool, psEccPoint_t *P, const pstm_int *modulus,
    const pstm_digit *mp)
{
    pstm_int t1, t2;
    pstm_digit *paD;
    int32 err;
    uint32 paDlen;

    if (pstm_init_size(pool, &t1, P->x.alloc) < 0)
    {
        return PS_MEM_FAIL;
    }
    if (pstm_init_size(pool, &t2, P->x.alloc) < 0)
    {
        pstm_clear(&t1);
        return PS_MEM_FAIL;
    }

    /* Pre-allocated digit.  Used for mul, sqr, AND reduce */
    paDlen = (modulus->used * 2 + 1) * sizeof(pstm_digit);
    if ((paD = psMalloc(pool, paDlen)) == NULL)
    {
        err = PS_MEM_FAIL;
        goto done;
    }

    /* first map z back to normal */
    if ((err = pstm_montgomery_reduce(pool, &P->z, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }

    /* get 1/z */
    if ((err = pstm_invmod(pool, &P->z, modulus, &t1)) != PS_SUCCESS)
    {
        goto done;
    }

    /* get 1/z^2 and 1/z^3 */
    if ((err = pstm_sqr_comba(pool, &t1, &t2, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_mod(pool, &t2, modulus, &t2)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_mul_comba(pool, &t1, &t2, &t1, paD, paDlen)) != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_mod(pool, &t1, modulus, &t1)) != PS_SUCCESS)
    {
        goto done;
    }

    /* multiply against x/y */
    if ((err = pstm_mul_comba(pool, &P->x, &t2, &P->x, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &P->x, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_mul_comba(pool, &P->y, &t1, &P->y, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    if ((err = pstm_montgomery_reduce(pool, &P->y, modulus, *mp, paD, paDlen))
        != PS_SUCCESS)
    {
        goto done;
    }
    pstm_set(&P->z, 1);
    err = PS_SUCCESS;
done:
    pstm_clear_multi(&t1, &t2, NULL, NULL, NULL, NULL, NULL, NULL);
    if (paD)
    {
        psFree(paD, pool);
    }
    return err;
}

/******************************************************************************/
/**
    Verify an ECDSA signature.

    @param pool Memory pool
    @param[in] key Public key to use for signature validation
    @param[in] buf Data that is signed by private 'key'
    @param[in] buflen Length in bytes of 'buf'
    @param[in] sig Signature of 'buf' by the private key pair of 'key'
    @param[in] siglen Length in bytes of 'sig'
    @param[out] status Result of the signature check. 1 on success, -1 on
        non-matching signature.
    @param usrData Data used by some hardware crypto. Can be NULL.
    @return < 0 on failure. Also 'status'.
 */
int32_t psEccDsaVerify(psPool_t *pool, const psEccKey_t *key,
    const unsigned char *buf, psSize_t buflen,
    const unsigned char *sig, psSize_t siglen,
    int32_t *status, void *usrData)
{
    psEccPoint_t *mG, *mQ;
    pstm_digit mp;
    pstm_int *A = NULL;
    pstm_int v, w, u1, u2, e, p, m, r, s;
    const unsigned char *c, *end;
    int32_t err, radlen;
    psSize_t len;

    /* default to invalid signature */
    *status = -1;

    c = sig;
    end = c + siglen;

    if ((err = getAsnSequence(&c, (uint16_t) (end - c), &len)) < 0)
    {
        psTraceCrypto("ECDSA subject signature parse failure 1\n");
        return err;
    }
    if ((err = pstm_read_asn(pool, &c, (uint16_t) (end - c), &r)) < 0)
    {
        psTraceCrypto("ECDSA subject signature parse failure 2\n");
        return err;
    }
    if ((err = pstm_read_asn(pool, &c, (uint16_t) (end - c), &s)) < 0)
    {
        psTraceCrypto("ECDSA subject signature parse failure 3\n");
        pstm_clear(&r);
        return err;
    }

    /* allocate ints */
    radlen = key->curve->size * 2;
    if (pstm_init_for_read_unsigned_bin(pool, &p, key->curve->size) < 0)
    {
        pstm_clear(&s);
        pstm_clear(&r);
        return PS_MEM_FAIL;
    }
    err = PS_MEM_FAIL;
    if (pstm_init_for_read_unsigned_bin(pool, &m, key->curve->size) < 0)
    {
        goto LBL_P;
    }
    if (pstm_init_size(pool, &v, key->pubkey.x.alloc) < 0)
    {
        goto LBL_M;
    }
    if (pstm_init_size(pool, &w, s.alloc) < 0)
    {
        goto LBL_V;
    }
    /* Shouldn't have signed more data than the key length.  Truncate if so */
    if (buflen > key->curve->size)
    {
        buflen = key->curve->size;
    }
    if (pstm_init_for_read_unsigned_bin(pool, &e, buflen) < 0)
    {
        goto LBL_W;
    }
    if (pstm_init_size(pool, &u1, e.alloc + w.alloc) < 0)
    {
        goto LBL_E;
    }
    if (pstm_init_size(pool, &u2, r.alloc + w.alloc) < 0)
    {
        goto LBL_U1;
    }

    /* allocate points */
    if ((mG = eccNewPoint(pool, key->pubkey.x.alloc * 2)) == NULL)
    {
        goto LBL_U2;
    }
    if ((mQ = eccNewPoint(pool, key->pubkey.x.alloc * 2)) == NULL)
    {
        goto LBL_MG;
    }

    /* get the order */
    if ((err = pstm_read_radix(pool, &p, key->curve->order, radlen, 16))
        != PS_SUCCESS)
    {
        goto error;
    }

    /* get the modulus */
    if ((err = pstm_read_radix(pool, &m, key->curve->prime, radlen, 16))
        != PS_SUCCESS)
    {
        goto error;
    }

    /* check for zero */
    if (pstm_iszero(&r) || pstm_iszero(&s) || pstm_cmp(&r, &p) != PSTM_LT ||
        pstm_cmp(&s, &p) != PSTM_LT)
    {
        err = PS_PARSE_FAIL;
        goto error;
    }

    /* read data */
    if ((err = pstm_read_unsigned_bin(&e, buf, buflen)) != PS_SUCCESS)
    {
        goto error;
    }

    /*  w  = s^-1 mod n */
    if ((err = pstm_invmod(pool, &s, &p, &w)) != PS_SUCCESS)
    {
        goto error;
    }

    /* u1 = ew */
    if ((err = pstm_mulmod(pool, &e, &w, &p, &u1)) != PS_SUCCESS)
    {
        goto error;
    }

    /* u2 = rw */
    if ((err = pstm_mulmod(pool, &r, &w, &p, &u2)) != PS_SUCCESS)
    {
        goto error;
    }

    /* find mG and mQ */
    if ((err = pstm_read_radix(pool, &mG->x, key->curve->Gx, radlen, 16))
        != PS_SUCCESS)
    {
        goto error;
    }
    if ((err = pstm_read_radix(pool, &mG->y, key->curve->Gy, radlen, 16))
        != PS_SUCCESS)
    {
        goto error;
    }
    pstm_set(&mG->z, 1);

    if ((err = pstm_copy(&key->pubkey.x, &mQ->x)) != PS_SUCCESS)
    {
        goto error;
    }
    if ((err = pstm_copy(&key->pubkey.y, &mQ->y)) != PS_SUCCESS)
    {
        goto error;
    }
    if ((err = pstm_copy(&key->pubkey.z, &mQ->z)) != PS_SUCCESS)
    {
        goto error;
    }

    if (key->curve->isOptimized == 0)
    {
        if ((A = psMalloc(pool, sizeof(pstm_int))) == NULL)
        {
            goto error;
        }

        if (pstm_init_for_read_unsigned_bin(pool, A, key->curve->size) < 0)
        {
            goto error;
        }

        if ((err = pstm_read_radix(pool, A, key->curve->A,
                 key->curve->size * 2, 16))
            != PS_SUCCESS)
        {
            goto error;
        }
    }

    /* compute u1*mG + u2*mQ = mG */
    if ((err = eccMulmod(pool, &u1, mG, mG, &m, 0, A)) != PS_SUCCESS)
    {
        goto error;
    }
    if ((err = eccMulmod(pool, &u2, mQ, mQ, &m, 0, A)) != PS_SUCCESS)
    {
        goto error;
    }

    /* find the montgomery mp */
    if ((err = pstm_montgomery_setup(&m, &mp)) != PS_SUCCESS)
    {
        goto error;
    }

    /* add them */
    if ((err = eccProjectiveAddPoint(pool, mQ, mG, mG, &m, &mp, A)) != PS_SUCCESS)
    {
        goto error;
    }

    /* reduce */
    if ((err = eccMap(pool, mG, &m, &mp)) != PS_SUCCESS)
    {
        goto error;
    }

    /* v = X_x1 mod n */
    if ((err = pstm_mod(pool, &mG->x, &p, &v)) != PS_SUCCESS)
    {
        goto error;
    }

    /* does v == r */
    if (pstm_cmp(&v, &r) == PSTM_EQ)
    {
        *status = 1;
    }

    /* clear up and return */
    err = PS_SUCCESS;

error:
    if (A)
    {
        pstm_clear(A);
        psFree(A, pool);
    }

    eccFreePoint(mQ);
LBL_MG:
    eccFreePoint(mG);
LBL_U2:
    pstm_clear(&u2);
LBL_U1:
    pstm_clear(&u1);
LBL_E:
    pstm_clear(&e);
LBL_W:
    pstm_clear(&w);
LBL_V:
    pstm_clear(&v);
LBL_M:
    pstm_clear(&m);
LBL_P:
    pstm_clear(&p);
    pstm_clear(&s);
    pstm_clear(&r);
    return err;
}

/**
    Sign a message digest.
    @param pool Memory pool
    @param[in] key Private ECC key
    @param[in] in The data to sign
    @param[in] inlen The length in bytes of 'in'
    @param[out] out The destination for the signature
    @param[in,out] outlen The max size and resulting size of the signature
    @param[in] includeSize Pass 1 to include size prefix in output.
    @param usrData Implementation specific data. Can pass NULL.
    @return PS_SUCCESS if successful

    @note TLS does use the size prefix in output.
 */
int32_t psEccDsaSign(psPool_t *pool, const psEccKey_t *privKey,
    const unsigned char *buf, psSize_t buflen,
    unsigned char *sig, psSize_t *siglen,
    uint8_t includeSize, void *usrData)
{
    psEccKey_t pubKey;      /* @note Large on the stack */
    pstm_int r, s;

    pstm_int e, p;
    psSize_t radlen;
    int32_t err = PS_MEM_FAIL;
    psSize_t olen, rLen, sLen;
    uint32_t rflag, sflag, sanity;

    rflag = sflag = 0;

    /* is this a private key? */
    if (privKey->type != PS_PRIVKEY)
    {
        return PS_ARG_FAIL;
    }

    /* Can't sign more data than the key length.  Truncate if so */
    if (buflen > privKey->curve->size)
    {
        buflen = privKey->curve->size;
    }

    radlen = privKey->curve->size * 2;
    if (pstm_init_for_read_unsigned_bin(pool, &p, privKey->curve->size) < 0)
    {
        return PS_MEM_FAIL;
    }
    if (pstm_init_for_read_unsigned_bin(pool, &e, buflen) < 0)
    {
        goto LBL_P;
    }
    if (pstm_init_size(pool, &r, p.alloc) < 0)
    {
        goto LBL_E;
    }
    if (pstm_init_size(pool, &s, p.alloc) < 0)
    {
        goto LBL_R;
    }

    if ((err = pstm_read_radix(pool, &p, privKey->curve->order, radlen,
             16)) != PS_SUCCESS)
    {
        goto errnokey;
    }
    if ((err = pstm_read_unsigned_bin(&e, buf, buflen)) != PS_SUCCESS)
    {
        goto errnokey;
    }

    /* make up a key and export the public copy */
    sanity = 0;
    for (;; )
    {
        if (sanity++ > 99)
        {
            psTraceCrypto("ECC Signature sanity exceeded. Verify PRNG output.\n");
            err = PS_PLATFORM_FAIL; /* possible problem with prng */
            goto errnokey;
        }
        if ((err = psEccGenKey(pool, &pubKey, privKey->curve, usrData))
            != PS_SUCCESS)
        {
            goto errnokey;
        }
        /* find r = x1 mod n */
        if ((err = pstm_mod(pool, &pubKey.pubkey.x, &p, &r)) != PS_SUCCESS)
        {
            goto error;
        }

        if (pstm_iszero(&r) == PS_TRUE)
        {
            psEccClearKey(&pubKey);
        }
        else
        {
            /* find s = (e + xr)/k */
            if ((err = pstm_invmod(pool, &pubKey.k, &p, &pubKey.k)) !=
                PS_SUCCESS)
            {
                goto error; /* k = 1/k */
            }
            if ((err = pstm_mulmod(pool, &privKey->k, &r, &p, &s))
                != PS_SUCCESS)
            {
                goto error; /* s = xr */
            }
            if ((err = pstm_add(&e, &s, &s)) != PS_SUCCESS)
            {
                goto error;  /* s = e +  xr */
            }
            if ((err = pstm_mod(pool, &s, &p, &s)) != PS_SUCCESS)
            {
                goto error; /* s = e +  xr */
            }
            if ((err = pstm_mulmod(pool, &s, &pubKey.k, &p, &s))
                != PS_SUCCESS)
            {
                goto error; /* s = (e + xr)/k */
            }
            psEccClearKey(&pubKey);

            rLen = pstm_unsigned_bin_size(&r);
            sLen = pstm_unsigned_bin_size(&s);

            /* Signatures can be smaller than the keysize but keep it sane */
            if (((rLen + 6) >= privKey->curve->size) &&
                ((sLen + 6) >= privKey->curve->size))
            {
                if (pstm_iszero(&s) == PS_FALSE)
                {
                    break;
                }
            }
        }
    }

    /* If r or s has the high bit set, the ASN.1 encoding should include
        a leading 0x0 byte to prevent it from being "negative". */
    /* We check high bit by checking if number of bits is multiple of 8. */
    rflag = (pstm_count_bits(&r) & 7) == 0;
    sflag = (pstm_count_bits(&s) & 7) == 0;
    rLen += rflag;
    sLen += sflag;
    olen = 6 + rLen + sLen;

    /* Handle lengths longer than 128.. but still only handling up to 256 */
    if (olen - 3 >= 128)
    {
        olen++;
    }

    /* TLS uses a two byte length specifier.  Others sometimes do not */
    if (includeSize)
    {
        if (olen + 2 > *siglen)
        {
            err = -1;
            goto errnokey;
        }

        *sig = olen >> 8 & 0xFF; sig++;
        *sig = olen & 0xFF; sig++;
    }
    else
    {
        if (olen > *siglen)
        {
            err = -1;
            goto errnokey;
        }
    }

    *sig = ASN_CONSTRUCTED | ASN_SEQUENCE; sig++;

    if ((olen - 3) >= 128)
    {
        *sig = 0x81; sig++; /* high bit to indicate 'long' and low for byte count */
        *sig = (olen & 0xFF) - 3; sig++;
        *siglen = 1;
    }
    else
    {
        *sig = (olen & 0xFF) - 2; sig++;
        *siglen = 0;
    }
    *sig = ASN_INTEGER; sig++;
    *sig = rLen & 0xFF; sig++;
    if (includeSize)
    {
        *siglen += 6;
    }
    else
    {
        *siglen += 4;
    }
    if (rflag)
    {
        *sig = 0x0; sig++;
    }
    if ((err = pstm_to_unsigned_bin(pool, &r, sig)) != PSTM_OKAY)
    {
        goto errnokey;
    }
    sig += rLen - rflag;  /* Moved forward rflag already */
    *siglen += rLen;
    *sig = ASN_INTEGER; sig++;
    *sig = sLen & 0xFF; sig++;
    if (sflag)
    {
        *sig = 0x0; sig++;
    }
    if ((err = pstm_to_unsigned_bin(pool, &s, sig)) != PSTM_OKAY)
    {
        goto errnokey;
    }
    *siglen += sLen + 2;
    err = PS_SUCCESS;
    goto errnokey;

error:
    psEccClearKey(&pubKey);
errnokey:
    pstm_clear(&s);
LBL_R:
    pstm_clear(&r);
LBL_E:
    pstm_clear(&e);
LBL_P:
    pstm_clear(&p);
    return err;
}

#endif  /* USE_MATRIX_ECC */

