/**
 *      @file    pubkey.h
 *      @version $Format:%h%d$
 *
 *      Public and Private key header.
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

#ifndef _h_PS_PUBKEY
# define _h_PS_PUBKEY

/******************************************************************************/

# include "pubkey_matrix.h"
# ifdef USE_OPENSSL_CRYPTO
#  include "pubkey_openssl.h"
# endif

/******************************************************************************/

# ifdef USE_RSA
/**
    The included pubkey_* header must define:
        typedef ... psRsaKey_t;
    and
        PS_RSA_STATIC_INIT
 */
#  ifndef PS_RSA_STATIC_INIT
#   define PS_RSA_STATIC_INIT  { .size = NULL }
#  endif

# endif  /* USE_RSA */

/******************************************************************************/

# ifdef USE_ECC

#  define ECC_MAXSIZE 132 /* max private key size */

/* NOTE: In MatrixSSL usage, the ecFlags are 24 bits only */
#  define IS_SECP192R1    0x00000001
#  define IS_SECP224R1    0x00000002
#  define IS_SECP256R1    0x00000004
#  define IS_SECP384R1    0x00000008
#  define IS_SECP521R1    0x00000010
/* WARNING: Public points on Brainpool curves are not validated */
#  define IS_BRAIN224R1   0x00010000
#  define IS_BRAIN256R1   0x00020000
#  define IS_BRAIN384R1   0x00040000
#  define IS_BRAIN512R1   0x00080000
/* TLS needs one bit of info (last bit) */
#  define IS_RECVD_EXT    0x00800000

/**
    @see https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
 */
enum
{
    IANA_SECP192R1 = 19,
    IANA_SECP224R1 = 21,
    IANA_SECP256R1 = 23,
    IANA_SECP384R1,
    IANA_SECP521R1,
    IANA_BRAIN256R1,
    IANA_BRAIN384R1,
    IANA_BRAIN512R1,

    IANA_BRAIN224R1 = 255 /**< @note this is not defined by IANA */
};

/**
    @see ANSI X9.62 or X9.63
 */
enum
{
    ANSI_INFINITY = 0,
    ANSI_COMPRESSED0 = 2,
    ANSI_COMPRESSED1,
    ANSI_UNCOMPRESSED,
    ANSI_HYBRID0 = 6,
    ANSI_HYBRID1
};

/**
    The included pubkey_* header must define the following.
        typedef ... psEccCurve_t;
        typedef ... psEccPoint_t;
        typedef ... psEccKey_t;
    and
        PS_ECC_STATIC_INIT
    and implement the following functions.
 */
#  ifndef PS_ECC_STATIC_INIT
#   define PS_ECC_STATIC_INIT  { .type = 0 }
#  endif
extern void psGetEccCurveIdList(unsigned char *curveList, uint8_t *len);
extern void userSuppliedEccList(unsigned char *curveList, uint8_t *len,
                                uint32_t curves);
extern uint32_t compiledInEcFlags(void);
extern int32_t getEcPubKey(psPool_t * pool, const unsigned char **pp, psSize_t len,
                           psEccKey_t * pubKey, unsigned char sha1KeyHash[SHA1_HASH_SIZE]);

extern int32_t getEccParamById(psCurve16_t curveId, const psEccCurve_t **curve);
extern int32_t getEccParamByName(const char *curveName,
                                 const psEccCurve_t **curve);
extern int32_t getEccParamByOid(uint32_t oid, const psEccCurve_t **curve);

# endif

/******************************************************************************/

# ifdef USE_DH
/**
    The included pubkey_* header must define:
        typedef ... psDhParams_t;
        typedef ... psDhKey_t;
    and
        PS_DH_STATIC_INIT
 */
#  ifndef PS_DH_STATIC_INIT
#   define PS_DH_STATIC_INIT  { .type = 0 }
#  endif

# endif

/******************************************************************************/

/** Public or private key */
enum PACKED
{
    PS_PUBKEY = 1,
    PS_PRIVKEY
};

/** Public Key types for psPubKey_t */
enum PACKED
{
    PS_NOKEY = 0,
    PS_RSA,
    PS_DSA,
    PS_ECC,
    PS_DH,
    PS_CL_PK /* A public key for CL Library. May contain any key format. */
};

/** Signature types */
enum PACKED
{
    RSA_TYPE_SIG = 5,
    ECDSA_TYPE_SIG,
    RSAPSS_TYPE_SIG,
    DSA_TYPE_SIG
};

/**
    Univeral public key type.
    The pubKey name comes from the generic public-key crypto terminology and
    does not mean these key are restricted to the public side only. These
    may be private keys.
 */
typedef struct
{
# if defined(USE_RSA) || defined(USE_ECC)
    union
    {
#  ifdef USE_RSA
        psRsaKey_t rsa;
#  endif
#  ifdef USE_ECC
        psEccKey_t ecc;
#  endif
#  ifdef USE_DH
        psDhKey_t dh;
#  endif
    }               key;
# endif
    psPool_t *pool;
    psSize_t keysize;           /* in bytes. 512 max for RSA 4096 */
    uint8_t type;               /* PS_RSA, PS_ECC, PS_DH */
} psPubKey_t;

extern int32_t pkcs1Pad(const unsigned char *in, psSize_t inlen,
                        unsigned char *out, psSize_t outlen,
                        uint8_t cryptType, void *userPtr);
extern int32_t pkcs1Unpad(const unsigned char *in, psSize_t inlen,
                          unsigned char *out, psSize_t outlen,
                          uint8_t decryptType);

# if defined(USE_RSA) || defined(USE_ECC)

int32_t psHashLenToSigAlg(psSize_t hash_len,
                          uint8_t key_type);

/*
    Hash some data for signature generation or verification
    purposes.

    Compute a digest that is to be signed or whose signature is
    to be verified.
 */
psRes_t psComputeHashForSig(const unsigned char *dataBegin,
                            psSizeL_t dataLen,
                            int32_t signatureAlgorithm,
                            unsigned char hashOut[SHA512_HASH_SIZE],
                            psSize_t * hashOutLen);

/*
    Struct for passing additional options to psVerifySig.
 */
typedef struct
{
    uint32 flags;
} psVerifySigOptions_t;

/*
    Verify the signature of a digest.
 */
psRes_t psVerifySig(psPool_t *pool,
                    const unsigned char hashIn[SHA512_HASH_SIZE],
                    psSize_t hashInLen,
                    const unsigned char *sig,
                    psSize_t sigLen,
                    psPubKey_t *key,
                    int32_t signatureAlgorithm,
                    psBool_t *verifyResult,
                    psVerifySigOptions_t *opts);

/*
    Hash some data _and_ verify the signature of the resulting
    digest.
 */
psRes_t psHashDataAndVerifySig(psPool_t *pool,
                               const unsigned char *dataBegin,
                               psSizeL_t dataLen,
                               const unsigned char *sig,
                               psSize_t sigLen,
                               psPubKey_t *key,
                               int32_t signatureAlgorithm,
                               psBool_t *verifyResult,
                               psVerifySigOptions_t *opts);
# endif
/******************************************************************************/

#endif /* _h_PS_PUBKEY */

