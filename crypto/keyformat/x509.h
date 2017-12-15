/**
 *      @file    x509.h
 *      @version $Format:%h%d$
 *
 *      X.509 header.
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

#ifndef _h_PS_X509
# define _h_PS_X509

# ifdef USE_X509

/******************************************************************************/

/* ClientCertificateType */
enum
{
    RSA_SIGN = 1,
    DSS_SIGN,
    RSA_FIXED_DH,
    DSS_FIXED_DH,
    ECDSA_SIGN = 64,
    RSA_FIXED_ECDH,
    ECDSA_FIXED_ECDH
};

/* The default value of allowed mismatch in times in X.509 messages and the
   local clock. The default value of 24 hours is mostly equivalent to old
   MatrixSSL behavior of ignoring hours, minutes and seconds in X.509 date
   comparison. Note: There is different value for CRL (PS_CRL_TIME_LINGER) and OCSP
   (PS_OCSP_TIME_LINGER). */
#  define PS_X509_TIME_LINGER (24 * 60 * 60)
/* This is approximately equivalent to old MatrixSSL behavior of
   only comparing date. */
#  define PS_CRL_TIME_LINGER (24 * 60 * 60)

/* Parsing flags */
#  define CERT_STORE_UNPARSED_BUFFER  0x1
#  define CERT_STORE_DN_BUFFER        0x2
/** Allow parsing of a certificate bundle (a concatenated PEM file
    or a DER stream) to succeed even when some certs could not be
    supported by MatrixSSL. */
#  define CERT_ALLOW_BUNDLE_PARTIAL_PARSE 0x4

#  ifdef USE_CERT_PARSE

/* Per specification, any critical extension in an X.509 cert should cause
    the connection to fail. SECURITY - Uncomment at your own risk */
/* #define ALLOW_UNKNOWN_CRITICAL_EXTENSIONS */

/* Support for multiple organizational units */
typedef struct x509OrgUnit
{
    struct x509OrgUnit *next;
    char *name;
    short type;
    psSize_t len;
} x509OrgUnit_t;

/* Support for multiple domainComponents */
typedef struct x509DomainComponent
{
    struct x509DomainComponent *next;
    char *name;
    short type;
    psSize_t len;
} x509DomainComponent_t;

/* Number of null-bytes to terminate parsed string-type DN attributes with. */
#   define DN_NUM_TERMINATING_NULLS 2

/*
    DN attributes are used outside the X509 area for cert requests,
    which have been included in the RSA portions of the code
 */
typedef struct
{
    /* MUST support according to RFC 5280: */
    char *country;
    char *organization;
    x509OrgUnit_t *orgUnit;
    char *dnQualifier;
    char *serialNumber;
    char *state;
    char *commonName;
    x509DomainComponent_t *domainComponent;
#   ifdef USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD
    char *locality;
    char *title;
    char *surname;
    char *givenName;
    char *initials;
    char *pseudonym;
    char *generationQualifier;
#   endif /* USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD */
#   ifdef USE_EXTRA_DN_ATTRIBUTES
    char *streetAddress;
    char *postalAddress;
    char *telephoneNumber;
    char *uid;
    char *name;
    char *email;
#   endif /* USE_EXTRA_DN_ATTRIBUTES */
    char hash[MAX_HASH_SIZE];
    char *dnenc;      /* CERT_STORE_DN_BUFFER */
    psSize_t dnencLen;
    /* MUST support according to RFC 5280: */
    short countryType;
    psSize_t countryLen;
    short stateType;
    psSize_t stateLen;
    short organizationType;
    psSize_t organizationLen;
    short dnQualifierType;
    psSize_t dnQualifierLen;
    short commonNameType;
    psSize_t commonNameLen;
    short serialNumberType;
    psSize_t serialNumberLen;
    short domainComponentType;
    psSize_t domainComponentLen;
#   ifdef USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD
    short localityType;
    psSize_t localityLen;
    short titleType;
    psSize_t titleLen;
    short surnameType;
    psSize_t surnameLen;
    short givenNameType;
    psSize_t givenNameLen;
    short initialsType;
    psSize_t initialsLen;
    short pseudonymType;
    psSize_t pseudonymLen;
    short generationQualifierType;
    psSize_t generationQualifierLen;
#   endif /* USE_EXTRA_DN_ATTRIBUTES_RFC5280_SHOULD */
#   ifdef USE_EXTRA_DN_ATTRIBUTES
    short streetAddressType;
    psSize_t streetAddressLen;
    short postalAddressType;
    psSize_t postalAddressLen;
    short telephoneNumberType;
    psSize_t telephoneNumberLen;
    short uidType;
    psSize_t uidLen;
    short nameType;
    psSize_t nameLen;
    short emailType;
    psSize_t emailLen;
#   endif /* USE_EXTRA_DN_ATTRIBUTES */

} x509DNattributes_t;

typedef enum
{
    CA_FALSE = 0,
    CA_UNDEFINED = 127,
    CA_TRUE = 255
} x509bcCAValue_t;

typedef struct
{
    x509bcCAValue_t cA;
    int32 pathLenConstraint;
} x509extBasicConstraints_t;

typedef enum
{
    GN_OTHER = 0,   /* OtherName */
    GN_EMAIL,       /* IA5String */
    GN_DNS,         /* IA5String */
    GN_X400,        /* ORAddress */
    GN_DIR,         /* Name */
    GN_EDI,         /* EDIPartyName */
    GN_URI,         /* IA5String */
    GN_IP,          /* OCTET STRING */
    GN_REGID        /* OBJECT IDENTIFIER */
} x509GeneralNameType_t;

typedef struct psGeneralNameEntry
{
    psPool_t *pool;
    x509GeneralNameType_t id;
    unsigned char name[16];
    unsigned char *oid;                   /* SubjectAltName OtherName */
    unsigned char *data;
    psSize_t oidLen;
    uint8_t oidHasTagLenPrefix;
    psSize_t dataLen;
    struct psGeneralNameEntry *next;
} x509GeneralName_t;

#   define MAX_POLICY_ATTRIB_LEN 512
#   define MAX_NUM_QUAL_INFOS 10
#   define MAX_POLICIES 10
#   define MAX_UNOTICE_NUMBERS 5

typedef struct
{
    unsigned char *id;
    psSize_t len;
} x509extSubjectKeyId_t;

typedef struct
{
    unsigned char *keyId;
    unsigned char *serialNum;
    x509DNattributes_t attribs;
    psSize_t keyLen;
    psSize_t serialNumLen;
} x509extAuthKeyId_t;

#   if defined(USE_FULL_CERT_PARSE) || defined(USE_CERT_GEN)
typedef struct
{
    x509GeneralName_t *permitted;
    x509GeneralName_t *excluded;
} x509nameConstraints_t;

typedef struct x509PolicyQualifierInfo_t
{
    char *cps;
    char *unoticeOrganization;
    char *unoticeExplicitText;
    int32_t unoticeNumbers[MAX_UNOTICE_NUMBERS];
    psSize_t cpsLen;
    psSize_t unoticeOrganizationLen;
    psSize_t unoticeExplicitTextLen;
    psSize_t unoticeNumbersLen;
    int unoticeExplicitTextEncoding;
    int unoticeOrganizationEncoding;
    struct x509PolicyQualifierInfo_t *next;
} x509PolicyQualifierInfo_t;

typedef struct x509PolicyInformation_t
{
    uint32_t *policyOid;
    psSize_t policyOidLen;
    x509PolicyQualifierInfo_t *qualifiers;
    struct x509PolicyInformation_t *next;
} x509PolicyInformation_t;

typedef struct x509certificatePolicies_t
{
    x509PolicyInformation_t *policy;
} x509certificatePolicies_t;

typedef struct x509policyConstraints_t
{
    int32_t requireExplicitPolicy;
    int32_t inhibitPolicyMappings;
} x509policyConstraints_t;

typedef struct x509policyMappings_t
{
    uint32_t *issuerDomainPolicy;
    uint32_t *subjectDomainPolicy;
    psSize_t issuerDomainPolicyLen;
    psSize_t subjectDomainPolicyLen;
    struct x509policyMappings_t *next;
} x509policyMappings_t;

typedef struct x509authorityInfoAccess_t
{
    char *ocsp;
    char *caIssuers;
    psSize_t ocspLen;
    psSize_t caIssuersLen;
    struct x509authorityInfoAccess_t *next;
} x509authorityInfoAccess_t;

typedef struct x509netscapeComment_t
{
    char *comment;
    psSize_t commentLen;
} x509netscapeComment_t;

#   endif /* USE_FULL_CERT_PARSE || USE_CERT_GEN */

/******************************************************************************/
/*
    OID parsing and lookup.
 */

/*
    X.509 Certificate Extension OIDs
    @see https://tools.ietf.org/html/rfc5280#section-4.2

    id-ce   OBJECT IDENTIFIER ::=  { joint-iso-ccitt(2) ds(5) 29 }

    id-ce-authorityKeyIdentifier        OBJECT IDENTIFIER ::=  { id-ce 35 }
    id-ce-subjectKeyIdentifier          OBJECT IDENTIFIER ::=  { id-ce 14 }
    id-ce-keyUsage                                      OBJECT IDENTIFIER ::=  { id-ce 15 }
    id-ce-certificatePolicies           OBJECT IDENTIFIER ::=  { id-ce 32 }
    id-ce-policyMappings                        OBJECT IDENTIFIER ::=  { id-ce 33 }
    id-ce-subjectAltName                        OBJECT IDENTIFIER ::=  { id-ce 17 }
    id-ce-issuerAltName                         OBJECT IDENTIFIER ::=  { id-ce 18 }
    id-ce-subjectDirectoryAttributes OBJECT IDENTIFIER ::= { id-ce  9 }
    id-ce-basicConstraints                      OBJECT IDENTIFIER ::=  { id-ce 19 }
    id-ce-nameConstraints                       OBJECT IDENTIFIER ::=  { id-ce 30 }
    id-ce-policyConstraints                     OBJECT IDENTIFIER ::=  { id-ce 36 }
    id-ce-extKeyUsage                           OBJECT IDENTIFIER ::=  { id-ce 37 }
    id-ce-cRLDistributionPoints         OBJECT IDENTIFIER ::=  { id-ce 31 }
    id-ce-inhibitAnyPolicy                      OBJECT IDENTIFIER ::=  { id-ce 54 }
    id-ce-freshestCRL                           OBJECT IDENTIFIER ::=  { id-ce 46 }
 */
#   define id_ce  2, 5, 29
enum
{
    id_ce_authorityKeyIdentifier = 35,
    id_ce_subjectKeyIdentifier = 14,
    id_ce_keyUsage = 15,
    id_ce_certificatePolicies = 32,
    id_ce_policyMappings = 33,
    id_ce_subjectAltName = 17,
    id_ce_issuerAltName = 18,
    id_ce_subjectDirectoryAttributes = 9,
    id_ce_basicConstraints = 19,
    id_ce_cRLNumber = 20,
    id_ce_issuingDistributionPoint = 28,
    id_ce_nameConstraints = 30,
    id_ce_policyConstraints = 36,
    id_ce_extKeyUsage = 37,
    id_ce_cRLDistributionPoints = 31,
    id_ce_inhibitAnyPolicy = 54,
    id_ce_freshestCRL = 46,
};

/*      id-pkix OBJECT IDENTIFIER  ::= {
        iso(1) identified-organization(3) dod(6) internet(1)
        security(5) mechanisms(5) pkix(7) }
 */
#   define id_pxix 1, 3, 6, 1, 5, 5, 7

/*   anyPolicy OBJECT IDENTIFIER ::= { id-ce-certificate-policies 0 } */
#   define id_anyPolicy 2, 5, 29, 32, 0

/*
   The following key usage purposes are defined:

   anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }

   id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }

   id_kp_serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
   -- TLS WWW server authentication
   -- Key usage bits that may be consistent: digitalSignature,
   -- keyEncipherment or keyAgreement

   id_kp_clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
   -- TLS WWW client authentication
   -- Key usage bits that may be consistent: digitalSignature
   -- and/or keyAgreement

   id_kp_codeSigning             OBJECT IDENTIFIER ::= { id-kp 3 }
   -- Signing of downloadable executable code
   -- Key usage bits that may be consistent: digitalSignature

   id_kp_emailProtection         OBJECT IDENTIFIER ::= { id-kp 4 }
   -- Email protection
   -- Key usage bits that may be consistent: digitalSignature,
   -- nonRepudiation, and/or (keyEncipherment or keyAgreement)

   id_kp_timeStamping            OBJECT IDENTIFIER ::= { id-kp 8 }
   -- Binding the hash of an object to a time
   -- Key usage bits that may be consistent: digitalSignature
   -- and/or nonRepudiation

   id_kp_OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
   -- Signing OCSP responses
   -- Key usage bits that may be consistent: digitalSignature
   -- and/or nonRepudiation
 */
#   define id_ce_eku  id_ce, id_ce_extKeyUsage
#   define id_kp  id_pxix, 3
enum
{
    id_ce_eku_anyExtendedKeyUsage = 0,
    id_kp_serverAuth = 1,
    id_kp_clientAuth = 2,
    id_kp_codeSigning = 3,
    id_kp_emailProtection = 4,
    id_kp_timeStamping = 8,
    id_kp_OCSPSigning = 9,
};

/*
   id-ad   id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }

   id-ad-caIssuers OBJECT IDENTIFIER ::= { id-ad 2 }

   id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }
 */
#   define id_ad id_pxix, 48
enum
{
    id_ad_ocsp = 1,
    id_ad_caIssuers = 2
};

/*
    id-pe       OBJECT IDENTIFIER  ::=  { id-pkix 1 }

    id-pe-authorityInfoAccess           OBJECT IDENTIFIER ::= { id-pe  1 }
    id-pe-subjectInfoAccess                     OBJECT IDENTIFIER ::= { id-pe 11 }
 */
#   define id_pe id_pxix, 1
enum
{
    id_pe_authorityInfoAccess = 1,
    id_pe_subjectInfoAccess = 11,
};

/*
   -- policyQualifierIds for Internet policy qualifiers

   id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
   id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
   id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }

   PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
 */
#   define id_qt id_pxix, 2
enum
{
    id_qt_cps = 1,
    id_qt_unotice = 2
};

#   define id_netscape 2, 16, 840, 1, 113730
enum
{
    id_netscape_comment = 13
};

#   define OID_ENUM(A) oid_ ## A
typedef enum
{
    OID_ENUM(0) = 0,
    /* X.509 certificate extensions */
    OID_ENUM(id_ce_authorityKeyIdentifier),
    OID_ENUM(id_ce_subjectKeyIdentifier),
    OID_ENUM(id_ce_keyUsage),
    OID_ENUM(id_ce_certificatePolicies),
    OID_ENUM(id_ce_policyMappings),
    OID_ENUM(id_ce_subjectAltName),
    OID_ENUM(id_ce_issuerAltName),
    OID_ENUM(id_ce_subjectDirectoryAttributes),
    OID_ENUM(id_ce_basicConstraints),
    OID_ENUM(id_ce_nameConstraints),
    OID_ENUM(id_ce_policyConstraints),
    OID_ENUM(id_ce_extKeyUsage),
    OID_ENUM(id_ce_cRLDistributionPoints),
    OID_ENUM(id_ce_cRLNumber),
    OID_ENUM(id_ce_issuingDistributionPoint),
    OID_ENUM(id_ce_inhibitAnyPolicy),
    OID_ENUM(id_ce_freshestCRL),
    OID_ENUM(id_pe_authorityInfoAccess),
    OID_ENUM(id_pe_subjectInfoAccess),
    OID_ENUM(id_netscape_comment),
    /* Extended Key Usage */
    OID_ENUM(id_ce_eku_anyExtendedKeyUsage),
    OID_ENUM(id_kp_serverAuth),
    OID_ENUM(id_kp_clientAuth),
    OID_ENUM(id_kp_codeSigning),
    OID_ENUM(id_kp_emailProtection),
    OID_ENUM(id_kp_timeStamping),
    OID_ENUM(id_kp_OCSPSigning),
    /* Internet policy qualifiers */
    OID_ENUM(id_qt_cps),
    OID_ENUM(id_qt_unotice),
    /* AccessDescriptions. */
    OID_ENUM(id_ad_caIssuers),
    OID_ENUM(id_ad_ocsp),
} oid_e;

/* Make the flag value, given the enum above */
#   define EXT_CRIT_FLAG(A) (unsigned int) (1 << (A))

/* Flags for known keyUsage (first byte) */
#   define KEY_USAGE_DIGITAL_SIGNATURE     0x0080
#   define KEY_USAGE_NON_REPUDIATION       0x0040
#   define KEY_USAGE_KEY_ENCIPHERMENT      0x0020
#   define KEY_USAGE_DATA_ENCIPHERMENT     0x0010
#   define KEY_USAGE_KEY_AGREEMENT         0x0008
#   define KEY_USAGE_KEY_CERT_SIGN         0x0004
#   define KEY_USAGE_CRL_SIGN              0x0002
#   define KEY_USAGE_ENCIPHER_ONLY         0x0001
/* Flags for known keyUsage (second, optional byte) */
#   define KEY_USAGE_DECIPHER_ONLY         0x8000

/* Flags for known extendedKeyUsage */
#   define EXT_KEY_USAGE_ANY               (1 << 0)
#   define EXT_KEY_USAGE_TLS_SERVER_AUTH   (1 << 1)
#   define EXT_KEY_USAGE_TLS_CLIENT_AUTH   (1 << 2)
#   define EXT_KEY_USAGE_CODE_SIGNING      (1 << 3)
#   define EXT_KEY_USAGE_EMAIL_PROTECTION  (1 << 4)
#   define EXT_KEY_USAGE_TIME_STAMPING     (1 << 8)
#   define EXT_KEY_USAGE_OCSP_SIGNING      (1 << 9)

/******************************************************************************/

/* Holds the known extensions we support */
typedef struct
{
    psPool_t *pool;
    x509extBasicConstraints_t bc;
    x509GeneralName_t *san;
    x509GeneralName_t *issuerAltName;
    uint32 critFlags;                           /* EXT_CRIT_FLAG(EXT_KEY_USE) */
    uint32 keyUsageFlags;                       /* KEY_USAGE_ */
    uint32 ekuFlags;                            /* EXT_KEY_USAGE_ */
    x509extSubjectKeyId_t sk;
    x509extAuthKeyId_t ak;
#   if defined(USE_FULL_CERT_PARSE) || defined(USE_CERT_GEN)
    x509nameConstraints_t nameConstraints;
    x509certificatePolicies_t certificatePolicy;
    x509policyConstraints_t policyConstraints;
    x509policyMappings_t *policyMappings;
    x509authorityInfoAccess_t *authorityInfoAccess;
    x509netscapeComment_t *netscapeComment;
#   endif /* USE_FULL_CERT_PARSE || USE_CERT_GEN */
#   ifdef USE_CRL
    x509GeneralName_t *crlDist;
    unsigned char *crlNum;
    int32 crlNumLen;
#   endif /* USE_CRL */
    psDynBuf_t *otherAttributes;
    int32_t refCount;
    void *reserved[3]; /* Allow future extensions with binary compatibility. */
} x509v3extensions_t;

#  endif /* USE_CERT_PARSE */

#  ifdef USE_CRL
typedef struct x509revoked
{
    unsigned char *serial;
    psSize_t serialLen;
    psBrokenDownTime_t revocationDateBDT;
    struct x509revoked *next;
} x509revoked_t;

typedef struct psCRL
{
    psPool_t *pool;
    int32_t authenticated;             /* Has this CRL been authenticated */
    unsigned char sigHash[MAX_HASH_SIZE];
    psSize_t sigHashLen;
    psBrokenDownTime_t thisUpdateBDT;
    psBrokenDownTime_t nextUpdateBDT;
    int32 nextUpdateType;
    char *nextUpdate;           /* Only concerned about expiration */
    int32_t sigAlg;             /* eg OID_SHA1_RSA_SIG */
    unsigned char *sig;
    psSize_t sigLen;
    uint16_t expired;
    x509DNattributes_t issuer;
    x509v3extensions_t extensions;
    x509revoked_t *revoked;
    struct psCRL *next;
} psX509Crl_t;
#  endif

typedef enum
{
    PS_X509_PARSE_SUCCESS = 0,
    /* Below are parse failures */
    PS_X509_PARSE_FAIL,            /* Unspecified parse failure, enable USE_CRYPTO_TRACE */
    PS_X509_WEAK_KEY,              /* RSA/DSA/ECC key size < MIN_*_BITS */
    PS_X509_UNSUPPORTED_VERSION,   /* Version unsupported */
    PS_X509_UNSUPPORTED_ECC_CURVE, /* Cert named curve not found in eccCurve list */
    PS_X509_UNSUPPORTED_SIG_ALG,   /* Unsupported cert algorithm: 1670,32859,32953,517 */
    PS_X509_UNSUPPORTED_KEY_ALG,   /* Unsupported public key algorithm in cert parse: 32969,515 */
    PS_X509_UNSUPPORTED_EXT,       /* Unknown extension */
    PS_X509_DATE,                  /* Validity date check failed */
    PS_X509_MISSING_NAME,          /* Error. Cert has no name information */
    PS_X509_MISSING_RSA,           /* Couldn't get RSA pub key from cert */
    PS_X509_ALG_ID,                /* Couldn't parse algorithm identifier for certAlgorithm */
    PS_X509_ISSUER_DN,             /* Couldn't parse issuer DN attributes */
    PS_X509_SIGNATURE,             /* Couldn't parse signature */
    PS_X509_SUBJECT_DN,            /* Couldn't parse subject DN attributes */
    PS_X509_EOF,                   /* Expecting end of cert */
    PS_X509_SIG_MISMATCH,          /* Parse error: mismatched signature type */
} parse_status_e;

typedef struct psCert
{
    psPool_t *pool;
    parse_status_e parseStatus;
    int32 sigAlgorithm;               /* Certificate sig alg OID */
    int32 certAlgorithm;              /* TBSCertificate sig alg OID */
    unsigned char *signature;
    psSize_t signatureLen;
#  ifdef USE_PKCS1_PSS
    int32 pssHash;               /* RSAPSS sig hash OID */
    int32 maskGen;               /* RSAPSS maskgen OID */
    int32 maskHash;              /* hash OID for MGF1 */
    psSize_t saltLen;            /* RSAPSS salt len param */
#  endif /* USE_PKCS1_PSS */
#  ifdef USE_CERT_PARSE
    psPubKey_t publicKey;
    int32 version;
    unsigned char *serialNumber;
    psSize_t serialNumberLen;
    x509DNattributes_t issuer;
    x509DNattributes_t subject;
    int32 notBeforeTimeType;
    int32 notAfterTimeType;
    char *notBefore;
    char *notAfter;
    int32 pubKeyAlgorithm;               /* public key algorithm OID */
    unsigned char *uniqueIssuerId;
    unsigned char *uniqueSubjectId;
    psSize_t uniqueIssuerIdLen;
    psSize_t uniqueSubjectIdLen;
    x509v3extensions_t extensions;
    int32 authStatus;     /* See psX509AuthenticateCert doc */
    uint32 authFailFlags; /* Flags for extension check failures */
#   ifdef USE_CRL         /* Use for OCSP later as well? */
    int32 revokedStatus;
#   endif
    unsigned char sigHash[MAX_HASH_SIZE];
#  endif /* USE_CERT_PARSE */
#  if defined(USE_OCSP_RESPONSE) || defined(USE_OCSP_REQUEST)
    unsigned char sha1KeyHash[SHA1_HASH_SIZE];
#  endif /* USE_OCSP_RESPONSE || USE_OCSP_REQUEST */
#  ifdef ENABLE_CA_CERT_HASH
    /** @note this is used only by MatrixSSL for Trusted CA Indication extension */
    unsigned char sha1CertHash[SHA1_HASH_SIZE];
#  endif
    unsigned char *unparsedBin;         /* see psX509ParseCertFile */
    psSize_t binLen;
    uint16_t publicKeyDerOffsetIntoUnparsedBin;
    psSize_t publicKeyDerLen;
    uint16_t subjectKeyDerOffsetIntoUnparsedBin;
    struct psCert *next;
} psX509Cert_t;

extern int32_t psX509GetSignature(psPool_t *pool,const unsigned char **pp,
        psSize_t len, unsigned char **sig, psSize_t *sigLen);
#  ifdef USE_CERT_PARSE
extern int32_t psX509GetDNAttributes(psPool_t *pool, const unsigned char **pp,
        psSize_t len, x509DNattributes_t *attribs, uint32_t flags);
extern void psX509FreeDNStruct(x509DNattributes_t *dn, psPool_t *allocPool);
extern int32_t getSerialNum(psPool_t *pool, const unsigned char **pp,
        psSize_t len, unsigned char **sn, psSize_t *snLen);
extern int32_t getExplicitExtensions(psPool_t *pool, const unsigned char **pp,
        psSize_t inlen, int32_t expVal, x509v3extensions_t *extensions,
        uint8_t known);
extern int32_t x509NewExtensions(x509v3extensions_t **extensions,
        psPool_t *pool);
extern void x509FreeExtensions(x509v3extensions_t *extensions);
extern int32_t psX509ValidateGeneralName(const char *n);
extern int32_t validateDateRange(psX509Cert_t *cert);

/** Get the number of organizationalUnits in a distinguished name (DN). */
extern int32_t psX509GetNumOrganizationalUnits(const x509DNattributes_t *DN);

/** Get the number of domainComponents in a distinguished name (DN). */
extern int32_t psX509GetNumDomainComponents(const x509DNattributes_t *DN);

/** Get a pointer to an organizationalUnit.

    Caller must NOT free the returned x509OrgUnit_t.

    @param[in] DN The DN struct from which to fetch the organizationalUnit.
    Note that freeing the DN will invalidate the returned x509OrgUnit_t.
    @param[in] index The index of the organizationalUnit in the order they
    appear in the DER encoding.
 */
extern x509OrgUnit_t *psX509GetOrganizationalUnit(
        const x509DNattributes_t *DN,
        int32_t index);

/** Get a pointer to a domain component.

    Caller must NOT free the returned x509DomainComponent_t.

    @param[in] DN The DN struct from which to fetch the domainComponent.
    Note that freeing the DN will invalidate the returned
    x509DomainComponent_t.
    @param[in] index The index of the domainComponent in the order they
    appear in the DER encoding.
 */
extern x509DomainComponent_t *psX509GetDomainComponent(
        const x509DNattributes_t *DN,
        int32_t index);

/** Get the concatenation of all domainComponents in a DN as a C string.

    This function returns the concanated domainComponents as a string terminated
    with DN_NUM_TERMINATING_NULLS NULL characters. The output string will
    contain     the components in the reverse order compared to the order in which
    they were encoded in the certificate. Usually, this will result in the
    usual print order, i.e. top-level component (.com, .org, ...) last.

    @param[in] DN The DN struct from which to fetch the domainComponent.
    @param[out] out_str The concanated domainComponents as a string. This
    function will malloc a string of suitable length. The caller is responsible
    for freeing it.
    @param[out] out_str_len Length of the returned string.
 */
extern int32_t psX509GetConcatenatedDomainComponent(
        const x509DNattributes_t *DN,
        char **out_str,
        size_t *out_str_len);
#  endif /* USE_CERT_PARSE */

#  ifdef USE_FULL_CERT_PARSE
/** Create a concatenated string containing all the supported fields of a DN
    component.

    This function creates a oneline string from a DN, using a format similar
    to OpenSSL's X509_NAME_oneline(). Only the fields supported by the
    current configuration are printed. Example:
    "C=US, ST=State, DC=com, DC=insidesecure, DC=test/street=street/title=Dr,
    GN=GivenName, SN=Surname/name=GivenName Surname."

    @param[in] DN The DN struct from which to build the oneline string.
    @param[out] out_str Pointer to the memory address where the resulting string
    will be allocated and copied to. Caller is responsible for freeing.
    @param[out] out_str_len Length of the resulting string.
 */
extern int32_t psX509GetOnelineDN(const x509DNattributes_t *DN,
        char **out_str,
        size_t *out_str_len);
#  endif /* USE_FULL_CERT_PARSE */

#  ifdef USE_OCSP_RESPONSE
#   include <time.h>
#   include <stdbool.h>

/* The default value of allowed mismatch in times in OCSP messages and the local
   clock. */
#   define PS_OCSP_TIME_LINGER (120)

/* The OCSP structure members point directly into an OCSPResponse stream.
    They are validated immediately after the parse so if a change request
    requires these fields to persist, this will all have to change */
typedef struct
{
    uint16_t certIdHashAlg;            /* hashAlgorithm in CertID */
    const unsigned char *certIdNameHash;
    const unsigned char *certIdKeyHash;
    const unsigned char *certIdSerial;
    short certIdSerialLen;
    short certStatus;
    unsigned char revocationTime[15];
    unsigned char revocationReason;
    const unsigned char *thisUpdate;
    short thisUpdateLen;
    const unsigned char *nextUpdate;
    short nextUpdateLen;
} psOcspSingleResponse_t;

#   define MAX_OCSP_RESPONSES 3

typedef struct
{
    const unsigned char *responderName;
    const unsigned char *responderKeyHash;
    const unsigned char *timeProduced;
    short timeProducedLen;
    psOcspSingleResponse_t singleResponse[MAX_OCSP_RESPONSES];
    uint16_t sigAlg;
    const unsigned char *sig;
    psSize_t sigLen;
    unsigned char hashResult[MAX_HASH_SIZE];
    psSize_t hashLen;
    psX509Cert_t *OCSPResponseCert;    /* Allocated to hsPool */
    psBuf_t nonce;                     /* Pointer to response. */
    int version;                       /* Response version (see
                                          PS_VERSION_UNSUPPORTED). */
    const unsigned char *responseType; /* Response type (OID tag). */
} psOcspResponse_t;

typedef enum
{
    PS_CRLREASON_UNSPECIFIED = 0,
    PS_CRLREASON_KEY_COMPROMISE = 1,
    PS_CRLREASON_CA_COMPROMISE = 2,
    PS_CRLREASON_AFFILIATION_CHANGED = 3,
    PS_CRLREASON_SUPERSEDED = 4,
    PS_CRLREASON_CESSATION_OF_OPERATION = 5,
    PS_CRLREASON_CERTIFICATE_HOLD = 6,
    /* value 7 is not used according to RFC 5280. */
    PS_CRLREASON_REMOVE_FROM_CRL = 8,
    PS_CRLREASON_PRIVILEGE_WITHDRAWN = 9,
    PS_CRLREASON_AA_COMPROMISE = 10
} x509CrlReason_t;

typedef struct
{
    /* Will be set to 1 if status is known, 0 if not. */
    psBool_t *knownFlag;
    /* Will be set to 1 if revoked, 0 if ok. */
    psBool_t *revocationFlag;
    /* If response included nonce or both request and response were
       without nonce, then set this flag. Requires request+requestLen to
       be provided. */
    psBool_t *nonceMatch;
    /* Will indicate revocation time (note: timezone = UTC). */
    psBrokenDownTime_t *revocationTime;
    /* Will indicate revocation reason. */
    x509CrlReason_t *revocationReason;
    /* The request for comparing nonce if nonce extension is used. */
    const void *request;
    size_t requestLen;
    /* The location for use response index. */
    int32 *index_p;
} psValidateOCSPResponseOptions_t;

/* Parse OCSP response received.
   The result shall be unitialized with psOcspResponseUninit(). */
extern int32_t psOcspParseResponse(psPool_t *pool, int32_t len,
        unsigned char **cp, unsigned char *end,
        psOcspResponse_t *response);

/* Convert OCSP response status code into integer representing status. */
extern int32_t psOcspResponseGetStatus(int32_t rc);

/* Get dates from OCSP response, to e.g. check how long server wants the
   response to remain valid. */
extern int32_t psOcspResponseCheckDates(psOcspResponse_t *response,
        int index,
        psBrokenDownTime_t *time_now,
        psBrokenDownTime_t *producedAt,
        psBrokenDownTime_t *thisUpdate,
        psBrokenDownTime_t *nextUpdate,
        int time_linger);

/** Validate OCSP response (find status of specific certificate)

    Validate the given OCSP response and determine the revocation
    status of a certificate.

    To validate the OCSP response, the the function will go through
    points 1-5 in section 3.2 of RFC 6960.

    To verify the response signature, the function first looks for the
    certificate of the signer of the OCSP response.
    Three places are searched for the signer certificate:
    - The OCSP response itself (according to RFC 6960: "The responder MAY
    include certificates in the certs field of BasicOCSPResponse that
    help the OCSP client verify the responder's signature").
    - The trustedOCSP list of CA certificates.
    - The srvCerts server certificate chain.
    If the signer's certificate is found in the OCSP response, the function
    will authenticate the certificate against the trustedOCSP CA list.
    If the signer's certificate is found in the trustedOCSP list or in the
    (already authenticated) server certificate chain, no further authentication
    is performed.
    Once the signer's certificate has been found and authenticated, the
    function will attempt to verify the response signature using the public
    key from that certificate. Both RSA and ECDSA signatures are supported.

    The function will try match the server certificate (pointed to by srvCerts)
    against each certificate in the singleResponse sequence in the OCSP response.

    To validate the response timestamp, the function will call
    psOcspResponseCheckDates. A configurable amount of clock skew between
    server and client (PS_OCSP_TIME_LINGER) is allowed. For details, see
    the Developer Guide and the header documentation for psOcspResponseCheckDates.

    @param[in] pool Pointer to the psPool_t structure.
    @param[in] trustedOCSP Pointer to a linked list of trusted CA certificates
    @param[in] srvCerts Pointer to the server certificate chain. The certificate
    whose revocation status is to be checked should be the leaf (i.e. first)
    certificate of this chain.
    @param[in] response Pointer to the parsed OCSP response to validate.
    @retval[out] PS_SUCCESS: the OCSP response was validated successfully.
    PS_FAILURE: unable to validate the OCSP response, or the OCSP response
    contained no revocation information for this certificate (srvCerts).
    PS_CERT_AUTH_FAIL_REVOKED: the OCSP response indicates the server certificate
    has been revoked.
 */
extern int32_t psOcspResponseValidateOld(psPool_t *pool,
        psX509Cert_t *trustedOCSP,
        psX509Cert_t *srvCerts,
        psOcspResponse_t *response);

/** Validate OCSP response with additional parameter to obtain more
    details, like revocation time and reason.

    See the documentation for psOcspResponseValidateOld for a description of the
    parameters and return codes. Here, only the effect of the additional
    parameters (vOpts) is described.

    It is possible to get more information on the OCSP response by assigning
    a non-NULL pointer to the following vOpts:
    - The psBool_t pointed by vOpts->knownFlag will be set to true (1) if OCSP
    response contained no revocation information for this certificate (srvCerts).
    - The psBool_t pointed by vOpts->revocationFlag will be set true (1) if the
    certificate has been revoked, and to 0 otherwise.
    - The psBrokenDownTime_t pointed by vOpts->revocationTime will be filled
    in to contain the revocation time.
    - The x509CrlReason_t pointed by vOpts->revocationReason will be filled
    to contain the revocation reason. See the "Revocation status and reason"
    section in the Developer Guide for details.
    - The psBool_t pointed to by vOpts->nonceMatch will be set to true (1) if the
    same nonce was found in the OCSP request and response. For this,
    the caller must provide the OCSP request and its length in vOpts->request
    and vOpts->requestLen, respectively. Note that when the OCSP response
    is valid and the certificate is not revoked, this function will return
    PS_SUCCESS even in the case of nonce mismatch.
 */
extern int32_t psOcspResponseValidate(psPool_t *pool,
        psX509Cert_t *trustedOCSP,
        psX509Cert_t *srvCerts,
        psOcspResponse_t *response,
        psValidateOCSPResponseOptions_t *vOpts);

/* Construct OCSP request used in OCSP protocol to obtain OCSP response.
   The request obtained typically needs to be sent to OCSP responder using
   HTTP protocol to obtain corresponding OCSP response.
   After finished with the request, it shall be freed using psFree(). */
extern int32_t psOcspRequestWriteOld(psPool_t *pool, psX509Cert_t *cert,
        psX509Cert_t *certIssuer, unsigned char **request,
        uint32_t *requestLen, int32_t flags);

/* Uninitialize OCSP response. */
void psOcspResponseUninit(psOcspResponse_t *res);

#  endif /* USE_OCSP_RESPONSE */

#  ifdef USE_OCSP_REQUEST

typedef struct
{
    int32_t flags;
    psBuf_t *requesterId;             /* Optional requestor id. */
    const psBuf_t *requestExtensions; /* Optional request extensions. */
    int ocspRequestVersion;           /* Default = 0 (v1). */
    int32_t sign_oid;                 /* Signing oid. */
    psPubKey_t *sign_key;             /* Signing key. */
    psX509Cert_t *sign_cert;          /* Certificate for the signing key. */
} psOcspRequestWriteInfo_t;

#   define MATRIXSSL_WRITE_OCSP_REQUEST_FLAG_NONCE 1     /* Use nonce. */
#   define MATRIXSSL_WRITE_OCSP_REQUEST_FLAG_CERT_LIST 2 /* Multiple requests. */
#   define MATRIXSSL_WRITE_OCSP_REQUEST_SIGN 4           /* Need signing. */
#   define MATRIXSSL_WRITE_OCSP_REQUEST_SIGN_CERT_LIST 8 /* Signing with
                                                            certificate list. */

/* Set Signing Info to psOcspRequestWriteInfo_t structure. */
extern int32_t psOcspRequestWriteInfoSetSigning(
    psOcspRequestWriteInfo_t *info_p,
    int32_t sign_oid,     /* designate algorithm to use for signing. */
    psPubKey_t *priv_key,
    psX509Cert_t *cert,
    int is_cert_chain);

/* Set Requester ID for psOcspRequestWriteInfo_t structure.
   It shall be freed using psOcspRequestWriteInfoFreeRequestorId.
   The data expected varies according to the general name, for instance, for
   IPv4 address, the data shall be array of 4 bytes containing the octets.
   However, for the most types the data shall be a string, and for this reason
   parameters are called str and strLen.
   For GN_DIR, the octet sequence can be created with psWriteCertDNAttributes()
   function. */
extern int32_t psOcspRequestWriteInfoSetRequestorId(
    psPool_t *pool,
    psOcspRequestWriteInfo_t *info,
    const char *str, size_t strLen, x509GeneralNameType_t type);

/* Free previously set Requester ID from psOcspRequestWriteInfo_t
   structure. */
extern void psOcspRequestWriteInfoFreeRequestorId(
    psPool_t *pool, psOcspRequestWriteInfo_t *info);

/* Extended version of psOcspRequestWriteOld: allows use of
   requestor name and nonce extension. */
extern int32_t psOcspRequestWrite(
    psPool_t *pool, psX509Cert_t *cert,
    psX509Cert_t *certIssuer, unsigned char **request,
    uint32_t *requestLen,
    psOcspRequestWriteInfo_t *info);

#   define MATRIXSSL_OCSP_VERSION_V1 0

/* Override version of OCSP request.
   If this function is not called, the lowest OCSP request version with all
   requested features is used. Currently, this version is
   MATRIXSSL_OCSP_VERSION_V1 (0).
 */
extern void psOcspRequestWriteVersion(
    int version,
    psOcspRequestWriteInfo_t *info);

#  endif /* USE_OCSP_REQUEST */

/******************************************************************************/

/******************************************************************************/

# endif /* USE_X509 */

#endif  /* _h_PS_X509 */

/******************************************************************************/
