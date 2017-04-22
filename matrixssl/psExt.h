/* psExt.h
 *
 * External API for signing message digests with RSA and ECC private keys.
 * This should be implemented by the the external module. For an example
 * implementation, see exampleExtCvSigModule.c.
 */

/*****************************************************************************
* Copyright (c) 2007-2017 INSIDE Secure Oy. All Rights Reserved.
*
* This confidential and proprietary software may be used only as authorized
* by a licensing agreement from INSIDE Secure.
*
* The entire notice above must be reproduced on all authorized copies that
* may only be made to the extent permitted by a licensing agreement from
* INSIDE Secure.
*
* For more information or support, please go to our online support system at
* https://essoemsupport.insidesecure.com.
* In case you do not have an account for this system, please send an e-mail to
* ESSEmbeddedHW-Support@insidesecure.com.
*****************************************************************************/

#ifndef INCLUDE_GUARD_EXAMPLEEXTCVSIGMODULE_H
#define INCLUDE_GUARD_EXAMPLEEXTCVSIGMODULE_H

/** Load a certificate from an external module.

   @param cert_key_id[in] ID of the certificate/private key pair whose certificate should be loaded.
   @param cert_buf[out] Pointer to a buffer containing the certificate in DER format. Allocated in this function. Caller must free.
   @param cert_len[out] Length of the certificate in bytes.
   @return 0 on success, < 0 on failure.
 */
int psExtLoadCert(unsigned int cert_key_id,
                  unsigned char **cert_buf,
                  size_t *cert_len);

/** Sign a hash using an RSA private key (PKCS #1.5 Encrypt).

   @param cert_key_id[in] ID of the certificate/private key pair whose private key should be used in the signing operation.
   @param hash_to_sign[in] Pointer to the hash value to sign.
   @param hash_len[in] Length of the hash in bytes. This value can be used to identify the hash algorithm, e.g. 32 implies SHA-256.
   @param signature[out] Pointer to a buffer containing the resulting signature. The buffer is allocated in this function. Caller must free.
   @param signature_len[out] Length of the resulting signature in bytes
   @return 0 on success, < 0 on failure.
 */
int psExtRsaSignHash(unsigned int cert_key_id,
                     unsigned char *hash_to_sign,
                     size_t hash_len,
                     unsigned char **signature,
                     size_t *signature_len);

/** Sign a hash using an ECDSA private key (ANS X9.62 / RFC 4492).

   @param cert_key_id[in] ID of the certificate/private key pair whose private key should be used in the signing operation.
   @param hash_to_sign[in] Pointer to the hash value to sign.
   @param hash_len[in] Length of the hash in bytes. This value can be used to identify the hash algorithm, e.g. 32 implies SHA-256.
   @param signature[out] Pointer to a buffer containing the resulting signature. The buffer is allocated in this function. Caller must free.
   @param signature_len[out] Length of the resulting signature in bytes.
   @return 0 on success, < 0 on failure.
 */
int psExtEcdsaSignHash(unsigned int cert_key_id,
                       unsigned char *hash_to_sign,
                       size_t hash_len,
                       unsigned char **signature,
                       size_t *signature_len);

/** Perform cleanup and finish operation.
 */
void psExtCleanup(void);

/** Example definitions of private key-certificate pair IDs.

    These example IDs can be used to communicate to the external module, which key-certificate pair should be used.
 */
#define CERT_KEY_ID_RSA1024 0
#define CERT_KEY_ID_RSA2048 1
#define CERT_KEY_ID_RSA3072 2
#define CERT_KEY_ID_RSA4096 3
#define CERT_KEY_ID_ECC192 4
#define CERT_KEY_ID_ECC224 5
#define CERT_KEY_ID_ECC256 6
#define CERT_KEY_ID_ECC384 7
#define CERT_KEY_ID_ECC521 8
#define CERT_KEY_ID_ECC256_ECDH_RSA 9
#define CERT_KEY_ID_ECC521_ECDH_RSA 10

#endif /* INCLUDE_GUARD_EXAMPLEEXTCVSIGMODULE_H */

/* end of file exampleExtCvSigModule.h */
