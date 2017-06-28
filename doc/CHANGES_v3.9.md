# MatrixSSL 3.9 changelog

## Changes between 3.9.2 and 3.9.3 [June 2017]

Fix serious buffer handling vulnerabilities along with other smaller bug fixes.

- Fixed buffer overflow vulnerability in parsePolicyMappings and buffer
  underflow in parseGeneralNames. Vulnerabilities discovered by Aleksandar
  Nikolic of Cisco Talos.

- psX509ParseCert modified not to call parse_single_cert when there are
  only a few bytes remaining.

- Fix compilation when USE_PKCS8 is not defined.

- Added common makefiles directory for reusable makefile components.

- Added new result code PS_SELFTEST_FAILED for detecting psCryptoOpen() failure
  due to self-test failure of underlying cryptographic primitivers.

- Debugging build log output can be redirected to a file using
  PSCORE_DEBUG_FILE/PSCORE_DEBUG_FILE_APPEND/FLPS_DEBUG_FILE/
  FLPS_DEBUG_FILE_APPEND environment variables.

- New example configuration for use of libopenssl-compat.
  This configuration enables TLS 1.0, which is common to use with
  libopenssl-compat.

- Add client side option for rejecting version downgrade during TLS handshake.

- ECDSA cipher suites were errorneously rejected by client using CAs with only
  RSA certificates.

- Small improvements to psBuf and psDynBuf functions.

- CMS library improvements, support for multiple recipients with
  authenticated encrypted data.

- CMS library improvements, support for zero or multiple signers
  for signed data.

- Signed data can now contain X.509 CRLs.

- Fixed handling of OCSP responses using OCSP responderName.

- Fixed memory leak in freeing of OCSP requestor id.

- MatrixSSL client sometimes prevented ECDSA cipher suites from being used
  due to flaw in key material compatibility test. The test has been removed.

## Changes between 3.9.1 and 3.9.2

3.9.2. only released as a part of SafeZone FIPS SW SDK.

- Added support for OCSP response with SHA-512 signature.

- psPkcs8ParsePrivBin() function now supports any SafeZone CL library supported
  PKCS #8 key formats, in addition to PKCS #8 keys ordinarily supported by
  MatrixSSL. (Only applicable to MatrixSSL FIPS Edition.)

- Added matrixSslLoadKeys and matrixSslLoadKeysMem. This key loading
  function can be used in situations where the type of private key
  (RSA or EC) to load is unknown.

- Added support for loading CA bundles containing both supported and
  unsupported certificates. Previously, the loading of a CA bundle failed
  if any of the certificates could not be fully parsed by MatrixSSL, due to
  e.g. disabled v1 certificate support. The new feature can be enabled
  by defining ALLOW_CA_BUNDLE_PARTIAL_PARSE in matrixsslConfig.h. Also
  the crypto-level psX509ParseCert and psX509ParseCertFile functions support
  the same feature when passed the CERT_ALLOW_BUNDLE_PARTIAL_PARSE flag.

- Added support for RSA-SHA224 and ECDSA-SHA224 signatures in CSR generation,
  CSR parsing and certificate generation. Expanded X.509 Generation API
  test.

## Changes between 3.9.0 and 3.9.1

- Disabled support for SHA-1 signed certificates by default. SHA-1 can
  no longer be considered secure for this purpose (see
  https://shattered.it/static/shattered.pdf). We decided to disable
  SHA-1 signed certificates by default to ensure that MatrixSSL
  customers consider the security implications before enabling them.
  Support for SHA-1 signed certificates can be restored by defining
  ENABLE_SHA1_SIGNED_CERTS in cryptoConfig.h.

- Regenerated all test certificates. Many of the old ones had exceeded
  their validity period. The new test certificates have some minor
  changes, such as the addition of some missing basicConstraints and
  authorityKeyIdentifier extensions. Note that the test certificates
  should never be used in production, but only for initial testing
  during development.

- Fixed bug that caused a segfault when
  ALLOW_VERSION_1_ROOT_CERT_PARSE was enabled and the peer sent a
  version 1 certificate. Correct behaviour is to just produce an
  internal certificate validation failure in this case, as the above
  define only allows parsing of locally stored trusted root
  certificates. This bug is minor as ALLOW_VERSION_1_ROOT_CERT_PARSE
  is disabled by default, and rarely used by MatrixSSL customers.

- Introduced new function setSocketTlsCertAuthCb for setting certificate
  authentication callback when using MatrixSSL via psSocket_t interface.
  Previously constant function name ssl_cert_auth was used for authentication
  callback.
