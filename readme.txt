MatrixSSL Directory Structure

/

Makefile
	Top level Makefile. Builds core, crypto, matrixssl and apps

common.mk
	Top level file for common make definitions.

matrixssl/
	This directory contains files the implement the SSL and TLS protocol.
	test/
		sslTest - Single-process SSL handshake test application that
		exercises the cipher suites and handshakes that are available
		in the currently built library.

crypto/
	digest/
		Message digests (SHA256, etc.)
	symmetric/
		Symmetric ciphers (AES-GCM, etc.)
	keyformat/
		Decode/encode Certificates and keys (X.509, .pem, etc.)
	pubkey/
		RSA, ECC and DH operations
	math/
		Large integer math operations
	prng/
		Psuedo random number generation
	layer/
		Cryptographic algorithm provider layer (FIPS, PKCS#11, etc.)
*	hardware/
		Platform specific hardware provider layer
*	cms/
		Cryptographic Messaging Syntax
	test/
		Functionality and performance tests.

* crypto-cl/
	SafeZone Cryptographic Library Integration. This directory replaces
	(the most) contents of crypto library when compiling with default,
	combined, fipsonly, or cl-nonfips configurations.

* FIPSLib11/
	SafeZone FIPS Lib version 1.1, FIPS 140-2 Validation Cert. #2389

core/
*	Pool based malloc() implementation
	Utility functions
	POSIX/
		Operating system layer for Linux, OS X, BSD
	WIN32/
		Operating system layer for Windows

apps/
*	crypto/
		certgen - generate X.509 cert from a certificate request or self-signed
		certrequest - generate a cert request from a private RSA key
		dertomem - convert a der format key or certificate to C header
		pemtomem - convert a pem format key or certificate to C header
		rsakeygen - generate an RSA public/private keypair
		ecckeygen - generate an ECC public/private keypair
		RSA and ECC key and certificate generation
	ssl/
		Example SSL client using blocking sockets and session resumption
		Example SSL server using non-blocking sockets and simultaneous connections
	dtls/
		Example DTLS client
		Example DTLS server

doc/
	Release notes
	Developer guides
	API documentation

testkeys/
	Sample RSA, ECC, DH and PSK keys and certificate files for test and example apps

xcode/
	Project files for XCode. These files directly call the Makefiles in
	the source directories to build the matrixssl static libraries and 
	example applications.

( * Not available in all versions of MatrixSSL )

