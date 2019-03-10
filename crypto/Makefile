#
#   Makefile for MatrixSSL crypto static library
#
#   Copyright (c) 2013-2018 INSIDE Secure Corporation. All Rights Reserved.
#

MATRIXSSL_ROOT:=..
include $(MATRIXSSL_ROOT)/common.mk

SRC:=\
	common/alg_info.c \
	common/digest_info.c \
	symmetric/aes.c \
	symmetric/aesCBC.c \
	symmetric/aesGCM.c \
	symmetric/aes_aesni.c \
	symmetric/arc4.c \
	symmetric/des3.c \
	symmetric/idea.c \
	symmetric/rc2.c \
	symmetric/seed.c \
	digest/sha256_standalone.c \
	digest/sha1.c \
	digest/sha256.c \
	digest/sha512.c \
	digest/md5sha1.c \
	digest/md5.c \
	digest/hmac.c \
	digest/md4.c \
	digest/md2.c \
	digest/hkdf.c \
	keyformat/asn1.c \
	keyformat/asn1fmt.c \
	keyformat/base64.c \
	keyformat/crl.c \
	keyformat/pem_decode_mem.c \
	keyformat/pem_decode_file.c \
	keyformat/pkcs.c \
	keyformat/x509.c \
	layer/matrix.c \
	math/pstm.c \
	math/pstmnt.c \
	math/pstm_montgomery_reduce.c \
	math/pstm_mul_comba.c \
	math/pstm_sqr_comba.c \
	prng/prng.c \
	prng/yarrow.c \
	pubkey/dh.c \
	pubkey/dh_params.c \
	pubkey/dh_export.c \
	pubkey/dh_import.c \
	pubkey/dh_gen_key.c \
	pubkey/dh_gen_secret.c \
	pubkey/dh_import_priv.c \
	pubkey/ecc.c \
	pubkey/ecc_curve.c \
	pubkey/ecc_curve_data.c \
	pubkey/ecc_curve_config.c \
	pubkey/ecc_math.c \
	pubkey/ecc_priv.c \
	pubkey/ecc_priv_el_gamal.c \
	pubkey/ecc_pub.c \
	pubkey/ecc_keygen.c \
	pubkey/ecc_gen_shared.c \
	pubkey/ecc_parse_file.c \
	pubkey/ecc_parse_mem.c \
	pubkey/ecc_write_mem.c \
	pubkey/ecc_write_file.c \
	pubkey/ecc_export.c \
	pubkey/ecc_import.c \
	pubkey/pubkey.c \
	pubkey/pubkey_sign.c \
	pubkey/pubkey_verify.c \
	pubkey/pubkey_parse_mem.c \
	pubkey/pubkey_parse_file.c \
	pubkey/rsa.c \
	pubkey/rsa_priv.c \
	pubkey/rsa_pub.c \
	pubkey/rsa_keygen.c \
	pubkey/rsa_parse_mem.c \
	pubkey/rsa_parse_file.c \
	pubkey/rsa_write_mem.c \
	pubkey/rsa_write_file.c \


SRC_CHACHA20POLY = \
        aead/chacha20poly1305ietf/sse2/poly1305_sse2.c \
	aead/chacha20poly1305ietf/donna/poly1305_donna.c \
	aead/chacha20poly1305ietf/dolbeau/chacha20_dolbeau-avx2.c \
	aead/chacha20poly1305ietf/dolbeau/chacha20_dolbeau-ssse3.c \
	aead/chacha20poly1305ietf/ref/chacha20_ref.c \
	aead/chacha20poly1305ietf/stream_chacha20.c \
	aead/chacha20poly1305ietf/onetimeauth_poly1305.c \
	aead/chacha20poly1305ietf/ps_chacha20poly1305ietf.c \
	aead/chacha20poly1305ietf/aead_chacha20poly1305.c \
	aead/chacha20poly1305ietf/utils.c \
	aead/chacha20poly1305ietf/verify.c \
	aead/chacha20poly1305ietf/runtime.c

SRC_CURVE25519 = \
	scalarmult/curve25519/scalarmult_curve25519.c \
	scalarmult/curve25519/ref10/x25519_ref10.c \
	scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.c \
	scalarmult/crypto_scalarmult.c \
	scalarmult/crypto_core/ed25519/core_ed25519.c \
	scalarmult/crypto_core/ed25519/ref10/ed25519_ref10.c \
	scalarmult/ps_x25519.c

SRC_ED25519 = \
	crypto_sign/crypto_sign.c \
	crypto_sign/ed25519/ref10/sign.c \
	crypto_sign/ed25519/ref10/open.c \
	crypto_sign/ps_ed25519.c

#	crypto_sign/ed25519/ref10/sign_ed25519.c

SRC+=$(SRC_CHACHA20POLY) $(SRC_CURVE25519) $(SRC_ED25519)
CFLAGS_ADDITIONAL_CHACHA20POLY=-I`pwd`/aead/chacha20poly1305ietf -I`pwd`
CFLAGS_ADDITIONAL_X25519=$(CFLAGS_ADDITIONAL_CHACHA20POLY) -I`pwd`/scalarmult/include/sodium
CFLAGS_ADDITIONAL_ED25519=$(CFLAGS_ADDITIONAL_X25519) -I`pwd`/crypto_sign/include/sodium -I`pwd`
ifdef MATRIX_DEBUG
OPT_CHACHA20POLY=-O2 -std=gnu99 -g
else
OPT_CHACHA20POLY=-O2 -std=gnu99
endif
aead/chacha20poly1305ietf/ps_chacha20poly1305ietf.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_CHACHA20POLY)
aead/chacha20poly1305ietf/ps_chacha20poly1305ietf.o: OPT=$(OPT_CHACHA20POLY)
aead/chacha20poly1305ietf/sse2/poly1305_sse2.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_CHACHA20POLY)
aead/chacha20poly1305ietf/sse2/poly1305_sse2.o: OPT=$(OPT_CHACHA20POLY)
aead/chacha20poly1305ietf/donna/poly1305_donna.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_CHACHA20POLY)
aead/chacha20poly1305ietf/donna/poly1305_donna.o: OPT=$(OPT_CHACHA20POLY)
aead/chacha20poly1305ietf/dolbeau/chacha20_dolbeau-avx2.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_CHACHA20POLY)
aead/chacha20poly1305ietf/dolbeau/chacha20_dolbeau-avx2.o: OPT=$(OPT_CHACHA20POLY)
aead/chacha20poly1305ietf/dolbeau/chacha20_dolbeau-ssse3.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_CHACHA20POLY)
aead/chacha20poly1305ietf/dolbeau/chacha20_dolbeau-ssse3.o: OPT=$(OPT_CHACHA20POLY)
aead/chacha20poly1305ietf/ref/chacha20_ref.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_CHACHA20POLY)
aead/chacha20poly1305ietf/ref/chacha20_ref.o: OPT=$(OPT_CHACHA20POLY)
aead/chacha20poly1305ietf/stream_chacha20.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_CHACHA20POLY)
aead/chacha20poly1305ietf/stream_chacha20.o: OPT=$(OPT_CHACHA20POLY)
aead/chacha20poly1305ietf/onetimeauth_poly1305.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_CHACHA20POLY)
aead/chacha20poly1305ietf/onetimeauth_poly1305.o: OPT=$(OPT_CHACHA20POLY)
aead/chacha20poly1305ietf/aead_chacha20poly1305.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_CHACHA20POLY)
aead/chacha20poly1305ietf/aead_chacha20poly1305.o: OPT=$(OPT_CHACHA20POLY)
aead/chacha20poly1305ietf/utils.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_CHACHA20POLY)
aead/chacha20poly1305ietf/utils.o: OPT=$(OPT_CHACHA20POLY)
aead/chacha20poly1305ietf/verify.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_CHACHA20POLY)
aead/chacha20poly1305ietf/verify.o: OPT=$(OPT_CHACHA20POLY)
aead/chacha20poly1305ietf/runtime.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_CHACHA20POLY)
aead/chacha20poly1305ietf/runtime.o: OPT=$(OPT_CHACHA20POLY)
scalarmult/curve25519/scalarmult_curve25519.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_X25519)
scalarmult/curve25519/scalarmult_curve25519.o: CFLAGS_OPTIMIZATION=$(OPT_X25519)
scalarmult/curve25519/ref10/x25519_ref10.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_X25519)
scalarmult/curve25519/ref10/x25519_ref10.o: CFLAGS_OPTIMIZATION=$(OPT_X25519)
scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_X25519)
scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.o: CFLAGS_OPTIMIZATION=$(OPT_X25519)
scalarmult/crypto_scalarmult.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_X25519)
scalarmult/crypto_scalarmult.o: CFLAGS_OPTIMIZATION=$(OPT_X25519)
scalarmult/crypto_core/ed25519/core_ed25519.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_X25519)
scalarmult/crypto_core/ed25519/core_ed25519.o: CFLAGS_OPTIMIZATION=$(OPT_X25519)
scalarmult/crypto_core/ed25519/ref10/ed25519_ref10.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_X25519)
scalarmult/crypto_core/ed25519/ref10/ed25519_ref10.o: CFLAGS_OPTIMIZATION=$(OPT_X25519)
crypto_sign/crypto_sign.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_ED25519)
crypto_sign/crypto_sign.o: CFLAGS_OPTIMIZATION=$(OPT_ED25519)
crypto_sign/ed25519/ref10/sign.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_ED25519)
crypto_sign/ed25519/ref10/sign.o: CFLAGS_OPTIMIZATION=$(OPT_ED25519)
crypto_sign/ed25519/ref10/open.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_ED25519)
crypto_sign/ed25519/ref10/open.o: CFLAGS_OPTIMIZATION=$(OPT_ED25519)
crypto_sign/ed25519/ref10/keypair.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_ED25519)
crypto_sign/ed25519/ref10/keypair.o: CFLAGS_OPTIMIZATION=$(OPT_ED25519)
crypto_sign/ed25519/ref10/sign_ed25519.o: CFLAGS_ADDITIONAL=$(CFLAGS_ADDITIONAL_ED25519)
crypto_sign/ed25519/ref10/sign_ed25519.o: CFLAGS_OPTIMIZATION=$(OPT_ED25519)

#ifdef USE_OPENSSL_CRYPTO
ifdef USE_OPENSSL_CRYPTO
SRC+=\
	digest/digest_openssl.c \
	symmetric/symmetric_openssl.c \
	pubkey/rsa_openssl.c
endif
#endif
#ifdef USE_LIBSODIUM_CRYPTO
ifdef USE_LIBSODIUM_CRYPTO
SRC+=\
	symmetric/symmetric_libsodium.c \
	digest/digest_libsodium.c
endif
#endif

# Deal with a build flags special case:
# Comba multiplier and squaring requires all registers it can get on x86.
# These extra compilation definitions make those registers available for
# these files to use.
COMBA_MULTIPLIER_DEBUG=ON # Default on non-x86 platforms (debug build).
INTEL_32BIT=NO
ifneq (,$(findstring i386-,$(CCARCH)))
COMBA_MULTIPLIER_DEBUG=OFF
INTEL_32BIT=YES
endif
ifneq (,$(findstring i486-,$(CCARCH)))
COMBA_MULTIPLIER_DEBUG=OFF
INTEL_32BIT=YES
endif
ifneq (,$(findstring i586-,$(CCARCH)))
COMBA_MULTIPLIER_DEBUG=OFF
INTEL_32BIT=YES
endif
ifneq (,$(findstring i686-,$(CCARCH)))
COMBA_MULTIPLIER_DEBUG=OFF
INTEL_32BIT=YES
endif
ifneq (,$(findstring x86_64-,$(CCARCH)))
INTEL_64BIT=YES
endif
ifeq '$(COMBA_MULTIPLIER_DEBUG)' 'OFF'
CFLAGS_BASE:=$(CFLAGS)
math/pstm_mul_comba.o: CFLAGS=$(CFLAGS_BASE) -fomit-frame-pointer
math/pstm_sqr_comba.o: CFLAGS=$(CFLAGS_BASE) -fomit-frame-pointer
endif

ifeq '$(INTEL_32BIT)' 'YES'
CFLAGS_ENABLE_SSE2=-msse2
CFLAGS_ENABLE_AVX2=-mavx2
CFLAGS_ENABLE_SSSE3=-mssse3
endif
ifeq '$(INTEL_64BIT)' 'YES'
CFLAGS_ENABLE_SSE2=-msse2
CFLAGS_ENABLE_AVX2=-mavx2
CFLAGS_ENABLE_SSSE3=-mssse3
endif

# Additional flags for CHACHA20-POLY1305 (support of SSE/AVX)
aead/chacha20poly1305ietf/sse2/poly1305_sse2.o: CFLAGS_ADDITIONAL+= $(CFLAGS_ENABLE_SSE2)
aead/chacha20poly1305ietf/dolbeau/chacha20_dolbeau-avx2.o: CFLAGS_ADDITIONAL+= $(CFLAGS_ENABLE_AVX2)
aead/chacha20poly1305ietf/dolbeau/chacha20_dolbeau-ssse3.o: CFLAGS_ADDITIONAL+= $(CFLAGS_ENABLE_SSSE3)

# Additional flags for AES-NI support.
# (note: only available on targets with AES-NI support detected.)
symmetric/aes_aesni.o: CFLAGS_ADDITIONAL+= $(CFLAGS_ENABLE_AESNI)

# Generated files
STATIC:=libcrypt_s.a

all: compile

compile: $(OBJS) $(STATIC)
	@echo $(STROPTS)

# Additional Dependencies
$(OBJS): $(MATRIXSSL_ROOT)/common.mk Makefile *.h */$(BLANK)*.h

# Build the static library

$(STATIC): $(OBJS)
	$(AR) -rcu $@ $^

asn1enc_test :
	gcc keyformat/asn1enc.c -o asn1enc_test

clean:
	rm -f $(STATIC) $(OBJS)

# Allows to check configuration options.
CPPFLAGS_EXTRACT_MACROS=-dM
parse-config:
	[ -f cryptoConfig.h ] && echo '#include "cryptoConfig.h"' | $(CC) $(CFLAGS) $(CPPFLAGS_EXTRACT_MACROS) -E -x c - || exit 0
