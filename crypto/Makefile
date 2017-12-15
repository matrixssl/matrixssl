#
#   Makefile for MatrixSSL crypto static library
#   'make' builds debug (Default).
#   'make gold' builds optimized.
#
#   Copyright (c) 2013-2017 INSIDE Secure Corporation. All Rights Reserved.
#

MATRIXSSL_ROOT:=..
include $(MATRIXSSL_ROOT)/common.mk

SRC:=\
	symmetric/aes.c \
	symmetric/aesCBC.c \
	symmetric/aesGCM.c \
	symmetric/aes_aesni.c \
	symmetric/arc4.c \
	symmetric/des3.c \
	symmetric/idea.c \
	symmetric/rc2.c \
	symmetric/seed.c \
	digest/sha1.c \
	digest/sha256.c \
	digest/sha512.c \
	digest/md5sha1.c \
	digest/md5.c \
	digest/hmac.c \
	digest/md4.c \
	digest/md2.c \
	keyformat/asn1.c \
	keyformat/asn1fmt.c \
	keyformat/base64.c \
	keyformat/crl.c \
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
	pubkey/ecc.c \
	pubkey/pubkey.c \
	pubkey/rsa.c

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
SRC+=$(SRC_CHACHA20POLY)
CFLAGS_ADDITIONAL_CHACHA20POLY=-I`pwd`/aead/chacha20poly1305ietf -I`pwd`
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

clean:
	rm -f $(STATIC) $(OBJS)

# Allows to check configuration options.
parse-config:
	echo '#include "cryptoConfig.h"' | $(CC) $(CFLAGS) -dM -E -x c -

