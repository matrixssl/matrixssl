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
ifneq (,$(findstring i386-,$(CCARCH)))
COMBA_MULTIPLIER_DEBUG=OFF
endif
ifneq (,$(findstring i486-,$(CCARCH)))
COMBA_MULTIPLIER_DEBUG=OFF
endif
ifneq (,$(findstring i586-,$(CCARCH)))
COMBA_MULTIPLIER_DEBUG=OFF
endif
ifneq (,$(findstring i686-,$(CCARCH)))
COMBA_MULTIPLIER_DEBUG=OFF
endif
ifeq '$(COMBA_MULTIPLIER_DEBUG)' 'OFF'
CFLAGS_BASE:=$(CFLAGS)
math/pstm_mul_comba.o: CFLAGS=$(CFLAGS_BASE) -fomit-frame-pointer
math/pstm_sqr_comba.o: CFLAGS=$(CFLAGS_BASE) -fomit-frame-pointer
endif

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

