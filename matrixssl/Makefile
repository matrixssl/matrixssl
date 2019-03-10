#
#	Makefile for MatrixSSL static library
#	'make' builds debug (Default).
#	'make gold' builds optimized.
#
#	Copyright (c) 2013-2016 INSIDE Secure Corporation. All Rights Reserved.
#

MATRIXSSL_ROOT:=..
include $(MATRIXSSL_ROOT)/common.mk

SRC:=\
	cipherSuite.c \
	dtls.c \
	extDecode.c \
	hsDecode.c \
	hsHash.c \
	hsNegotiateVersion.c \
	matrixssl.c \
	matrixsslKeys.c \
	matrixsslApi.c \
	matrixsslInitVer.c \
	matrixsslSecConfig.c \
	prf.c \
	psk.c \
	sslDecode.c \
	sslEncode.c \
	tlsDefaults.c \
	tlsSelectKeys.c \
	tlsSigVer.c \
	tlsTrace.c \
	tls13Authenticate.c \
	tls13CipherSuite.c \
	tls13Encode.c \
	tls13EncodeExt.c \
	tls13Decode.c \
	tls13DecodeExt.c \
	tls13KeyAgree.c \
	tls13KeySchedule.c \
	tls13Negotiate.c \
	tls13Psk.c \
	tls13Resume.c \
	tls13SigVer.c \
	tls13TrHash.c \
	sslv3.c \
	tls.c

# Generated files
STATIC:=libssl_s.a

all: compile

compile: $(OBJS) $(STATIC)

# Additional Dependencies
$(OBJS): $(MATRIXSSL_ROOT)/common.mk Makefile *.h

# Build the static library
include $(use_ar_mk)
$(STATIC): $(OBJS)
	$(AR) $(ARCOMMAND) $@ $^

clean:
	rm -f $(STATIC) $(OBJS)

# Allows to check configuration options.
CPPFLAGS_EXTRACT_MACROS=-dM
parse-config:
	[ -f matrixsslConfig.h ] && echo '#include "matrixsslConfig.h"' | $(CC) $(CFLAGS) $(CPPFLAGS_EXTRACT_MACROS) -E -x c - || exit 0
