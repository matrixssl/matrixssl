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
	matrixssl.c \
	matrixsslApi.c \
	prf.c \
	psk.c \
	sslDecode.c \
	sslEncode.c \
	sslv3.c \
	tls.c

# Generated files
STATIC:=libssl_s.a

all: compile

compile: $(OBJS) $(STATIC)

# Additional Dependencies
$(OBJS): $(MATRIXSSL_ROOT)/common.mk Makefile *.h

# Build the static library

$(STATIC): $(OBJS)
	$(AR) -rcu $@ $^

clean:
	rm -f $(STATIC) $(OBJS)

# Allows to check configuration options.
parse-config:
	echo '#include "matrixsslConfig.h"' | $(CC) $(CFLAGS) -dM -E -x c -
