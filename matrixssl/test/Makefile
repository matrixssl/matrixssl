#
#	Makefile for MatrixSSL testing
#
#	Copyright (c) 2013-2016 INSIDE Secure Corporation. All Rights Reserved.
#

MATRIXSSL_ROOT:=../..
TEST_SRC:=sslTest.c
CERT_SRC:=certValidate.c
PROVIDER_SRC:=provider.c
SRC:=$(TEST_SRC) $(CERT_SRC) $(PROVIDER_SRC)

# Linked files
STATIC:=../libssl_s.a $(MATRIXSSL_ROOT)/crypto/libcrypt_s.a $(MATRIXSSL_ROOT)/core/libcore_s.a

include $(MATRIXSSL_ROOT)/common.mk

# Include possible additional MatrixSSL test program build instructions
-include Makefile.add

# Generated files
CERT_EXE:=certValidate$(E)
TEST_EXE:=sslTest$(E)
PROVIDER_EXE:=provider$(E)

ifeq '$(CL_NO_PKCS)' ''
CFLAGS+=-DUSE_CL_PKCS -DUSE_CL_CERTLIB
endif

# Generate map file with sections and C source reference for sslTest
ifndef MATRIX_DEBUG
ifeq (,$(findstring -apple,$(CCARCH)))
ifeq (,$(findstring -android,$(CCARCH)))
LDFLAGS += \
 -Wl,--cref \
 -Wl,-s \
 -Wl,-Map="$@.map"
endif
endif
endif

all: compile

compile: $(OBJS) $(CERT_EXE) $(TEST_EXE)

# Additional Dependencies
$(OBJS): $(MATRIXSSL_ROOT)/common.mk Makefile $(wildcard *.h)

$(TEST_EXE): $(TEST_SRC:.c=.o) $(STATIC)
	$(CC) -o $@ $^ $(LDFLAGS)

$(CERT_EXE): $(CERT_SRC:.c=.o) $(STATIC)
	$(CC) -o $@ $^ $(LDFLAGS)

$(PROVIDER_EXE): $(PROVIDER_SRC:.c=.o) $(STATIC)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TEST_EXE) $(CERT_EXE) $(PROVIDER_EXE) $(OBJS) $(CLEAN_EXTRA_FILES) *.map
