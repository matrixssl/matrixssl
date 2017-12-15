#
#   Makefile for common apps code
#
#	Copyright (c) 2013-2016 INSIDE Secure Corporation. All Rights Reserved.
#

MATRIXSSL_ROOT:=../..
CLIENT_COMMON_SRC:=client_common.c clientconfig.c load_keys.c
CLIENT_COMMON_OBJS:=$(CLIENT_COMMON_SRC:.c=.o)

SRC:=$(CLIENT_COMMON_SRC)

# Generated files
CLIENT_COMMON_STATIC:=client_common_s.a
STATIC:=$(CLIENT_COMMON_STATIC)

# Optional extensions to CFLAGS/LDFLAGS
CFLAGS+=$(CFLAGS_INTERNAL) -Wextra -Wno-old-style-declaration
LDFLAGS+=$(LDFLAGS_INTERNAL) -Wextra

# Allow selecting the client auth identity (ID_RSA, ID_ECDH_ECDSA,
# etc.) via an environment variable.
ifneq '$(CIPHER_OPTION)' ''
  CFLAGS+=-D$(CIPHER_OPTION)
endif

include $(MATRIXSSL_ROOT)/common.mk

all: compile

compile: $(OBJS) $(STATIC)

# Additional Dependencies
$(OBJS): $(MATRIXSSL_ROOT)/common.mk Makefile $(wildcard *.h)

$(CLIENT_COMMON_STATIC): $(CLIENT_COMMON_OBJS)
	$(AR) -rc $@ $^

clean:
	rm -f $(OBJS) $(STATIC)
