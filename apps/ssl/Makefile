#
#   Makefile for MatrixSSL example apps
#   'make' builds debug (Default).
#   'make gold' builds optimized.
#
#	Copyright (c) 2013-2016 INSIDE Secure Corporation. All Rights Reserved.
#

MATRIXSSL_ROOT:=../..
SERVER_SRC:=server.c http.c
CLIENT_SRC:=client.c http.c
NET_SRC:=net.c
SRC=$(SERVER_SRC) $(CLIENT_SRC)
SERVER_EXE:=server$(E)
CLIENT_EXE:=client$(E)
NET_EXE:=matrixnet$(E)
EXE=$(SERVER_EXE) $(CLIENT_EXE)

#The Mac OS X Xcode project has a target name of 'server' or 'client'
ifneq (,$(TARGET_NAME))
 ifneq (,$(findstring server,$(TARGET_NAME)))
  CLIENT_EXE:=
  CLIENT_SRC:=
 else
  SERVER_EXE:=
  SERVER_SRC:=
 endif
endif

# Optional extensions to CFLAGS/LDFLAGS
CFLAGS+=$(CFLAGS_INTERNAL)
LDFLAGS+=$(LDFLAGS_INTERNAL)

# Extra dependencies
MATRIXSSL_CONFIG:=$(shell make parse-config --directory $(MATRIXSSL_ROOT)/matrixssl)

ifneq (,$(findstring USE_ZLIB_COMPRESSION, $(MATRIXSSL_CONFIG)))
LDFLAGS+=-lz
endif

include $(MATRIXSSL_ROOT)/common.mk

# Linked files
STATIC:=\
	$(MATRIXSSL_ROOT)/matrixssl/libssl_s.a \
	$(MATRIXSSL_ROOT)/crypto/libcrypt_s.a \
	$(MATRIXSSL_ROOT)/core/libcore_s.a \
	$(STATIC_INTERNAL)

STATIC_CLIENT:=\
	$(MATRIXSSL_ROOT)/apps/common/client_common_s.a

# Allow selecting the client auth identity (ID_RSA, ID_ECDH_ECDSA,
# etc.) via an environment variable.
ifneq '$(CIPHER_OPTION)' ''
  CFLAGS+=-D$(CIPHER_OPTION)
endif

compile: $(OBJS) $(EXE)

# Additional Dependencies
$(OBJS): $(MATRIXSSL_ROOT)/common.mk Makefile $(wildcard *.h)

$(SERVER_EXE): $(SERVER_SRC:.c=.o) $(STATIC)
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

$(CLIENT_EXE): $(CLIENT_SRC:.c=.o) $(STATIC) $(STATIC_CLIENT)
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

$(NET_EXE): $(NET_SRC:.c=.o) $(STATIC)
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

clean:
	rm -f $(EXE) $(OBJS) TLS_*.tmp SSL_*.tmp

