#
#   Makefile for MatrixDTLS example apps
#   'make' builds debug (Default).
#   'make gold' builds optimized.
#
#	Copyright (c) 2013-2016 INSIDE Secure Corporation. All Rights Reserved.
#

MATRIXSSL_ROOT:=../..

SERVER_SRC:=dtlsServer.c dtlsCommon.c
CLIENT_SRC:=dtlsClient.c dtlsCommon.c

SERVER_EXE:=dtlsServer$(E)
CLIENT_EXE:=dtlsClient$(E)

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

SRC:=$(SERVER_SRC) $(CLIENT_SRC)

include $(MATRIXSSL_ROOT)/common.mk

# Linked files
STATIC:=\
	$(MATRIXSSL_ROOT)/matrixssl/libssl_s.a \
	$(MATRIXSSL_ROOT)/crypto/libcrypt_s.a \
	$(MATRIXSSL_ROOT)/core/libcore_s.a

STATIC_CLIENT:=\
	$(MATRIXSSL_ROOT)/apps/common/client_common_s.a

CIPHER_OPTION=ID_RSA # The default cipher option
CFLAGS+=-D$(CIPHER_OPTION)

ifdef DTLS_PACKET_LOSS_TEST
# Enable all packet-loss related tests
CFLAGS+=-DDTLS_PACKET_LOSS_TEST -DTEST_DTLS_CLIENT_REHANDSHAKE=1 -DDTLS_TEST_LOST_CIPHERSPEC_CHANGE_REHANDSHAKE
endif

all: compile

compile: $(OBJS) $(SERVER_EXE) $(CLIENT_EXE)

# Additional Dependencies
$(OBJS): $(MATRIXSSL_ROOT)/common.mk Makefile $(wildcard *.h)

$(SERVER_EXE): $(SERVER_SRC:.c=.o) $(STATIC)
	$(CC) -o $@ $^ $(LDFLAGS)

$(CLIENT_EXE): $(CLIENT_SRC:.c=.o) $(STATIC) $(STATIC_CLIENT)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(SERVER_EXE) $(CLIENT_EXE) $(OBJS) TLS_*.tmp SSL_*.tmp

