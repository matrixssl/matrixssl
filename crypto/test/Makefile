#
#	Makefile for crypto testing
#   'make' builds debug (Default).
#   'make gold' builds optimized.
#
#	Copyright (c) PeerSec Networks, 2002-2010. All Rights Reserved
#	Copyright (c) 2013-2017 INSIDE Secure Corporation. All Rights Reserved.
#

MATRIXSSL_ROOT:=../..

VECTOR_SRC:=algorithmTest.c
SPEED_SRC:=throughputTest.c
SRC:=$(VECTOR_SRC) $(SPEED_SRC)

VECTOR_EXE:=algorithmTest$(E)
SPEED_EXE:=throughputTest$(E)
EXE:=$(VECTOR_EXE) $(SPEED_EXE)

CRYPTOOPEN_SRC:=cryptoOpen.c
CRYPTOOPEN_EXE:=cryptoOpen$(E)
SRC+=$(CRYPTOOPEN_SRC)
EXE+=$(CRYPTOOPEN_EXE)

ECCTEST_SRC:=eccTest.c
ECCTEST_EXE:=eccTest$(E)
SRC+=$(ECCTEST_SRC)
EXE+=$(ECCTEST_EXE)

RSATEST_SRC:=rsaTest.c
RSATEST_EXE:=rsaTest$(E)
SRC+=$(RSATEST_SRC)
EXE+=$(RSATEST_EXE)

HMACTEST_SRC:=hmacTest.c
HMACTEST_EXE:=hmacTest$(E)
SRC+=$(HMACTEST_SRC)
EXE+=$(HMACTEST_EXE)

include $(MATRIXSSL_ROOT)/common.mk

# Linked files
STATICS:=../libcrypt_s.a $(MATRIXSSL_ROOT)/core/libcore_s.a

all: compile

compile: $(OBJS) $(EXE)
	if [ -e rsaperf ]; then $(MAKE) --directory=rsaperf; fi
	if [ -e eccperf ]; then $(MAKE) --directory=eccperf; fi
	if [ -e dhperf ]; then $(MAKE) --directory=dhperf; fi
	if [ -e clperf ]; then $(MAKE) --directory=clperf; fi

# Additional Dependencies
$(OBJS): $(MATRIXSSL_ROOT)/common.mk Makefile $(wildcard *.h)

$(SPEED_EXE): $(SPEED_SRC:.c=.o) $(STATICS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(VECTOR_EXE): $(VECTOR_SRC:.c=.o) $(STATICS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(CRYPTOOPEN_EXE): $(CRYPTOOPEN_SRC:.c=.o) $(STATICS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(ECCTEST_EXE): $(ECCTEST_SRC:.c=.o) $(STATICS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(RSATEST_EXE): $(RSATEST_SRC:.c=.o) $(STATICS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(HMACTEST_EXE): $(HMACTEST_SRC:.c=.o) $(STATICS)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(EXE) $(OBJS)
	if [ -e rsaperf ]; then $(MAKE) clean --directory=rsaperf;fi
	if [ -e eccperf ]; then $(MAKE) clean --directory=eccperf;fi
	if [ -e dhperf ]; then $(MAKE) clean --directory=dhperf;fi
	if [ -e clperf ]; then $(MAKE) clean --directory=clperf;fi
