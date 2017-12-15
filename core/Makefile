#
#	Makefile for core static library
#
#	Copyright (c) 2013-2016 INSIDE Secure Corporation. All Rights Reserved.
#

MATRIXSSL_ROOT:=..
include $(MATRIXSSL_ROOT)/common.mk

SRC:=\
	memset_s.c \
	corelib.c \
	psbuf.c \
	psUtil.c \
	$(OSDEP)/osdep.c \
	$(OSDEP)/psLog.c \
	$(OSDEP)/psPrnf.c

ASM:=memset_s.s

# Generated files
STATIC:=libcore_s.a

CFLAGS+=$(CFLAGS_ARCHITECTURE_VARIANT) $(FLAGS_ARCHITECTURE_VARIANT)
LDFLAGS+=$(LDFLAGS_ARCHITECTURE_VARIANT) $(FLAGS_ARCHITECTURE_VARIANT)

all: compile

compile: $(ASM) $(OBJS) $(STATIC)

# Special rule to build memset_s function without optimization
memset_s.o: memset_s.c
	$(CC) -O0 -Wall -ffunction-sections -fdata-sections -o $@ $(CFLAGS_MEMSET_S) $(CFLAGS_ARCHITECTURE_VARIANT) $(FLAGS_ARCHITECTURE_VARIANT) -c $<

# Generate the (.s) assembly file to verify zero is being performed
$(ASM): memset_s.c
	$(CC) -O0 -g -fverbose-asm $(CFLAGS_MEMSET_S) $(ASFLAGS_ARCHITECTURE_VARIANT) $(FLAGS_ARCHITECTURE_VARIANT) -S $<

# Additional Dependencies
$(OBJS): $(MATRIXSSL_ROOT)/common.mk Makefile *.h

# Build the static library

$(STATIC): $(OBJS)
	$(AR) -rcu $@ $^

clean:
	rm -f $(STATIC) $(OBJS) $(ASM)

# Allows to check configuration options.
parse-config:
	echo '#include "coreConfig.h"' | $(CC) $(CFLAGS) -dM -E -x c -
