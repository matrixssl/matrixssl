#
#	Path and linkage information for core static library
#
#	Copyright (c) 2017 INSIDE Secure. All Rights Reserved.
#

# This Makefile.inc is used from other Makefiles to reference
# parts of the core library.

# Find path of the current directory (unless previously specified)
ifeq '$(origin CORE_PATH)' 'undefined'
CORE_PATH:=$(patsubst %/,%/,$(dir $(lastword $(MAKEFILE_LIST))))
endif

# Find path of the core module
CFLAGS_CORE_INCLUDE=\
-I$(CORE_PATH)/config -I$(CORE_PATH)/include -I$(CORE_PATH)/osdep/include \
-I$(CORE_PATH)/include/sfzcl -I$(CORE_PATH)/osdep/include

LIB_CORE_S=$(CORE_PATH)/libcore_s.a
LDADD_CORE_S=$(CORE_PATH)/libcore_s.a -lpthread
