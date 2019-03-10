##
# Support for platform specific build instructions.
# @version $Format:%h%d$
# Copyright (c) 2013-2017 INSIDE Secure Corporation. All Rights Reserved.
#
#-------------------------------------------------------------------------------

# If CCARCH has not been requested yet, request it.
ifeq '$(CPU_BITS)' ''
include makefiles/get_CCARCH.mk
endif

# Detect flags to enable NEON capability
ifneq (,$(findstring arm,$(CCARCH)))
CPPFLAGS_EXTRACT_MACROS=-dM
NEON_VARIANT=$(shell $(CC) -march=armv7-a -mfpu=neon $(CPPFLAGS_EXTRACT_MACROS) -E - </dev/null |grep NEON)
ifneq (,$(NEON_VARIANT))
# Detected neon in C compiler output => do not set float abi.
CFLAGS_ENABLE_NEON=-march=armv7-a -mfpu=neon
else
# No neon mentioned. Request float abi to be softfp.
CFLAGS_ENABLE_NEON=$(CFLAGS_ARCHITECTURE_VARIANT) -mfloat-abi=softfp -mfpu=neon
endif
endif

CFLAGS_PIC_OPTION=-fPIC
CFLAGS_POSITION_INDEPENDENT=$(CFLAGS_PIC_OPTION)
