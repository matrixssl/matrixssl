##
# Environment detection: detect flags for ar.
# @version $Format:%h%d$
# Copyright (c) 2018 INSIDE Secure Oy. All Rights Reserved.
#
#-------------------------------------------------------------------------------

# Set AR variable unless already available.
AR?=ar

# Get AR flags: use different flags with deterministic and
# non-deterministic ar implementations.
ifeq '$(AR_IS_NONDETERMINISTIC)' ''
AR_IS_NONDETERMINISTIC:=$(shell echo foo>foo.o;$(AR) rcD libfoo.a foo.o 2>/dev/null;echo $$?;rm -f libfoo.a foo.o)
export AR_IS_NONDETERMINISTIC
ifneq '$(AR_IS_NONDETERMINISTIC)' ''
AR_DETECTED=1
endif
endif
# Default: non-deterministic ar
ARCOMMAND=-rcu
ifeq '$(AR_IS_NONDETERMINISTIC)' '0'
# Deterministic ar (common in newer linux distributions).
ARCOMMAND=rcD
endif

# Allow build message for detected AR arguments.
ifeq '$(AR_DETECTED)' '1'
ifeq '$(AR_DETECTION_VERBOSE)' '1'
$(info ar command detected: $(AR) $(ARCOMMAND))
endif
AR_DETECTED=0
endif
