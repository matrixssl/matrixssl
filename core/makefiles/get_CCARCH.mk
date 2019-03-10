# Get or detect compilation architecture.

# Detect target architecture
ifeq '$(CCARCH)' ''
CCARCH:=$(shell $(CLEAN_ENV) $(CC) $(CFLAGS_ARCHITECTURE_VARIANT) $(FLAGS_ARCHITECTURE_VARIANT) -print-multiarch)
ifeq '$(CCARCH)' ''
CCARCH:=$(shell $(CLEAN_ENV) $(CC) -v 2>&1 | sed -n '/Target: / s/// p')
ifeq '$(CCARCH)' ''
# Could not obtain target triplet: Try still -dumpmachine (supported by
# some versions of GCC)
CCARCH:=$(shell $(CLEAN_ENV) $(CC) -dumpmachine)

ARM_ARCH ?= armv7-a

ifeq '$(CCARCH)' ''
$(error Unable to determine compiler architecture.)
$(CC) $(CFLAGS_ARCHITECTURE_VARIANT) $(FLAGS_ARCHITECTURE_VARIANT) -print-multiarch or $(CC) -v or $(CC) -dumpmachine does not work. Please, provide CCARCH manually via an environment variable.)
endif
endif
endif
ifeq '$(CCARCH_PRINTED)' ''
ifeq ($(origin CCARCH),file)
ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),clobber)
ifneq ($(MAKECMDGOALS),get-CCARCH)
ifneq ($(MAKECMDGOALS),print-CCARCH)
$(info Compiling target architecture: $(CCARCH))
$(info If this is incorrect, provide the CCARCH variable manually to make.)
CCARCH_PRINTED=1
export CCARCH_PRINTED
endif
endif
endif
endif
endif
endif
endif

CPU_GUESS=1
CPU_BITS=32
ifneq (,$(findstring x86_64-,$(CCARCH)))
CPU_ARCHITECTURE_FAMILY=x86
CPU_BITS=64
CPU_GUESS=
endif
ifneq (,$(findstring i686-,$(CCARCH)))
CPU_ARCHITECTURE_FAMILY=x86
CPU_GUESS=
endif
ifneq (,$(findstring i586-,$(CCARCH)))
CPU_ARCHITECTURE_FAMILY=x86
CPU_GUESS=
endif
ifneq (,$(findstring i486-,$(CCARCH)))
CPU_ARCHITECTURE_FAMILY=x86
CPU_GUESS=
endif
ifneq (,$(findstring i386-,$(CCARCH)))
CPU_ARCHITECTURE_FAMILY=x86
CPU_GUESS=
endif
ifneq (,$(findstring arm,$(CCARCH)))
CPPFLAGS_EXTRACT_MACROS=-dM
NEON=$(shell $(CC) $(CPPFLAGS_EXTRACT_MACROS) -E - </dev/null |grep NEON)
CPU_ARCHITECTURE_FAMILY=arm
CPU_BITS=32
CPU_GUESS=
endif
ifneq (,$(findstring aarch64,$(CCARCH)))
CPU_ARCHITECTURE_FAMILY=aarch64
CPU_BITS=64
CPU_GUESS=
endif

ifeq '$(MAKECMDGOALS)' 'print-CCARCH'

.phony: print-CCARCH
print-CCARCH:
	@echo Detected CCARCH: $(CCARCH)
	@echo Detected CPU_ARCHITECTURE_FAMILY: $(CPU_ARCHITECTURE_FAMILY)
	@echo Detected CPU_BITS: $(CPU_BITS)
endif

ifeq '$(MAKECMDGOALS)' 'get-CCARCH'

.phony: get-CCARCH
get-CCARCH:
	@echo $(CCARCH)
endif
