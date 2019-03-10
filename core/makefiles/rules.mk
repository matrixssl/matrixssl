#
#	Build rules file for test applications using CL.
#
#	Copyright (c) 2016-2017 INSIDE Secure Corporation. All Rights Reserved.
#
#       This file is included from Makefile with include rules.mk


# Translate between filenames and variable names.
vname=$(subst -,_,$(subst .,_,$(1)))
vsname=$(subst -,_,$(subst .,_,$(1)))
program_SOURCES=$(call $(call vname,$(1))_SOURCES)

EXTRA_PROGRAMS_V=$(foreach name,$(EXTRA_PROGRAMS) $(noinst_LIBRARIES),$(call vname,$(name)))

# Get API
program_API=$(if $(call $(call vname,$(1))_API),$(call $(call vname,$(1))_API),CL)

# Collect SRC files to objects
SRC:=$(foreach program,$(EXTRA_PROGRAMS) $(noinst_LIBRARIES),$(call program_SOURCES,$(program)))
OBJS=$(addsuffix .o,$(basename $(SRC))) $(EXTRA_OBJ)

$(foreach program,$(EXTRA_PROGRAMS) $(noinst_LIBRARIES),$(if $(call program_SOURCES,$(program)),,$(error no sources defined for $(program))))

RULES_MK=$(CORE_DIR)/makefiles/rules.mk

ifneq '$(USE_EXPORT_LEVEL_CRYPTO)' ''
CPPFLAGS += -DUSE_EXPORT_LEVEL_CRYPTO
endif

# Provide CFLAGS if it has not been specified on command line or base makefile
# and if CFLAGS has not been overriden on command line or env override
ifeq '$(filter file override command automatic,$(origin CFLAGS))' ''
# Build CFLAGS:
ifeq '$(origin DEBUGGABLE)$(origin CFLAGS_DEBUGGABLE)' 'undefinedundefined'
CFLAGS_OPTIMIZE=-O2
endif
CFLAGS_DEBUGGABLE=$(DEBUGGABLE)
CFLAGS_PLATFORM=
CFLAGS_ADDITIONAL=
CFLAGS_CAPABILITIES=
CFLAGS+=$(CFLAGS_STANDARD) $(CFLAGS_DEBUGGABLE) $(CFLAGS_ARCHITECTURE_VARIANT) $(FLAGS_ARCHITECTURE_VARIANT) $(CFLAGS_PLATFORM) $(CFLAGS_ADDITIONAL) $(CFLAGS_EXTRA) $(EXTRA_CFLAGS) $(CFLAGS_WARNINGS) $(CFLAGS_EXTRA_INCLUDE) $(CFLAGS_OPTIMIZE) $(CFLAGS_CAPABILITIES)
endif

# Provide CXXFLAGS if it has not been specified on command line or base makefile
# and if CXXFLAGS has not been overriden on command line or env override
ifeq '$(filter file override command automatic,$(origin CXXFLAGS))' ''
# Build CFLAGS:
ifeq '$(origin DEBUGGABLE)$(origin CXXFLAGS_DEBUGGABLE)' 'undefinedundefined'
CXXFLAGS_OPTIMIZE=-O2
endif
CXXFLAGS_DEBUGGABLE=$(DEBUGGABLE)
CXXFLAGS_PLATFORM=
CXXFLAGS_ADDITIONAL=
CXXFLAGS_CAPABILITIES=
CXXFLAGS+=$(CXXFLAGS_STANDARD) $(CXXFLAGS_DEBUGGABLE) $(CXXFLAGS_ARCHITECTURE_VARIANT) $(FLAGS_ARCHITECTURE_VARIANT) $(CXXFLAGS_PLATFORM) $(CXXFLAGS_ADDITIONAL) $(CXXFLAGS_EXTRA) $(EXTRA_CXXFLAGS) $(CXXFLAGS_WARNINGS) $(CXXFLAGS_EXTRA_INCLUDE) $(CXXFLAGS_OPTIMIZE) $(CXXFLAGS_CAPABILITIES)
endif

ifneq '$(filter file override environment command automatic,$(origin MATRIX_DEBUG))' ''
ifeq '$(MATRIX_DEBUG)' '1'
DEBUGGABLE=-O0 -g -DDEBUG -Wall
CFLAGS_DEBUGGABLE=$(DEBUGGABLE)
CXXFLAGS_DEBUGGABLE=$(DEBUGGABLE)
# When debugging, override OPT.
OPT=
endif
endif

#Override CFLAGS_OPTIMIZE with OPT if specified
ifneq '$(filter file override command automatic,$(origin OPT))' ''
CFLAGS_OPTIMIZE=$(OPT)
CXXFLAGS_OPTIMIZE=$(OPT)
endif


# Provide LDFLAGS if it has not been specified on command line or base makefile
# and if LDFLAGS has not been overriden on command line or env override
ifeq '$(filter file override command automatic,$(origin LDFLAGS))' ''
# Build LDFLAGS:
LDFLAGS_DEBUGGABLE=$(DEBUGGABLE)
LDFLAGS+=$(LDFLAGS_ARCHITECTURE_VARIANT) $(FLAGS_ARCHITECTURE_VARIANT) $(LDFLAGS_DEBUGGABLE) $(LDFLAGS_EXTRA) $(EXTRA_LDFLAGS)
endif

# Extra includes to find core and CL headers
include $(CORE_DIR)/Makefile.inc

# Common dependencies
DL=-ldl
PTHREAD=-lpthread

# API spec for core (only)
core_API_CFLAGS:=$(CFLAGS_CORE_INCLUDE)
core_API_CXXFLAGS:=$(CFLAGS_CORE_INCLUDE)
core_API_LIBADD=$(CORE_DIR)/libcore_s.a $(PTHREAD)

# API spec for software using matrixssl API and/or psCrypto API.
MATRIXSSL_PATH=$(CORE_PATH)/../matrixssl/matrixssl
PSCRYPTO_PATH=$(CORE_PATH)/../matrixssl/crypto
matrixssl_API_CPPFLAGS=-I$(PSCRYPTO_PATH) -I$(MATRIXSSL_PATH) $(CL_API_CPPFLAGS)
matrixssl_API_LIBADD=$(MATRIXSSL_PATH)/libssl_s.a $(PSCRYPTO_PATH)/libcrypt_s.a $(core_API_LIBADD) $(DL) $(PTHREAD)

# API spec for sfzutf tests
sfzutf_API_CFLAGS:=-I$(CORE_PATH)/include/testsupp
sfzutf_API_CXXFLAGS:=-I$(CORE_PATH)/include/testsupp
sfzutf_API_LIBADD=$(CORE_DIR)/libsfzutf_s.a

# API spec for testsupp tests
testsupp_API_CFLAGS:=$(CFLAGS_CORE_INCLUDE) -I$(CORE_PATH)/include/testsupp
testsupp_API_CXXFLAGS:=-I$(CORE_PATH)/include/testsupp
testsupp_API_LIBADD=$(CORE_DIR)/libtestsupp_s.a $(CORE_DIR)/libcore_s.a

# API spec for CL (includes core)
CL_DIR:=$(CORE_DIR)/../CL
CL_API_CPPFLAGS=-I$(CL_DIR)/include $(core_API_CFLAGS)
CL_API_LIBADD=$(CL_DIR)/../CL/libsafezone-sw-common.a $(DL) $(PTHREAD)

# API spec for ASN1 (includes core)
ASN1_DIR:=$(CORE_DIR)/../ASN1
ASN1_API_CPPFLAGS=-I$(ASN1_DIR)/include $(core_API_CFLAGS)
ASN1_API_LIBADD=$(ASN1_DIR)/libasn1_s.a $(CORE_DIR)/libcore_s.a $(PTHREAD)

# API spec for PKCS (includes core)
PKCS_DIR:=$(CORE_DIR)/../PKCS
PKCS_API_CPPFLAGS=-I$(ASN1_DIR)/include -I$(PKCS_DIR)/include \
$(core_API_CFLAGS) \
-DSFZCLDIST_CRYPT_MAC -DCFG_P11_MINI -DCFG_IMPLDEFS_NO_DEBUG 
PKCS_API_LIBADD=$(PKCS_DIR)/libpkcs_s.a $(ASN1_DIR)/libasn1_s.a $(CORE_DIR)/libcore_s.a $(PTHREAD)

# Generated files
EXE=$(EXTRA_PROGRAMS)
LIB=$(noinst_LIBRARIES)

# Linked files
STATICS=
DYNAMIC=

# Add linked files to linking
LOADLIBES+=$(STATICS) $(DYNAMIC) $(EXTRA_LDADD)

all: compile

compile: $(OBJS) $(EXE) $(LIB)

# Additional Dependencies
$(OBJS): GNUmakefile $(RULES_MK) $(wildcard *.h)

# Template for C linking
define LINK_TEMPLATE_C
$(1): $(2) $$(STATICS)
	$$(CC_LD) -o $$@ $(2) $$(call $(3)_LDFLAGS) $$(LDFLAGS) $$(LOADLIBES) $$(call $(3)_PROGRAM_LIBADD) $$(call $(3)_LIBADD) $$(LDADD)
endef

# Template for C++ linking
define LINK_TEMPLATE_CXX
$(1): $(2) $$(STATICS)
	$$(CXX) -o $$@ $(2) $$(call $(3)_LDFLAGS) $$(LDFLAGS) $$(LOADLIBES) $$(call $(3)_PROGRAM_LIBADD) $$(call $(3)_LIBADD) $$(LDADD)
endef

# Template for C compiling
define COMPILE_TEMPLATE_C
$(1): $(2)
	$$(CC) -c -o $$@ $$< $$(call $(3)_CFLAGS) $$(call $(3)_PROGRAM_CFLAGS) $$(CPPFLAGS) $$(CFLAGS)
endef

# Template for C++ compiling
define COMPILE_TEMPLATE_CXX
$(1): $(2)
	$$(CXX) -c -o $$@ $$< $$(call $(3)_CXXFLAGS) $$(call $(3)_PROGRAM_CXXFLAGS) $$(CPPFLAGS) $$(CXXFLAGS)
endef

# Template for archiving
define ARCHIVE_TEMPLATE
$(1): $(2)
	$$(AR) $$(call $(3)_ARFLAGS) $$(ARCOMMAND) $$@ $$^
endef

CC_LD?=$(CC)
AR?=ar

# Get AR flags: use different flags with deterministic and
# non-deterministic ar implementations.
ifeq '$(AR_IS_NONDETERMINISTIC)' ''
AR_IS_NONDETERMINISTIC=$(shell echo foo>foo.o;$(AR) rcD libfoo.a foo.o 2>/dev/null;echo $$?;rm -f libfoo.a foo.o)
endif
# Default: non-deterministic ar
ARCOMMAND=-rcu
ifeq '$(AR_IS_NONDETERMINISTIC)' '0'
# Deterministic ar (common in newer linux distributions).
ARCOMMAND=rcD
endif

# Configure libraries and header dependencies to accommodate the program needs.
$(foreach program,$(EXTRA_PROGRAMS) $(noinst_LIBRARIES),$(foreach api,$(call program_API,$(program)),$(eval $(call vname,$(program))_PROGRAM_CPPFLAGS+=$(call $(api)_API_CPPFLAGS))))
$(foreach program,$(EXTRA_PROGRAMS) $(noinst_LIBRARIES),$(foreach api,$(call program_API,$(program)),$(eval $(call vname,$(program))_PROGRAM_CFLAGS+=$(call $(api)_API_CFLAGS))))
$(foreach program,$(EXTRA_PROGRAMS) $(noinst_LIBRARIES),$(foreach api,$(call program_API,$(program)),$(eval $(call vname,$(program))_PROGRAM_CXXFLAGS+=$(call $(api)_API_CXXFLAGS))))
$(foreach program,$(EXTRA_PROGRAMS) $(noinst_LIBRARIES),$(foreach api,$(call program_API,$(program)),$(eval $(call vname,$(program))_PROGRAM_LDFLAGS+=$(call $(api)_API_LDFLAGS))))
$(foreach program,$(EXTRA_PROGRAMS) $(noinst_LIBRARIES),$(foreach api,$(call program_API,$(program)),$(eval $(call vname,$(program))_PROGRAM_LIBADD+=$(call $(api)_API_LIBADD))))

# provide program flags for sources
# Note: if a source is in many programs, it will get all combination of flags.
$(foreach program,$(EXTRA_PROGRAMS) $(noinst_LIBRARIES),$(foreach source,$(filter %.c, $(call program_SOURCES,$(program))),$(eval $(call vsname,$(source))_PROGRAM_CFLAGS+=$$($(call vname,$(program))_PROGRAM_CPPFLAGS) $$($(call vname,$(program))_PROGRAM_CFLAGS) $$($(call vname,$(program))_CPPFLAGS) $$($(call vname,$(program))_CFLAGS))))
$(foreach program,$(EXTRA_PROGRAMS) $(noinst_LIBRARIES),$(foreach source,$(filter %.cc, $(call program_SOURCES,$(program))),$(eval $(call vsname,$(source))_PROGRAM_CXXFLAGS+=$$($(call vname,$(program))_PROGRAM_CPPFLAGS) $$($(call vname,$(program))_PROGRAM_CXXFLAGS) $$($(call vname,$(program))_CPPFLAGS) $$($(call vname,$(program))_CXXFLAGS))))

# Construct compiler command.
SRC_C:=$(foreach program,$(EXTRA_PROGRAMS_V),$(filter %.c, $(call program_SOURCES,$(program))))
SRC_CXX:=$(foreach program,$(EXTRA_PROGRAMS_V),$(filter %.cc, $(call program_SOURCES,$(program))))
$(foreach source,$(SRC_C),$(eval $(call COMPILE_TEMPLATE_C,$(source:%.c=%.o),$(source),$(call vsname,$(source)))))
$(foreach source,$(SRC_CXX),$(eval $(call COMPILE_TEMPLATE_CXX,$(source:%.cc=%.o),$(source),$(call vsname,$(source)))))

# Construct linker command. The linker command will use C++ (for symbol
# mangling support) if any of source files are C++.
$(foreach program,$(EXTRA_PROGRAMS),$(eval $(call $(if $(filter %.cc, $(call program_SOURCES,$(program))),LINK_TEMPLATE_CXX,LINK_TEMPLATE_C),$(program),$(patsubst %.cc,%.o,$(filter %.cc, $(call program_SOURCES,$(program)))) $(patsubst %.c,%.o,$(filter-out %.cc, $(call program_SOURCES,$(program)))),$(call vname,$(program)))))

# Construct archive
$(foreach program,$(noinst_LIBRARIES),$(eval $(call $(if $(filter %.cc, $(call program_SOURCES,$(program))),ARCHIVE_TEMPLATE,ARCHIVE_TEMPLATE),$(program),$(patsubst %.cc,%.o,$(filter %.cc, $(call program_SOURCES,$(program)))) $(patsubst %.c,%.o,$(filter-out %.cc, $(call program_SOURCES,$(program)))),$(call vname,$(program)))))

clean:
	rm -f $(OBJS) $(EXE) $(LIB)
