##
# Optional libsodium inclusion.
# @version $Format:%h%d$
# Copyright (c) 2017 INSIDE Secure Corporation. All Rights Reserved.
#
#-------------------------------------------------------------------------------

# MatrixSSL supports importing some cryptographic algorithms from libsodium.
# TODO: Allow more control over libsodium unpacking process.
# Currently only control options are LIBSODIUM_CONFIGURE_ENVIRONMENT and
# LIBSODIUM_CONFIGURE_ARGUMENTS to set environment variables and configuration
# for compilation.

THIRDPARTY_DIRECTORY=$(COMMON_MK_PATH)/thirdparty

ifneq "$(wildcard $(THIRDPARTY_DIRECTORY)/libsodium-1.0.8.tar.gz)" ""
# Has libsodium 1.0.8.
ifeq "$(wildcard $(THIRDPARTY_DIRECTORY)/libsodium-1.0.8)" ""
ifeq (,$(filter clean clobber parse-config,$(MAKECMDGOALS)))
# libsodium is not unpacked.
$(warning automatically unpacking, configuring and compiling thirdparty/libsodium-1.0.8)
UNPACK_AND_COMPILE:=$(shell cd $(THIRDPARTY_DIRECTORY);tar zxf libsodium-1.0.8.tar.gz && cd libsodium-1.0.8 && $(LIBSODIUM_CONFIGURE_ENVIRONMENT) ./configure $(LIBSODIUM_CONFIGURE_ARGUMENTS) && make)
endif
endif
endif

ifneq "$(wildcard $(THIRDPARTY_DIRECTORY)/libsodium-1.0.8)" ""
USE_LIBSODIUM_CRYPTO:=1
LIBSODIUM_ROOT=$(THIRDPARTY_DIRECTORY)/libsodium-1.0.8/src/libsodium
endif

ifneq "$(wildcard $(THIRDPARTY_DIRECTORY)/libsodium-1.0.12.tar.gz)" ""
# Has libsodium 1.0.12.
ifeq "$(wildcard $(THIRDPARTY_DIRECTORY)/libsodium-1.0.12)" ""
ifeq (,$(filter clean clobber parse-config rebuild,$(MAKECMDGOALS)))
# libsodium is not unpacked.
$(warning automatically unpacking, configuring and compiling thirdparty/libsodium-1.0.12)
UNPACK_AND_COMPILE:=$(shell cd $(THIRDPARTY_DIRECTORY);tar zxf libsodium-1.0.12.tar.gz && cd libsodium-1.0.12 && $(LIBSODIUM_CONFIGURE_ENVIRONMENT) ./configure $(LIBSODIUM_CONFIGURE_ARGUMENTS) && make)
endif
endif
endif

ifneq "$(wildcard $(THIRDPARTY_DIRECTORY)/libsodium-1.0.12)" ""
USE_LIBSODIUM_CRYPTO:=1
LIBSODIUM_ROOT=$(THIRDPARTY_DIRECTORY)/libsodium-1.0.12/src/libsodium
endif

ifeq (,$(filter rebuild,$(MAKECMDGOALS)))
 ifdef USE_LIBSODIUM_CRYPTO
  ifdef LIBSODIUM_ROOT
   # Statically link against a given libsodium
   CFLAGS_LIBSODIUM=-DUSE_LIBSODIUM_CRYPTO -I$(LIBSODIUM_ROOT)/include
   LDFLAGS_LIBSODIUM=$(LIBSODIUM_ROOT)/.libs/libsodium.a
   STROPTS_LIBSODIUM=", USE_LIBSODIUM_CRYPTO"
   STROPTS+=$(STROPTS_LIBSODIUM)
   CFLAGS_MAKEFILES+=$(CFLAGS_LIBSODIUM)
   LDFLAGS_MAKEFILES+=$(LDFLAGS_LIBSODIUM)
   PS_LIBSODIUM:=1
  endif
  ifndef LIBSODIUM_ROOT
   # No library path defined regardless of USE_LIBSODIUM_CRYPTO being defined.
   $(error Please define LIBSODIUM_ROOT)
  endif
 endif
endif
