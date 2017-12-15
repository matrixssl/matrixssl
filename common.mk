##
# Common Makefile definitions.
# @version $Format:%h%d$
# Copyright (c) 2013-2017 INSIDE Secure Corporation. All Rights Reserved.
#
#-------------------------------------------------------------------------------

# Allow building inclusion paths relative to location of common.mk file.
COMMON_MK_PATH:=$(dir $(lastword $(MAKEFILE_LIST)))

# Allow extra CFLAGS, CPPFLAGS and LDFLAGS to be used.
CFLAGS_DEBUGGABLE=$(DEBUGGABLE)
CPPFLAGS_DEBUGGABLE=$(DEBUGGABLE)
LDFLAGS += $(EXTRA_LDFLAGS) $(LDFLAGS_MAKEFILES)
CFLAGS += $(CFLAGS_STANDARD) $(CFLAGS_PLATFORM) $(CFLAGS_ADDITIONAL) $(CFLAGS_WARNINGS) $(CFLAGS_CPU) $(CFLAGS_ASM) $(CFLAGS_PROFILE) $(CFLAGS_MAKEFILES) $(CFLAGS_DEBUGGABLE) $(CFLAGS_EXTRA) $(EXTRA_CFLAGS)
CPPFLAGS += $(CPPFLAGS_STANDARD) $(CPPFLAGS_PLATFORM) $(CPPFLAGS_ADDITIONAL) $(CPPFLAGS_WARNINGS) $(CPPFLAGS_CPU) $(CPPFLAGS_CPPPU) $(CPPFLAGS_ASM) $(CPPFLAGS_PROFILE) $(CPPFLAGS_MAKEFILES) $(CPPFLAGS_DEBUGGABLE) $(CPPFLAGS_EXTRA) $(EXTRA_CPPFLAGS)

#-------------------------------------------------------------------------------
## Makefile variables that must be defined in this file
# @param[out] $(BUILD) Set here for release or debug
BUILD:=release  ##< Release build strips binary and optimizes
#BUILD:=debug 	##< Debug build keeps debug symbols and disables compiler optimizations. Assembly language optimizations remain enabled

#-------------------------------------------------------------------------------
## Makefile variables that are read by this file.
# @param[in] $(MATRIXSSL_ROOT) Must be set to root MatrixSSL directory
# @param[in] $(CC) Used to determine the target platform, which will differ
# from host if cross compiling.
# @param[in] $(CPU) If set, should be the target cpu for the compiler,
# suitable for the '-mcpu=' flag. See 'gcc --help=target' for valid values.
# @param[in] $(SRC) List of source files to be compiled. Used to make $(OBJS),
# the list of object files to build.

#-------------------------------------------------------------------------------
## Makefile variables that are modified by this file
# @param[in,out] $(CFLAGS) Appended with many options as determined by this file, to be passed to compiler
# @param[in,out] $(LDFLAGS) Appended with many options as determined by this file, to be passed to linker

#-------------------------------------------------------------------------------
## Makefile variables that are created by this file
# @param[out] $(OSDEP) Set to platform code directory (./core/$OSDEP/osdep.c), based on $(CC)
# @param[out] $(CCARCH) Set to compilers target architecture, based on $(CC)
# @param[out] $(STRIP) Set to the executable to use to strip debug symbols from executables
# @param[out] $(STROPS) Human readable description of relevant MatrixSSL compile options.
# @param[out] $(O) Set to the target platform specific object file extension
# @param[out] $(A) Set to the target phatform specific static library (archive) file extension
# @param[out] $(E) Set to the target platform specific executable file extension
# @param[out] $(OBJS) Set to the list of objects that is to be built

#-------------------------------------------------------------------------------

## Auto-detect cross compiler for some platforms based on environment variables

# Execute commands in environment with default locale.
CLEAN_ENV=LC_ALL=POSIX

## Based on the value of CC, determine the target, eg.
#  x86_64-redhat-linux
#  i686-linux-gnu
#  x86_64-apple-darwin14.0.0
#  arm-linux-gnueabi
#  arm-linux-gnueabihf
#  arm-none-eabi
#  mips-linux-gnu
#  mipsisa64-octeon-elf-gcc
#  powerpc-linux-gnu
#  i386-redhat-linux
#  x86_64-redhat-linux
ifeq '$(CCARCH)' ''
CCARCH:=$(shell $(CLEAN_ENV) $(CC) $(CFLAGS_ARCHITECTURE_VARIANT) $(FLAGS_ARCHITECTURE_VARIANT) -print-multiarch)
ifeq '$(CCARCH)' ''
CCARCH:=$(shell $(CLEAN_ENV) $(CC) -v 2>&1 | sed -n '/Target: / s/// p')
ifeq '$(CCARCH)' ''
# Could not obtain target triplet: Try still -dumpmachine (supported by
# some versions of GCC)
CCARCH:=$(shell $(CLEAN_ENV) $(CC) -dumpmachine)
ifeq '$(CCARCH)' ''
$(error Unable to determine compiler architecture.
$(CC) $(CFLAGS_ARCHITECTURE_VARIANT) $(FLAGS_ARCHITECTURE_VARIANT) -print-multiarch or $(CC) -v or $(CC) -dumpmachine does not work. Please, provide CCARCH manually via an environment variable.)
endif
endif
endif
ifeq ($(origin CCARCH),file)
ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),clobber)
$(info Compiling target architecture: $(CCARCH))
$(info If this is incorrect, provide the CCARCH variable manually to make.)
endif
endif
endif
endif
CCVER:=$(shell $(CC) --version 2>&1)
STROPTS:="Built for $(CCARCH)"

## uname of the Host environment, eg.
#  Linux
#  Darwin
# @note Unused
#UNAME:=$(shell uname)

## Standard file extensions for Linux/OS X.
O:=.o
A:=.a
E=

# Check if this version of make supports undefine
ifneq (,$(findstring undefine,$(.FEATURES)))
 HAVE_UNDEFINE:=1
endif

#On OS X, Xcode sets CURRENT_VARIANT to normal, debug or profile
ifneq (,$(findstring -apple,$(CCARCH)))
 ifneq (,$(findstring ebug,$(CONFIGURATION)))
  MATRIX_DEBUG:=1
 endif
endif

# Select options affecting C language and API standards to enable.
C_STD:=
ifneq (,$(findstring (GCC),$(CCVER)))
 ifneq (,$(findstring 3.4,$(CCVER)))
  # Enable linux platform extensions for APIs and provide the length of
  # types.
  # Also remove spurious warnings on some opaque types
  ifneq (,$(findstring x86_64,$(CCARCH)))
   C_STD := -D_GNU_SOURCE -D__SIZEOF_LONG_LONG__=8 -DSIZEOF_LONG=8
  else
   C_STD := -D_GNU_SOURCE -D__SIZEOF_LONG_LONG__=8 -DSIZEOF_LONG=4
  endif
 endif
endif

#Manually enable debug here
#MATRIX_DEBUG:=1

ifdef MATRIX_DEBUG
 OPT:=-O0 -g -DDEBUG -Wall
 #OPT+=-Wconversion
 STRIP:=test # no-op
endif
ifndef MATRIX_DEBUG
 OPT:=-O3 -Wall		# Default compile for speed
 ifneq (,$(findstring -none,$(CCARCH)))
  OPT:=-Os -Wall	# Compile bare-metal for size
 endif
 STRIP:=strip
endif
CFLAGS+=$(OPT) $(C_STD)

ifdef MATRIX_SSL_TRACE
 CFLAGS+=-DUSE_SSL_HANDSHAKE_MSG_TRACE
 CFLAGS+=-DUSE_SSL_INFORMATIONAL_TRACE
 CFLAGS+=-DUSE_DTLS_DEBUG_TRACE
endif

ifeq "$(COMMON_MK_NO_TARGETS)" ""
default: $(BUILD)

debug:
	@$(MAKE) compile "MATRIX_DEBUG=1"

release:
	@$(MAKE) $(JOBS) compile
endif

ifeq ($(SSH_PACKAGE),1)
 CFLAGS+=-DSSH_PACKAGE
endif

# 64 Bit Intel Target
ifneq (,$(findstring x86_64-,$(CCARCH)))
 CFLAGS_ARCHITECTURE_VARIANT=-m64
 STROPTS+=", 64-bit Intel RSA/ECC ASM"
 # Provide flags for AES-NI if the host supports it (assumes Host is Target)
 ifneq (,$(findstring -linux,$(CCARCH)))
  ifeq ($(shell grep -o -m1 aes /proc/cpuinfo),aes)
   CFLAGS_ENABLE_AESNI=-maes -mpclmul -msse4.1
   CFLAGS_ENABLE_AES=-maes
   CFLAGS+=$(CFLAGS_ENABLE_AES)
   STROPTS+=", AES-NI ASM"
  endif
 endif
 ifneq (,$(findstring apple,$(CCARCH)))
  ifeq ($(shell sysctl -n hw.optional.aes),1)
   CFLAGS_ENABLE_AESNI=-maes -mpclmul -msse4.1
   CFLAGS_ENABLE_AES=-maes
   CFLAGS+=$(CFLAGS_ENABLE_AES)
   STROPTS+=", AES-NI ASM"
  endif
 endif
endif

# 32 Bit Intel Target
ifneq (,$(findstring i586-,$(CCARCH)))
 CFLAGS_ARCHITECTURE_VARIANT=-m32
 ifneq (,$(findstring edison,$(shell uname -n)))
  ifneq (,$(findstring -O3,$(OPT)))
   #Edison does not like -O3
   OPT:=-O2
  endif
  CFLAGS+=-DEDISON
  CFLAGS_ENABLE_AESNI=-maes -mpclmul -msse4.1
  CFLAGS_ENABLE_AES=-maes
  CFLAGS+=$(CFLAGS_ENABLE_AES)
  STROPTS+=", 32-bit Intel RSA/ECC ASM, AES-NI ASM, Intel Edison"
 else
  STROPTS+=", 32-bit Intel RSA/ECC ASM"
 endif
endif

# 32 Bit Intel Target Alternate
ifneq (,$(findstring i686-,$(CCARCH)))
 CFLAGS_ARCHITECTURE_VARIANT=-m32
 STROPTS+=", 32-bit Intel RSA/ECC ASM"
endif
ifneq (,$(findstring i386-,$(CCARCH)))
 STROPTS+=", 32-bit Intel RSA/ECC ASM"
endif

# MIPS Target
ifneq (,$(findstring mips-,$(CCARCH)))
 STROPTS+=", 32-bit MIPS RSA/ECC ASM"
endif

# MIPS64 Target
ifneq (,$(filter mips%64-,$(CCARCH)))
endif

# ARM Target
ifneq (,$(findstring arm,$(CCARCH)))
 STROPTS+=", 32-bit ARM RSA/ECC ASM"
 ifneq (,$(findstring linux-,$(CCARCH)))
  HARDWARE:=$(shell sed -n '/Hardware[ \t]*: / s/// p' /proc/cpuinfo)
  # Raspberry Pi Host and Target
  ifneq (,$(findstring BCM2708,$(HARDWARE)))
   CFLAGS+=-DRASPBERRYPI -mfpu=vfp -mfloat-abi=hard -ffast-math -march=armv6zk -mtune=arm1176jzf-s
   STROPTS+=", Raspberry Pi"
  endif
  # Raspberry Pi 2 Host and Target
  ifneq (,$(findstring BCM2709,$(HARDWARE)))
   ifneq (,$(findstring 4.6,$(CCVER)))
    CFLAGS+=-march=armv7-a
   else
    # Newer gcc (4.8+ supports this cpu type)
    CFLAGS+=-mcpu=cortex-a7
   endif
   CFLAGS+=-DRASPBERRYPI2 -mfpu=neon-vfpv4 -mfloat-abi=hard
   STROPTS+=", Raspberry Pi2"
  endif
  # Beagleboard/Beaglebone Host and Target
  ifneq (,$(findstring AM33XX,$(HARDWARE)))
   CFLAGS+=-BEAGLEBOARD -mfpu=neon -mfloat-abi=hard -ffast-math -march=armv7-a -mtune=cortex-a8
   STROPTS+=", Beagleboard"
  endif
  # Samsung Exynos 5 (Can also -mtune=cortex-a15 or a8)
  ifneq (,$(findstring EXYNOS5,$(HARDWARE)))
   CFLAGS+=-DEXYNOS5 -mfpu=neon -mfloat-abi=hard -ffast-math -march=armv7-a
   STROPTS+=", Exynos 5"
  endif
  ifdef HAVE_UNDEFINE
   undefine HARDWARE
  endif
 endif
endif

CFLAGS_GARBAGE_COLLECTION=-ffunction-sections -fdata-sections
ifdef MATRIX_DEBUG
CFLAGS+=$(CFLAGS_GARBAGE_COLLECTION)
endif
ifndef MATRIX_DEBUG
CFLAGS_OMIT_FRAMEPOINTER=-fomit-frame-pointer
CFLAGS+=$(CFLAGS_GARBAGE_COLLECTION) $(CFLAGS_OMIT_FRAMEPOINTER)
endif

# If we are using clang (it may be invoked via 'cc' or 'gcc'),
#  handle minor differences in compiler behavior vs. gcc
ifneq (,$(findstring clang,$(CCVER)))
 CFLAGS+=-Wno-error=unused-variable -Wno-error=\#warnings -Wno-error=\#pragma-messages
endif

# Handle differences between the OS X ld and GNU ld
ifneq (,$(findstring -apple,$(CCARCH)))
 LDFLAGS_GARBAGE_COLLECTION=-Wl,-dead_strip
else
 LDFLAGS_GARBAGE_COLLECTION+=-Wl,--gc-sections
endif

# Optionally turn on garbage collection.
ifeq '$(NO_LINKER_GARBAGE_COLLECTION)' ''
LDFLAGS += $(LDFLAGS_GARBAGE_COLLECTION)
endif

CFLAGS+=-I$(MATRIXSSL_ROOT)

#ifdef USE_OPENSSL_CRYPTO
#USE_OPENSSL_CRYPTO:=1
ifdef USE_OPENSSL_CRYPTO
 OPENSSL_ROOT:=/opt/openssl-1.0.2d
 ifdef OPENSSL_ROOT
  # Statically link against a given openssl tree
  CFLAGS+=-I$(OPENSSL_ROOT)/include
  LDFLAGS+=$(OPENSSL_ROOT)/libcrypto.a -ldl
 endif
 ifneq (,$(findstring -apple,$(CCARCH)))
  # Dynamically link against the system default openssl tree
  # Apple has deprecated the built in openssl, so suppress warnings here
  CFLAGS+=-Wno-error=deprecated-declarations -Wno-deprecated-declarations
  LDFLAGS+=-lcrypto
  OPENSSL_ROOT=included_in_the_OS
 endif
 ifneq (,$(findstring -linux,$(CCARCH)))
  # Dynamically link against the sytem default openssl tree
  LDFLAGS+=-lcrypto
  OPENSSL_ROOT=shall_be_included_in_distribution
 endif
 ifndef OPENSSL_ROOT
  $(error Please define OPENSSL_ROOT)
 endif
 CFLAGS+=-DUSE_OPENSSL_CRYPTO
 STROPTS+=", USE_OPENSSL_CRYPTO"
endif
#endif

# Include optional support for libsodium
-include $(COMMON_MK_PATH)/makefiles/libsodium_support.mk

# Linux Target
ifneq (,$(findstring -linux,$(CCARCH)))
 OSDEP:=POSIX
 #For USE_HIGHRES_TIME
 LDFLAGS+=-lrt
 #For multithreading
 LDFLAGS+=-lpthread
endif

# OS X Target
ifneq (,$(findstring -apple,$(CCARCH)))
 OSDEP:=POSIX
 CFLAGS+=-isystem -I/usr/include
endif

# Bare Metal / RTOS Target
ifneq (,$(findstring -none,$(CCARCH)))
 OSDEP:=METAL
 CFLAGS+=-fno-exceptions -fno-unwind-tables -fno-non-call-exceptions -fno-asynchronous-unwind-tables -ffreestanding -fno-builtin -nostartfiles
 ifneq (,$(findstring cortex-,$(CPU)))
  CFLAGS+=-mthumb -mcpu=$(CPU) -mslow-flash-data
  ifeq (cortex-m4,$(CPU))
   CFLAGS+=-mcpu=cortex-m4 -mtune=cortex-m4
  endif
  ifeq (cortex-m3,$(CPU))
   CFLAGS+=-mcpu=cortex-m3 -mtune=cortex-m3 -mfpu=vpf
  endif
  ifeq (cortex-m0,$(CPU))
   CFLAGS+=-mcpu=cortex-m0 -mtune=cortex-m0 -mfpu=vpf
  endif
 endif
endif

# This must be defined after OSDEP, because core/Makefile uses OSDEP in SRC
OBJS=$(SRC:.c=.o) $(SRC:.S:*.o)

# Remove extra spaces in CFLAGS
#CFLAGS=$(strip $(CFLAGS))

ifneq (,$(filter defines,$(MAKECMDGOALS)))
# Display the precompiler defines for the current build settings
# The rule is only available if explicitly requested on command line.

defines:
	:| $(CC) $(CFLAGS) -dM -E -x c -
endif

# Introduce here paths to additional build files (services) available.
use_prepkg_mk=$(MATRIXSSL_ROOT)/makefiles/prepkg.mk
use_testsupp_mk=$(MATRIXSSL_ROOT)/makefiles/testsupp.mk
use_rules_mk=$(MATRIXSSL_ROOT)/makefiles/rules.mk

# Provide names of built packages for interpackage references
# Note: Some of these may not be built in some cases.
LIBCORE_S_A=$(MATRIXSSL_ROOT)/core/libcore_s$(A)
LIBCRYPT_S_A=$(MATRIXSSL_ROOT)/crypto/libcrypt_s$(A)
LIBCMS_S_A=$(MATRIXSSL_ROOT)/crypto/cms/libcms_s$(A)
LIBSSL_S_A=$(MATRIXSSL_ROOT)/matrixssl/libssl_s$(A)

# Optional external libraries
LIBZ=-lz
LIBDL=-ldl
LIBTHREAD=-lpthread

# When linking use default compiler front-end
CC_LD=$(CC)
