#
#	Makefile for core static library
#
#	Copyright (c) 2013-2017 INSIDE Secure Corporation. All Rights Reserved.
#

ifeq ($(wildcard Makefile),)

# Override according to the type of the system
OSDEP=osdep/POSIX
SRC_CORE=\
	memset_s.c \
	corelib_main.c \
	corelib_trace.c \
	corelib_date.c \
	corelib_strings.c \
	corelib_list.c \
	psbuf.c \
	psUtil.c \
	psStat.c \
	$(OSDEP)/osdep.c \
	osdep/ANSI/osdep_break.c \
	$(OSDEP)/psLog.c \
	$(OSDEP)/psPrnf.c \
	c_lib.c \
	cl_basic.c \
	debug_abort.c \
	debug_printf.c \
	psprintf.c \
	psmalloc.c \
	psmalloc_ext.c \
	sfzclbuffer.c \
	sfzclcalendar.c \
	sfzclfastalloc.c \
	sfzclfileio.c \
	sfzclmalloc.c \
	sfzclmemparser.c \
	sfzcltimemeasure.c \
	sfzclobstack.c \
	sfzclsnprintf.c \
	sfzclbase64.c \
	sfzclstr.c \
	sfzcltime.c \
	osdep/ANSI/spal_memory_ansi.c \
	utils.c \
	$(OSDEP)/spal_posix_mutex.c \
	$(OSDEP)/spal_posix_semaphore.c \
	$(OSDEP)/spal_posix_sleep.c \
	$(OSDEP)/spal_posix_thread.c \
	sl_cpu.c \
	sl_neon.c \
	osdep/src/cl_memset.c \
	osdep/src/runtime.c

# Flags for garbage collection to allow selection of a subset of libcore_s.a.
CFLAGS_GARBAGE_COLLECTION ?= -ffunction-sections -fdata-sections

noinst_LIBRARIES=libcore_s.a libsfzutf_s.a libtestsupp_s.a
libcore_s_a_SOURCES=$(SRC_CORE)
libcore_s_a_API=core
libcore_s_a_CFLAGS=$(CFLAGS_POSITION_INDEPENDENT) $(CFLAGS_GARBAGE_COLLECTION)
VPATH+=src

libsfzutf_s_a_SOURCES=$(addprefix testsupp/src/sfzutf/, \
sfzutf.c sfzutf-heap.c sfzutf_interactive.c sfzutf_main_stdio.c \
sfzutf-perf.c sfzutf-stack.c sfzutf-utils.c)
libsfzutf_s_a_API=core sfzutf
libsfzutf_s_a_CFLAGS=$(CFLAGS_POSITION_INDEPENDENT)

libtestsupp_s_a_SOURCES=$(addprefix testsupp/src/, testsupp.c)
libtestsupp_s_a_API=core testsupp
libtestsupp_s_a_CFLAGS=$(CFLAGS_POSITION_INDEPENDENT)

# Special case: on ARM platforms sl_neon.c needs NEON compilation flags.
include makefiles/platform_specific.mk
sl_neon_c_CFLAGS=$(CFLAGS_ENABLE_NEON)

CORE_DIR=../core
include $(CORE_DIR)/makefiles/rules.mk

CPPFLAGS_EXTRACT_MACROS=-dM
# Allows to check configuration options.
parse-config:
	echo '#include "coreConfig.h"' | $(CC) $(CFLAGS) -I config $(CPPFLAGS_EXTRACT_MACROS) -E -x c -

else

# Makefile exists. Let it override this build file.
# (Note: This modifies priority of make built-in lookup priority.)
# This rule will allow the user to override this GNUmakefile with
# build rules from eg. cmake.

include Makefile

endif
