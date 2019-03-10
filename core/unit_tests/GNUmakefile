#
#	Makefile for unit testing applications.
#
#	Copyright (c) 2018 INSIDE Secure Corporation. All Rights Reserved.
#
#

ifeq ($(wildcard Makefile),)

# Source library files (detect automatically)
LIB_C:=$(wildcard lib_*.c)
LIB_CC:=$(wildcard lib_*.cc)
ifneq '$(LIB_C) $(LIB_CC)' ' '
LIB_TEST_COMMON=libtest_common_s.a
noinst_LIBRARIES=libtest_common_s.a
libtest_common_s_a_SOURCES=$(LIB_C) $(LIB_CC)
libtest_common_s_a_API=core testsupp
endif

# Source files (detect automatically)
# All sources depend on and include libtest_common_s.a
TESTS_C:=$(patsubst %.c,%,$(wildcard test_*.c))
TESTS_CC:=$(patsubst %.cc,%,$(wildcard test_*.cc))
EXTRA_PROGRAMS = $(TESTS_C) $(TESTS_CC)
$(foreach test,$(TESTS_C),$(eval $(test)_SOURCES = $(test:%=%.c)))
$(foreach test,$(TESTS_C),$(eval $(test)_CFLAGS = -g))
$(foreach test,$(TESTS_C),$(eval $(test)_LDFLAGS = -g))
$(foreach test,$(TESTS_C),$(eval $(test)_API = test_common core testsupp))
ifneq '$(LIB_C) $(LIB_CC)' ' '
$(foreach test,$(TESTS_C),$(eval $(test): libtest_common_s.a))
endif
$(foreach test,$(TESTS_CC),$(eval $(test)_SOURCES = $(test:%=%.cc)))
$(foreach test,$(TESTS_CC),$(eval $(test)_CPPFLAGS = -g))
$(foreach test,$(TESTS_CC),$(eval $(test)_LDFLAGS = -g))
$(foreach test,$(TESTS_CC),$(eval $(test)_API = test_common core testsupp))
ifneq '$(LIB_C) $(LIB_CC)' ' '
$(foreach test,$(TESTS_CC),$(eval $(test): libtest_common_s.a))
endif
CFLAGS_STANDARD=-std=c99

# API spec for common testing aid library.
test_common_API_CFLAGS:=
test_common_API_CXXFLAGS:=
test_common_API_LIBADD=$(LIB_TEST_COMMON)

# Construct build rules using makefiles/rules.mk
CORE_DIR=../../core
include $(CORE_DIR)/makefiles/rules.mk

$(foreach test,$(TESTS_C),$(eval $(test:%=check_%): $(test);	./$(test)))
$(foreach test,$(TESTS_CC),$(eval $(test:%=check_%): $(test);	./$(test)))

check: $(TESTS_C:%=check_%) $(TESTS_CC:%=check_%)

else

# Makefile exists. Let it override this build file.
# (Note: This modifies priority of make built-in lookup priority.)
# This rule will allow the user to override this GNUmakefile with
# build rules from eg. cmake.

include Makefile

endif
