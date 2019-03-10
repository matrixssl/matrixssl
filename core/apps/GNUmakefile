#
#   Makefile for core testing
#
#   Copyright (c) 2013-2016 INSIDE Secure Corporation. All Rights Reserved.
#

ifeq ($(wildcard Makefile),)

EXTRA_PROGRAMS=log logcc
log_SOURCES=log.c
log_API=core
logcc_SOURCES=logcc.cc
logcc_API=core

CORE_DIR=../../core
include $(CORE_DIR)/makefiles/rules.mk

else

# Makefile exists. Let it override this build file.
# (Note: This modifies priority of make built-in lookup priority.)
# This rule will allow the user to override this GNUmakefile with
# build rules from eg. cmake.

include Makefile

endif
