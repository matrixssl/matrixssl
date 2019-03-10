#
#       Skeleton of build file with generic rules
#
#       Copyright (c) 2017 INSIDE Secure Oy. All Rights Reserved.
#

# Generate list of generated executables (currently supports test)
TEST_EXE    = $(foreach name,$(TEST_PROGRAMS),$(name)$(E))

# Generally, our default target is all:

all: compile

compile: $(OBJS) $(TEST_EXE)

define FILELIST_AND_LINK_TEMPLATE
$(1): $(2) $$(STATICS) $(LOCAL_LDADD)
	$$(CC_LD) -o $$@ $$^ $$(LDFLAGS) $(STATICS) $(LOCAL_LDADD)
OBJS += $(2)
endef

$(foreach program,$(TEST_PROGRAMS),$(eval $(call FILELIST_AND_LINK_TEMPLATE,$(program),$(patsubst %.cc,%.o,$(patsubst %.c,%.o,$(call $(program)_SOURCES))))))

# Additional Dependencies for objects
$(OBJS): $(MAKEFILE_LIST) $(LOCAL_HEADERS) $(DATA_HEADERS)

# Generic build suffix rules
%.o : %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_CFLAGS) -c -o $@ $<

%.o : %.cc
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LOCAL_CPPFLAGS) $(LOCAL_CXXFLAGS) -c -o $@ $<

#
#	Clean up all generated files
#
clean:
	rm -f $(TEST_EXE) $(OBJS) $(TEMP_FILES) $(EXTRA_CLEAN_CMDS)
