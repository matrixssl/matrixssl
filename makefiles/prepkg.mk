#
#       Construct header files from keys and other cryptographic properties.
#       The constructed files can be built during packaging.
#
#       Copyright (c) 2013-2016 INSIDE Secure Corporation. All Rights Reserved.
#

# Check if prepkg has already been done
ifneq '$(FORCE_PREPKG)' '1'
-include prepkg_done.mk
endif

# Empty list of generated PEM headers
DATA_HEADERS =

ifneq '$(PREPKG_DONE)' '1'

# Add search paths for locating pem files
vpath %.pem data:$(MATRIXSSL_ROOT)/testkeys:$(MATRIXSSL_ROOT)/sampleCerts
vpath %.txt data
vpath %.bin data

# Helper rule for building temporary working directory

build-temp:
	mkdir -p build-temp

# Rules for constructing header files containing data

define VERBATIM_HEADER_TEMPLATE
data/$(2).h : $(1) build-temp
	cp $$< build-temp/$(2); mkdir -p data; (cd build-temp;xxd -i $(2)) >$$@
DATA_HEADERS += data/$(2).h
endef
$(foreach key_file,$(VERBATIM_FILES),$(eval $(call VERBATIM_HEADER_TEMPLATE,$(key_file),$(subst /,_,$(key_file:%.pem=%)))))

define PEM_HEADER_TEMPLATE
data/$(2).h : $(1) build-temp
	openssl base64 -d -in $$< -out build-temp/$(2); mkdir -p data; (cd build-temp;xxd -i $(2)) >$$@
DATA_HEADERS += data/$(2).h
endef
$(foreach key_file,$(PEM_FILES),$(eval $(call PEM_HEADER_TEMPLATE,$(key_file),$(subst /,_,$(key_file:%.pem=%)))))

define ECC_PEM_HEADER_TEMPLATE
data/$(2).h : $(1) build-temp
	openssl ec -in $$< -out build-temp/$(2) -outform DER; mkdir -p data; (cd build-temp;xxd -i $(2)) >$$@
DATA_HEADERS += data/$(2).h
endef
$(foreach key_file,$(ECC_PEM_FILES),$(eval $(call ECC_PEM_HEADER_TEMPLATE,$(key_file),$(subst /,_,$(key_file:%.pem=%)))))

prepkg: $(PEM_HEADERS)
clean-prepkg: clean
	rm -f $(PEM_HEADERS)
	rm -rf build-temp

endif

# Extra cleaning commands
EXTRA_CLEAN_CMDS += && rm -rf build-temp
