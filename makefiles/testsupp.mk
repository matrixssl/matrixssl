#
#       Build test executable(s) using testsupp and catch.hpp
#
#       Copyright (c) 2013-2016 INSIDE Secure Corporation. All Rights Reserved.
#

# Include test materials to path
CPPFLAGS += -I$(MATRIXSSL_ROOT)/../testsupp

# Building with testsupp requires C++: define additional rules allowing
# compilation of C++ files inheriting options from C files compilation.
CXXFLAGS=$(CFLAGS)
OBJS += $(SRC_CC:.cc=.o)

# Override compiler used in linking rules
CC_LD=$(CXX)
