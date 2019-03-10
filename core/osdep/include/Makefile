##############################################################################
# Copyright (c) 2017 INSIDE Secure Oy. All Rights Reserved.
#
# This confidential and proprietary software may be used only as authorized
# by a licensing agreement from INSIDE Secure.
#
# The entire notice above must be reproduced on all authorized copies that
# may only be made to the extent permitted by a licensing agreement from
# INSIDE Secure.
##############################################################################

all:
	@echo make osdep_foo.h to build include template osdep_foo.h that includes
	@echo system include foo.h or make osdep_foo.h FUNCS="malloc free"

default_set:
	@echo WARNING: Executing this rule will overwrite some of header files
	@echo that have been handtuned. This may affect your 
	$(MAKE) -B osdep_stdint.h FUNCS=""
	$(MAKE) -B osdep_stdbool.h FUNCS=""
	$(MAKE) -B osdep_stdlib.h FUNCS="malloc free calloc realloc abort getenv"
	$(MAKE) -B osdep_stdio.h FUNCS="fopen ferror fread fwrite fclose fflush fprintf printf puts snprintf sprintf sscanf"
	$(MAKE) -B osdep_string.h FUNCS="memcmp memmove memcpy memset strcmp strncmp strcpy strncpy strcat strlen strstr strtol strchr strtok memchr"
	$(MAKE) -B osdep_strings.h FUNCS="ffsll"
	$(MAKE) -B osdep_ctype.h FUNCS="tolower toupper isdigit isalpha isxalpha isxdigit isspace"
	$(MAKE) -B osdep_unistd.h FUNCS="select sysconf sleep" REQUIRES="#if defined _POSIX_C_SOURCE || defined __unix__ || defined __linux__ || defined __android__" END_REQUIRES="#endif /* system that usually has unistd.h. */"
	$(MAKE) -B osdep_intrin.h FUNCS=""
	$(MAKE) -B osdep_inttypes.h DEFINED="PRIi32 PRIx32"
	$(MAKE) -B osdep_stdarg.h FUNCS=""
	$(MAKE) -B osdep_stddef.h FUNCS="" DEFINED="NULL offsetof"
	$(MAKE) -B osdep_assert.h FUNCS="assert"
	$(MAKE) -B osdep_pthread.h FUNCS="pthread_create pthread_join pthread_mutex_init pthread_mutex_lock pthread_mutex_unlock"
	$(MAKE) -B osdep_errno.h FUNCS=""
	$(MAKE) -B osdep_time.h FUNCS="time strftime"
	$(MAKE) -B osdep_semaphore.h FUNCS=""
	$(MAKE) -B osdep_cpu-features.h FUNCS=""
	$(MAKE) -B osdep_wincrypt.h FUNCS=""
	$(MAKE) -B osdep_windows.h FUNCS="lstrcmpiA"
	$(MAKE) -B osdep_libc-version.h FUNCS="" PATH_PREFIX="gnu/"
	$(MAKE) -B osdep_sys_auxv.h FUNCS="" DESTFILE="sys/auxv.h"
	$(MAKE) -B osdep_arm_neon.h FUNCS=""
	$(MAKE) -B osdep_arm_acle.h FUNCS=""
	$(MAKE) -B osdep_setjmp.h FUNCS="setjmp longjmp"
	$(MAKE) -B osdep_signal.h FUNCS="signal sigprocmask"
	$(MAKE) -B osdep_limits.h FUNCS=""
	$(MAKE) -B osdep_sys_mman.h FUNCS="" DESTFILE="sys/mman.h"
	$(MAKE) -B osdep_sys_types.h FUNCS="" DESTFILE="sys/types.h"
	$(MAKE) -B osdep_sys_time.h FUNCS="" DESTFILE="sys/time.h"
	$(MAKE) -B osdep_sys_types.h FUNCS="" DESTFILE="sys/types.h"
	$(MAKE) -B osdep_sys_socket.h FUNCS="socket connect send" DESTFILE="sys/socket.h"
	$(MAKE) -B osdep_sys_ioctl.h FUNCS="" DESTFILE="sys/ioctl.h"
	$(MAKE) -B osdep_netinet_in.h FUNCS="" DESTFILE="netinet/in.h"
	$(MAKE) -B osdep_netinet_tcp.h FUNCS="" DESTFILE="netinet/tcp.h"
	$(MAKE) -B osdep_netdb.h FUNCS=""
	$(MAKE) -B osdep_fcntl.h FUNCS=""
	$(MAKE) -B osdep_wchar.h FUNCS=""
	$(MAKE) -B osdep_sched.h FUNCS=""
	$(MAKE) -B osdep_malloc.h FUNCS="malloc free calloc realloc"
	$(MAKE) -B osdep_dlfcn.h FUNCS="dlopen dlclose dlsym"
	$(MAKE) -B osdep_x86intrin.h FUNCS=""
	$(MAKE) -B osdep_emmintrin.h FUNCS=""
	$(MAKE) -B osdep_tmmintrin.h FUNCS=""
	$(MAKE) -B osdep_smmintrin.h FUNCS=""
	$(MAKE) -B osdep_nmmintrin.h FUNCS=""
	$(MAKE) -B osdep_wmmintrin.h FUNCS=""
	$(MAKE) -B osdep_immintrin.h FUNCS=""
	$(MAKE) -B osdep_zmmintrin.h FUNCS=""
	$(MAKE) -B osdep_termios.h FUNCS=""

osdep_%.h: template.h
	perl -0777 -pe 's(__DOC__(.*?)__END__\n?\n?)()sg; s(__FILENAME__)($@)g; s(__REQUIRES__)($(REQUIRES))g; s(__END_REQUIRES__)($(END_REQUIRES))g; $$u="\U$@\E"; $$u=~tr(.-)(__); s(__UC_FILENAME__)($$u)g; s(__TOFILE__)("$(DESTFILE)" eq "" ? "$(PATH_PREFIX)$*.h" : "$(DESTFILE)")eg; s(__FUNCS__)(join("/", qw($(FUNCS))))eg; s(__DEFINED__)(join("", map {"/* System must defin $$_ */\n#ifndef $$_\n#error $$_ is not defined.\n#endif" } qw($(DEFINED))))eg; s(__FUNCS_REDIRECT__(.*)__END__)($$e=$$1; join("\n", map {eval($$e)} qw($(FUNCS))))seg;' <$< >$@
