compile: all

all: wrap-malloc.so wrap-malloc-include.txt

wrap-malloc.so: wrap-malloc.c
	$(CC) -shared -Wall -Werror -o $@ $< -fPIC

wrap-malloc-include.txt:
	echo 'EXTRA_CFLAGS="-include $(PWD)/wrap-malloc.h"' 'EXTRA_LDFLAGS="$(PWD)/wrap-malloc.so"' >$@

clean:
	rm -f wrap-malloc.o wrap-malloc.so wrap-malloc-include.txt
