/* Provide this file via EXTRA_CFLAGS to compilation. */

#ifndef WRAP_MALLOC_H_DEFINED
#define WRAP_MALLOC_H_DEFINED 1

#include <stddef.h>
void *myMalloc(size_t size);
void myFree(void *ptr);
void *myCalloc(size_t nmemb, size_t size);
void *myRealloc(void *ptr, size_t size);

#ifdef Malloc
#error "Malloc is already defined!"
#endif

#define Malloc myMalloc
#define Free myFree
#define Calloc myCalloc
#define Realloc myRealloc

#endif /* WRAP_MALLOC_H_DEFINED */
