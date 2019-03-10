/* Provide this file after compilation via EXTRA_LDFLAGS to compilation. */

#include <stdlib.h>
#include "wrap-malloc.h"

void *myMalloc(size_t size)
{
    /* Resolve ambiquity on zero byte allocation: always allocate one byte. */
    return size > (size_t)0 ? malloc(size) : malloc(1);
}

void myFree(void *ptr)
{
    free(ptr);
}

void *myCalloc(size_t nmemb, size_t size)
{
    /* Resolve ambiquity on zero byte allocation: always allocate one byte. */
    return nmemb > (size_t)0 && size > (size_t)0 ?
        calloc(nmemb, size) : malloc(1);
}

void *myRealloc(void *ptr, size_t size)
{
    return realloc(ptr, size);
}
