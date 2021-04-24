#ifndef ALLOC_H
#define ALLOC_H
#include "os_dep.h"

extern void *xcalloc(size_t nmemb, size_t size);
extern char *xstrdup(const char *ptr);
extern void xfree(void *ptr);
extern void xfree_overwrite(char *ptr);
extern void *xrealloc(void *ptr, size_t nmemb, size_t size);
#endif
