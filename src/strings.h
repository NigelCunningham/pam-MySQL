#ifndef STRINGS_H
#define STRINGS_H
#include "context.h"

typedef struct _pam_mysql_str_t {
    char *p;
    size_t len;
    size_t alloc_size;
    int mangle;
} pam_mysql_str_t;

extern size_t strnncpy(char *dest, size_t dest_size, const char *src, size_t src_len);
extern void pam_mysql_str_destroy(pam_mysql_str_t *str);
extern pam_mysql_err_t pam_mysql_str_init(pam_mysql_str_t *str, int mangle);
#endif
