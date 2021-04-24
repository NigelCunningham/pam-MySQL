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
extern pam_mysql_err_t pam_mysql_str_append(pam_mysql_str_t *str,
    const char *s, size_t len);
extern pam_mysql_err_t pam_mysql_str_append_char(pam_mysql_str_t *str, char c);
extern pam_mysql_err_t pam_mysql_quick_escape(pam_mysql_ctx_t *ctx, pam_mysql_str_t *append_to, const char *val, size_t val_len);
extern pam_mysql_err_t pam_mysql_str_truncate(pam_mysql_str_t *str, size_t len);
extern pam_mysql_err_t pam_mysql_str_reserve(pam_mysql_str_t *str, size_t len);
extern void *memspn(void *buf, size_t buf_len, const unsigned char *delims,
    size_t ndelims);
extern void *memcspn(void *buf, size_t buf_len, const unsigned char *delims,
    size_t ndelims);
#endif
