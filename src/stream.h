#include "configuration.h"

typedef struct _pam_mysql_stream_t {
  int fd;
  unsigned char buf[2][2048];
  unsigned char *buf_start;
  unsigned char *buf_ptr;
  unsigned char *buf_end;
  unsigned char *pushback;
  size_t buf_in_use;
  int eof;
} pam_mysql_stream_t;

typedef struct _pam_mysql_config_scanner_t {
  pam_mysql_ctx_t *ctx;
  pam_mysql_str_t image;
  pam_mysql_config_token_t token;
  pam_mysql_stream_t *stream;
  int state;
} pam_mysql_config_scanner_t;

extern pam_mysql_err_t pam_mysql_stream_open(pam_mysql_stream_t *stream,
    pam_mysql_ctx_t *ctx, const char *file);
extern void pam_mysql_stream_close(pam_mysql_stream_t *stream);
extern pam_mysql_err_t pam_mysql_stream_getc(pam_mysql_stream_t *stream,
    int *retval);
extern pam_mysql_err_t pam_mysql_stream_read_cspn(pam_mysql_stream_t *stream,
    pam_mysql_str_t *append_to, int *found_delim, const char *delims,
    size_t ndelims);
extern pam_mysql_err_t pam_mysql_stream_ungetc(pam_mysql_stream_t *stream, int c);
extern pam_mysql_err_t pam_mysql_stream_skip_spn(pam_mysql_stream_t *stream,
    const char *accept_cset, size_t naccepts);
