#ifndef CONTEXT_H
#define CONTEXT_H
#include "os_dep.h"

typedef struct _pam_mysql_ctx_t {
  MYSQL *mysql_hdl;
  char *host;
  char *where;
  char *db;
  char *user;
  char *passwd;
  char *table;
  char *update_table;
  char *usercolumn;
  char *passwdcolumn;
  char *statcolumn;
  char *select;
  int crypt_type;
  int use_323_passwd;
  int md5;
  int sha256;
  int sha512;
  int blowfish;
  int rounds;
  int sqllog;
  int verbose;
  int use_first_pass;
  int try_first_pass;
  int disconnect_every_op;
  char *logtable;
  char *logmsgcolumn;
  char *logpidcolumn;
  char *logusercolumn;
  char *loghostcolumn;
  char *logrhostcolumn;
  char *logtimecolumn;
  char *config_file;
  char *my_host_info;
  char *ssl_mode;
  char *ssl_cert;
  char *ssl_key;
  char *ssl_ca;
  char *ssl_capath;
  char *ssl_cipher;
} pam_mysql_ctx_t; /*Max length for most MySQL fields is 16 */

enum _pam_mysql_err_t {
  PAM_MYSQL_ERR_SUCCESS = 0,
  PAM_MYSQL_ERR_UNKNOWN = -1,
  PAM_MYSQL_ERR_NO_ENTRY = 1,
  PAM_MYSQL_ERR_ALLOC = 2,
  PAM_MYSQL_ERR_INVAL = 3,
  PAM_MYSQL_ERR_BUSY = 4,
  PAM_MYSQL_ERR_DB = 5,
  PAM_MYSQL_ERR_MISMATCH = 6,
  PAM_MYSQL_ERR_IO = 7,
  PAM_MYSQL_ERR_SYNTAX = 8,
  PAM_MYSQL_ERR_EOF = 9,
  PAM_MYSQL_ERR_NOTIMPL = 10
};

typedef enum _pam_mysql_err_t pam_mysql_err_t;

extern pam_mysql_err_t pam_mysql_retrieve_ctx(pam_mysql_ctx_t **pretval, pam_handle_t *pamh);

extern pam_mysql_err_t pam_mysql_parse_args(pam_mysql_ctx_t *, int argc, const char **argv);

#endif
