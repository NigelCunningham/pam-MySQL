#include "context.h"
#include "strings.h"

enum _pam_mysql_config_token_t {
  PAM_MYSQL_CONFIG_TOKEN_EQUAL = 0,
  PAM_MYSQL_CONFIG_TOKEN_NEWLINE,
  PAM_MYSQL_CONFIG_TOKEN_STRING,
  PAM_MYSQL_CONFIG_TOKEN_SEMICOLON,
  PAM_MYSQL_CONFIG_TOKEN_COMMENT,
  PAM_MYSQL_CONFIG_TOKEN__LAST
};

typedef enum _pam_mysql_config_token_t pam_mysql_config_token_t;

extern pam_mysql_err_t pam_mysql_read_config_file(pam_mysql_ctx_t *ctx,
    const char *path);

extern pam_mysql_err_t pam_mysql_get_option(pam_mysql_ctx_t *ctx, const char **pretval, int *to_release, const char *name, size_t name_len);

extern pam_mysql_err_t pam_mysql_set_option(pam_mysql_ctx_t *ctx, const char *name, size_t name_len, const char *val);

extern pam_mysql_err_t pam_mysql_format_string(pam_mysql_ctx_t *ctx,
    pam_mysql_str_t *pretval, const char *template, int mangle, ...);

