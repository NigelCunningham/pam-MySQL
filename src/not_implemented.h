/**
 * Common macro for unimplemented encryption methods.
 */

#define NOT_IMPLEMENTED(f) \
  pam_mysql_err_t pam_mysql_encrypt_password_drupal7(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted) { \
    (void) ctx; \
    (void) unencrypted; \
    (void) encrypted; \
    return PAM_MYSQL_ERR_NOTIMPL; \
  }
