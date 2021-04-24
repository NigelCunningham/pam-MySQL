#include "logging.h"
#include "password.h"
#include "context.h"
#include "mysql.h"
#include "alloc.h"

pam_mysql_err_t pam_mysql_encrypt_password_noop(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted)
{
  (void) ctx;

  if (!strcpy(encrypted, unencrypted)) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "Failed to strcpy plaintext password");
    return PAM_MYSQL_ERR_ALLOC;
  }

  return PAM_MYSQL_ERR_SUCCESS;
}

