#include "logging.h"
#include "password.h"
#include "context.h"
#include "alloc.h"

pam_mysql_err_t pam_mysql_encrypt_password_crypt(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted) {
  (void) ctx;

  char *crypted_password = crypt(unencrypted, encrypted);
  if (!crypted_password) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "something went wrong when invoking crypt() - %s", strerror(errno));
    return PAM_MYSQL_ERR_ALLOC;
  }

  strncpy(encrypted, crypted_password, strlen((char *) encrypted));

  return PAM_MYSQL_ERR_SUCCESS;
}
