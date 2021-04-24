#include "context.h"
#include "md5.h"
#include "alloc.h"

pam_mysql_err_t pam_mysql_encrypt_password_md5(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted)
{
  (void) ctx;

  pam_mysql_md5_data((unsigned char *) unencrypted, strlen(unencrypted), encrypted);

  return PAM_MYSQL_ERR_SUCCESS;
}

