#include <openssl/sha.h>
#include "logging.h"
#include "password.h"
#include "context.h"
#include "alloc.h"
#include "mysql.h"

/**
 * Calculate the SHA256 hash of input and return as a hex string.
 *
 * @param const char *d
 *   The input buffer location.
 * @param unsigned int sz
 *   The size of the input.
 * @param char *md
 *   A pointer to the output buffer (NULL or at least 65 bytes).
 */
void pam_mysql_sha256_data(const char *d, unsigned int sz, char *md)
{
  size_t i, j;
  unsigned char buf[32];

  SHA256((unsigned char *) d, (unsigned long)sz, (unsigned char *) buf);

  for (i = 0, j = 0; i < 32; i++, j += 2) {
    md[j + 0] = "0123456789abcdef"[(int)(buf[i] >> 4)];
    md[j + 1] = "0123456789abcdef"[(int)(buf[i] & 0x0f)];
  }
  md[j] = '\0';
}

pam_mysql_err_t pam_mysql_encrypt_password_sha256(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted)
{
  (void) ctx;

  pam_mysql_sha256_data(unencrypted, strlen(unencrypted), encrypted);

  return PAM_MYSQL_ERR_SUCCESS;
}

