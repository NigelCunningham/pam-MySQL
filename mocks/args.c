#include "src/context.h"
#include "src/logging.h"
#include "src/strings.h"
#include "src/configuration.h"
#include "src/mysql.h"

/**
 * Mock pam_mysql_parse_args and setter for result code.
 */
static pam_mysql_err_t pam_mysql_parse_args_result;

void set_mock_result_pam_mysql_parse_args(pam_mysql_err_t result) {
  pam_mysql_parse_args_result = result;
}

pam_mysql_err_t pam_mysql_parse_args(pam_mysql_ctx_t *ctx, int argc, const char **argv)
{
  (void) ctx;
  (void) argc;
  (void) argv;

  return PAM_MYSQL_ERR_SUCCESS;
}

void reset_args(void) {
  pam_mysql_parse_args_result = PAM_MYSQL_ERR_SUCCESS;
}
