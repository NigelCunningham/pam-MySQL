#include "src/os_dep.h"
#include "src/alloc.h"
#include "src/context.h"
#include "src/logging.h"
#include "src/strings.h"
#include "src/mysql.h"

pam_mysql_err_t pam_mysql_init_ctx(pam_mysql_ctx_t *ctx) {
  (void) ctx;

  return PAM_MYSQL_ERR_SUCCESS;
}

pam_mysql_ctx_t *mock_context;

void pam_mysql_set_mock_context(pam_mysql_ctx_t *context) {
  mock_context = context;
}

pam_mysql_err_t pam_mysql_retrieve_ctx(pam_mysql_ctx_t **pretval, pam_handle_t *pamh)
{
  (void) pretval;
  (void) pamh;

  *pretval = mock_context;
  return PAM_MYSQL_ERR_SUCCESS;
}

