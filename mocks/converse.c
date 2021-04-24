#include "src/converse.h"
#include "src/logging.h"
#include "src/alloc.h"
#include "src/strings.h"

char **pam_mysql_mock_converse_result;

void pam_mysql_set_mock_converse_result(char **result) {
  pam_mysql_mock_converse_result = result;
}

/**
 * Mock a conversation with an application via PAM.
 *
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 * @param char **pretval
 *   The address of a pointer to the return value.
 * @param pam_handle_t *pamh
 *   A pointer to the PAM handle.
 * @param size_t nargs
 *   The number of messages to be sent.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
pam_mysql_err_t pam_mysql_converse(pam_mysql_ctx_t *ctx, char ***pretval,
    pam_handle_t *pamh, size_t nargs, ...)
{
  (void) ctx;
  (void) pamh;
  (void) nargs;

  *pretval = pam_mysql_mock_converse_result;
  return PAM_SUCCESS;
}

