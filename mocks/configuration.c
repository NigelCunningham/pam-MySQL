#include "src/context.h"
#include "src/strings.h"
#include "src/logging.h"
#include "src/alloc.h"

/**
 * Mock pam_mysql_format_string and setter for result code.
 */
static pam_mysql_err_t pam_mysql_format_string_result = PAM_MYSQL_ERR_SUCCESS;
static char *pam_mysql_format_string_template = NULL;

void set_mock_result_pam_mysql_format_string(pam_mysql_err_t result)
{
  pam_mysql_format_string_result = result;
}

pam_mysql_err_t pam_mysql_format_string(pam_mysql_ctx_t *ctx,
    pam_mysql_str_t *pretval, const char *template, int mangle, ...)
{
  (void) ctx;
  (void) pretval;
  (void) template;
  (void) mangle;

  pam_mysql_format_string_template = strdup(template);
  return pam_mysql_format_string_result;
}

/**
 * Mock pam_mysql_read_config_file and setter for result code.
 */
static pam_mysql_err_t pam_mysql_read_config_file_result;

void set_mock_result_pam_mysql_read_config_file(pam_mysql_err_t result)
{
  pam_mysql_read_config_file_result = result;
}

pam_mysql_err_t pam_mysql_read_config_file(pam_mysql_ctx_t *ctx,
    const char *path) {
  (void) ctx;
  (void) path;

  return PAM_MYSQL_ERR_SUCCESS;
}

void reset_config(void) {
  pam_mysql_read_config_file_result = PAM_MYSQL_ERR_SUCCESS;
  pam_mysql_format_string_result = PAM_MYSQL_ERR_SUCCESS;
  if (pam_mysql_format_string_template) {
    xfree(pam_mysql_format_string_template);
    pam_mysql_format_string_template = NULL;
  }
}

