#include "src/os_dep.h"
#include "src/strings.h"
#include "src/alloc.h"
#include "src/logging.h"

void pam_mysql_str_destroy(pam_mysql_str_t *str) {
  (void) str;
}

/**
 * Mock pam_mysql_str_init and setter for result code.
 */
static pam_mysql_err_t pam_mysql_str_init_result;
static pam_mysql_str_t *pam_mysql_str_init_ptr;

void set_mock_result_pam_mysql_str_init(pam_mysql_err_t result) {
  pam_mysql_str_init_result = result;
}

void set_mock_alloc_pam_mysql_str_init(pam_mysql_str_t *mock) {
  pam_mysql_str_init_ptr = mock;
}

pam_mysql_err_t pam_mysql_str_init(pam_mysql_str_t *str, int mangle) {
  (void) str;
  (void) mangle;

  if (pam_mysql_str_init_ptr) {
    str->p = pam_mysql_str_init_ptr->p;
    str->len = pam_mysql_str_init_ptr->len;
    str->alloc_size = pam_mysql_str_init_ptr->alloc_size;
  }

  return pam_mysql_str_init_result;
}

void reset_strings(void) {
  pam_mysql_str_init_result = PAM_MYSQL_ERR_SUCCESS;
  pam_mysql_str_init_ptr = NULL;
}
