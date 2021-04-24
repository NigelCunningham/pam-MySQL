#include "src/os_dep.h"

char *pam_user_result = NULL;

void pam_mysql_set_user_name(char *user)
{
  pam_user_result = user;
}

int pam_mysql_get_user(const pam_handle_t *pamh, const char **user, const char *prompt)
{
  (void) pamh;
  (void) prompt;

  *user = pam_user_result;
  return PAM_SUCCESS;
}

struct pam_get_item_result_struct {
  char *result;
  int retval;
};

struct pam_get_item_result_struct pam_get_item_result[13];

void pam_mysql_set_item(int index, char *result, int retval)
{
  pam_get_item_result[index].result = result;
  pam_get_item_result[index].retval = retval;
}

int pam_mysql_get_item(const pam_handle_t *pamh, int item_type, const void **item) {
  (void) pamh;
  *item = pam_get_item_result[item_type].result;
  return pam_get_item_result[item_type].retval;
}
