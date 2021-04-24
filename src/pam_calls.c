#include "src/os_dep.h"

int pam_mysql_get_user(pam_handle_t *pamh, const char **user, const char *prompt)
{
  return pam_get_user(pamh, user, prompt);
}

int pam_mysql_get_item(const pam_handle_t *pamh, int item_type, const void **item) {
  return pam_mysql_get_item(pamh, item_type, item);
}
