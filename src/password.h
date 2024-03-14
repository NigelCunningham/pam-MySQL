#include "context.h"

#define IS_ERR(val) (val < 256)

typedef pam_mysql_err_t (*pam_mysql_password_encrypt_t)(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted);
typedef void (*pam_mysql_password_free_encrypted_t)(char *encrypt_t_result);

typedef struct _pam_mysql_password_encryption_t {
  int index;
  char *name;
  size_t encryption_size;
  pam_mysql_password_encrypt_t encrypt;
  pam_mysql_password_free_encrypted_t free;
} pam_mysql_password_encryption_t;

extern pam_mysql_password_encryption_t pam_mysql_password_plugins[];
extern long unsigned int pam_mysql_num_plugins(void);
extern char **pam_mysql_password_plugin_test_passwords(int pluginid);
