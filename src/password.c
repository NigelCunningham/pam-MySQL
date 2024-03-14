#include "password.h"
#include "alloc.h"

extern pam_mysql_err_t pam_mysql_encrypt_password_noop(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted);
extern pam_mysql_err_t pam_mysql_encrypt_password_crypt(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted);
extern pam_mysql_err_t pam_mysql_encrypt_password_323(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted);
extern pam_mysql_err_t pam_mysql_encrypt_password_md5(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted);
extern pam_mysql_err_t pam_mysql_encrypt_password_sha1(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted);
extern pam_mysql_err_t pam_mysql_encrypt_password_drupal7(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted);
extern pam_mysql_err_t pam_mysql_encrypt_password_joomla15(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted);
extern pam_mysql_err_t pam_mysql_encrypt_password_ssha(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted);
extern pam_mysql_err_t pam_mysql_encrypt_password_sha512(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted);
extern pam_mysql_err_t pam_mysql_encrypt_password_sha256(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted);
extern pam_mysql_err_t pam_mysql_encrypt_password_blowfish(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted);

static void pam_mysql_free_encrypted_xallocd(char *buf) {
  char *p = buf - 1;
  while (*(++p)) *p = '\0';
  xfree(buf);
}

pam_mysql_password_encryption_t pam_mysql_password_plugins[] = {
  {0, "plain", 0, pam_mysql_encrypt_password_noop, NULL },
  {1, "crypt", 0, pam_mysql_encrypt_password_crypt, pam_mysql_free_encrypted_xallocd },
  {2, "323", 42, pam_mysql_encrypt_password_323, pam_mysql_free_encrypted_xallocd },
  {3, "md5", 33, pam_mysql_encrypt_password_md5, pam_mysql_free_encrypted_xallocd },
  {4, "sha1", 41, pam_mysql_encrypt_password_sha1, pam_mysql_free_encrypted_xallocd },
  {5, "drupal7", 128, pam_mysql_encrypt_password_drupal7, pam_mysql_free_encrypted_xallocd },
  {6, "joomla15", 0, pam_mysql_encrypt_password_joomla15, pam_mysql_free_encrypted_xallocd },
  {7, "ssha", 41, pam_mysql_encrypt_password_ssha, pam_mysql_free_encrypted_xallocd },
  {8, "sha512", 128, pam_mysql_encrypt_password_sha512, pam_mysql_free_encrypted_xallocd },
  {9, "sha256", 64, pam_mysql_encrypt_password_sha256, pam_mysql_free_encrypted_xallocd },
  {10, "blowfish", 60, pam_mysql_encrypt_password_crypt, pam_mysql_free_encrypted_xallocd },
};

typedef struct _test_password_data_t {
  int pluginid;
  char *encrypted;
} test_password_data_t;

test_password_data_t test_password_data[] = {
  { 0, "this is a passwd" },
  { 1, "th/MvOljQRiww" },
  { 2, "*DE939D0BA37D13289F3E1E1D3229A20612BBC4D8" },
  { 3, "20a94b82ce464160d2c43f6421d3f1cd" },
  { 4, "93912a048645641d5f99a0aa12a7984893bfbf53" },
  { 5, "$S$5FS2XtrzQh7m/lF9AR4c6u.Htxafz1S5COOZIWaKSFHVZ0ZYyPK0" },
  { 6, "6bf3889c770c47bc30110df5b371ac2c:FtzH9dNdQZYPvpn9RBp5JaVGUa6nlDvl" },
  { 6, "$2y$10$u0WSFSxkUxDU4eikH6aZBejx/lwAGazHZnRAksrLf/orUJwzbCQ9m" },
  { 7, "TZgPw6HJaiWzaqkXgAyyyh2IoGhjNGVm" },
  { 8, "ee5f868a7d5194434d0a70c8464439848fc5f8b0719f3929877e05b62053edd6fca02171ce561da335632d6e3e59f1b47059cd2b83e940702eab3a3f4305185f" },
  { 9, "c6e8cefec7fea272e327c452c74cf7f6335193efb28dfb7063cf22b998fc6f9a" },
  { 10, "$2y$10$onYkUEKoKBcWnrgFqjq5.eTPF1oRE.WZ9bG6u9MqgUVDeukGzyqIy" },
};

/**
 * Since we can have multiple tests passwords for each plugin (different salts
 * / algorithms), we can't include them in the initialisation above. In lieu
 * of that, provide a function to retrieve an array of test passwords for a
 * given plugin here.
 */
char **pam_mysql_password_plugin_test_passwords(int pluginid) {
  int count = 0;
  long unsigned int i;

  for (i = 0; i < sizeof(test_password_data); i++) {
    if (test_password_data[i].pluginid == pluginid) {
      count++;
    }
  }

  char **buf = (char **) xcalloc(count + 1, sizeof(char *));
  count = 0;
  for (i = 0; i < sizeof(test_password_data); i++) {
    if (test_password_data[i].pluginid == pluginid) {
      buf[count] = test_password_data[i].encrypted;
      count++;
    }
  }

  return buf;
}

long unsigned int pam_mysql_num_plugins(void)
{
  return (sizeof(pam_mysql_password_plugins) / sizeof(pam_mysql_password_encryption_t));
}
