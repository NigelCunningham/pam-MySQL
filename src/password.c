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

static void pam_mysql_free_encrypted_xallocd(char *buf) {
  char *p = buf - 1;
  while (*(++p)) *p = '\0';
  xfree(buf);
}

pam_mysql_password_encryption_t pam_mysql_password_plugins[] = {
  {0, "plain", 0, pam_mysql_encrypt_password_noop, NULL, "this is a passwd" },
  {1, "crypt", 0, pam_mysql_encrypt_password_crypt, pam_mysql_free_encrypted_xallocd, "th/MvOljQRiww" },
  {2, "323", 42, pam_mysql_encrypt_password_323, pam_mysql_free_encrypted_xallocd, "*DE939D0BA37D13289F3E1E1D3229A20612BBC4D8" },
  {3, "md5", 33, pam_mysql_encrypt_password_md5, pam_mysql_free_encrypted_xallocd, "20a94b82ce464160d2c43f6421d3f1cd" },
  {4, "sha1", 41, pam_mysql_encrypt_password_sha1, pam_mysql_free_encrypted_xallocd, "93912a048645641d5f99a0aa12a7984893bfbf53" },
  {5, "drupal7", 128, pam_mysql_encrypt_password_drupal7, pam_mysql_free_encrypted_xallocd, "$S$5FS2XtrzQh7m/lF9AR4c6u.Htxafz1S5COOZIWaKSFHVZ0ZYyPK0" },
  {6, "joomla15", 66, pam_mysql_encrypt_password_joomla15, pam_mysql_free_encrypted_xallocd, "6bf3889c770c47bc30110df5b371ac2c:FtzH9dNdQZYPvpn9RBp5JaVGUa6nlDvl" },
  {7, "ssha", 41, pam_mysql_encrypt_password_ssha, pam_mysql_free_encrypted_xallocd, "TZgPw6HJaiWzaqkXgAyyyh2IoGhjNGVm" },
  {8, "sha512", 128, pam_mysql_encrypt_password_sha512, pam_mysql_free_encrypted_xallocd, "ee5f868a7d5194434d0a70c8464439848fc5f8b0719f3929877e05b62053edd6fca02171ce561da335632d6e3e59f1b47059cd2b83e940702eab3a3f4305185f" },
  {9, "sha256", 64, pam_mysql_encrypt_password_sha256, pam_mysql_free_encrypted_xallocd, "c6e8cefec7fea272e327c452c74cf7f6335193efb28dfb7063cf22b998fc6f9a" },
};

long unsigned int pam_mysql_num_plugins(void)
{
  return (sizeof(pam_mysql_password_plugins) / sizeof(pam_mysql_password_encryption_t));
}
