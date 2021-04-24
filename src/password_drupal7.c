#include <openssl/sha.h>
#include "logging.h"
#include "password.h"
#include "context.h"
#include "alloc.h"
#include "config.h"
#include "not_implemented.h"
#include "md5.h"

#if 1
#define HAVE_PAM_MYSQL_DRUPAL7
/**
 * The standard log2 number of iterations for password stretching. This should
 * increase by 1 every Drupal version in order to counteract increases in the
 * speed and power of computers available to crack the hashes.
 */
#define DRUPAL_HASH_COUNT 14

/**
 * The minimum allowed log2 number of iterations for password stretching.
 */
#define DRUPAL_MIN_HASH_COUNT 7

/**
 * The maximum allowed log2 number of iterations for password stretching.
 */
#define DRUPAL_MAX_HASH_COUNT 30

/**
 * The expected (and maximum) number of characters in a hashed password.
 */
#define DRUPAL_HASH_LENGTH 55

/**
 * Returns a string for mapping an int to the corresponding base 64 character.
 *
 * @return char *
 *   The string for use in mapping ints to base 64 characters.
 */
static char * _password_itoa64(void)
{
  return "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
}

/**
 * Parse the log2 iteration count from a stored hash or setting string.
 *
 * @param char *setting
 *   The Drupal 7 password setting string.
 *
 * @return mixed
 *   -1 if the character wasn't found or the log2 iteration count.
 */
static int d7_password_get_count_log2(char *setting)
{
  char *itoa64 = _password_itoa64();
  unsigned long i;

  for (i = 0; i < strlen(itoa64); i++) {
    if (itoa64[i] == setting[3])
      return i;
  }
  return -1;
}

/**
 * Base64 encode a password.
 *
 * @param char *input
 *   The unencoded password.
 * @param int count
 *   The length of the input.
 * @param char *output
 *   The buffer for the encoded password.
 *
 * @return char *
 *   The location of the NULL terminating the output buffer.
 */
static unsigned char * _password_base64_encode(unsigned char *input, int count, unsigned char *output) {
  int i = 0, off = 0;
  char *itoa64 = _password_itoa64();
  unsigned long value;

  do {
    value = (unsigned long) input[i++];
    output[off++] = itoa64[value & 0x3f];
    if (i < count) {
      value |= (((unsigned long) input[i]) << 8);
    }
    output[off++] = itoa64[(value >> 6) & 0x3f];
    if (i++ >= count) {
      break;
    }
    if (i < count) {
      value |= (((unsigned long) input[i]) << 16);
    }
    output[off++] = itoa64[(value >> 12) & 0x3f];
    if (i++ >= count) {
      break;
    }
    output[off++] = itoa64[(value >> 18) & 0x3f];
  } while (i < count);

  output[off] = 0;

  return output;
}

/**
 * Calculate the Drupal 7 hash for a password.
 *
 * Strings may be binary and contain \0, so we can't use strlen.
 *
 * @param int use_md5
 *   Whether to use MD5 (non zero) or SHA512.
 * @param char *string1
 *   The first string (setting string)
 * @param int len1
 *   The length of the first string.
 * @param char *string2
 *   The second string (password)
 * @param int len2
 *   The length of the second string.
 *
 * @return mixed
 *   The D7 hash or NULL if memory could not be allocated.
 */
static unsigned char *d7_hash(int use_md5, unsigned char *string1, int len1, unsigned char *string2, int len2)
{
  int len = len1 + len2;
  unsigned char *combined = xcalloc(len, sizeof(char)), *output = xcalloc(129, sizeof(char));

  if (!combined) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "hash: Failed to allocate memory for combined value.");
    return NULL;
  }

  memcpy(combined, string1, len1);
  memcpy(combined + len1, string2, len2);

  if (use_md5)
    MD5(combined, (unsigned long)len, output);
  else
    SHA512(combined, (unsigned long)len, output);

  xfree(combined);
  return output;
}

/**
 * Encrypt a Drupal 7 password.
 *
 * The first 12 characters of an existing hash are its setting string.
 *
 * @param int use_md5
 *   Whether to use MD5 or SHA512.
 * @param char *password
 *   The unencryped password.
 * @param char *setting
 *   The setting string.
 *
 * @return mixed
 *   NULL if memory allocation failed or inputs were invalid, else a ponter to
 *   the encrypted password.
 */
static char * d7_password_crypt(int use_md5, unsigned char *password, char *setting) {
  char salt[9], *final;
  unsigned char *old, *new;
  int count, count_log2 = d7_password_get_count_log2(setting);
  int len;
  unsigned long expected;

  // Hashes may be imported from elsewhere, so we allow != DRUPAL_HASH_COUNT
  if (count_log2 < DRUPAL_MIN_HASH_COUNT || count_log2 > DRUPAL_MAX_HASH_COUNT) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "_password_crypt: count_log2 outside of range.");
    return NULL;
  }

  strncpy(salt, &setting[4], 8);
  salt[8] = '\0';
  if (strlen(salt) != 8) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "_password_crypt: Salt length is not 8.");
    return NULL;
  }

  // Convert the base 2 logarithm into an integer.
  count = 1 << count_log2;

  old = d7_hash(use_md5, (unsigned char *) salt , 8, password, strlen((char *) password));

  do {
    new = d7_hash(use_md5, old , use_md5 ? 16 : 64, password, strlen((char *) password));
    xfree(old);
    if (!new)
      return NULL;
    old = new;
  } while (--count);

  len = use_md5 ? 16 : 64;

  new = xcalloc(129, sizeof(char));
  memcpy(new, setting, 12);
  _password_base64_encode(old, len, &new[12]);
  xfree(old);
  // _password_base64_encode() of a 16 byte MD5 will always be 22 characters.
  // _password_base64_encode() of a 64 byte sha512 will always be 86 characters.
  expected = 12 + ((8 * len + 5) / 6);
  if (strlen((char *) new) != expected) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "_password_crypt: Hash length not as expected.");
    xfree(new);
    return NULL;
  }

  final = xcalloc(DRUPAL_HASH_LENGTH + 1, sizeof(char));
  strncpy(final, (char *) new, DRUPAL_HASH_LENGTH);
  xfree(new);
  return final;
}

/**
 * Encrypt a provided password, using the same method applied to the password in
 * the database.
 *
 * @param const char *pwd
 *   The unencrypted password.
 * @param unsigned int sz
 *   The size of the password.
 * @param char *md
 *   The hashed, crypted password.
 * @param char *db_pwd
 *   The password stored in the DB.
 *
 * @return char *
 *   The encrypted password.
 */
static char *pam_mysql_drupal7_data(const char *pwd, unsigned int sz, char *md, char *db_pwd)
{
  char *stored_hash = db_pwd, *hashed;
  unsigned char *pwd_ptr = (unsigned char *) pwd;
  int match = 0, offset = 0;

  // Algorithm taken from user_check_password in includes/password.c in D7.0.
  if (db_pwd[0] == 'U' && db_pwd[1] == '$') {
    // This may be an updated password from user_update_7000(). Such hashes
    // have 'U' added as the first character and need an extra md5().
    stored_hash = &db_pwd[1];
    offset++;
    pwd_ptr = (unsigned char *) pam_mysql_md5_data((const unsigned char *) pwd, (unsigned long)sz, md);
  } else
    stored_hash = &db_pwd[0];

  if (stored_hash[0] == '$' && stored_hash[2] == '$') {
    switch (stored_hash[1]) {
      case 'S':
        match = 1;
        hashed = d7_password_crypt(0, pwd_ptr, stored_hash);
        break;
      case 'H':
        // phpBB3 uses "$H$" for the same thing as "$P$".
      case 'P':
        match = 1;
        hashed = d7_password_crypt(1, pwd_ptr, stored_hash);
        break;
    }
  }

  if (!match || !hashed) {
    md[0] = db_pwd[0] + 1;
    return NULL;
  }
  memcpy(md, hashed, strlen(hashed));
  xfree(hashed);

  return md;
}

pam_mysql_err_t pam_mysql_encrypt_password_drupal7(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted)
{
  (void) ctx;

  pam_mysql_drupal7_data(unencrypted, strlen(unencrypted), encrypted, encrypted);

  return PAM_MYSQL_ERR_SUCCESS;
}
#else
NOT_IMPLEMENTED(pam_mysql_encrypt_password_drupal7)
#endif
