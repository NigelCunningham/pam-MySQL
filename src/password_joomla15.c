#include "logging.h"
#include "context.h"
#include "alloc.h"
#include "md5.h"

pam_mysql_err_t pam_mysql_encrypt_password_joomla15(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted)
{
  (void) ctx;
  (void) unencrypted;
  (void) encrypted;

  // If we are using phpass
  if (!strncmp(encrypted, "$P$", 3))
  {
    /*
    // Use PHPass's portable hashes with a cost of 10.
    $phpass = new \PasswordHash(10, true);

    $match = $phpass->CheckPassword($password, encrypted);
    */
  }
  // Check for Argon2id hashes
  else if (!strncmp(encrypted, "$argon2id", 9))
  {
    /**
    // This implementation is not supported through any existing polyfills
    $match = password_verify($password, encrypted);
    */
  }
  // Check for Argon2i hashes
  else if (!strncmp(encrypted, "$argon2i", 8))
  {
    /*
    // This implementation is not supported through any existing polyfills
    $match = password_verify($password, encrypted);
    */
  }
  // Check for bcrypt hashes
  else if (!strncmp(encrypted, "$2", 2))
  {
    /**
    // \JCrypt::hasStrongPasswordSupport() includes a fallback for us in the worst case
    \JCrypt::hasStrongPasswordSupport();
    $match = password_verify($password, encrypted);
    */
  }
  else if (!strncmp(encrypted, "{SHA256}", 8))
  {
    /**
    // Check the password
    $parts     = explode(':', encrypted);
    $salt      = @$parts[1];
    $testcrypt = static::getCryptedPassword($password, $salt, 'sha256', true);

    $match = \JCrypt::timingSafeCompare(encrypted, $testcrypt);
    */
  }
  else
  {
    unsigned char *md5input, *salt, *check;
    int ln = strlen(encrypted), i;

    for (i = 1; i < ln; i++) {
      if (encrypted[i] == ':') {
        break;
      }
    }

    if (i == ln) {
      return PAM_MYSQL_ERR_INVAL;
    }

    if (ln - i) {
      salt = xcalloc(ln - i, sizeof(char));
      if (!salt) {
        return PAM_MYSQL_ERR_ALLOC;
      }
      strncpy((char *) salt, &encrypted[i + 1], ln - i - 1);
    }

    md5input = (unsigned char *) xcalloc(100, sizeof(char));
    if (!md5input) {
      xfree(salt);
      return PAM_MYSQL_ERR_ALLOC;
    }

    check = (unsigned char *) xcalloc(100, sizeof(char));
    if (!check) {
      xfree(salt);
      xfree(md5input);
      return PAM_MYSQL_ERR_ALLOC;
    }

    strcat((char *) md5input, (char *) unencrypted);
    strcat((char *) md5input, (char *) salt);

    pam_mysql_md5_data(md5input, strlen((char *) md5input), (char *) check);

    if (i) {
      strcat((char *) check, ":");
      strcat((char *) check, (char *) salt);
    }
    else {
      unsigned int j;
      for (j=0; j < strlen(encrypted); j++) {
        if (encrypted[j] == ':') {
          break;
        }
      }

      if (j < strlen(encrypted)) {
        strcat((char *) check, ":");
      }
    }

    strcpy((char *) encrypted, (char *) check);

    xfree(md5input);
    xfree(check);
    xfree(salt);

    /*
    // Check the password
    $parts = explode(':', encrypted);
    $salt  = @$parts[1];

    $rehash = true;

    // Compile the hash to compare
    // If the salt is empty AND there is a ':' in the original hash, we must append ':' at the end
    $testcrypt = md5($password . $salt) . ($salt ? ':' . $salt : (strpos(encrypted, ':') !== false ? ':' : ''));

    $match = \JCrypt::timingSafeCompare(encrypted, $testcrypt);
    */
  }

  return PAM_MYSQL_ERR_SUCCESS;
}

