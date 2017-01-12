/*
 * PAM module for MySQL
 *
 * Copyright (C) 1998-2005 Gunay Arslan and the contributors.
 * Copyright (C) 2015-2017 Nigel Cunningham and contributors.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Original Version written by: Gunay ARSLAN <arslan@gunes.medyatext.com.tr>
 * This version by: James O'Kane <jo2y@midnightlinux.com>
 * Modifications by Steve Brown, <steve@electronic.co.uk>
 * B.J. Black, <bj@taos.com>
 * Kyle Smith, <kyle@13th-floor.org>
 * Patch integration by Moriyoshi Koizumi, <moriyoshi@at.wakwak.com>,
 * based on the patches by the following contributors:
 * Paul Bryan (check_acct_mgmt service support)
 * Kev Green (Documentation, UNIX socket option)
 * Kees Cook (Misc. clean-ups and more)
 * Fredrik Rambris (RPM spec file)
 * Peter E. Stokke (chauthtok service support)
 * Sergey Matveychuk (OpenPAM support)
 * Package unmaintained for some years; now taken care of by Nigel Cunningham
 * https://github.com/NigelCunningham/pam-MySQL
 */

#if defined(HAVE_PAM_MYSQL_SHA1_DATA) && defined(HAVE_PAM_MYSQL_MD5_DATA)
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
 */
static char * _password_itoa64(void)
{
  return "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
}

/**
 * Parse the log2 iteration count from a stored hash or setting string.
 */
static int d7_password_get_count_log2(char *setting)
{
  char *itoa64 = _password_itoa64();
  int i;

  for (i = 0; i < strlen(itoa64); i++) {
    if (itoa64[i] == setting[3])
      return i;
  }
  return -1;
}

static char * _password_base64_encode(unsigned char *input, int count, char *output)
{
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
 * d7_hash
 *
 * Strings may be binary and contain \0, so we can't use strlen
 */
static char *d7_hash(int use_md5, char *string1, int len1, char *string2, int len2)
{
  int len = len1 + len2;
  char *combined = xcalloc(len, sizeof(char)), *output = xcalloc(129, sizeof(char));

  if (!combined) {
    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "hash: Failed to allocate memory for combined value.");
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

// The first 12 characters of an existing hash are its setting string.
static char * d7_password_crypt(int use_md5, char *password, char *setting)
{
  char salt[9], *old, *new, *final;
  int expected, count, count_log2 = d7_password_get_count_log2(setting);
  int len;

  // Hashes may be imported from elsewhere, so we allow != DRUPAL_HASH_COUNT
  if (count_log2 < DRUPAL_MIN_HASH_COUNT || count_log2 > DRUPAL_MAX_HASH_COUNT) {
    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "_password_crypt: count_log2 outside of range.");
    return NULL;
  }

  strncpy(salt, &setting[4], 8);
  salt[8] = '\0';
  if (strlen(salt) != 8) {
    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "_password_crypt: Salt length is not 8.");
    return NULL;
  }

  // Convert the base 2 logarithm into an integer.
  count = 1 << count_log2;

  old = d7_hash(use_md5, salt , 8, password, strlen(password));

  do {
    new = d7_hash(use_md5, old , use_md5 ? 16 : 64, password, strlen(password));
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
  if (strlen(new) != expected) {
    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "_password_crypt: Hash length not as expected.");
    xfree(new);
    return NULL;
  }

  final = xcalloc(DRUPAL_HASH_LENGTH + 1, sizeof(char));
  strncpy(final, new, DRUPAL_HASH_LENGTH);
  xfree(new);
  return final;
}

char *pam_mysql_drupal7_data(const unsigned char *pwd, unsigned int sz, char *md, char *db_pwd)
{
  char *stored_hash = db_pwd, *pwd_ptr = (char *) pwd, *hashed;
  int match = 0, offset = 0;

  // Algorithm taken from user_check_password in includes/password.c in D7.0.
  if (db_pwd[0] == 'U' && db_pwd[1] == '$') {
    // This may be an updated password from user_update_7000(). Such hashes
    // have 'U' added as the first character and need an extra md5().
    stored_hash = &db_pwd[1];
    offset++;
    pwd_ptr = pam_mysql_md5_data(pwd, (unsigned long)sz, md);
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
#endif

