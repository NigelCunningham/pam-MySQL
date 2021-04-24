#include "logging.h"
#include "password.h"
#include "alloc.h"
#include "mysql.h"

/* Copyright (C) 2000 MySQL AB & MySQL Finland AB & TCX DataKonsult AB

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA */

/* password checking routines */
/*****************************************************************************
  The main idea is that no password are sent between client & server on
  connection and that no password are saved in mysql in a decodable form.

  On connection a random string is generated and sent to the client.
  The client generates a new string with a random generator inited with
  the hash values from the password and the sent string.
  This 'check' string is sent to the server where it is compared with
  a string generated from the stored hash_value of the password and the
  random string.

  The password is saved (in user.password) by using the PASSWORD() function in
  mysql.

  This is .c file because it's used in libmysqlclient, which is entirely in C.
  (we need it to be portable to a variety of systems).
Example:
update user set password=PASSWORD("hello") where user="test"
This saves a hashed number as a string in the password field.

The new authentication is performed in following manner:

SERVER:  public_seed=create_random_string()
send(public_seed)

CLIENT:  recv(public_seed)
hash_stage1=sha1("password")
hash_stage2=sha1(hash_stage1)
reply=xor(hash_stage1, sha1(public_seed,hash_stage2)

// this three steps are done in scramble() 

send(reply)


SERVER:  recv(reply)
hash_stage1=xor(reply, sha1(public_seed,hash_stage2))
candidate_hash2=sha1(hash_stage1)
check(candidate_hash2==hash_stage2)

// this three steps are done in check_scramble()

 *****************************************************************************/


/*
   Generate binary hash from raw text string 
   Used for Pre-4.1 password handling
   SYNOPSIS
   hash_password()
   result       OUT store hash in this location
   password     IN  plain text password to build hash
   password_len IN  password length (password may be not null-terminated)
   */

#ifndef HAVE_MAKE_SCRAMBLED_PASSWORD_323
#include "os_dep.h"
#include "crypto.h"
#include "crypto-sha1.h"

void compat_323_hash_password(ulong *result, const char *password, uint password_len)
{
  register ulong nr=1345345333L, add=7, nr2=0x12345671L;
  ulong tmp;
  const char *password_end= password + password_len;
  for (; password < password_end; password++)
  {
    if (*password == ' ' || *password == '\t')
      continue;                                 /* skip space in password */
    tmp= (ulong) (unsigned char) *password;
    nr^= (((nr & 63)+add)*tmp)+ (nr << 8);
    nr2+=(nr2 << 8) ^ nr;
    add+=tmp;
  }
  result[0]=nr & (((ulong) 1L << 31) -1L); /* Don't use sign bit (str2int) */;
  result[1]=nr2 & (((ulong) 1L << 31) -1L);
}


/*
   Create password to be stored in user database from raw string
   Used for pre-4.1 password handling
   SYNOPSIS
   make_scrambled_password_323()
   to        OUT store scrambled password here
   password  IN  user-supplied password
   */

void compat_make_scrambled_password_323(char *to, const char *password)
{
  ulong hash_res[2];
  compat_323_hash_password(hash_res, password, (uint) strlen(password));
  sprintf(to, "%08lx%08lx", hash_res[0], hash_res[1]);
}

/**
 * Implementation of make_scrambled_password.
 *
 * Taken from commit 2db6b50c7b7c638104bd9639994f0574e8f4813c in Pure-ftp
 * source.
 *
 * @param char scrambled_password
 *   The buffer into which the password should be saved.
 * @param char password
 *   The password to be scrambled.
 */
void make_scrambled_password(char scrambled_password[42], const char password[255])
{
  SHA1_CTX ctx;
  unsigned char h0[20], h1[20];

  SHA1Init(&ctx);
  SHA1Update(&ctx, (unsigned char *) password, strlen(password));
  SHA1Final(h0, &ctx);
  SHA1Init(&ctx);
  SHA1Update(&ctx, h0, sizeof h0);
#ifdef HAVE_EXPLICIT_BZERO
  explicit_bzero(h0, strlen(password));
#else
  volatile char *pnt_ = (volatile char *) h0;
  size_t i = (size_t) 0U;

  while (i < strlen(password)) {
    pnt_[i++] = 0U;
  }
#endif

  SHA1Final(h1, &ctx);
  *scrambled_password = '*';
  hexify((unsigned char *) scrambled_password + 1U, h1, 42, sizeof h1);
}
#endif

pam_mysql_err_t pam_mysql_encrypt_password_323(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted)
{
#ifdef HAVE_MAKE_SCRAMBLED_PASSWORD_323
  if (ctx->use_323_passwd) {
    pam_mysql_syslog(LOG_DEBUG, "use_323_passwd defined and enabled in pam_mysql_check_passwd");
    make_scrambled_password_323(encrypted, unencrypted);
  } else {
    pam_mysql_syslog(LOG_DEBUG, "use_323_passwd defined and not enabled in pam_mysql_check_passwd");
    make_scrambled_password(encrypted, unencrypted);
  }
#else
  if (ctx->use_323_passwd) {
    pam_mysql_syslog(LOG_WARNING, "Workaround applied. use_323_passwd not defined but use attempted in pam_mysql_check_passwd");
    compat_make_scrambled_password_323(encrypted, unencrypted);
  } else {
    pam_mysql_syslog(LOG_DEBUG, "use_323_passwd not defined and use not attempted in pam_mysql_check_passwd");
    make_scrambled_password(encrypted, unencrypted);
  }
#endif

  return PAM_MYSQL_ERR_SUCCESS;
}

