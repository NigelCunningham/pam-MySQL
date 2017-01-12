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

#include "common.h"
#include "memory.h"
#include "string.h"

/**
 * pam_mysql_str_init()
 **/
pam_mysql_err_t pam_mysql_str_init(pam_mysql_str_t *str, int mangle)
{
  str->p = "";
  str->len = 0;
  str->alloc_size = 0;
  str->mangle = mangle;

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * pam_mysql_str_destroy()
 */
void pam_mysql_str_destroy(pam_mysql_str_t *str)
{
  if (str->alloc_size > 0) {
    if (str->mangle) {
      memset(str->p, 0, str->len);
    }
    xfree(str->p);
  }
}

/**
 * pam_mysql_str_reserve()
 **/
pam_mysql_err_t pam_mysql_str_reserve(pam_mysql_str_t *str, size_t len)
{
  size_t len_req;

  {
    len_req = str->len + len;
    if (len_req < str->len) {
      syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "integer overflow at " __FILE__ ":%d", __LINE__);
      return PAM_MYSQL_ERR_INVAL;
    }

    len_req += sizeof(char); // space for a string terminator
  }

  if (len_req >= str->alloc_size) {
    size_t cv = 0;
    size_t new_size = (str->alloc_size == 0 ? 1: str->alloc_size);
    char *new_buf;

    do {
      new_size *= 2;
      if (cv > new_size) {
        syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
        return PAM_MYSQL_ERR_ALLOC;
      }
      cv = new_size;
    } while (new_size < len_req);

    if (str->mangle) {
      if (NULL == (new_buf = xcalloc(new_size, sizeof(char)))) {
        syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
        return PAM_MYSQL_ERR_ALLOC;
      }

      memcpy(new_buf, str->p, str->len);
      memset(str->p, 0, str->len);
      if (str->alloc_size > 0) {
        xfree(str->p);
      }
    } else {
      if (str->alloc_size == 0) {
        if (NULL == (new_buf = xcalloc(new_size, sizeof(char)))) {
          syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
          return PAM_MYSQL_ERR_ALLOC;
        }
      } else {
        if (NULL == (new_buf = xrealloc(str->p, new_size, sizeof(char)))) {
          syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
          return PAM_MYSQL_ERR_ALLOC;
        }
      }
    }
    str->p = new_buf;
    str->alloc_size = new_size;
  }

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * pam_mysql_str_append()
 **/
pam_mysql_err_t pam_mysql_str_append(pam_mysql_str_t *str, const char
    *s, size_t len)
{
  pam_mysql_err_t err;

  if ((err = pam_mysql_str_reserve(str, len))) {
    return err;
  }

  memcpy(str->p + str->len, s, len);
  str->len += len;
  str->p[str->len] = '\0';

  return PAM_MYSQL_ERR_SUCCESS;
}

pam_mysql_err_t pam_mysql_str_append_char(pam_mysql_str_t *str, char c)
{
  return pam_mysql_str_append(str, &c, sizeof(c));
}

/**
 * pam_mysql_str_truncate()
 **/
pam_mysql_err_t pam_mysql_str_truncate(pam_mysql_str_t *str, size_t len)
{
  if (len > str->len) {
    return PAM_MYSQL_ERR_INVAL;
  }

  str->len = len;

  if (str->alloc_size != 0) {
    str->p[len] = '\0';
  }

  return PAM_MYSQL_ERR_SUCCESS;
}
