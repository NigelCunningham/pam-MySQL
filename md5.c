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

/**
 * pam_mysql_md5_data
 *
 * AFAIK, only FreeBSD has MD5Data() defined in md5.h
 * better MD5 support will appear in 0.5
 **/
#ifdef HAVE_MD5DATA
#define HAVE_PAM_MYSQL_MD5_DATA
#define pam_mysql_md5_data MD5Data
#elif defined(HAVE_OPENSSL) || (defined(HAVE_SASL_MD5_H) && defined(USE_SASL_MD5)) || (!defined(HAVE_OPENSSL) && defined(HAVE_SOLARIS_MD5))
#if defined(USE_SASL_MD5)
static unsigned char *MD5(const unsigned char *d, unsigned int n,
 unsigned char *md)
{
  MD5_CTX ctx;

  _sasl_MD5Init(&ctx);

  _sasl_MD5Update(&ctx, (unsigned char *)d, n);

  _sasl_MD5Final(md, &ctx);

  return md;
}
#elif defined(USE_SOLARIS_MD5)
#define MD5(d, n, md) md5_calc(d, md, n)
#endif
#define HAVE_PAM_MYSQL_MD5_DATA
static char *pam_mysql_md5_data(const unsigned char *d, unsigned int sz, char *md)
{
  size_t i, j;
  unsigned char buf[16];

  if (md == NULL) {
    if ((md = xcalloc(32 + 1, sizeof(char))) == NULL) {
      return NULL;
    }
  }

  MD5(d, (unsigned long)sz, buf);

  for (i = 0, j = 0; i < 16; i++, j += 2) {
    md[j + 0] = "0123456789abcdef"[(int)(buf[i] >> 4)];
    md[j + 1] = "0123456789abcdef"[(int)(buf[i] & 0x0f)];
  }
  md[j] = '\0';

  return md;
}
#endif

