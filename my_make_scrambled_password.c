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

#ifndef my_make_scrambled_password
#include "common.h"
#include "memory.h"
#include "crypto.h"
#include "crypto-sha1.h"

// Implementation from commit 2db6b50c7b7c638104bd9639994f0574e8f4813c in Pure-ftp source.
void my_make_scrambled_password(char scrambled_password[42], const char password[255], int len)
{
  SHA1_CTX ctx;
  unsigned char h0[20], h1[20];

  SHA1Init(&ctx);
  SHA1Update(&ctx, password, strlen(password));
  SHA1Final(h0, &ctx);
  SHA1Init(&ctx);
  SHA1Update(&ctx, h0, sizeof h0);
#ifdef HAVE_EXPLICIT_BZERO
  explicit_bzero(h0, len);
#else
  volatile unsigned char *pnt_ = (volatile unsigned char *) h0;
  size_t i = (size_t) 0U;

  while (i < len) {
    pnt_[i++] = 0U;
  }
#endif

  SHA1Final(h1, &ctx);
  *scrambled_password = '*';
  hexify(scrambled_password + 1U, h1, 42, sizeof h1);
}
#endif
