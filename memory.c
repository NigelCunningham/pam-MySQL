/**
 * String functions for pam-MySQL
 *
 * Copyright (C) 1998-2005 Gunay Arslan and the contributors.
 * Copyright (C) 2015-2017 Nigel Cunningham and contributors.
 *
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
 *
 * @TODO:
 * - Couldn't we use standard libc linkage? (Trust issues?)
 */

#include "memory.h";

size_t strnncpy(char *dest, size_t dest_size, const char *src, size_t src_len)
{
  size_t cpy_len;
  dest_size--;
  cpy_len = (dest_size < src_len ? dest_size: src_len);

  memcpy(dest, src, cpy_len);

  dest[cpy_len] = '\0';

  return cpy_len;
}

void *xcalloc(size_t nmemb, size_t size)
{
  void *retval;
  double v = ((double)size) * (int)(nmemb & (((size_t)-1) >> 1));

  if (v != nmemb * size) {
    return NULL;
  }

  retval = calloc(nmemb, size);

  return retval;
}

void *xrealloc(void *ptr, size_t nmemb, size_t size)
{
  void *retval;
  size_t total = nmemb * size;

  if (((double)size) * (int)(nmemb & (((size_t)-1) >> 1)) != total) {
    return NULL;
  }

  retval = realloc(ptr, total);

  return retval;
}

char *xstrdup(const char *ptr)
{
  size_t len = strlen(ptr) + sizeof(char);
  char *retval = xcalloc(sizeof(char), len);

  if (retval == NULL) {
    return NULL;
  }

  memcpy(retval, ptr, len);

  return retval;
}

void xfree(void *ptr)
{
  if (ptr != NULL) {
    free(ptr);
  }
}

void xfree_overwrite(char *ptr)
{
  if (ptr != NULL) {
    char *p;
    for (p = ptr; *p != '\0'; p++) {
      *p = '\0';
    }
    free(ptr);
  }
}

