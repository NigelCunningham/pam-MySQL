/**
 * pam_mysql_md5_data
 *
 * AFAIK, only FreeBSD has MD5Data() defined in md5.h
 * better MD5 support will appear in 0.5
 */
#include <stddef.h>
#include "md5.h"
#include "context.h"
#include "config.h"
#include "alloc.h"

#ifdef HAVE_MD5DATA
#elif defined(HAVE_OPENSSL) || (defined(HAVE_SASL_MD5_H) && defined(USE_SASL_MD5)) || (!defined(HAVE_OPENSSL) && defined(HAVE_SOLARIS_MD5))
#if defined(USE_SASL_MD5)
/**
 * Get the MD5 hash of a string.
 *
 * @param const unsigned char *d
 *   The string for which a MD5 sum is to be computed.
 * @param unsigned int n
 *   The length of the input.
 * @param unsigned char *md
 *   The buffer into which the MD5 sum will be placed.
 *
 * @return unsigned char *
 *   The output buffer location.
 */
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
/**
 * Calculate a MD5 sum and return as a hex string.
 *
 * @param const unsigned char *d
 *   The input buffer.
 * @param unsigned int sz
 *   The size of the input.
 * @param char *md
 *   A pointer to the output buffer (NULL or at least 33 bytes).
 */
char *pam_mysql_md5_data(const unsigned char *d, unsigned int sz, char *md)
{
  size_t i, j;
  unsigned char buf[16];

  MD5(d, (unsigned long)sz, buf);

  for (i = 0, j = 0; i < 16; i++, j += 2) {
    md[j + 0] = "0123456789abcdef"[(int)(buf[i] >> 4)];
    md[j + 1] = "0123456789abcdef"[(int)(buf[i] & 0x0f)];
  }
  md[j] = '\0';

  return md;
}
#endif
