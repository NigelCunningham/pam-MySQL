/**
 * pam_mysql_md5_data
 */
#include "config.h"
#include <openssl/md5.h>

#ifdef HAVE_MD5DATA
#define pam_mysql_md5_data MD5Data
#elif defined(HAVE_OPENSSL) || (defined(HAVE_SASL_MD5_H) && defined(USE_SASL_MD5)) || (!defined(HAVE_OPENSSL) && defined(HAVE_SOLARIS_MD5))
extern char *pam_mysql_md5_data(const unsigned char *d, unsigned int sz, char *md);
#else
#warning No MD5data
#endif
