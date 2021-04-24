#ifndef __CRYPTO_H__
#define __CRYPTO_H__ 1

#include <stdlib.h>

#if SIZEOF_SHORT == 4
typedef short crypto_int4;
typedef unsigned short crypto_uint4;
#elif SIZEOF_INT == 4
typedef int crypto_int4;
typedef unsigned int crypto_uint4;
#elif SIZEOF_LONG == 4
typedef long crypto_int4;
typedef unsigned long crypto_uint4;
#elif SIZEOF_SHORT > 4
typedef short crypto_int4;
typedef unsigned short crypto_uint4;
#elif SIZEOF_INT > 4
typedef int crypto_int4;
typedef unsigned int crypto_uint4;
#elif SIZEOF_LONG > 4
typedef long crypto_int4;
typedef unsigned long crypto_uint4;
#else
# error Please report your architecture and OS type to j at pureftpd dot org
#endif

unsigned char *crypto_hash_sha1(const unsigned char *string, const int hex);
unsigned char *crypto_hash_ssha1(const unsigned char *string, const unsigned char *stored);
unsigned char *crypto_hash_md5(const unsigned char *string, const int hex);
unsigned char *crypto_hash_smd5(const unsigned char *string, const unsigned char *stored);
unsigned char *hexify(unsigned char * const result, const unsigned char *digest,
    const size_t size_result, size_t size_digest);

#endif
