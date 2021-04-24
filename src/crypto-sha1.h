/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#ifndef __SHA1_H__
#define __SHA1_H__ 1

typedef struct {
  crypto_uint4    state[5];
  crypto_uint4    count[2];
  unsigned char   buffer[64];
} SHA1_CTX;

extern void SHA1Init(SHA1_CTX * context);
extern void SHA1Update(SHA1_CTX * context, const unsigned char * data, size_t len);
extern void SHA1Final(unsigned char digest[20], SHA1_CTX * context);

#endif
