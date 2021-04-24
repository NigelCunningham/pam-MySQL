#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <assert.h>
#include "logging.h"
#include "password.h"
#include "context.h"
#include "alloc.h"
#include "mysql.h"
#include "config.h"

/**
 * Implementation of calcDecodeLength
 *
 * Calculates the length of a decoded string
 * Copyright (c) 2013 Barry Steyn
 * https://gist.github.com/barrysteyn/7308212
 *
 * @param char* b64input
 *   The buffer of the encoded string.
 *
 * @return size_t
 *   The length of the decoded string
 */
static size_t calcDecodeLength(const char* b64input) {
  size_t len = strlen(b64input),
         padding = 0;

  if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    padding = 2;
  else if (b64input[len-1] == '=') //last char is =
    padding = 1;

  return (len*3)/4 - padding;
}

/**
 * Implementation of Base64Decode
 *
 * Decodes a base64 encoded string
 * Copyright (c) 2013 Barry Steyn
 * https://gist.github.com/barrysteyn/7308212
 *
 * @param char* b64message
 *   The buffer of the Base64 encoded string as input.
 * @param char** buffer
 *   The buffer of the decoded string.
 * @param size_t length
 *   The length of the decoded string.
 *
 * @return int
 *   0 = success
 */
static int Base64Decode(char* b64message, char** buffer, size_t* length) {
  BIO *bio, *b64;

  size_t decodeLen = calcDecodeLength(b64message);
  *buffer = (char*)malloc(decodeLen + 1);
  (*buffer)[decodeLen] = '\0';

  bio = BIO_new_mem_buf(b64message, -1);
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
  *length = BIO_read(bio, *buffer, strlen(b64message));
  assert(*length == decodeLen); //length should equal decodeLen, else something went horribly wrong
  BIO_free_all(bio);

  return (0); //success
}

/**
 * Implementation of Base64Encode
 *
 * Encodes a binary safe base 64 string
 * Copyright (c) 2013 Barry Steyn
 * https://gist.github.com/barrysteyn/7308212
 *
 * @param char* buffer
 *   The buffer of the "normal" string as input.
 * @param size_t length
 *   The length of the "normal" string.
 * @param char** b64text
 *   The buffer of the encoded string.
 *
 * @return int
 *   0 = success
 */
int Base64Encode(const char* buffer, size_t length, char** b64text) {
  BIO *bio, *b64;
  BUF_MEM *bufferPtr;
  size_t b64len;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
  BIO_set_close(bio, BIO_CLOSE);
  BIO_write(bio, buffer, length);
  BIO_flush(bio);

  BIO_get_mem_ptr(bio, &bufferPtr);
  b64len = bufferPtr->length;
  (*b64text) = (char *) malloc((b64len + 1) * sizeof(char));
  memcpy(*b64text, bufferPtr->data, b64len);
  (*b64text)[b64len] = '\0';
  BIO_free_all(bio);

  return (0); //success
}

/**
 * Calculate the salted SHA hash and return as a base64 string.
 *
 * @param const char *d
 *   The input buffer.
 * @param unsigned int sz
 *   The size of the input.
 * @param char *salt
 *   A pointer to the salt string.
 * @param size_t salt_length
 *   The size of the salt string.
 * @param char *md
 *   A pointer to the output buffer (NULL or at least 33 bytes).
 *
 * @return char *
 *   A pointer to the output buffer.
 */
static char *pam_mysql_ssha_data(const char *d, size_t sz, char *salt, size_t salt_length, char *md)
{
  char sha_hash_data[sz + salt_length];
  memcpy(sha_hash_data, d, sz);
  memcpy(&(sha_hash_data[sz]), salt, salt_length);

  char buf[20];
  SHA1((unsigned char *) sha_hash_data, sz + salt_length, (unsigned char *) buf);

  char b64_hash_data[20 + salt_length];
  memcpy(b64_hash_data, buf, 20);
  memcpy(&(b64_hash_data[20]), salt, salt_length);

  char* base64EncodeOutput;
  Base64Encode(b64_hash_data, 20 + salt_length, &base64EncodeOutput);

  memcpy(md, base64EncodeOutput, strlen(base64EncodeOutput) + 1);

  return md;
}

pam_mysql_err_t pam_mysql_encrypt_password_ssha(pam_mysql_ctx_t *ctx, const char *unencrypted, char *encrypted)
{
  (void) ctx;

  char* hash;
  size_t sha1_size;

  Base64Decode(encrypted, &hash, &sha1_size);
  size_t salt_length = sha1_size - 20;
  char salt[salt_length];
  memcpy(salt, &(hash[20]), salt_length);

  pam_mysql_ssha_data(unencrypted, strlen(unencrypted), salt, salt_length, encrypted);

  return PAM_MYSQL_ERR_SUCCESS;
}

