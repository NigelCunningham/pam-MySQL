#include "os_dep.h"
#include "strings.h"
#include "alloc.h"
#include "logging.h"

/**
 * Local strnncpy.
 *
 * @param char* dest
 *   Pointer to a string into which the string should be copied.
 * @param size_t dest_size
 *   The size of the destination buffer.
 * @param char *src
 *   Pointer to the source string.
 * @param size_t src_len
 *   The length of the source string.
 *
 * @return size_t
 *   The length of the copied data.
 */
size_t strnncpy(char *dest, size_t dest_size, const char *src, size_t src_len)
{
  size_t cpy_len;
  dest_size--;
  cpy_len = (dest_size < src_len ? dest_size: src_len);

  memcpy(dest, src, cpy_len);

  dest[cpy_len] = '\0';

  return cpy_len;
}

/**
 * String destructor. Clears memory if mangle is set.
 *
 * @param pam_mysql_str_t *str
 *   Pointer to the string to be freed.
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
 * String initialisor.
 *
 * @param pam_mysql_str_t *str
 *   Pointer to the string to be initialised.
 * @param int mangle
 *   Value for the mangle attribute.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
pam_mysql_err_t pam_mysql_str_init(pam_mysql_str_t *str, int mangle)
{
  str->p = "";
  str->len = 0;
  str->alloc_size = 0;
  str->mangle = mangle;

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * Modify a string structure to allow for a longer string.
 *
 * @param pam_mysql_str_t *str
 *   Pointer to the structure.
 * @param size_t len
 *   The amount of additional space required.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
pam_mysql_err_t pam_mysql_str_reserve(pam_mysql_str_t *str, size_t len)
{
  size_t len_req;

  {
    len_req = str->len + len;
    if (len_req < str->len) {
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "integer overflow at " __FILE__ ":%d", __LINE__);
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
        pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
        return PAM_MYSQL_ERR_ALLOC;
      }
      cv = new_size;
    } while (new_size < len_req);

    if (str->mangle) {
      if (NULL == (new_buf = xcalloc(new_size, sizeof(char)))) {
        pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
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
          pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
          return PAM_MYSQL_ERR_ALLOC;
        }
      } else {
        if (NULL == (new_buf = xrealloc(str->p, new_size, sizeof(char)))) {
          pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
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
 * Escape a string and append it to another.
 *
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 * @param pam_mysql_str_t *append_to
 *   The string to which the escaped text should be appended.
 * @param const char *val
 *   The string to be escaped and appended.
 * @param size_t val_len
 *   The length of the string to be escaped and appended.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
pam_mysql_err_t pam_mysql_quick_escape(pam_mysql_ctx_t *ctx, pam_mysql_str_t *append_to, const char *val, size_t val_len)
{
  size_t len;

  if (ctx->verbose) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_mysql_quick_escape() called.");
  }

  if (val_len >= (((size_t)-1)>>1) || pam_mysql_str_reserve(append_to, val_len * 2)) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
    return PAM_MYSQL_ERR_ALLOC;
  }

#ifdef HAVE_MYSQL_REAL_ESCAPE_STRING
  len = mysql_real_escape_string(ctx->mysql_hdl, &append_to->p[append_to->len], val, val_len);
#else
  len = mysql_escape_string(&append_to->p[append_to->len], val, val_len);
#endif
  append_to->p[append_to->len += len] = '\0';

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * Append new content to an existing string.
 *
 * @param pam_mysql_str_t *str
 *   Pointer to the structure.
 * @param const char *s
 *   The string to be appended.
 * @param size_t len
 *   The length of the new string.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
pam_mysql_err_t pam_mysql_str_append(pam_mysql_str_t *str,
    const char *s, size_t len)
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

/**
 * Append a single character to a string.
 *
 * @param pam_mysql_str_t *str
 *   Pointer to the structure.
 * @param char c
 *   The character to be appended.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
pam_mysql_err_t pam_mysql_str_append_char(pam_mysql_str_t *str, char c)
{
  return pam_mysql_str_append(str, &c, sizeof(c));
}

/**
 * Truncate a string.
 *
 * @param pam_mysql_str_t *str
 *   Pointer to the structure.
 * @param size_t len
 *   The new string length.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
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

/**
 * Skip instances of a list of delimiters in an input buffer.
 *
 * @param void *buf
 *   The memory
 * @param size_t buf_len
 *   The length of the input buffer.
 * @param const unsigned char *delims
 *   A pointer to an array of single character delimiters.
 * @param size_t ndelims
 *   The number of delimiters provided.
 *
 * @return unsigned char
 *   A pointer to the first delimiter found, or the end of the input buffer.
 */
void *memspn(void *buf, size_t buf_len, const unsigned char *delims,
    size_t ndelims)
{
  unsigned char *buf_end = ((unsigned char *)buf) + buf_len;
  unsigned char *p;

  switch (ndelims) {
    case 0:
      return buf_end;

    case 1:
      {
        unsigned char c = delims[0];

        for (p = (unsigned char *)buf; p < buf_end; p++) {
          if (*p != c) {
            return (void *)p;
          }
        }
      }

      break;

    case 2:
      {
        unsigned char c1 = delims[0], c2 = delims[1];

        for (p = (unsigned char *)buf; p < buf_end; p++) {
          if (*p != c1 && *p != c2) {
            return (void *)p;
          }
        }
      }

      break;

    default:
      {
        const unsigned char *delims_end = delims + ndelims;
        unsigned char and_mask = ~0, or_mask = 0;
        const unsigned char *q;

        for (q = delims; q < delims_end; q++) {
          and_mask &= *q;
          or_mask |= *q;
        }

        for (p = (unsigned char *)buf; p < buf_end; p++) {
          if ((*p & and_mask) == and_mask && (*p & or_mask) != 0) {
            for (q = delims; *p != *q; q++) {
              if (q >= delims_end) {
                return (void *)p;
              }
            }
          }
        }
      }

      break;
  }

  return NULL;
}

/**
 * Locate a delimiter or delimiters within a string.
 *
 * Scan for the earliest instance of a list of delimiters.
 *
 * @param void *buf
 *   The input buffer.
 * @param size_t buf_len
 *   The size of the input buffer.
 * @param const unsigned char *delims
 *   An array of single character delimiters.
 * @param size_t ndelims
 *   The number of delimiters.
 *
 * @return mixed
 *   The location of the first matching delimiter or NULL.
 */
void *memcspn(void *buf, size_t buf_len, const unsigned char *delims,
    size_t ndelims)
{
  if (ndelims == 1) {
    return memchr(buf, delims[0], buf_len);
  } else {
    unsigned char *buf_end = ((unsigned char *)buf) + buf_len;
    const unsigned char *delims_end = delims + ndelims;
    unsigned char *p;

    for (p = (unsigned char *)buf; p < buf_end; p++) {
      const unsigned char *q;

      for (q = delims; q < delims_end; q++) {
        if (*p == *q) {
          return (void *)p;
        }
      }
    }

    return NULL;
  }
}

