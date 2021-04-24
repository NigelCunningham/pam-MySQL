#include "os_dep.h"
#include "stream.h"
#include "strings.h"
#include "alloc.h"
#include "logging.h"

/**
 * Open a stream.
 *
 * @param pam_mysql_stream_t *stream
 *   Pointer to the stream structure.
 * @param pam_mysql_ctx_t *ctx
 *   Pointer to the context data structure.
 * @param const char *file
 *   Pointer to the file name.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
pam_mysql_err_t pam_mysql_stream_open(pam_mysql_stream_t *stream,
    pam_mysql_ctx_t *ctx, const char *file)
{
  stream->buf_end = stream->buf_start = stream->buf_ptr = stream->buf[0];
  stream->pushback = NULL;
  stream->buf_in_use = 0;
  stream->eof = 0;

  if ((stream->fd = open(file, O_RDONLY)) == -1) {
    if (ctx->verbose) {
      switch (errno) {
        case EACCES:
        case EPERM:
          pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "access to %s not permitted", file);
          break;

        case EISDIR:
          pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "%s is directory", file);
          break;

#if HAVE_DECL_ELOOP
        case ELOOP:
          pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "%s refers to an inresolvable symbolic link", file);
          break;
#endif

        case EMFILE:
          pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "too many opened files");
          break;

        case ENFILE:
          pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "too many opened files within this system");
          break;

        case ENOENT:
          pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "%s does not exist", file);
          break;

        case ENOMEM:
          pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "kernel resource exhausted");
          break;

#if HAVE_DECL_EOVERFLOW
        case EOVERFLOW:
          pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "%s is too big", file);
          break;
#endif

        default:
          pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "unknown error while opening %s", file);
          break;
      }
    }

    return PAM_MYSQL_ERR_IO;
  }

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * Close a stream.
 *
 * @param pam_mysql_stream_t *stream
 *   Pointer to the stream data structure.
 */
void pam_mysql_stream_close(pam_mysql_stream_t *stream)
{
  if (stream->fd != -1) {
    close(stream->fd);
  }
}

/**
 * Get a single character from a stream.
 *
 * @param pam_mysql_stream_t *stream
 *   Pointer to the stream data structure.
 * @param int *retval
 *   Pointer to the int where the index should be stored.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
extern pam_mysql_err_t pam_mysql_stream_getc(pam_mysql_stream_t *stream,
    int *retval)
{
  if (stream->buf_ptr >= stream->buf_end) {
    ssize_t new_buf_len;
    unsigned char *new_buf = stream->buf[1 - stream->buf_in_use];

    if (stream->pushback != NULL) {
      stream->buf_end = stream->pushback;
      stream->pushback = NULL;
    } else {
      if (stream->eof) {
        return PAM_MYSQL_ERR_EOF;
      }

      if ((new_buf_len = read(stream->fd, new_buf, sizeof(stream->buf[0]))) == -1) {
        pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "I/O error");
        return PAM_MYSQL_ERR_IO;
      }

      if (new_buf_len == 0) {
        stream->eof = 1;
        return PAM_MYSQL_ERR_EOF;
      }

      stream->buf_end = new_buf + new_buf_len;
    }

    stream->buf_start = stream->buf_ptr = new_buf;
    stream->buf_in_use = 1 - stream->buf_in_use;
  }

  *retval = *(stream->buf_ptr++);

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * Put back a character to the stream.
 *
 * @param pam_mysql_stream_t *stream
 *   Pointer to the stream structure.
 * @param int c
 *   The character to 'return' to the stream.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
pam_mysql_err_t pam_mysql_stream_ungetc(pam_mysql_stream_t *stream, int c)
{
  if (stream->buf_ptr == stream->buf_start) {
    if (stream->pushback != NULL) {
      return PAM_MYSQL_ERR_IO;
    }

    stream->pushback = stream->buf_end;
    stream->buf_in_use = 1 - stream->buf_in_use;
    stream->buf_start = stream->buf[stream->buf_in_use];
    stream->buf_ptr = stream->buf_start + sizeof(stream->buf[0]);
  }

  *(--stream->buf_ptr) = c;

  return PAM_MYSQL_ERR_SUCCESS;
}

/* pam_mysql_stream_skip_spn */
/**
 * Skip instances of a list of characters in the input stream.
 *
 * @param pam_mysql_stream_t *stream
 *   A pointer to the stream data structure.
 * @param const char *accept_cset
 *   A pointer to the set of characters to be skipped.
 * @param size_t naccepts
 *   The length of the list of characters to skip.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
pam_mysql_err_t pam_mysql_stream_skip_spn(pam_mysql_stream_t *stream,
    const char *accept_cset, size_t naccepts)
{
  unsigned char *p;

  if (stream->eof) {
    return PAM_MYSQL_ERR_EOF;
  }

  if ((p = (unsigned char *)memspn(stream->buf_ptr,
          stream->buf_end - stream->buf_ptr, (const unsigned char *)accept_cset,
          naccepts)) != NULL) {
    stream->buf_ptr = p;

    return PAM_MYSQL_ERR_SUCCESS;
  }

  if (stream->pushback != NULL) {
    stream->buf_in_use = 1 - stream->buf_in_use;
    stream->buf_start = stream->buf_ptr = stream->buf[stream->buf_in_use];
    stream->buf_end = stream->pushback;
    stream->pushback = NULL;

    if ((p = (unsigned char *)memspn(stream->buf_ptr,
            stream->buf_end - stream->buf_ptr, (const unsigned char *)accept_cset,
            naccepts)) != NULL) {
      stream->buf_ptr = p;

      return PAM_MYSQL_ERR_SUCCESS;
    }
  }

  for (;;) {
    ssize_t new_buf_len;

    if ((new_buf_len = read(stream->fd, stream->buf_start, sizeof(stream->buf[0]))) == -1) {
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "I/O error");
      return PAM_MYSQL_ERR_IO;
    }

    if (new_buf_len == 0) {
      stream->eof = 1;
      return PAM_MYSQL_ERR_EOF;
    }

    stream->buf_end = stream->buf_start + new_buf_len;

    if ((p = (unsigned char *)memspn(stream->buf_start, new_buf_len,
            (const unsigned char *)accept_cset, naccepts)) != NULL) {
      stream->buf_ptr = p;

      break;
    }
  }

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * Read a stream until a character in the list of delimiters is found, and
 * append the substr to an existing string.
 *
 * @param pam_mysql_stream_t *stream
 *   A pointer to the stream data structure.
 * @param pam_mysql_str_t *append_to
 *   A pointer to the string to which data should be appended.
 * @param int *found_delim
 *   A pointer to the delimiter that was found.
 * @param const char *delims
 *   A pointer to the list of delimiters to match.
 * @param size_t ndelims
 *   The number of items in the delims list.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
extern pam_mysql_err_t pam_mysql_stream_read_cspn(pam_mysql_stream_t *stream,
    pam_mysql_str_t *append_to, int *found_delim, const char *delims,
    size_t ndelims)
{
  pam_mysql_err_t err;
  unsigned char *p;
  ssize_t len;
  size_t rem_len;

  if (stream->eof) {
    return PAM_MYSQL_ERR_EOF;
  }

  if ((p = (unsigned char *)memcspn(stream->buf_ptr,
          stream->buf_end - stream->buf_ptr, (const unsigned char *)delims,
          ndelims)) != NULL) {
    if ((err = pam_mysql_str_append(append_to, (char *)stream->buf_ptr,
            p - stream->buf_ptr))) {
      return err;
    }

    *found_delim = *p;
    stream->buf_ptr = p;

    return PAM_MYSQL_ERR_SUCCESS;
  }

  if ((err = pam_mysql_str_append(append_to, (char *)stream->buf_ptr,
          stream->buf_end - stream->buf_ptr))) {
    return err;
  }

  if (stream->pushback != NULL) {
    stream->buf_in_use = 1 - stream->buf_in_use;
    stream->buf_start = stream->buf_ptr = stream->buf[stream->buf_in_use];
    stream->buf_end = stream->pushback;
    stream->pushback = NULL;

    if ((p = (unsigned char *)memcspn(stream->buf_ptr,
            stream->buf_end - stream->buf_ptr,
            (const unsigned char *)delims, ndelims)) != NULL) {
      if ((err = pam_mysql_str_append(append_to, (char *)stream->buf_ptr,
              p - stream->buf_ptr))) {
        return err;
      }

      *found_delim = *p;
      stream->buf_ptr = p;

      return PAM_MYSQL_ERR_SUCCESS;
    }

    if ((err = pam_mysql_str_append(append_to, (char *)stream->buf_ptr,
            stream->buf_end - stream->buf_ptr))) {
      return err;
    }
  }

  rem_len = 0;

  for (;;) {
    unsigned char *block;

    if ((err = pam_mysql_str_reserve(append_to,
            sizeof(stream->buf[0]) - rem_len))) {
      return err;
    }

    block = (unsigned char*)append_to->p + append_to->len;

    if ((len = read(stream->fd, block, sizeof(stream->buf[0]))) == -1) {
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "I/O error");
      return PAM_MYSQL_ERR_IO;
    }

    if (len == 0) {
      stream->eof = 1;
      return PAM_MYSQL_ERR_EOF;
    }

    if ((p = (unsigned char *)memcspn(block, len,
            (const unsigned char *)delims, ndelims)) != NULL) {
      size_t new_buf_len;

      append_to->len += p - block;
      new_buf_len = len - (p - block);

      memcpy(stream->buf_start, p, new_buf_len);

      stream->buf_ptr = stream->buf_start;
      stream->buf_end = stream->buf_start + new_buf_len;

      break;
    }

    append_to->len += len;
    rem_len = sizeof(stream->buf[0]) - len;
  }

  *found_delim = *p;
  append_to->p[append_to->len] = '\0';

  return PAM_MYSQL_ERR_SUCCESS;
}

