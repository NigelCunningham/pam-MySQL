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

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "string.h"
#include "memory.h"
#include "configuration.h"
#include "database.h"

enum _pam_mysql_config_token_t {
  PAM_MYSQL_CONFIG_TOKEN_EQUAL = 0,
  PAM_MYSQL_CONFIG_TOKEN_NEWLINE,
  PAM_MYSQL_CONFIG_TOKEN_STRING,
  PAM_MYSQL_CONFIG_TOKEN_SEMICOLON,
  PAM_MYSQL_CONFIG_TOKEN_COMMENT,
  PAM_MYSQL_CONFIG_TOKEN__LAST
};

struct _pam_mysql_entry_handler_t;

typedef pam_mysql_err_t (*pam_mysql_handle_entry_fn_t)(
    struct _pam_mysql_entry_handler_t *, int, const char *, size_t,
    const char *, size_t);

typedef int(*pam_mysql_option_getter_t)(void *val, const char **pretval, int *to_release);
typedef int(*pam_mysql_option_setter_t)(void *val, const char *newval_str);

typedef struct _pam_mysql_option_accessor_t {
  pam_mysql_option_getter_t get_op;
  pam_mysql_option_setter_t set_op;
} pam_mysql_option_accessor_t;

typedef struct _pam_mysql_option_t {
  const char *name;
  size_t name_len;
  size_t offset;
  pam_mysql_option_accessor_t *accessor;
} pam_mysql_option_t;

typedef struct _pam_mysql_entry_handler_t {
  pam_mysql_ctx_t *ctx;
  pam_mysql_handle_entry_fn_t handle_entry_fn;
  pam_mysql_option_t *options;
} pam_mysql_entry_handler_t;

typedef struct _pam_mysql_config_parser_t {
  pam_mysql_ctx_t *ctx;
  pam_mysql_entry_handler_t *hdlr;
} pam_mysql_config_parser_t;

typedef struct _pam_mysql_stream_t {
  int fd;
  unsigned char buf[2][2048];
  unsigned char *buf_start;
  unsigned char *buf_ptr;
  unsigned char *buf_end;
  unsigned char *pushback;
  size_t buf_in_use;
  int eof;
} pam_mysql_stream_t;

typedef enum _pam_mysql_config_token_t pam_mysql_config_token_t;

typedef struct _pam_mysql_config_scanner_t {
  pam_mysql_ctx_t *ctx;
  pam_mysql_str_t image;
  pam_mysql_config_token_t token;
  pam_mysql_stream_t *stream;
  int state;
} pam_mysql_config_scanner_t;

/**
 * config file scanner / parser
 **/
static const char * pam_mysql_config_token_name[] = {
  "=",
  "<NEWLINE>",
  "<STRING_LITERAL>",
  ";",
  "<COMMENT>",
  NULL
};

static void *memspn(void *buf, size_t buf_len, const unsigned char *delims,
 size_t ndelims)
{
  unsigned char *buf_end = ((unsigned char *)buf) + buf_len;
  unsigned char *p;

  switch (ndelims) {
    case 0:
      return buf_end;

    case 1: {
              unsigned char c = delims[0];

              for (p = (unsigned char *)buf; p < buf_end; p++) {
                if (*p != c) {
                  return (void *)p;
                }
              }
            } break;

    case 2: {
              unsigned char c1 = delims[0], c2 = delims[1];

              for (p = (unsigned char *)buf; p < buf_end; p++) {
                if (*p != c1 && *p != c2) {
                  return (void *)p;
                }
              }
            } break;

    default: {
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
             } break;
  }

  return NULL;
}

static void *memcspn(void *buf, size_t buf_len, const unsigned char *delims,
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

/**
 * pam_mysql_stream_skip_spn
 **/
static pam_mysql_err_t pam_mysql_stream_skip_spn(pam_mysql_stream_t *stream,
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
      syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "I/O error");
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
 * pam_mysql_stream_read_cspn
 **/
static pam_mysql_err_t pam_mysql_stream_read_cspn(pam_mysql_stream_t *stream,
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
      syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "I/O error");
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

/**
 * pam_mysql_stream_ungetc
 **/
static pam_mysql_err_t pam_mysql_stream_ungetc(pam_mysql_stream_t *stream, int c)
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

/**
 * pam_mysql_stream_getc
 **/
static pam_mysql_err_t pam_mysql_stream_getc(pam_mysql_stream_t *stream,
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
        syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "I/O error");
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
 * pam_mysql_config_scanner_next_token
 **/
static pam_mysql_err_t pam_mysql_config_scanner_next_token(
 pam_mysql_config_scanner_t *scanner)
{
  pam_mysql_err_t err;
  int c;

  switch (scanner->state) {
    case 0:
      if ((err = pam_mysql_str_truncate(&scanner->image, 0))) {
        return err;
      }

      if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
        return err;
      }

      if (c == '#') {
        if ((err = pam_mysql_str_append_char(&scanner->image, c))) {
          return err;
        }

        if ((err = pam_mysql_stream_read_cspn(scanner->stream,
                &scanner->image, &c, "\n\r", sizeof("\n\r") - 1))) {
          return err;
        }

        scanner->token = PAM_MYSQL_CONFIG_TOKEN_COMMENT;

        if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
          return err;
        }

        if (c == '\r') {
          if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
            return err;
          }

          if (c != '\n') {
            if ((err = pam_mysql_stream_ungetc(scanner->stream, c))) {
              return err;
            }
          }
        }
        break;
      } else {
        if ((err = pam_mysql_stream_ungetc(scanner->stream, c))) {
          return err;
        }
      }

    case 1:
      if ((err = pam_mysql_stream_skip_spn(scanner->stream,
              " \t", sizeof(" \t") - 1))) {
        return err;
      }

      if ((err = pam_mysql_str_truncate(&scanner->image, 0))) {
        return err;
      }

      if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
        return err;
      }

      if ((err = pam_mysql_str_append_char(&scanner->image, c))) {
        return err;
      }

      switch (scanner->image.p[0]) {
        case '=':
          scanner->token = PAM_MYSQL_CONFIG_TOKEN_EQUAL;
          scanner->state = 2;
          break;

        case ';':
          scanner->token = PAM_MYSQL_CONFIG_TOKEN_SEMICOLON;
          scanner->state = 1;
          break;

        default:
          if ((err = pam_mysql_stream_read_cspn(scanner->stream,
                  &scanner->image, &c, "=; \t\n\r", sizeof("=; \t\n\r") - 1))) {
            return err;
          }
          scanner->token = PAM_MYSQL_CONFIG_TOKEN_STRING;
          scanner->state = 1;
          break;

        case '\r':
          if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
            return err;
          }

          if (c != '\n') {
            if ((err = pam_mysql_stream_ungetc(scanner->stream, c))) {
              return err;
            }
          } else {
            if ((err = pam_mysql_str_append_char(&scanner->image, c))) {
              return err;
            }
          }

          scanner->token = PAM_MYSQL_CONFIG_TOKEN_NEWLINE;
          scanner->state = 0;
          break;

        case '\n':
          scanner->token = PAM_MYSQL_CONFIG_TOKEN_NEWLINE;
          scanner->state = 0;
          break;
      }
      break;

    case 2:
      if ((err = pam_mysql_stream_skip_spn(scanner->stream,
              " \t", sizeof(" \t") - 1))) {
        return err;
      }

      if ((err = pam_mysql_str_truncate(&scanner->image, 0))) {
        return err;
      }

      if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
        return err;
      }

      if ((err = pam_mysql_str_append_char(&scanner->image, c))) {
        return err;
      }

      switch (scanner->image.p[0]) {
        case ';':
          scanner->token = PAM_MYSQL_CONFIG_TOKEN_SEMICOLON;
          scanner->state = 1;
          break;

        default:
          if ((err = pam_mysql_stream_read_cspn(scanner->stream,
                  &scanner->image, &c, ";\n\r", sizeof(";\n\r") - 1))) {
            return err;
          }
          scanner->token = PAM_MYSQL_CONFIG_TOKEN_STRING;
          break;

        case '\r':
          if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
            return err;
          }

          if (c != '\n') {
            if ((err = pam_mysql_stream_ungetc(scanner->stream, c))) {
              return err;
            }
          } else {
            if ((err = pam_mysql_str_append_char(&scanner->image, c))) {
              return err;
            }
          }

          scanner->token = PAM_MYSQL_CONFIG_TOKEN_NEWLINE;
          scanner->state = 0;
          break;

        case '\n':
          scanner->token = PAM_MYSQL_CONFIG_TOKEN_NEWLINE;
          scanner->state = 0;
          break;
      }
      break;
  }

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * pam_mysql_config_scanner_init
 **/
static pam_mysql_err_t pam_mysql_config_scanner_init(
 pam_mysql_config_scanner_t *scanner, pam_mysql_ctx_t *ctx,
 pam_mysql_stream_t *stream)
{
  pam_mysql_err_t err;

  if ((err = pam_mysql_str_init(&scanner->image, 1))) {
    return err;
  }

  scanner->ctx = ctx;
  scanner->stream = stream;
  scanner->state = 0;

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * pam_mysql_config_scanner_destroy
 **/
static void pam_mysql_config_scanner_destroy(
 pam_mysql_config_scanner_t *scanner)
{
  pam_mysql_str_destroy(&scanner->image);
}

/**
 * pam_mysql_config_parser_parse
 **/
static pam_mysql_err_t pam_mysql_config_parser_parse(
 pam_mysql_config_parser_t *parser, pam_mysql_stream_t *stream)
{
  pam_mysql_err_t err;
  pam_mysql_config_scanner_t scanner;
  char *name = NULL;
  size_t name_len = 0;
  char *value = NULL;
  size_t value_len = 0;

  int state = 0;
  int line_num = 1;

  if ((err = pam_mysql_config_scanner_init(&scanner, parser->ctx, stream))) {
    return err;
  }

  while (!(err = pam_mysql_config_scanner_next_token(&scanner))) {
    switch (state) {
      case 0:
        switch (scanner.token) {
          case PAM_MYSQL_CONFIG_TOKEN_STRING:
            if (name == NULL || name_len < scanner.image.len) {
              char *new_buf;

              if (NULL == (new_buf = xrealloc(name,
                      scanner.image.len + 1, sizeof(char)))) {
                syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
                err = PAM_MYSQL_ERR_ALLOC;
                goto out;
              }

              name = new_buf;
            }

            memcpy(name, scanner.image.p, scanner.image.len + 1);
            name_len = scanner.image.len;

            state = 1;
            break;

          case PAM_MYSQL_CONFIG_TOKEN_NEWLINE:
            line_num++;
            break;

          case PAM_MYSQL_CONFIG_TOKEN_COMMENT:
            line_num++;
            break;

          default:
            err = PAM_MYSQL_ERR_SYNTAX;
            goto out;
        }
        break;

      case 1:
        switch (scanner.token) {
          case PAM_MYSQL_CONFIG_TOKEN_EQUAL:
            state = 2;
            break;

          default:
            err = PAM_MYSQL_ERR_SYNTAX;
            goto out;
        }
        break;

      case 2:
        switch (scanner.token) {
          case PAM_MYSQL_CONFIG_TOKEN_SEMICOLON:
            if (parser->hdlr &&
                (err = parser->hdlr->handle_entry_fn(
                                                     parser->hdlr, line_num, name, name_len,
                                                     "", 0))) {
              goto out;
            }
            state = 4;
            break;

          case PAM_MYSQL_CONFIG_TOKEN_NEWLINE:
            if (parser->hdlr &&
                (err = parser->hdlr->handle_entry_fn(
                                                     parser->hdlr, line_num, name, name_len,
                                                     "", 0))) {
              goto out;
            }
            line_num++;
            state = 0;
            break;

          case PAM_MYSQL_CONFIG_TOKEN_STRING:
            if (value == NULL || value_len < scanner.image.len) {
              char *new_buf;

              if (NULL == (new_buf = xrealloc(value,
                      scanner.image.len + 1, sizeof(char)))) {
                syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
                err = PAM_MYSQL_ERR_ALLOC;
                goto out;
              }

              value = new_buf;
            }

            memcpy(value, scanner.image.p, scanner.image.len + 1);
            value_len = scanner.image.len;

            if (parser->hdlr &&
                (err = parser->hdlr->handle_entry_fn(
                                                     parser->hdlr, line_num, name, name_len,
                                                     value, value_len))) {
              goto out;
            }
            state = 3;
            break;

          default:
            err = PAM_MYSQL_ERR_SYNTAX;
            goto out;
        }
        break;

      case 3:
        switch (scanner.token) {
          case PAM_MYSQL_CONFIG_TOKEN_SEMICOLON:
            state = 4;
            break;

          case PAM_MYSQL_CONFIG_TOKEN_NEWLINE:
            line_num++;
            state = 0;
            break;

          default:
            err = PAM_MYSQL_ERR_SYNTAX;
            goto out;
        }
        break;

      case 4:
        switch (scanner.token) {
          case PAM_MYSQL_CONFIG_TOKEN_NEWLINE:
            line_num++;
            state = 0;
            break;

          default:
            err = PAM_MYSQL_ERR_SYNTAX;
            goto out;
        }
        break;
    }
  }

  if (err == PAM_MYSQL_ERR_EOF) {
    err = PAM_MYSQL_ERR_SUCCESS;
  }

out:
  if (err == PAM_MYSQL_ERR_SYNTAX) {
    if (parser->ctx->verbose) {
      syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "unexpected token %s on line %d\n",
          pam_mysql_config_token_name[scanner.token],
          line_num);
    }
  }

  if (name != NULL) {
    xfree(name);
  }

  if (value != NULL) {
    xfree(value);
  }

  pam_mysql_config_scanner_destroy(&scanner);

  return err;
}

/**
 * pam_mysql_string_opt_getter
 */
static pam_mysql_err_t pam_mysql_string_opt_getter(void *val, const char **pretval, int *to_release)
{
  *pretval = *(char **)val;
  *to_release = 0;

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * pam_mysql_string_opt_setter
 */
static pam_mysql_err_t pam_mysql_string_opt_setter(void *val, const char *newval_str)
{
  if (*(char **)val != NULL) {
    xfree(*(char **)val);
  }

  if (NULL == (*(char **)val = xstrdup(newval_str))) {
    syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
    return PAM_MYSQL_ERR_ALLOC;
  }

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * pam_mysql_boolean_opt_getter
 **/
static pam_mysql_err_t pam_mysql_boolean_opt_getter(void *val, const char **pretval, int *to_release)
{
  *pretval = (*(int *)val ? "true": "false");
  *to_release = 0;

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * pam_mysql_boolean_opt_setter
 **/
static pam_mysql_err_t pam_mysql_boolean_opt_setter(void *val, const char *newval_str)
{
  *(int *)val = (strcmp(newval_str, "0") != 0 &&
      strcasecmp(newval_str, "N") != 0 &&
      strcasecmp(newval_str, "false") != 0 &&
      strcasecmp(newval_str, "no") != 0);

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * pam_mysql_crypt_opt_getter
 **/
static pam_mysql_err_t pam_mysql_crypt_opt_getter(void *val, const char **pretval, int *to_release)
{
  switch (*(int *)val) {
    case 0:
      *pretval = "plain";
      break;

    case 1:
      *pretval = "Y";
      break;

    case 2:
      *pretval = "mysql";
      break;

    case 3:
      *pretval = "md5";
      break;

    case 4:
      *pretval = "sha1";
      break;

    case 5:
      *pretval = "drupal7";
      break;

    case 6:
      *pretval = "joomla15";
      break;

    default:
      *pretval = NULL;
  }

  *to_release = 0;

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * pam_mysql_crypt_opt_setter
 **/
static pam_mysql_err_t pam_mysql_crypt_opt_setter(void *val, const char *newval_str)
{
  if (strcmp(newval_str, "0") == 0 || strcasecmp(newval_str, "plain") == 0) {
    *(int *)val = 0;
    return PAM_MYSQL_ERR_SUCCESS;
  }

  if (strcmp(newval_str, "1") == 0 || strcasecmp(newval_str, "Y") == 0) {
    *(int *)val = 1;
    return PAM_MYSQL_ERR_SUCCESS;
  }

  if (strcmp(newval_str, "2") == 0 || strcasecmp(newval_str, "mysql") == 0) {
    *(int *)val = 2;
    return PAM_MYSQL_ERR_SUCCESS;
  }
  if (strcmp(newval_str, "3") == 0 || strcasecmp(newval_str, "md5") == 0) {
    *(int *)val = 3;
    return PAM_MYSQL_ERR_SUCCESS;
  }
  if (strcmp(newval_str, "4") == 0 || strcasecmp(newval_str, "sha1") == 0) {
    *(int *)val = 4;
    return PAM_MYSQL_ERR_SUCCESS;
  }

  if (strcmp(newval_str, "5") == 0 || strcasecmp(newval_str, "drupal7") == 0) {
    *(int *)val = 5;
    return PAM_MYSQL_ERR_SUCCESS;
  }

  if (strcmp(newval_str, "6") == 0 || strcasecmp(newval_str, "joomla15") == 0) {
    *(int *)val = 6;
    return PAM_MYSQL_ERR_SUCCESS;
  }

  *(int *)val = 0;

  return PAM_MYSQL_ERR_INVAL;
}

static pam_mysql_option_accessor_t pam_mysql_string_opt_accr = {
  pam_mysql_string_opt_getter,
  pam_mysql_string_opt_setter
};

static pam_mysql_option_accessor_t pam_mysql_boolean_opt_accr = {
  pam_mysql_boolean_opt_getter,
  pam_mysql_boolean_opt_setter
};

static pam_mysql_option_accessor_t pam_mysql_crypt_opt_accr = {
  pam_mysql_crypt_opt_getter,
  pam_mysql_crypt_opt_setter
};

/**
 * option definitions
 **/
#define PAM_MYSQL_OFFSETOF(type, x) ((size_t)&((type *)0)->x)

#define PAM_MYSQL_DEF_OPTION(name, accr) PAM_MYSQL_DEF_OPTION2(name, name, accr)


#define PAM_MYSQL_DEF_OPTION2(name, sname, accr) \
{ #name, sizeof(#name) - 1, PAM_MYSQL_OFFSETOF(pam_mysql_ctx_t, sname), accr }

static pam_mysql_option_t options[] = {
  PAM_MYSQL_DEF_OPTION(host, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(where, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(db, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(user, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(passwd, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(table, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(update_table, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(usercolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(passwdcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(statcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(crypt, crypt_type, &pam_mysql_crypt_opt_accr),
  PAM_MYSQL_DEF_OPTION(md5, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION(sqllog, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION(verbose, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION(logtable, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(logmsgcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(logpidcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(logusercolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(loghostcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(logrhostcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(logtimecolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(config_file, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(use_323_passwd, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION(use_first_pass, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION(try_first_pass, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION(disconnect_every_op, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION2(debug, verbose, &pam_mysql_boolean_opt_accr),
  { NULL, 0, 0, NULL }
};

/**
 * entry handler
 **/
static pam_mysql_option_t pam_mysql_entry_handler_options[] = {
  PAM_MYSQL_DEF_OPTION2(users.host, host, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.database, db, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.db_user, user, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.db_passwd, passwd, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.where_clause, where, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.table, table, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.update_table, update_table, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.user_column, usercolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.password_column, passwdcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.status_column, statcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.password_crypt, crypt_type, &pam_mysql_crypt_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.use_md5, md5, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION2(verbose, verbose, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION2(log.enabled, sqllog, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION2(log.table, logtable, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(log.message_column, logmsgcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(log.pid_column, logpidcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(log.user_column, logusercolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(log.host_column, loghostcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(log.rhost_column, logrhostcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(log.time_column, logtimecolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.use_323_password, use_323_passwd, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.disconnect_every_operation, disconnect_every_op, &pam_mysql_boolean_opt_accr),
  { NULL, 0, 0, NULL }
};

/**
 * pam_mysql_stream_open
 **/
static pam_mysql_err_t pam_mysql_stream_open(pam_mysql_stream_t *stream,
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
          syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "access to %s not permitted", file);
          break;

        case EISDIR:
          syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "%s is directory", file);
          break;

#if HAVE_DECL_ELOOP
        case ELOOP:
          syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "%s refers to an inresolvable symbolic link", file);
          break;
#endif

        case EMFILE:
          syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "too many opened files");
          break;

        case ENFILE:
          syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "too many opened files within this system");
          break;

        case ENOENT:
          syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "%s does not exist", file);
          break;

        case ENOMEM:
          syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "kernel resource exhausted");
          break;

#if HAVE_DECL_EOVERFLOW
        case EOVERFLOW:
          syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "%s is too big", file);
          break;
#endif

        default:
          syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "unknown error while opening %s", file);
          break;
      }
    }

    return PAM_MYSQL_ERR_IO;
  }

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * pam_mysql_stream_close
 **/
static void pam_mysql_stream_close(pam_mysql_stream_t *stream)
{
  if (stream->fd != -1) {
    close(stream->fd);
  }
}

/**
 * pam_mysql_config_parser_init
 **/
static pam_mysql_err_t pam_mysql_config_parser_init(
 pam_mysql_config_parser_t *parser, pam_mysql_ctx_t *ctx,
 pam_mysql_entry_handler_t *hdlr)
{
  parser->ctx = ctx;
  parser->hdlr = hdlr;

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * pam_mysql_config_parser_destroy
 **/
static void pam_mysql_config_parser_destroy(pam_mysql_config_parser_t *parser)
{
  /* do nothing */
}

/**
 * pam_mysql_entry_handler_destroy
 **/
static void pam_mysql_entry_handler_destroy( pam_mysql_entry_handler_t *hdlr)
{
  /* do nothing */
}

/**
 * pam_mysql_find_option()
 **/
static pam_mysql_option_t *pam_mysql_find_option(pam_mysql_option_t *options,
 const char *name, size_t name_len)
{
  /* set the various ctx */
  pam_mysql_option_t *retval;

  for (retval = options; retval->name != NULL; retval++) {
    if (retval->name_len == name_len &&
        memcmp(retval->name, name, name_len) == 0) {
      return retval;
    }
  }

  return NULL;
}

/**
 * pam_mysql_handle_entry
 **/
static pam_mysql_err_t pam_mysql_handle_entry( pam_mysql_entry_handler_t *hdlr,
    int line_num, const char *name, size_t name_len, const char *value, size_t
    value_len)
{
  pam_mysql_err_t err;
  pam_mysql_option_t *opt = pam_mysql_find_option(hdlr->options, name,
      name_len);

  if (opt == NULL) {
    if (hdlr->ctx->verbose) {
      char buf[1024];
      strnncpy(buf, sizeof(buf), name, name_len);
      syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "unknown option %s on line %d", buf, line_num);
    }

    return PAM_MYSQL_ERR_SUCCESS;
  }

  err = opt->accessor->set_op((void*)((char *)hdlr->ctx + opt->offset), value);
  if (!err && hdlr->ctx->verbose) {
    char buf[1024];
    strnncpy(buf, sizeof(buf), name, name_len);
    syslog(LOG_AUTHPRIV | LOG_INFO, PAM_MYSQL_LOG_PREFIX "option %s is set to \"%s\"", buf, value);
  }

  return err;
}

/**
 * pam_mysql_entry_handler_init
 **/
static pam_mysql_err_t pam_mysql_entry_handler_init( pam_mysql_entry_handler_t
    *hdlr, pam_mysql_ctx_t *ctx)
{
  hdlr->handle_entry_fn = pam_mysql_handle_entry;
  hdlr->ctx = ctx;
  hdlr->options = pam_mysql_entry_handler_options;

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * pam_mysql_read_config_file()
 **/
pam_mysql_err_t pam_mysql_read_config_file(pam_mysql_ctx_t *ctx,
 const char *path)
{
  pam_mysql_err_t err;
  pam_mysql_entry_handler_t handler;
  pam_mysql_config_parser_t parser;
  pam_mysql_stream_t stream;


  if ((err = pam_mysql_entry_handler_init(&handler, ctx))) {
    return err;
  }

  if ((err = pam_mysql_stream_open(&stream, ctx, path))) {
    pam_mysql_entry_handler_destroy(&handler);
    return err;
  }

  if ((err = pam_mysql_config_parser_init(&parser, ctx, &handler))) {
    pam_mysql_stream_close(&stream);
    pam_mysql_entry_handler_destroy(&handler);
    return err;
  }

  err = pam_mysql_config_parser_parse(&parser, &stream);

  pam_mysql_config_parser_destroy(&parser);
  pam_mysql_stream_close(&stream);
  pam_mysql_entry_handler_destroy(&handler);

  return err;
}

/**
 * pam_mysql_get_option()
 **/
pam_mysql_err_t pam_mysql_get_option(pam_mysql_ctx_t *ctx, const char **pretval, int *to_release, const char *name, size_t name_len)
{
  pam_mysql_option_t *opt = pam_mysql_find_option(options, name, name_len);

  if (opt == NULL) {
    if (ctx->verbose) {
      char buf[1024];
      strnncpy(buf, sizeof(buf), name, name_len);
      syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "unknown option: %s", buf);
    }

    return PAM_MYSQL_ERR_NO_ENTRY;
  }

  return opt->accessor->get_op((void *)((char *)ctx + opt->offset), pretval, to_release);
}

/**
 * pam_mysql_set_option()
 **/
static pam_mysql_err_t pam_mysql_set_option(pam_mysql_ctx_t *ctx, const char *name, size_t name_len, const char *val)
{
  pam_mysql_option_t *opt = pam_mysql_find_option(options, name, name_len);

  if (opt == NULL) {
    if (ctx->verbose) {
      char buf[1024];
      strnncpy(buf, sizeof(buf), name, name_len);
      syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "unknown option: %s", buf);
    }

    return PAM_MYSQL_ERR_NO_ENTRY;
  }

  return opt->accessor->set_op((void *)((char *)ctx + opt->offset), val);
}

/**
 * pam_mysql_parse_args()
 **/
pam_mysql_err_t pam_mysql_parse_args(pam_mysql_ctx_t *ctx, int argc, const char **argv)
{
  pam_mysql_err_t err;
  int param_changed = 0;
  char *value = NULL;
  int i;

  /* process all the arguments */
  for (i = 0; i < argc; i++) {
    const char *name = argv[i];
    size_t name_len;

    if ((value = strchr(name, '=')) != NULL) {
      name_len = (size_t)(value - name);
      value++; /* get past the '=' */
    } else {
      name_len = strlen(name);
      value = "";
    }

    err = pam_mysql_set_option(ctx, name, name_len, value);
    if (err == PAM_MYSQL_ERR_NO_ENTRY) {
      continue;
    } else if (err) {
      return err;
    }

    param_changed = 1;

    if (ctx->verbose) {
      char buf[1024];
      strnncpy(buf, sizeof(buf), name, name_len);
      syslog(LOG_AUTHPRIV | LOG_INFO, PAM_MYSQL_LOG_PREFIX "option %s is set to \"%s\"", buf, value);
    }
  }

  /* close the database in case we get new args */
  if (param_changed) {
    pam_mysql_close_db(ctx);
  }

  return PAM_MYSQL_ERR_SUCCESS;
}

