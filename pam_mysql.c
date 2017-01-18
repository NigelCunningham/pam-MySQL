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

/*
 * We make definitions for the externally accessible functions
 * in this file (these definitions are required for static modules
 * but strongly encouraged generally). They are used to instruct the
 * modules' include files to define their prototypes.
 */

#include "common.h"
#include "memory.h"
#include "configuration.h"
#include "database.h"
#include "drupal7.h"

#ifndef HAVE_MAKE_SCRAMBLED_PASSWORD_323
#include "my_make_scrambled_password.h"
#endif

#define PLEASE_ENTER_PASSWORD "Password:"
#define PLEASE_ENTER_OLD_PASSWORD "Current password:"
#define PLEASE_ENTER_NEW_PASSWORD "New password:"
#define PLEASE_REENTER_NEW_PASSWORD "Retype new Password:"

#define PAM_MYSQL_USER_STAT_EXPIRED 0x0001
#define PAM_MYSQL_USER_STAT_AUTHTOK_EXPIRED 0x0002
#define PAM_MYSQL_USER_STAT_NULL_PASSWD 0x0004

#define PAM_MYSQL_CAP_CHAUTHTOK_SELF 0x0001
#define PAM_MYSQL_CAP_CHAUTHTOK_OTHERS 0x0002

/**
 * pam_mysql_get_host_info
 **/
static pam_mysql_err_t pam_mysql_get_host_info(pam_mysql_ctx_t *ctx,
 const char **pretval)
{
  char hostname[MAXHOSTNAMELEN + 1];
  char *retval;

  if (ctx->my_host_info) {
    *pretval = ctx->my_host_info;
    return PAM_MYSQL_ERR_SUCCESS;
  }

  if (gethostname(hostname, sizeof(hostname))) {
    return PAM_MYSQL_ERR_UNKNOWN;
  }
#ifdef HAVE_GETADDRINFO
  {
    struct addrinfo *ainfo = NULL;
    static const struct addrinfo hint = {
      AI_CANONNAME, PF_INET, 0, 0, 0, NULL, NULL, NULL
    };

    switch (getaddrinfo(hostname, NULL, &hint, &ainfo)) {
      case 0:
        break;

      case EAI_MEMORY:
        return PAM_MYSQL_ERR_ALLOC;

      default:
        return PAM_MYSQL_ERR_UNKNOWN;
    }

    switch (ainfo->ai_family) {
      case AF_INET:
        if (NULL == (retval = xcalloc(INET_ADDRSTRLEN, sizeof(char)))) {
          syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
          freeaddrinfo(ainfo);
          return PAM_MYSQL_ERR_ALLOC;
        }

        if (!inet_ntop(AF_INET,
              &((struct sockaddr_in *)ainfo->ai_addr)->sin_addr,
              retval, INET_ADDRSTRLEN)) {
          xfree(retval);
          freeaddrinfo(ainfo);
          return PAM_MYSQL_ERR_UNKNOWN;
        }
        break;
#ifdef HAVE_IPV6
      case AF_INET6:
        if (NULL == (retval = xcalloc(INET6_ADDRSTRLEN,sizeof(char)))) {
          syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
          freeaddrinfo(ainfo);
          return PAM_MYSQL_ERR_ALLOC;
        }

        if (!inet_ntop(AF_INET6,
              &((struct sockaddr_in6 *)ainfo->ai_addr)->sin6_addr,
              retval, INET6_ADDRSTRLEN)) {
          xfree(retval);
          freeaddrinfo(ainfo);
          return PAM_MYSQL_ERR_UNKNOWN;
        }
        break;
#endif /* HAVE_IPV6 */
      default:
        freeaddrinfo(ainfo);
        return PAM_MYSQL_ERR_NOTIMPL;
    }

    freeaddrinfo(ainfo);
  }
#else
  {
    struct hostent *hent = NULL;
    struct hostent *tmp;
    size_t hent_size = sizeof(struct hostent) + 64;
    int herr = 0;

#if defined(HAVE_SUNOS_GETHOSTBYNAME_R)
    for (;;) {
      if (NULL == (tmp = xrealloc(hent, hent_size, sizeof(char)))) {
        syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);

        if (hent != NULL) {
          xfree(hent);
        }

        return PAM_MYSQL_ERR_ALLOC;
      }

      hent = tmp;

      if (gethostbyname_r(hostname, hent,
            (char *)hent + sizeof(struct hostent),
            hent_size - sizeof(struct hostent), &herr) != NULL) {
        break;
      }

      if (errno != ERANGE) {
        xfree(hent);
        return PAM_MYSQL_ERR_UNKNOWN;
      }

      if (hent_size + 32 < hent_size) {
        syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
        xfree(hent);
        return PAM_MYSQL_ERR_ALLOC;
      }

      hent_size += 32;
    }
#elif defined(HAVE_GNU_GETHOSTBYNAME_R)
    for (;;) {
      if (NULL == (tmp = xrealloc(hent, hent_size, sizeof(char)))) {
        syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);

        if (hent != NULL) {
          xfree(hent);
        }

        return PAM_MYSQL_ERR_ALLOC;
      }

      hent = tmp;

      if (!gethostbyname_r(hostname, hent,
            (char *)hent + sizeof(struct hostent),
            hent_size - sizeof(struct hostent), &tmp, &herr)) {
        break;
      }

      if (errno != ERANGE) {
        xfree(hent);
        return PAM_MYSQL_ERR_UNKNOWN;
      }

      if (hent_size + 32 < hent_size) {
        syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
        xfree(hent);
        return PAM_MYSQL_ERR_ALLOC;
      }

      hent_size += 32;
    }
#else
    return PAM_MYSQL_ERR_NOTIMPL;
#endif

    switch (hent->h_addrtype) {
      case AF_INET:
        if (NULL == (retval = xcalloc(INET_ADDRSTRLEN, sizeof(char)))) {
          syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
          xfree(hent);
          return PAM_MYSQL_ERR_ALLOC;
        }

        if (!inet_ntop(AF_INET, hent->h_addr_list[0], retval,
              INET_ADDRSTRLEN)) {
          xfree(retval);
          xfree(hent);
          return PAM_MYSQL_ERR_UNKNOWN;
        }
        break;
#ifdef HAVE_IPV6
      case AF_INET6:
        if (NULL == (retval = xcalloc(INET6_ADDRSTRLEN,sizeof(char)))) {
          syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
          xfree(hent);
          return PAM_MYSQL_ERR_ALLOC;
        }

        if (!inet_ntop(AF_INET6, hent->h_addr_list[0], retval,
              INET6_ADDRSTRLEN)) {
          xfree(retval);
          xfree(hent);
          return PAM_MYSQL_ERR_UNKNOWN;
        }
        break;
#endif /* HAVE_IPV6 */
      default:
        xfree(hent);
        return PAM_MYSQL_ERR_NOTIMPL;
    }

    xfree(hent);
  }
#endif /* HAVE_GETADDRINFO */

  *pretval = ctx->my_host_info = retval;

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * pam_mysql_init_ctx()
 **/
static pam_mysql_err_t pam_mysql_init_ctx(pam_mysql_ctx_t *ctx)
{
  ctx->mysql_hdl = NULL;
  ctx->host = NULL;
  ctx->where = NULL;
  ctx->db = NULL;
  ctx->user = NULL;
  ctx->passwd = NULL;
  ctx->table = NULL;
  ctx->update_table =NULL;
  ctx->usercolumn = NULL;
  ctx->passwdcolumn = NULL;
  ctx->statcolumn = xstrdup("0");
  ctx->crypt_type = 0;
  ctx->use_323_passwd = 0;
  ctx->md5 = -1;
  ctx->sqllog = 0;
  ctx->verbose = 0;
  ctx->use_first_pass = 0;
  ctx->try_first_pass = 1;
  ctx->disconnect_every_op = 0;
  ctx->logtable = NULL;
  ctx->logmsgcolumn = NULL;
  ctx->logpidcolumn = NULL;
  ctx->logusercolumn = NULL;
  ctx->loghostcolumn = NULL;
  ctx->logrhostcolumn = NULL;
  ctx->logtimecolumn = NULL;
  ctx->config_file = NULL;
  ctx->my_host_info = NULL;

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * pam_mysql_destroy_ctx()
 **/
static void pam_mysql_destroy_ctx(pam_mysql_ctx_t *ctx)
{
  if (ctx->verbose) {
    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_destroy_ctx() called.");
  }

  pam_mysql_close_db(ctx);

  xfree(ctx->host);
  ctx->host = NULL;

  xfree(ctx->where);
  ctx->where = NULL;

  xfree(ctx->db);
  ctx->db = NULL;

  xfree(ctx->user);
  ctx->user = NULL;

  xfree(ctx->passwd);
  ctx->passwd = NULL;

  xfree(ctx->table);
  ctx->table = NULL;

  xfree(ctx->update_table);
  ctx->update_table = NULL;

  xfree(ctx->usercolumn);
  ctx->usercolumn = NULL;

  xfree(ctx->passwdcolumn);
  ctx->passwdcolumn = NULL;

  xfree(ctx->statcolumn);
  ctx->statcolumn = NULL;

  xfree(ctx->logtable);
  ctx->logtable = NULL;

  xfree(ctx->logmsgcolumn);
  ctx->logmsgcolumn = NULL;

  xfree(ctx->logpidcolumn);
  ctx->logpidcolumn = NULL;

  xfree(ctx->logusercolumn);
  ctx->logusercolumn = NULL;

  xfree(ctx->loghostcolumn);
  ctx->loghostcolumn = NULL;

  xfree(ctx->logrhostcolumn);
  ctx->logrhostcolumn = NULL;

  xfree(ctx->logtimecolumn);
  ctx->logtimecolumn = NULL;

  xfree(ctx->config_file);
  ctx->config_file = NULL;

  xfree(ctx->my_host_info);
  ctx->my_host_info = NULL;
}

/**
 * pam_mysql_release_ctx()
 **/
static void pam_mysql_release_ctx(pam_mysql_ctx_t *ctx)
{
  if (ctx->verbose) {
    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_release_ctx() called.");
  }

  if (ctx != NULL) {
    pam_mysql_destroy_ctx(ctx);
    xfree(ctx);
  }
}

/**
 * pam_mysql_cleanup_hdlr()
 **/
static void pam_mysql_cleanup_hdlr(pam_handle_t *pamh, void * voiddata, int status)
{
  pam_mysql_release_ctx((pam_mysql_ctx_t*)voiddata);
}

/**
 * pam_mysql_retrieve_ctx()
 **/
pam_mysql_err_t pam_mysql_retrieve_ctx(pam_mysql_ctx_t **pretval, pam_handle_t *pamh)
{
  pam_mysql_err_t err;

  switch (pam_get_data(pamh, PAM_MODULE_NAME,
        (PAM_GET_DATA_CONST void**)pretval)) {
    case PAM_NO_MODULE_DATA:
      *pretval = NULL;
      break;

    case PAM_SUCCESS:
      break;

    default:
      return PAM_MYSQL_ERR_UNKNOWN;
  }

  if (*pretval == NULL) {
    /* allocate global data space */
    if (NULL == (*pretval = (pam_mysql_ctx_t*)xcalloc(1, sizeof(pam_mysql_ctx_t)))) {
      syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
      return PAM_MYSQL_ERR_ALLOC;
    }

    /* give the data back to PAM for management */
    if (pam_set_data(pamh, PAM_MODULE_NAME, (void*)*pretval, pam_mysql_cleanup_hdlr)) {
      syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "failed to set context to PAM at " __FILE__ ":%d", __LINE__);
      xfree(*pretval);
      *pretval = NULL;
      return PAM_MYSQL_ERR_UNKNOWN;
    }

    if ((err = pam_mysql_init_ctx(*pretval))) {
      syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "cannot initialize context at " __FILE__ ":%d", __LINE__);
      pam_mysql_destroy_ctx(*pretval);
      xfree(*pretval);
      *pretval = NULL;
      return err;
    }
  }

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * pam_mysql_format_string()
 **/
static pam_mysql_err_t pam_mysql_format_string(pam_mysql_ctx_t *ctx,
 pam_mysql_str_t *pretval, const char *template, int mangle, ...)
{
  pam_mysql_err_t err = PAM_MYSQL_ERR_SUCCESS;
  const char *p;
  const char *name = NULL;
  const char *commit_ptr;
  int state;
  va_list ap;

  if (ctx->verbose) {
    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_format_string() called");
  }

  va_start(ap, mangle);

  state = 0;
  for (commit_ptr = p = template; *p != '\0'; p++) {
    switch (state) {
      case 0:
        if (*p == '%') {
          if ((err = pam_mysql_str_append(pretval, commit_ptr, (size_t)(p - commit_ptr)))) {
            goto out;
          }

          commit_ptr = p;
          state = 1;
        }
        break;

      case 1:
        switch (*p) {
          case '{':
            state = 2;
            break;

          case '[':
            state = 4;
            break;

          case 's': {
                      const char *val = va_arg(ap, char *);

                      if ((err = pam_mysql_quick_escape(ctx, pretval, val, strlen(val)))) {
                        goto out;
                      }

                      state = 0;
                      commit_ptr = p + 1;
                    } break;

          case 'S': {
                      const char *val = va_arg(ap, char *);

                      if ((err = pam_mysql_str_append(pretval, val, strlen(val)))) {
                        goto out;
                      }

                      state = 0;
                      commit_ptr = p + 1;
                    } break;

          case 'u': {
                      char buf[128];
                      unsigned int val = va_arg(ap, unsigned int);
                      char *q = buf + sizeof(buf);

                      while (--q >= buf) {
                        *q = "0123456789"[val % 10];
                        val /= 10;
                        if (val == 0) break;
                      }

                      if ((err = pam_mysql_str_append(pretval, q, sizeof(buf) - (size_t)(q - buf)))) {
                        goto out;
                      }

                      state = 0;
                      commit_ptr = p + 1;
                    } break;

          default:
                    if ((err = pam_mysql_str_append_char(pretval, '%'))) {
                      goto out;
                    }

                    if ((err = pam_mysql_str_append_char(pretval, *p))) {
                      goto out;
                    }

                    state = 0;
                    commit_ptr = p + 1;
                    break;
        }
        break;

      case 2:
        name = p;
        state = 3;
        break;

      case 3:
        if (*p == '}') {
          const char *val;
          int to_release;

          if ((err = pam_mysql_get_option(ctx, &val, &to_release, name, (size_t)(p - name)))) {
            goto out;
          }

          if (val == NULL) {
            val = xstrdup("");
          }

          if ((err = pam_mysql_quick_escape(ctx, pretval, val, strlen(val)))) {
            if (to_release) {
              xfree((char *)val);
            }
            goto out;
          }

          if (to_release) {
            xfree((char *)val);
          }

          state = 0;
          commit_ptr = p + 1;
        }
        break;

      case 4:
        name = p;
        state = 5;
        break;

      case 5:
        if (*p == ']') {
          const char *val;
          int to_release;

          if ((err = pam_mysql_get_option(ctx, &val, &to_release, name, (size_t)(p - name)))) {
            goto out;
          }

          if (val == NULL) {
            val = xstrdup("");
          }

          if ((err = pam_mysql_str_append(pretval, val, strlen(val)))) {
            if (to_release) {
              xfree((char *)val);
            }
            goto out;
          }

          if (to_release) {
            xfree((char *)val);
          }

          state = 0;
          commit_ptr = p + 1;
        }
        break;
    }
  }

  if (commit_ptr < p) {
    if ((err = pam_mysql_str_append(pretval, commit_ptr, (size_t)(p - commit_ptr)))) {
      goto out;
    }
  }

out:
  if (err) {
    pam_mysql_str_destroy(pretval);
  }

  va_end(ap);

  return err;
}

/**
 * pam_mysql_check_passwd
 **/
static pam_mysql_err_t pam_mysql_check_passwd(pam_mysql_ctx_t *ctx,
 const char *user, const char *passwd, int null_inhibited)
{
  pam_mysql_err_t err;
  pam_mysql_str_t query;
  MYSQL_RES *result = NULL;
  MYSQL_ROW row;
  int vresult;

  if (ctx->verbose) {
    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_check_passwd() called.");
  }

  /* To avoid putting a plain password in the MySQL log file and on
   * the wire more than needed we will request the encrypted password
   * from MySQL. We will check encrypt the passed password against the
   * one returned from MySQL.
   */
  if ((err = pam_mysql_str_init(&query, 1))) {
    return err;
  }

  err = pam_mysql_format_string(ctx, &query,
      (ctx->where == NULL ?
       "SELECT %[passwdcolumn] FROM %[table] WHERE %[usercolumn] = '%s'":
       "SELECT %[passwdcolumn] FROM %[table] WHERE %[usercolumn] = '%s' AND (%S)"),
      1, user, ctx->where);

  if (err) {
    goto out;
  }

  if (ctx->verbose) {
    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "%s", query.p);
  }

#ifdef HAVE_MYSQL_REAL_QUERY
  if (mysql_real_query(ctx->mysql_hdl, query.p, query.len)) {
#else
    if (mysql_query(ctx->mysql_hdl, query.p)) {
#endif
      err = PAM_MYSQL_ERR_DB;
      goto out;
    }

    if (NULL == (result = mysql_store_result(ctx->mysql_hdl))) {
      err = PAM_MYSQL_ERR_DB;
      goto out;
    }

    switch (mysql_num_rows(result)) {
      case 0:
        syslog(LOG_AUTHPRIV | LOG_ERR, "%s", PAM_MYSQL_LOG_PREFIX "SELECT returned no result.");
        err = PAM_MYSQL_ERR_NO_ENTRY;
        goto out;

      case 1:
        break;

      case 2:
        syslog(LOG_AUTHPRIV | LOG_ERR, "%s", PAM_MYSQL_LOG_PREFIX "SELECT returned an indetermined result.");
        err = PAM_MYSQL_ERR_UNKNOWN;
        goto out;
    }

    /* Grab the password from RESULT_SET. */
    if (NULL == (row = mysql_fetch_row(result))) {
      err = PAM_MYSQL_ERR_DB;
      goto out;
    }

    vresult = -1;

    if (row[0] != NULL) {
      if (passwd != NULL) {
        char *crypted_password = NULL;
        switch (ctx->crypt_type) {
          /* PLAIN */
          case 0:
            vresult = strcmp(row[0], passwd);
            break;

            /* ENCRYPT */
          case 1:
            crypted_password = crypt(passwd, row[0]);
            if (crypted_password == NULL) {
              syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "something went wrong when invoking crypt() - %s", strerror(errno));
              vresult = 1; // fail
            } else {
              vresult = strcmp(row[0], crypted_password);
            }
            break;

            /* PASSWORD */
          case 2: {
                    char buf[42];
#ifdef HAVE_MAKE_SCRAMBLED_PASSWORD_323
                    if (ctx->use_323_passwd) {
                      make_scrambled_password_323(buf, passwd);
                    } else {
                      my_make_scrambled_password(buf, passwd, strlen(passwd));
                    }
#else
                    my_make_scrambled_password(buf, passwd, strlen(passwd));
#endif

                    vresult = strcmp(row[0], buf);
                    {
                      char *p = buf - 1;
                      while (*(++p)) *p = '\0';
                    }
                  } break;

                  /* MD5 hash (not MD5 crypt()) */
          case 3: {
#ifdef HAVE_PAM_MYSQL_MD5_DATA
                    char buf[33];
                    pam_mysql_md5_data((unsigned char*)passwd, strlen(passwd),
                        buf);
                    vresult = strcmp(row[0], buf);
                    {
                      char *p = buf - 1;
                      while (*(++p)) *p = '\0';
                    }
#else
                    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "non-crypt()ish MD5 hash is not supported in this build.");
#endif
                  } break;

          case 4: {
#ifdef HAVE_PAM_MYSQL_SHA1_DATA
                    char buf[41];
                    pam_mysql_sha1_data((unsigned char*)passwd, strlen(passwd),
                        buf);
                    vresult = strcmp(row[0], buf);
                    {
                      char *p = buf - 1;
                      while (*(++p)) *p = '\0';
                    }
#else
                    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "non-crypt()ish SHA1 hash is not supported in this build.");
#endif
                  } break;

          case 5: {
#if defined(HAVE_PAM_MYSQL_MD5_DATA) && defined(HAVE_PAM_MYSQL_SHA1_DATA)
                    char buf[128];
                    memset(buf, 0, 128);
                    pam_mysql_drupal7_data((unsigned char*)passwd, strlen(passwd),
                        buf, row[0]);
                    vresult = strcmp(row[0], buf);
                    {
                      char *p = buf - 1;
                      while (*(++p)) *p = '\0';
                    }
#else
                    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "non-crypt()ish MD5 hash or SHA support lacking in this build.");
#endif
                  } break;

                  /* joomla 1.5 like passwd*/
          case 6:
                  {
                    /* Joomla 1.5 like password */
#ifdef HAVE_PAM_MYSQL_MD5_DATA
                    char buf[33];
                    buf[32]=0;

                    char *salt = row[0];
                    char *hash = strsep(&salt,":");

                    int len = strlen(passwd)+strlen(salt);

                    char *tmp;

                    if (NULL == (tmp = xcalloc(len+1, sizeof(char)))) {
                      syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
                      err = PAM_MYSQL_ERR_ALLOC;
                      goto out;
                    }

                    strcat(tmp,passwd);
                    strcat(tmp,salt);

                    pam_mysql_md5_data((unsigned char*)tmp, len, buf);

                    vresult = strcmp(hash, buf);
                    {
                      char *p = buf - 1;
                      while (*(++p)) *p = '\0';
                    }

                    xfree(tmp);
#else
                    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "non-crypt()ish MD5 hash is not supported in this build.");
#endif
                  } break;

          default: {
                   }
        }
      }
    } else {
      vresult = null_inhibited;
    }

    if (vresult == 0) {
      err = PAM_MYSQL_ERR_SUCCESS;
    } else {
      err = PAM_MYSQL_ERR_MISMATCH;
    }

out:
    if (err == PAM_MYSQL_ERR_DB) {
      syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "MySQL error(%s)", mysql_error(ctx->mysql_hdl));
    }

    if (result != NULL) {
      mysql_free_result(result);
    }

    pam_mysql_str_destroy(&query);

    if (ctx->verbose) {
      syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_check_passwd() returning %i.", err);
    }

    return err;
}

/**
 * pam_mysql_saltify()
 * Create a random salt for use with CRYPT() when changing passwords
 **/
static void pam_mysql_saltify(pam_mysql_ctx_t *ctx, char *salt, const char *salter)
{
  unsigned int i = 0;
  char *q;
  unsigned int seed = 0;
  static const char saltstr[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";

  if (ctx->verbose) {
    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "saltify called.");
  }

  if (salter != NULL) {
    const char *p;
    for (p = salter; *p != '\0'; p++) {
      seed += salter[i];
    }
  }

#ifdef HAVE_GETTIMEOFDAY
  {
    struct timeval *tv;
    if (gettimeofday(&tv, NULL)) {
      tv.tv_usec = 0;
    }
    seed = (unsigned int)((tv.tv_usec + j) % 65535);
  }
#endif

  q = salt;
  if (ctx->md5) {
    strcpy(salt, "$1$");
    q += sizeof("$1$") - 1;
    i = 8;
  } else {
    i = 2;
  }

  while (i-- > 0) {
    *(q++) = saltstr[seed % 64];
    seed = (((seed ^ 0x967e3c5a) << 3) ^ (~(seed >> 2) + i));
  }

  if (ctx->md5) {
    *(q++) = '$';
  }
  *q = '\0';

  if (ctx->verbose) {
    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_saltify() returning salt = %s.", salt);
  }
}

/**
 * pam_mysql_update_passwd
 *
 * Update the password in MySQL
 * To reduce the number of calls to the DB, I'm now assuming that the old
 * password has been verified elsewhere, so I only check for null/not null
 * and is_root.
 **/
static pam_mysql_err_t pam_mysql_update_passwd(pam_mysql_ctx_t *ctx, const char *user, const char *new_passwd)
{
 pam_mysql_err_t err = PAM_MYSQL_ERR_SUCCESS;
 pam_mysql_str_t query;
 char *encrypted_passwd = NULL;

 if ((err = pam_mysql_str_init(&query, 1))) {
 return err;
 }

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_update_passwd() called.");
 }

 if (user == NULL) {
 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "user is NULL.");
 }

 syslog(LOG_NOTICE, PAM_MYSQL_LOG_PREFIX "unable to change password");
 return PAM_MYSQL_ERR_INVAL;
 }

 if (new_passwd != NULL) {
 switch (ctx->crypt_type) {
 case 0:
 if (NULL == (encrypted_passwd = xstrdup(new_passwd))) {
 syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
 err = PAM_MYSQL_ERR_ALLOC;
 goto out;
 }
 break;

 case 1: {
 char salt[18];
 pam_mysql_saltify(ctx, salt, new_passwd);
 if (NULL == (encrypted_passwd = xstrdup(crypt(new_passwd, salt)))) {
 syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
 err = PAM_MYSQL_ERR_ALLOC;
 goto out;
 }
 } break;

 case 2:
 if (NULL == (encrypted_passwd = xcalloc(41 + 1, sizeof(char)))) {
 syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
 err = PAM_MYSQL_ERR_ALLOC;
 goto out;
 }
#ifdef HAVE_MAKE_SCRAMBLED_PASSWORD_323
 if (ctx->use_323_passwd) {
 make_scrambled_password_323(encrypted_passwd, new_passwd);
 } else {
 my_make_scrambled_password(encrypted_passwd, new_passwd, strlen(new_passwd));
 }
#else
 my_make_scrambled_password(encrypted_passwd, new_passwd, strlen(new_passwd));
#endif
 break;

 case 3:
#ifdef HAVE_PAM_MYSQL_MD5_DATA
 if (NULL == (encrypted_passwd = xcalloc(32 + 1, sizeof(char)))) {
 syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
 err = PAM_MYSQL_ERR_ALLOC;
 goto out;
 }
 pam_mysql_md5_data((unsigned char*)new_passwd,
 strlen(new_passwd), encrypted_passwd);
#else
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "non-crypt()ish MD5 hash is not supported in this build.");
 err = PAM_MYSQL_ERR_NOTIMPL;
 goto out;
#endif
 break;

 case 4:
#ifdef HAVE_PAM_MYSQL_SHA1_DATA
 if (NULL == (encrypted_passwd = xcalloc(40 + 1, sizeof(char)))) {
 syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
 err = PAM_MYSQL_ERR_ALLOC;
 goto out;
 }
 pam_mysql_sha1_data((unsigned char*)new_passwd,
 strlen(new_passwd), encrypted_passwd);
#else
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "non-crypt()ish SHA1 hash is not supported in this build.");
 err = PAM_MYSQL_ERR_NOTIMPL;
 goto out;
#endif
 break;

 case 6:
 {
#ifdef HAVE_PAM_MYSQL_MD5_DATA
 if (NULL == (encrypted_passwd = xcalloc(32 + 1+ 32 +1, sizeof(char)))) {
 syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
 err = PAM_MYSQL_ERR_ALLOC;
 goto out;
 }

 int len=strlen(new_passwd)+32;

 char *tmp;

 if (NULL == (tmp = xcalloc(len+1, sizeof(char)))) {
 syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
 err = PAM_MYSQL_ERR_ALLOC;
 goto out;
 }

 char salt[33];
 salt[32]=0;

 srandom(time(NULL));

 int i;
 for(i=0;i<32; i++)
 salt[i]=(char)((random()/(double)RAND_MAX * 93.0) +33.0);

 strcat(tmp,new_passwd);
 strcat(tmp,salt);

 pam_mysql_md5_data((unsigned char*)tmp, len, encrypted_passwd);

 xfree(tmp);

 strcat(encrypted_passwd,":");
 strcat(encrypted_passwd,salt);

#else
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "non-crypt()ish MD5 hash is not supported in this build.");
 err = PAM_MYSQL_ERR_NOTIMPL;
 goto out;
#endif
 break;
 }
 default:
 encrypted_passwd = NULL;
 break;
 }
 }

 err = pam_mysql_format_string(ctx, &query,
 (ctx->where == NULL ?
 "UPDATE %[table] SET %[passwdcolumn] = '%s' WHERE %[usercolumn] = '%s'":
 "UPDATE %[table] SET %[passwdcolumn] = '%s' WHERE %[usercolumn] = '%s' AND (%S)"),
 1, (encrypted_passwd == NULL ? "": encrypted_passwd), user, ctx->where);
 if (err) {
 goto out;
 }

#ifdef HAVE_MYSQL_REAL_QUERY
 if (mysql_real_query(ctx->mysql_hdl, query.p, query.len)) {
#else
 if (mysql_query(ctx->mysql_hdl, query.p)) {
#endif
 err = PAM_MYSQL_ERR_DB;
 goto out;
 }

out:
 if (err == PAM_MYSQL_ERR_DB) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "MySQL error (%s)", mysql_error(ctx->mysql_hdl));
 }

 if (encrypted_passwd != NULL) {
 char *p;
 for (p = encrypted_passwd; *p != '\0'; p++) {
 *p = '\0';
 }
 xfree(encrypted_passwd);
 }

 pam_mysql_str_destroy(&query);

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_update_passwd() returning %i.", err);
 }

 return err;
 }

/**
 * pam_mysql_query_user_stat
 **/
static pam_mysql_err_t pam_mysql_query_user_stat(pam_mysql_ctx_t *ctx,
 int *pretval, const char *user)
{
 pam_mysql_err_t err = PAM_MYSQL_ERR_SUCCESS;
 pam_mysql_str_t query;
 MYSQL_RES *result = NULL;
 MYSQL_ROW row;

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_query_user_stat() called.");
 }

 if ((err = pam_mysql_str_init(&query, 0))) {
 return err;
 }

 err = pam_mysql_format_string(ctx, &query,
 (ctx->where == NULL ?
 "SELECT %[statcolumn], %[passwdcolumn] FROM %[table] WHERE %[usercolumn] = '%s'":
 "SELECT %[statcolumn], %[passwdcolumn] FROM %[table] WHERE %[usercolumn] = '%s' AND (%S)"),
 1, user, ctx->where);

 if (err) {
 goto out;
 }

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "%s", query.p);
 }

#ifdef HAVE_MYSQL_REAL_QUERY
 if (mysql_real_query(ctx->mysql_hdl, query.p, query.len)) {
#else
 if (mysql_query(ctx->mysql_hdl, query.p)) {
#endif
 err = PAM_MYSQL_ERR_DB;
 goto out;
 }

 if (NULL == (result = mysql_store_result(ctx->mysql_hdl))) {
 err = PAM_MYSQL_ERR_DB;
 goto out;
 }

 switch (mysql_num_rows(result)) {
 case 0:
 syslog(LOG_AUTHPRIV | LOG_ERR, "%s", PAM_MYSQL_LOG_PREFIX "SELECT returned no result.");
 err = PAM_MYSQL_ERR_NO_ENTRY;
 goto out;

 case 1:
 break;

 case 2:
 syslog(LOG_AUTHPRIV | LOG_ERR, "%s", PAM_MYSQL_LOG_PREFIX "SELECT returned an indetermined result.");
 err = PAM_MYSQL_ERR_UNKNOWN;
 goto out;
 }

 if (NULL == (row = mysql_fetch_row(result))) {
 err = PAM_MYSQL_ERR_DB;
 goto out;
 }

 if (row[0] == NULL) {
 *pretval = PAM_MYSQL_USER_STAT_EXPIRED;
 } else {
 *pretval = strtol(row[0], NULL, 10) & ~PAM_MYSQL_USER_STAT_NULL_PASSWD;
 }

 if (row[1] == NULL) {
 *pretval |= PAM_MYSQL_USER_STAT_NULL_PASSWD;
 }

out:
 if (err == PAM_MYSQL_ERR_DB) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "MySQL error (%s)", mysql_error(ctx->mysql_hdl));
 }

 if (result != NULL) {
 mysql_free_result(result);
 }

 pam_mysql_str_destroy(&query);

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_query_user_stat() returning %i.", err);
 }

 return err;
 }

/**
 * pam_mysql_sql_log()
 **/
static pam_mysql_err_t pam_mysql_sql_log(pam_mysql_ctx_t *ctx, const char *msg, const char *user, const char *rhost)
{
 pam_mysql_err_t err;
 pam_mysql_str_t query;
 const char *host;

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_sql_log() called.");
 }

 if ((err = pam_mysql_str_init(&query, 1))) {
 return err;
 }

 if (!ctx->sqllog) {
 err = PAM_MYSQL_ERR_SUCCESS;
 goto out;
 }

 if (pam_mysql_get_host_info(ctx, &host)) {
 host = "(unknown)";
 }

 if (ctx->logtable == NULL) {
 syslog(LOG_AUTHPRIV | LOG_ERR, "%s",
 PAM_MYSQL_LOG_PREFIX "sqllog set but logtable not set");
 return PAM_MYSQL_ERR_INVAL;
 }

 if (ctx->logmsgcolumn == NULL) {
 syslog(LOG_AUTHPRIV | LOG_ERR, "%s",
 PAM_MYSQL_LOG_PREFIX "sqllog set but logmsgcolumn not set");
 return PAM_MYSQL_ERR_INVAL;
 }

 if (ctx->logusercolumn == NULL) {
 syslog(LOG_AUTHPRIV | LOG_ERR, "%s",
 PAM_MYSQL_LOG_PREFIX "sqllog set but logusercolumn not set");
 return PAM_MYSQL_ERR_INVAL;
 }

 if (ctx->loghostcolumn == NULL) {
 syslog(LOG_AUTHPRIV | LOG_ERR, "%s",
 PAM_MYSQL_LOG_PREFIX "sqllog set but loghostcolumn not set");
 return PAM_MYSQL_ERR_INVAL;
 }

 if (ctx->logtimecolumn == NULL) {
 syslog(LOG_AUTHPRIV | LOG_ERR, "%s",
 PAM_MYSQL_LOG_PREFIX "sqllog set but logtimecolumn not set");
 return PAM_MYSQL_ERR_INVAL;
 }

 if (ctx->logrhostcolumn) {
 err = pam_mysql_format_string(ctx, &query,
 "INSERT INTO %[logtable] (%[logmsgcolumn], %[logusercolumn], %[loghostcolumn], %[logrhostcolumn], %[logpidcolumn], %[logtimecolumn]) VALUES ('%s', '%s', '%s', '%s', '%u', NOW())", 1,
 msg, user, host, rhost == NULL ? "(unknown)": rhost, getpid());
 } else {
 err = pam_mysql_format_string(ctx, &query,
 "INSERT INTO %[logtable] (%[logmsgcolumn], %[logusercolumn], %[loghostcolumn], %[logpidcolumn], %[logtimecolumn]) VALUES ('%s', '%s', '%s', '%u', NOW())", 1,
 msg, user, host, getpid());
 }

 if (err) {
 goto out;
 }

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "%s", query.p);
 }

#ifdef HAVE_MYSQL_REAL_QUERY
 if (mysql_real_query(ctx->mysql_hdl, query.p, query.len)) {
#else
 if (mysql_query(ctx->mysql_hdl, query.p)) {
#endif
 err = PAM_MYSQL_ERR_DB;
 goto out;
 }

 err = PAM_MYSQL_ERR_SUCCESS;

out:
 if (err == PAM_MYSQL_ERR_DB) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "MySQL error (%s)", mysql_error(ctx->mysql_hdl));
 }

 pam_mysql_str_destroy(&query);

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_sql_log() returning %d.", err);
 }

 return err;
 }

/**
 * pam_mysql_query_user_caps
 **/
static pam_mysql_err_t pam_mysql_query_user_caps(pam_mysql_ctx_t *ctx,
 int *pretval, const char *user)
{
 *pretval = 0;

 if (geteuid() == 0) {
 *pretval |= PAM_MYSQL_CAP_CHAUTHTOK_SELF;

 if (getuid() == 0) {
 *pretval |= PAM_MYSQL_CAP_CHAUTHTOK_OTHERS;
 }
 }

 return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * PAM Authentication services
 **/
/**
 * pam_sm_authenticate
 **/
PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags,
 int argc, const char **argv)
{
 int retval;
 int err;
 const char *user;
 const char *rhost;
 char *passwd = NULL;
 pam_mysql_ctx_t *ctx = NULL;
 char **resps = NULL;
 int passwd_is_local = 0;

 switch (pam_mysql_retrieve_ctx(&ctx, pamh)) {
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 case PAM_MYSQL_ERR_ALLOC:
 return PAM_BUF_ERR;

 default:
 return PAM_SERVICE_ERR;
 }

 switch (pam_mysql_parse_args(ctx, argc, argv)) {
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }

 if (ctx->config_file != NULL) {
 switch (pam_mysql_read_config_file(ctx, ctx->config_file)) {
 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 default:
 break;
 }
 }

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_authenticate() called.");
 }

 /* Get User */
 if ((retval = pam_get_user(pamh, (PAM_GET_USER_CONST char **)&user,
 NULL))) {
 goto out;
 }

 if (user == NULL) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "no user specified.");
 retval = PAM_USER_UNKNOWN;
 goto out;
 }

 switch (pam_get_item(pamh, PAM_RHOST,
 (PAM_GET_ITEM_CONST void **)&rhost)) {
 case PAM_SUCCESS:
 break;

 default:
 rhost = NULL;
 }

 if (ctx->use_first_pass || ctx->try_first_pass) {
 retval = pam_get_item(pamh, PAM_AUTHTOK,
 (PAM_GET_ITEM_CONST void **)&passwd);

 switch (retval) {
 case PAM_SUCCESS:
 break;

 case PAM_NO_MODULE_DATA:
 passwd = NULL;
 goto askpass;

 default:
 retval = PAM_AUTH_ERR;
 goto out;
 }

 switch (pam_mysql_open_db(ctx)) {
 case PAM_MYSQL_ERR_BUSY:
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 case PAM_MYSQL_ERR_DB:
 retval = PAM_AUTHINFO_UNAVAIL;
 goto out;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }

 err = pam_mysql_check_passwd(ctx, user, passwd,
 !(flags & PAM_DISALLOW_NULL_AUTHTOK));

 if (err == PAM_MYSQL_ERR_SUCCESS) {
 pam_mysql_sql_log(ctx, "AUTHENTICATION SUCCESS (FIRST_PASS)", user, rhost);
 } else {
 pam_mysql_sql_log(ctx, "AUTHENTICATION FALURE (FIRST_PASS)", user, rhost);
 }

 switch (err) {
 case PAM_MYSQL_ERR_SUCCESS:
 if (ctx->use_first_pass || ctx->try_first_pass) {
 retval = PAM_SUCCESS;
 goto out;
 }
 break;

 case PAM_MYSQL_ERR_NO_ENTRY:
 if (ctx->use_first_pass) {
 retval = PAM_USER_UNKNOWN;
 goto out;
 }
 break;

 case PAM_MYSQL_ERR_MISMATCH:
 if (ctx->use_first_pass) {
 retval = PAM_AUTH_ERR;
 goto out;
 }
 break;

 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }
 }

askpass:
 switch (pam_mysql_converse(ctx, &resps, pamh, 1,
 PAM_PROMPT_ECHO_OFF, PLEASE_ENTER_PASSWORD)) {
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }

 passwd = resps[0];
 passwd_is_local = 1;
 resps[0] = NULL;
 xfree(resps);

 if (passwd == NULL) {
 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "failed to retrieve authentication token.");
 }
 retval = PAM_AUTH_ERR;
 goto out;
 }

 if (passwd_is_local) {
 (void) pam_set_item(pamh, PAM_AUTHTOK, passwd);
 }

 switch (pam_mysql_open_db(ctx)) {
 case PAM_MYSQL_ERR_BUSY:
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 case PAM_MYSQL_ERR_DB:
 retval = PAM_AUTHINFO_UNAVAIL;
 goto out;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }

 err = pam_mysql_check_passwd(ctx, user, passwd,
 !(flags & PAM_DISALLOW_NULL_AUTHTOK));

 if (err == PAM_MYSQL_ERR_SUCCESS) {
 pam_mysql_sql_log(ctx, "AUTHENTICATION SUCCESS", user, rhost);
 } else {
 pam_mysql_sql_log(ctx, "AUTHENTICATION FAILURE", user, rhost);
 }

 switch (err) {
 case PAM_MYSQL_ERR_SUCCESS:
 retval = PAM_SUCCESS;
 break;

 case PAM_MYSQL_ERR_NO_ENTRY:
 retval = PAM_USER_UNKNOWN;
 goto out;

 case PAM_MYSQL_ERR_MISMATCH:
 retval = PAM_AUTH_ERR;
 goto out;

 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }

out:
 if (ctx->disconnect_every_op) {
 pam_mysql_close_db(ctx);
 }

 if (passwd != NULL && passwd_is_local) {
 xfree_overwrite(passwd);
 }

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_authenticate() returning %d.", retval);
 }

 return retval;
}

/**
 * pam_sm_acct_mgmt
 **/
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t * pamh, int flags, int argc,
 const char **argv)
{
 int retval;
 int err;
 int stat;
 const char *user;
 const char *rhost;
 pam_mysql_ctx_t *ctx = NULL;

 switch (pam_mysql_retrieve_ctx(&ctx, pamh)) {
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 case PAM_MYSQL_ERR_ALLOC:
 return PAM_BUF_ERR;

 default:
 return PAM_SERVICE_ERR;
 }

 switch (pam_mysql_parse_args(ctx, argc, argv)) {
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }

 if (ctx->config_file != NULL) {
 switch (pam_mysql_read_config_file(ctx, ctx->config_file)) {
 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 default:
 break;
 }
 }

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_acct_mgmt() called.");
 }

 /* Get User */
 if ((retval = pam_get_user(pamh, (PAM_GET_USER_CONST char **)&user,
 NULL))) {
 goto out;
 }

 if (user == NULL) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "no user specified.");
 retval = PAM_USER_UNKNOWN;
 goto out;
 }

 switch (pam_get_item(pamh, PAM_RHOST,
 (PAM_GET_ITEM_CONST void **)&rhost)) {
 case PAM_SUCCESS:
 break;

 default:
 rhost = NULL;
 }

 switch (pam_mysql_open_db(ctx)) {
 case PAM_MYSQL_ERR_BUSY:
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 case PAM_MYSQL_ERR_DB:
 retval = PAM_AUTHINFO_UNAVAIL;
 goto out;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }

 err = pam_mysql_query_user_stat(ctx, &stat, user);

 if (err == PAM_MYSQL_ERR_SUCCESS) {
 pam_mysql_sql_log(ctx, "QUERYING SUCCESS", user, rhost);
 } else {
 pam_mysql_sql_log(ctx, "QUERYING FAILURE", user, rhost);
 }

 switch (err) {
 case PAM_MYSQL_ERR_SUCCESS:
 retval = PAM_SUCCESS;
 break;

 case PAM_MYSQL_ERR_NO_ENTRY:
 retval = PAM_USER_UNKNOWN;
 goto out;

 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }

 if (stat & PAM_MYSQL_USER_STAT_EXPIRED) {
 retval = PAM_ACCT_EXPIRED;
 } else if (stat & PAM_MYSQL_USER_STAT_AUTHTOK_EXPIRED) {
 if (stat & PAM_MYSQL_USER_STAT_NULL_PASSWD) {
#if defined(HAVE_PAM_NEW_AUTHTOK_REQD)
 retval = PAM_NEW_AUTHTOK_REQD;
#else
 retval = PAM_AUTHTOK_EXPIRED;
#endif
 } else {
 retval = PAM_AUTHTOK_EXPIRED;
 }
 }

out:
 if (ctx->disconnect_every_op) {
 pam_mysql_close_db(ctx);
 }

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_acct_mgmt() returning %i.",retval);
 }

 return retval;
}

/**
 * pam_sm_setcred
 **/
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc,
 const char **argv)
{
#ifdef DEBUG
 syslog(LOG_INFO, "%s", PAM_MYSQL_LOG_PREFIX "setcred called but not implemented.");
#endif
 return PAM_SUCCESS;
}

/**
 * pam_sm_chauthtok
 **/
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh,int flags,int argc,
 const char **argv)
{
 int retval;
 int err;
 const char *user;
 const char *rhost;
 char *old_passwd = NULL;
 char *first_enter = NULL;
 char *new_passwd = NULL;
 int old_passwd_should_be_freed = 0;
 int new_passwd_is_local = 0;
 int caps = 0;
 int stat = 0;
 pam_mysql_ctx_t *ctx = NULL;

 switch (pam_mysql_retrieve_ctx(&ctx, pamh)) {
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 case PAM_MYSQL_ERR_ALLOC:
 return PAM_BUF_ERR;

 default:
 return PAM_SERVICE_ERR;
 }

 switch (pam_mysql_parse_args(ctx, argc, argv)) {
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }

 if (ctx->config_file != NULL) {
 switch (pam_mysql_read_config_file(ctx, ctx->config_file)) {
 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 default:
 break;
 }
 }

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_chauthtok() called.");
 }

 /* Get User */
 if ((retval = pam_get_user(pamh, (PAM_GET_USER_CONST char **)&user,
 NULL))) {
 goto out;
 }

 if (user == NULL) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "no user specified.");
 retval = PAM_USER_UNKNOWN;
 goto out;
 }

 switch (pam_get_item(pamh, PAM_RHOST,
 (PAM_GET_ITEM_CONST void **)&rhost)) {
 case PAM_SUCCESS:
 break;

 default:
 rhost = NULL;
 }

 err = pam_mysql_open_db(ctx);

 if (flags & PAM_PRELIM_CHECK) {
 switch (err) {
 case PAM_MYSQL_ERR_BUSY:
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 default:
 retval = PAM_TRY_AGAIN;
 goto out;
 }
 } else {
 switch (err) {
 case PAM_MYSQL_ERR_BUSY:
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 case PAM_MYSQL_ERR_DB:
 retval = PAM_PERM_DENIED;
 goto out;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }
 }

 if (!(flags & PAM_UPDATE_AUTHTOK)) {
 goto out;
 }

 err = pam_mysql_query_user_caps(ctx, &caps, user);

 switch (err) {
 case PAM_MYSQL_ERR_SUCCESS:
 retval = PAM_SUCCESS;
 break;

 case PAM_MYSQL_ERR_NO_ENTRY:
 retval = PAM_SUCCESS;
 caps = 0;
 break;

 default:
 retval = PAM_PERM_DENIED;
 goto out;
 }

 if (!(caps & (PAM_MYSQL_CAP_CHAUTHTOK_SELF
 | PAM_MYSQL_CAP_CHAUTHTOK_OTHERS))) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "User is not allowed to change the authentication token.");
 retval = PAM_PERM_DENIED;
 goto out;
 }

 err = pam_mysql_query_user_stat(ctx, &stat, user);

 if (err == PAM_MYSQL_ERR_SUCCESS) {
 pam_mysql_sql_log(ctx, "QUERYING SUCCESS", user, rhost);
 } else {
 pam_mysql_sql_log(ctx, "QUERYING FAILURE", user, rhost);
 }

 switch (err) {
 case PAM_MYSQL_ERR_SUCCESS:
 retval = PAM_SUCCESS;
 break;

 default:
 retval = PAM_PERM_DENIED;
 goto out;
 }

 if (!(flags & PAM_CHANGE_EXPIRED_AUTHTOK) &&
 (stat & PAM_MYSQL_USER_STAT_EXPIRED)) {
 retval = PAM_AUTHTOK_LOCK_BUSY;
 goto out;
 }

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "update authentication token");
 }

 if (!(caps & PAM_MYSQL_CAP_CHAUTHTOK_OTHERS) &&
 !(stat & PAM_MYSQL_USER_STAT_NULL_PASSWD)) {
 if (ctx->use_first_pass || ctx->try_first_pass) {
 retval = pam_get_item(pamh, PAM_OLDAUTHTOK,
 (PAM_GET_ITEM_CONST void **)&old_passwd);
 switch (retval) {
 case PAM_SUCCESS:
 break;

 case PAM_NO_MODULE_DATA:
 old_passwd = NULL;
 break;

 default:
 retval = PAM_AUTHTOK_ERR;
 goto out;
 }

 if (old_passwd != NULL) {
 switch (pam_mysql_check_passwd(ctx, user, old_passwd, 0)) {
 case PAM_MYSQL_ERR_SUCCESS:
 retval = PAM_SUCCESS;
 break;

 case PAM_MYSQL_ERR_NO_ENTRY:
 retval = PAM_USER_UNKNOWN;
 goto out;

 case PAM_MYSQL_ERR_MISMATCH:
 if (ctx->use_first_pass) {
 retval = PAM_AUTH_ERR;
 goto out;
 }
 retval = PAM_SUCCESS;
 break;

 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }
 }
 }

 if (!ctx->use_first_pass) {
 char **resps;

 if (flags & PAM_SILENT) {
 retval = PAM_AUTHTOK_RECOVERY_ERR;
 goto out;
 }

 switch (pam_mysql_converse(ctx, &resps, pamh, 1,
 PAM_PROMPT_ECHO_OFF, PLEASE_ENTER_OLD_PASSWORD)) {
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }
 old_passwd = resps[0];
 old_passwd_should_be_freed = 1;
 resps[0] = NULL;
 xfree(resps);

 if (old_passwd == NULL) {
 retval = PAM_AUTHTOK_RECOVERY_ERR;
 goto out;
 }

 switch (pam_mysql_check_passwd(ctx, user, old_passwd, 0)) {
 case PAM_MYSQL_ERR_SUCCESS:
 retval = PAM_SUCCESS;
 break;

 case PAM_MYSQL_ERR_NO_ENTRY:
 retval = PAM_USER_UNKNOWN;
 goto out;

 case PAM_MYSQL_ERR_MISMATCH:
 retval = PAM_AUTH_ERR;
 goto out;

 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }

 if ((retval = pam_set_item(pamh, PAM_OLDAUTHTOK,
 old_passwd)) != PAM_SUCCESS) {
 goto out;
 }
 }
 }

 retval = pam_get_item(pamh, PAM_AUTHTOK,
 (PAM_GET_ITEM_CONST void **)&new_passwd);

 switch (retval) {
 case PAM_SUCCESS:
 break;

 case PAM_NO_MODULE_DATA:
 new_passwd = NULL;
 break;

 default:
 retval = PAM_AUTHTOK_ERR;
 goto out;
 }

 if (new_passwd == NULL) {
 char **resps;

 if (ctx->use_first_pass) {
 retval = PAM_AUTHTOK_RECOVERY_ERR;
 goto out;
 }

 if (flags & PAM_SILENT) {
 retval = PAM_AUTHTOK_RECOVERY_ERR;
 goto out;
 }

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, "Asking for new password (1)");
 }

 switch (pam_mysql_converse(ctx, &resps, pamh, 1,
 PAM_PROMPT_ECHO_OFF, PLEASE_ENTER_NEW_PASSWORD)) {
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }

 first_enter = resps[0];
 resps[0] = NULL;
 xfree(resps);

 switch (pam_mysql_converse(ctx, &resps, pamh, 1,
 PAM_PROMPT_ECHO_OFF, PLEASE_REENTER_NEW_PASSWORD)) {
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }

 new_passwd = resps[0];
 new_passwd_is_local = 1;
 resps[0] = NULL;
 xfree(resps);

 if (new_passwd == NULL || strcmp(first_enter, new_passwd) != 0) {
 retval = PAM_AUTHTOK_RECOVERY_ERR;
 goto out;
 }
 }

 switch (pam_mysql_update_passwd(ctx, user, new_passwd)) {
 case PAM_MYSQL_ERR_SUCCESS:
 if (new_passwd_is_local) {
 (void) pam_set_item(pamh, PAM_AUTHTOK, new_passwd);
 }
 retval = PAM_SUCCESS;
 break;

 default:
 retval = PAM_AUTHTOK_ERR;
 break;
 }

 if (retval == PAM_SUCCESS) {
 pam_mysql_sql_log(ctx, "ALTERATION SUCCESS", user, rhost);
 } else {
 pam_mysql_sql_log(ctx, "ALTERATION FAILURE", user, rhost);
 }

out:
 if (ctx->disconnect_every_op) {
 pam_mysql_close_db(ctx);
 }

 if (new_passwd != NULL && new_passwd_is_local) {
 xfree_overwrite(new_passwd);
 }

 if (first_enter != NULL) {
 xfree_overwrite(first_enter);
 }

 if (old_passwd != NULL && old_passwd_should_be_freed) {
 xfree_overwrite(old_passwd);
 }

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_chauthtok() returning %d.", retval);
 }

 return retval;
}

/**
 * pam_sm_open_session
 **/
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
 const char **argv)
{
 int retval;
 pam_mysql_ctx_t *ctx = NULL;
 const char *user;
 const char *rhost;

 switch (pam_mysql_retrieve_ctx(&ctx, pamh)) {
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 case PAM_MYSQL_ERR_ALLOC:
 return PAM_BUF_ERR;

 default:
 return PAM_SERVICE_ERR;
 }

 switch (pam_mysql_parse_args(ctx, argc, argv)) {
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }

 if (ctx->config_file != NULL) {
 switch (pam_mysql_read_config_file(ctx, ctx->config_file)) {
 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 default:
 break;
 }
 }

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_open_session() called.");
 }

 /* Get User */
 if ((retval = pam_get_user(pamh, (PAM_GET_USER_CONST char **)&user,
 NULL))) {
 goto out;
 }

 if (user == NULL) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "no user specified.");
 retval = PAM_USER_UNKNOWN;
 goto out;
 }

 switch (pam_get_item(pamh, PAM_RHOST,
 (PAM_GET_ITEM_CONST void **)&rhost)) {
 case PAM_SUCCESS:
 break;

 default:
 rhost = NULL;
 }

 switch (pam_mysql_open_db(ctx)) {
 case PAM_MYSQL_ERR_BUSY:
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 case PAM_MYSQL_ERR_DB:
 retval = PAM_AUTHINFO_UNAVAIL;
 goto out;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }

 pam_mysql_sql_log(ctx, "OPEN SESSION", user, rhost);

out:
 if (ctx->disconnect_every_op) {
 pam_mysql_close_db(ctx);
 }

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_open_session() returning %i.", retval);
 }

 return retval;
}

/**
 * pam_sm_close_session
 **/
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
 const char **argv)
{
 int retval;
 pam_mysql_ctx_t *ctx = NULL;
 const char *user;
 const char *rhost;

 switch (pam_mysql_retrieve_ctx(&ctx, pamh)) {
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 case PAM_MYSQL_ERR_ALLOC:
 return PAM_BUF_ERR;

 default:
 return PAM_SERVICE_ERR;
 }

 switch (pam_mysql_parse_args(ctx, argc, argv)) {
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }

 if (ctx->config_file != NULL) {
 switch (pam_mysql_read_config_file(ctx, ctx->config_file)) {
 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 default:
 break;
 }
 }

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_close_session() called.");
 }

 /* Get User */
 if ((retval = pam_get_user(pamh, (PAM_GET_USER_CONST char **)&user,
 NULL))) {
 goto out;
 }

 if (user == NULL) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "no user specified.");
 retval = PAM_USER_UNKNOWN;
 goto out;
 }

 switch (pam_get_item(pamh, PAM_RHOST,
 (PAM_GET_ITEM_CONST void **)&rhost)) {
 case PAM_SUCCESS:
 break;

 default:
 rhost = NULL;
 }

 switch (pam_mysql_open_db(ctx)) {
 case PAM_MYSQL_ERR_BUSY:
 case PAM_MYSQL_ERR_SUCCESS:
 break;

 case PAM_MYSQL_ERR_ALLOC:
 retval = PAM_BUF_ERR;
 goto out;

 case PAM_MYSQL_ERR_DB:
 retval = PAM_AUTHINFO_UNAVAIL;
 goto out;

 default:
 retval = PAM_SERVICE_ERR;
 goto out;
 }

 pam_mysql_sql_log(ctx, "CLOSE SESSION", user, rhost);

out:
 if (ctx->disconnect_every_op) {
 pam_mysql_close_db(ctx);
 }

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_close_session() returning %i.", retval);
 }

 return retval;
}

/* end of module definition */

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_mysql_modstruct = {
 PAM_MODULE_NAME,
 pam_sm_authenticate,
 pam_sm_setcred,
 pam_sm_acct_mgmt,
 pam_sm_open_session,
 pam_sm_close_session,
 pam_sm_chauthtok
};

#endif
