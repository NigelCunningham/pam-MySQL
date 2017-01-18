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

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include "common.h"
#include "memory.h"
#include "database.h"
#include "my_make_scrambled_password.h"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
    const char **argv);
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const
    char **argv);
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const
    char **argv);
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const
    char **argv);
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
    const char **argv);
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
    const char **argv);

extern void pam_mysql_cleanup_hdlr(pam_handle_t *pamh, void * voiddata, int status);

extern pam_mysql_err_t pam_mysql_retrieve_ctx(pam_mysql_ctx_t **pretval, pam_handle_t *pamh);

extern pam_mysql_err_t pam_mysql_init_ctx(pam_mysql_ctx_t *);
extern void pam_mysql_destroy_ctx(pam_mysql_ctx_t *);

extern void pam_mysql_saltify(pam_mysql_ctx_t *, char *salt, const char *salter );
extern pam_mysql_err_t pam_mysql_check_passwd(pam_mysql_ctx_t *ctx, const char
    *user, const char *passwd, int null_inhibited);
extern pam_mysql_err_t pam_mysql_update_passwd(pam_mysql_ctx_t *, const char
    *user, const char *new_passwd);
extern pam_mysql_err_t pam_mysql_query_user_stat(pam_mysql_ctx_t *, int
    *pretval, const char *user);
extern pam_mysql_err_t pam_mysql_query_user_caps(pam_mysql_ctx_t *, int
    *pretval, const char *user);
extern pam_mysql_err_t pam_mysql_sql_log(pam_mysql_ctx_t *, const char *msg,
    const char *user, const char *host);
extern pam_mysql_err_t pam_mysql_get_host_info(pam_mysql_ctx_t *, const char
    **pretval);

/**
 * pam_mysql_close_db()
 **/
void pam_mysql_close_db(pam_mysql_ctx_t *ctx)
{
  if (ctx->verbose) {
    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_close_db() called.");
  }

  if (ctx->mysql_hdl == NULL) {
    return; /* closed already */
  }

  mysql_close(ctx->mysql_hdl);

  mysql_library_end();

  xfree(ctx->mysql_hdl);
  ctx->mysql_hdl = NULL;
}

/**
 * pam_mysql_open_db()
 **/
pam_mysql_err_t pam_mysql_open_db(pam_mysql_ctx_t *ctx)
{
  pam_mysql_err_t err;
  char *host = NULL;
  char *socket = NULL;
  int port = 0;

  if (ctx->verbose) {
    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_open_db() called.");
  }

  if (ctx->mysql_hdl != NULL) {
    return PAM_MYSQL_ERR_BUSY;
  }

  if (NULL == (ctx->mysql_hdl = xcalloc(1, sizeof(MYSQL)))) {
    syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
    return PAM_MYSQL_ERR_ALLOC;
  }

  if (ctx->user == NULL) {
    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "required option \"user\" is not set");
    return PAM_MYSQL_ERR_INVAL;
  }

  if (ctx->db == NULL) {
    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "required option \"db\" is not set");
    return PAM_MYSQL_ERR_INVAL;
  }

  if (ctx->host != NULL) {
    if (ctx->host[0] == '/') {
      host = NULL;
      socket = ctx->host;
    } else {
      char *p;

      if ((p = strchr(ctx->host, ':')) != NULL) {
        size_t len = (size_t)(p - ctx->host);

        if (NULL == (host = xcalloc(len + 1, sizeof(char)))) {
          syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
          return PAM_MYSQL_ERR_ALLOC;
        }
        memcpy(host, ctx->host, len);
        host[len] = '\0';
        port = strtol(p + 1, NULL, 10);
      } else {
        host = ctx->host;
      }
      socket = NULL;
    }
  }

  if (NULL == mysql_init(ctx->mysql_hdl)) {
    err = PAM_MYSQL_ERR_ALLOC;
    goto out;
  }

  if (NULL == mysql_real_connect(ctx->mysql_hdl, host,
        ctx->user, (ctx->passwd == NULL ? "": ctx->passwd),
        ctx->db, port, socket, 0)) {
    err = PAM_MYSQL_ERR_DB;
    goto out;
  }

  if (mysql_select_db(ctx->mysql_hdl, ctx->db)) {
    err = PAM_MYSQL_ERR_DB;
    goto out;
  }

  err = PAM_MYSQL_ERR_SUCCESS;

out:
  if (err == PAM_MYSQL_ERR_DB) {
    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "MySQL error (%s)\n", mysql_error(ctx->mysql_hdl));
  }

  if (ctx->verbose) {
    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_open_db() returning %d.", err);
  }

  if (host != ctx->host) {
    xfree(host);
  }

  return err;
}

/**
 * pam_mysql_quick_escape()
 **/
pam_mysql_err_t pam_mysql_quick_escape(pam_mysql_ctx_t *ctx, pam_mysql_str_t *append_to, const char *val, size_t val_len)
{
  size_t len;

  if (ctx->verbose) {
    syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_quick_escape() called.");
  }

  if (val_len >= (((size_t)-1)>>1) || pam_mysql_str_reserve(append_to, val_len * 2)) {
    syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
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
 * pam_mysql_converse()
 **/
pam_mysql_err_t pam_mysql_converse(pam_mysql_ctx_t *ctx, char ***pretval,
 pam_handle_t *pamh, size_t nargs, ...)
{
 pam_mysql_err_t err = PAM_MYSQL_ERR_SUCCESS;
 int perr;
 struct pam_message **msgs = NULL;
 struct pam_message *bulk_msg_buf = NULL;
 struct pam_response *resps = NULL;
 struct pam_conv *conv = NULL;
 va_list ap;
 size_t i;
 char **retval = NULL;

 if (ctx->verbose) {
 syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_converse() called.");
 }

 va_start(ap, nargs);

 /* obtain conversation interface */
 if ((perr = pam_get_item(pamh, PAM_CONV,
 (PAM_GET_ITEM_CONST void **)&conv))) {
 syslog(LOG_AUTHPRIV | LOG_ERR,
 PAM_MYSQL_LOG_PREFIX "could not obtain coversation interface (reason: %s)", pam_strerror(pamh, perr));
 err = PAM_MYSQL_ERR_UNKNOWN;
 goto out;
 }

 /* build message array */
 if (NULL == (msgs = xcalloc(nargs, sizeof(struct pam_message *)))) {

 syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
 err = PAM_MYSQL_ERR_ALLOC;
 goto out;
 }

 for (i = 0; i < nargs; i++) {
 msgs[i] = NULL;
 }

 if (NULL == (bulk_msg_buf = xcalloc(nargs, sizeof(struct pam_message)))) {

 syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
 err = PAM_MYSQL_ERR_ALLOC;
 goto out;
 }

 for (i = 0; i < nargs; i++) {
 msgs[i] = &bulk_msg_buf[i];
 msgs[i]->msg_style = va_arg(ap, int);
 msgs[i]->msg = va_arg(ap, char *);
 }

 if (NULL == (retval = xcalloc(nargs + 1, sizeof(char **)))) {
 syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
 err = PAM_MYSQL_ERR_ALLOC;
 goto out;
 }

 for (i = 0; i < nargs; i++) {
 retval[i] = NULL;
 }

 switch ((perr = conv->conv(nargs,
 (PAM_CONV_CONST struct pam_message **)msgs, &resps,
 conv->appdata_ptr))) {
 case PAM_SUCCESS:
 break;

#ifdef HAVE_PAM_CONV_AGAIN
 case PAM_CONV_AGAIN:
 break;
#endif
 default:
 syslog(LOG_DEBUG, PAM_MYSQL_LOG_PREFIX "conversation failure (reason: %s)",
 pam_strerror(pamh, perr));
 err = PAM_MYSQL_ERR_UNKNOWN;
 goto out;
 }

 for (i = 0; i < nargs; i++) {
 if (resps && resps[i].resp != NULL &&
 NULL == (retval[i] = xstrdup(resps[i].resp))) {
 syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
 err = PAM_MYSQL_ERR_ALLOC;
 goto out;
 }
 }

 retval[i] = NULL;

out:
 if (resps != NULL) {
 size_t i;
 for (i = 0; i < nargs; i++) {
 xfree_overwrite(resps[i].resp);
 }
 xfree(resps);
 }

 if (bulk_msg_buf != NULL) {
 memset(bulk_msg_buf, 0, sizeof(*bulk_msg_buf) * nargs);
 xfree(bulk_msg_buf);
 }

 xfree(msgs);

 if (err) {
 if (retval != NULL) {
 for (i = 0; i < nargs; i++) {
 xfree_overwrite(retval[i]);
 retval[i] = NULL;
 }
 xfree(retval);
 }
 } else {
 *pretval = retval;
 }

 va_end(ap);

 return err;
}
