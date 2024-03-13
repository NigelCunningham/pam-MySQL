#include "os_dep.h"
#include "context.h"
#include "alloc.h"
#include "logging.h"
#include "configuration.h"
#include "mysql.h"
#include "converse.h"
#include "password.h"
#include "pam_calls.h"

/**
 * Check a password.
 *
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 * @ param const char *user
 *   A pointer to the user name string.
 * @param const char *password
 *   A pointer to the unencrypted password string.
 * @param int null_inhibited
 *   Whether null authentication tokens should be disallowed.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
pam_mysql_err_t pam_mysql_check_passwd(pam_mysql_ctx_t *ctx,
    const char *user, const char *passwd, int null_inhibited)
{
  pam_mysql_err_t err;
  pam_mysql_str_t query;
  MYSQL_RES *result = NULL;
  char **row;
  int vresult;
  size_t enc_size;
  char *encrypted_passwd = NULL;

  if (ctx->verbose) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_mysql_check_passwd() called.");
  }

  /* To avoid putting a plain password in the MySQL log file and on
   * the wire more than needed we will request the encrypted password
   * from MySQL. We will check encrypt the passed password against the
   * one returned from MySQL.
   */
  err = pam_mysql_str_init(&query, 1);
  if (err) {
    return err;
  }

  err = ctx->select == NULL ?
    pam_mysql_format_string(ctx, &query,
        (ctx->where == NULL ?
         "SELECT %[passwdcolumn] FROM %[table] WHERE %[usercolumn] = '%s'":
         "SELECT %[passwdcolumn] FROM %[table] WHERE %[usercolumn] = '%s' AND (%S)"),
        1, user, ctx->where) :
    pam_mysql_format_string(ctx, &query, ctx->select, 1, user);

  if (err) {
    goto out;
  }

  if (ctx->verbose) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "%s", query.p);
  }

  if (MYSQL_QUERY(ctx, query)) {
    err = PAM_MYSQL_ERR_DB;
    goto out;
  }

  result = mysql_store_result(ctx->mysql_hdl);
  if (!result) {
    err = PAM_MYSQL_ERR_DB;
    goto out;
  }

  switch (mysql_num_rows(result)) {
    case 0:
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_DEBUG, "%s", "SELECT returned no result.");
      err = PAM_MYSQL_ERR_NO_ENTRY;
      goto out;

    case 1:
      break;

    default:
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "%s", "SELECT returned an indeterminate result.");
      err = PAM_MYSQL_ERR_UNKNOWN;
      goto out;
  }

  /* Grab the password from RESULT_SET. */
  row = mysql_fetch_row(result);
  if (!row) {
    err = PAM_MYSQL_ERR_DB;
    goto out;
  }

  vresult = -1;

  if (row[0] && strlen(row[0])) {
    if (passwd && strlen(passwd)) {
      pam_mysql_password_encryption_t *plugin = &pam_mysql_password_plugins[ctx->crypt_type];
      enc_size = plugin->encryption_size ? plugin->encryption_size : strlen(passwd + 1);
      encrypted_passwd = xcalloc(enc_size, sizeof(char));
      if (!encrypted_passwd) {
        pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
        return PAM_MYSQL_ERR_ALLOC;
      }

      // Some plugins (ssha) need the stored password to get the salt.
      strcpy(encrypted_passwd, row[0]);
      err = plugin->encrypt(ctx, passwd, encrypted_passwd);
      if (ctx->verbose) {
        pam_mysql_syslog(LOG_AUTHPRIV | LOG_DEBUG,"'%s' v '%s' (<= '%s'). Error = %d.\n", row[0], encrypted_passwd, passwd, err);
      }
      if (!err) {
        vresult = strcmp(row[0], encrypted_passwd);
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
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "MySQL error(%s)", mysql_error(ctx->mysql_hdl));
  }

  if (encrypted_passwd) {
    xfree(encrypted_passwd);
  }

  if (result) {
    mysql_free_result(result);
    if (ctx->select) {
      while (mysql_next_result(ctx->mysql_hdl) == 0) {
        result = mysql_store_result(ctx->mysql_hdl);
        if (result)
          mysql_free_result(result);
      }
    }
  }

  pam_mysql_str_destroy(&query);

  if (ctx->verbose) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_mysql_check_passwd() returning %i.", err);
  }

  return err;
}
/**
 * Authenticate a user.
 *
 * @param pam_handle_t *pamh
 *   A pointer to the PAM handle.
 * @param int flags
 *   Flags indicating desired behaviour.
 * @param int argc
 *   The number of arguments provided.
 * @param const char **argv
 *   An array of arguments.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
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
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_sm_authenticate() called.");
  }

  /* Get User */
  if ((retval = pam_mysql_get_user(pamh, (PAM_GET_USER_CONST char **)&user,
          NULL))) {
    goto out;
  }

  if (user == NULL) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "no user specified.");
    retval = PAM_USER_UNKNOWN;
    goto out;
  }

  switch (pam_mysql_get_item(pamh, PAM_RHOST,
        (PAM_GET_ITEM_CONST void **)&rhost)) {
    case PAM_SUCCESS:
      break;

    default:
      rhost = NULL;
  }

  if (ctx->use_first_pass || ctx->try_first_pass) {
    retval = pam_mysql_get_item(pamh, PAM_AUTHTOK,
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
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "failed to retrieve authentication token.");
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
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_sm_authenticate() returning %d.", retval);
  }

  return retval;
}

/**
 * Set a user's credentials.
 *
 * @param pam_handle_t *pamh
 *   A pointer to the PAM handle.
 * @param int flags
 *   An integer indicating desired behaviour.
 * @param int argc
 *   The number of arguments provided.
 * @param const char **argv
 *   An array of arguments.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc,
    const char **argv)
{
  (void) pamh;
  (void) flags;
  (void) argc;
  (void) argv;

#ifdef DEBUG
  pam_mysql_syslog(LOG_INFO, "%s", "setcred called but not implemented.");
#endif
  return PAM_SUCCESS;
}

