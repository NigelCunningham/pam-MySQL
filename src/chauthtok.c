#include "os_dep.h"
#include "context.h"
#include "args.h"
#include "configuration.h"
#include "converse.h"
#include "mysql.h"
#include "alloc.h"
#include "logging.h"
#include "authenticate.h"
#include "password.h"
#include "pam_calls.h"

/**
 * Update the password in MySQL.
 *
 * To reduce the number of calls to the DB, I'm now assuming that the old
 * password has been verified elsewhere, so I only check for null/not null
 * and is_root.
 *
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 * @param const char *user
 *   A pointer to the string containing the username.
 * @param const char *new_passwd
 *   A pointer to the string containing the new password.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
static pam_mysql_err_t pam_mysql_update_passwd(pam_mysql_ctx_t *ctx, const char *user, const char *new_passwd)
{
  pam_mysql_err_t err = PAM_MYSQL_ERR_SUCCESS;
  pam_mysql_str_t query;
  char *encrypted_passwd = NULL;

  if ((err = pam_mysql_str_init(&query, 1))) {
    return err;
  }

  if (ctx->verbose) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_mysql_update_passwd() called.");
  }

  if (user == NULL) {
    if (ctx->verbose) {
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "user is NULL.");
    }

    pam_mysql_syslog(LOG_NOTICE, "unable to change password");
    return PAM_MYSQL_ERR_INVAL;
  }

  if (new_passwd != NULL) {
    int result = pam_mysql_password_plugins[ctx->crypt_type].encrypt(ctx, new_passwd, encrypted_passwd);
    if (IS_ERR(result)) {
      err = (pam_mysql_err_t) result;
      encrypted_passwd = NULL;
      goto out;
    }
  }

  err = pam_mysql_format_string(ctx, &query,
      (ctx->where == NULL ?
       "UPDATE %[table] SET %[passwdcolumn] = '%s' WHERE %[usercolumn] = '%s'":
       "UPDATE %[table] SET %[passwdcolumn] = '%s' WHERE %[usercolumn] = '%s' AND (%S)"),
      1, (encrypted_passwd == NULL ? "": encrypted_passwd), user, ctx->where);

  if (!err && MYSQL_QUERY(ctx, query)) {
    err = PAM_MYSQL_ERR_DB;
  }

out:
  if (err == PAM_MYSQL_ERR_DB) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "MySQL error (%s)", mysql_error(ctx->mysql_hdl));
  }

  if (encrypted_passwd) {
    char *p;
    for (p = encrypted_passwd; *p != '\0'; p++) {
      *p = '\0';
    }
    pam_mysql_password_plugins[ctx->crypt_type].free(encrypted_passwd);
  }

  pam_mysql_str_destroy(&query);

  if (ctx->verbose) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_mysql_update_passwd() returning %i.", err);
  }

  return err;
}

/**
 * Query the capabilities of a user.
 *
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 * @param int *pretval
 *   A pointer to the integer where the result should be stored.
 * @param const char *user
 *   A pointer to the username (unused).
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
static pam_mysql_err_t pam_mysql_query_user_caps(pam_mysql_ctx_t *ctx,
    int *pretval, const char *user)
{
  (void) ctx;
  (void) user;

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
 * Detemine whether a username is known.
 *
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 * @param int pretval
 *   A pointer to the result.
 * @param const char *user
 *   A pointer to the username string to be checked.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
static pam_mysql_err_t pam_mysql_query_user_stat(pam_mysql_ctx_t *ctx,
    int *pretval, const char *user)
{
  pam_mysql_err_t err = PAM_MYSQL_ERR_SUCCESS;
  pam_mysql_str_t query;
  MYSQL_RES *result = NULL;
  char **row;

  if (ctx->verbose) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_mysql_query_user_stat() called.");
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
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "%s", query.p);
  }

  if (MYSQL_QUERY(ctx, query)) {
    err = PAM_MYSQL_ERR_DB;
    goto out;
  }

  if (NULL == (result = mysql_store_result(ctx->mysql_hdl))) {
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

    case 2:
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "%s", "SELECT returned an indetermined result.");
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
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "MySQL error (%s)", mysql_error(ctx->mysql_hdl));
  }

  if (result != NULL) {
    mysql_free_result(result);
  }

  pam_mysql_str_destroy(&query);

  if (ctx->verbose) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_mysql_query_user_stat() returning %i.", err);
  }

  return err;
}

/**
 * Check a user's credentials, possibly force a password change.
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
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_sm_chauthtok() called.");
  }

  /* Get User */
  if ((retval = pam_get_user(pamh, (PAM_GET_USER_CONST char **)&user,
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
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "User is not allowed to change the authentication token.");
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
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "update authentication token");
  }

  if (!(caps & PAM_MYSQL_CAP_CHAUTHTOK_OTHERS) &&
      !(stat & PAM_MYSQL_USER_STAT_NULL_PASSWD)) {
    if (ctx->use_first_pass || ctx->try_first_pass) {
      retval = pam_mysql_get_item(pamh, PAM_OLDAUTHTOK,
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

  retval = pam_mysql_get_item(pamh, PAM_AUTHTOK,
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
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "Asking for new password (1)");
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
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_sm_chauthtok() returning %d.", retval);
  }

  return retval;
}

