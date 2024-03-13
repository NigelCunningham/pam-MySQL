#include "context.h"
#include "args.h"
#include "logging.h"
#include "mysql.h"
#include "configuration.h"
#include "converse.h"
#include "pam_calls.h"

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
pam_mysql_err_t pam_mysql_query_user_stat(pam_mysql_ctx_t *ctx,
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
 * Get the status of a user account.
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
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t * pamh, int flags, int argc,
    const char **argv)
{
  int retval;
  int err;
  int stat;
  const char *user;
  const char *rhost;
  pam_mysql_ctx_t *ctx = NULL;

  (void) flags;

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
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_sm_acct_mgmt() called.");
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
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_sm_acct_mgmt() returning %i.",retval);
  }

  return retval;
}

