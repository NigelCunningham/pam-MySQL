/**
 * pam-MySQL session management.
 */

#include "os_dep.h"
#include "context.h"
#include "logging.h"
#include "mysql.h"
#include "args.h"

int pam_mysql_initialise(pam_mysql_ctx_t *ctx, pam_handle_t *pamh, int argc,
    const char **argv) {

  const char *user;
  const char *rhost;
  int retval = pam_mysql_retrieve_ctx(&ctx, pamh);

  switch (retval) {
    case PAM_MYSQL_ERR_SUCCESS:
      break;

    case PAM_MYSQL_ERR_ALLOC:
      return PAM_BUF_ERR;

    default:
      return PAM_SERVICE_ERR;
  }

  retval = pam_mysql_parse_args(ctx, argc, argv);

  switch (retval) {
    case PAM_MYSQL_ERR_SUCCESS:
      break;

    case PAM_MYSQL_ERR_ALLOC:
      retval = PAM_BUF_ERR;
      goto out;

    default:
      retval = PAM_SERVICE_ERR;
      goto out;
  }

  if (ctx->config_file) {
    switch (pam_mysql_read_config_file(ctx, ctx->config_file)) {
      case PAM_MYSQL_ERR_ALLOC:
        retval = PAM_BUF_ERR;
        goto out;

      default:
        break;
    }
  }

  if (ctx->verbose) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_mysql_initialise() called.");
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

  pam_mysql_sql_log(ctx, "pam_mysql_initialise", user, rhost);

out:
  if (ctx->disconnect_every_op) {
    pam_mysql_close_db(ctx);
  }

  if (ctx->verbose) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_sm_open_session() returning %i.", retval);
  }

  return retval;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
    const char **argv) {

  (void) flags;
  pam_mysql_ctx_t *ctx = NULL;

  return pam_mysql_initialise(ctx, pamh, argc, argv);
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
    const char **argv) {

  (void) flags;
  pam_mysql_ctx_t *ctx = NULL;

  return pam_mysql_initialise(ctx, pamh, argc, argv);
}
