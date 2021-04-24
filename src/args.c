#include "context.h"
#include "logging.h"
#include "strings.h"
#include "configuration.h"
#include "mysql.h"

/**
 * Parse arguments.
 *
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 * @param int argc
 *   The number of arguments.
 * @param const char **argv
 *   A pointer to the string containing arguments.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
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
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_INFO, "option %s is set to \"%s\"", buf, value);
    }
  }

  /* close the database in case we get new args */
  if (param_changed) {
    pam_mysql_close_db(ctx);
  }

  return PAM_MYSQL_ERR_SUCCESS;
}

