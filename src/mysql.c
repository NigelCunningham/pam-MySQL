#include "os_dep.h"
#include "mysql.h"
#include "strings.h"
//#include "syslog.h"
#include "logging.h"
#include "alloc.h"

/**
 * Attempt to open a connection to the database server.
 *
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
pam_mysql_err_t pam_mysql_open_db(pam_mysql_ctx_t *ctx)
{
  pam_mysql_err_t err;
  char *host = NULL;
  char *socket = NULL;
  int port = 0;

  if (ctx->verbose) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_mysql_open_db() called.");
  }

  if (ctx->mysql_hdl != NULL) {
    return PAM_MYSQL_ERR_BUSY;
  }

  if (NULL == (ctx->mysql_hdl = xcalloc(1, sizeof(MYSQL)))) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
    return PAM_MYSQL_ERR_ALLOC;
  }

  if (ctx->user == NULL) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "required option \"user\" is not set");
    return PAM_MYSQL_ERR_INVAL;
  }

  if (ctx->db == NULL) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "required option \"db\" is not set");
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
          pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
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

  if (ctx->ssl_cert != NULL || ctx->ssl_key != NULL ||
      ctx->ssl_ca != NULL || ctx->ssl_capath != NULL || ctx->ssl_cipher != NULL) {
    mysql_ssl_set(ctx->mysql_hdl, ctx->ssl_key, ctx->ssl_cert,
        ctx->ssl_ca, ctx->ssl_capath, ctx->ssl_cipher);
  }

  if (ctx->ssl_mode != NULL) {
#ifdef MARIADB_BASE_VERSION
    my_bool enable = 1;
    if (strcasecmp(ctx->ssl_mode, "required") == 0 ||
        strcasecmp(ctx->ssl_mode, "enforce")) {
      if (mysql_optionsv(ctx->mysql_hdl, MYSQL_OPT_SSL_ENFORCE,
            (void *)&enable) != 0) {
        err = PAM_MYSQL_ERR_DB;
        goto out;
      }
    } else if (strcasecmp(ctx->ssl_mode, "verify_identity") == 0) {
      if (mysql_optionsv(ctx->mysql_hdl, MYSQL_OPT_SSL_VERIFY_SERVER_CERT,
            (void *)&enable) != 0) {
        err = PAM_MYSQL_ERR_DB;
        goto out;
      }
    }
#else
    int ssl_mode = SSL_MODE_PREFERRED;
    if (strcasecmp(ctx->ssl_mode, "disabled") == 0) {
      ssl_mode = SSL_MODE_DISABLED;
    } else if (strcasecmp(ctx->ssl_mode, "preferred") == 0) {
      ssl_mode = SSL_MODE_PREFERRED;
    } else if (strcasecmp(ctx->ssl_mode, "required") == 0 ||
        strcasecmp(ctx->ssl_mode, "enforced")) {
      ssl_mode = SSL_MODE_REQUIRED;
    } else if (strcasecmp(ctx->ssl_mode, "verify_ca") == 0) {
      ssl_mode = SSL_MODE_VERIFY_CA;
    } else if (strcasecmp(ctx->ssl_mode, "verify_identity") == 0) {
      ssl_mode = SSL_MODE_VERIFY_IDENTITY;
    }
    if (mysql_options(ctx->mysql_hdl, MYSQL_OPT_SSL_MODE, ssl_mode) != 0) {
      err = PAM_MYSQL_ERR_DB;
      goto out;
    }
#endif
  }

  if (NULL == mysql_real_connect(ctx->mysql_hdl, host,
        ctx->user, (ctx->passwd == NULL ? "": ctx->passwd),
        ctx->db, port, socket, ctx->select != NULL ? CLIENT_MULTI_RESULTS : 0)) {
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
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "MySQL error (%s)\n", mysql_error(ctx->mysql_hdl));
  }

  if (ctx->verbose) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_mysql_open_db() returning %d.", err);
  }

  if (host != ctx->host) {
    xfree(host);
  }

  return err;
}

/**
 * Close a connection to the database.
 *
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 */
void pam_mysql_close_db(pam_mysql_ctx_t *ctx)
{
  if (ctx->verbose) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_mysql_close_db() called.");
  }

  if (ctx->mysql_hdl == NULL) {
    return; /* closed already */
  }

  mysql_close(ctx->mysql_hdl);

  mysql_library_end();

  xfree(ctx->mysql_hdl);
  ctx->mysql_hdl = NULL;
}

