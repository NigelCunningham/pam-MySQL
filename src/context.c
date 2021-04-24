#include "os_dep.h"
#include "alloc.h"
#include "context.h"
#include "logging.h"
#include "mysql.h"

/**
 * Destroy the context data structure.
 *
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 */
static void pam_mysql_destroy_ctx(pam_mysql_ctx_t *ctx)
{
  if (ctx->verbose) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_mysql_destroy_ctx() called.");
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

  xfree(ctx->select);
  ctx->select = NULL;

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

  xfree(ctx->ssl_mode);
  ctx->ssl_mode = NULL;

  xfree(ctx->ssl_cert);
  ctx->ssl_cert = NULL;

  xfree(ctx->ssl_key);
  ctx->ssl_key = NULL;

  xfree(ctx->ssl_ca);
  ctx->ssl_ca = NULL;

  xfree(ctx->ssl_capath);
  ctx->ssl_capath = NULL;

  xfree(ctx->ssl_cipher);
  ctx->ssl_cipher = NULL;
}

/**
 * Free a context data structure.
 *
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to a context data structure.
 */
static void pam_mysql_release_ctx(pam_mysql_ctx_t *ctx)
{
  if (ctx->verbose) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_mysql_release_ctx() called.");
  }

  if (ctx != NULL) {
    pam_mysql_destroy_ctx(ctx);
    xfree(ctx);
  }
}

/**
 * Cleanup everything.
 *
 * @param pam_handle_t *pamh
 *   A pointer to the pam_handle_t data structure.
 * @param void *voiddata
 *   A pointer to our context data structure.
 * @param int status
 *   The unused status value from PAM.
 */
static void pam_mysql_cleanup_hdlr(pam_handle_t *pamh, void * voiddata, int status)
{
  (void) pamh;
  (void) status;

  pam_mysql_release_ctx((pam_mysql_ctx_t*)voiddata);
}

/**
 * Initialise the context data structure.
 *
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
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
  ctx->select = NULL;
  ctx->crypt_type = 0;
  ctx->use_323_passwd = 0;
  ctx->md5 = 0;
  ctx->sha256 = 0;
  ctx->sha512 = 0;
  ctx->blowfish = 0;
  ctx->rounds = -1;
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
  ctx->ssl_mode = NULL;
  ctx->ssl_cert = NULL;
  ctx->ssl_key = NULL;
  ctx->ssl_ca = NULL;
  ctx->ssl_capath = NULL;
  ctx->ssl_cipher = NULL;

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * Retrieve context information from PAM.
 *
 * @param pam_mysql_ctx_t **pretval
 *   A pointer to a data provided by PAM.
 * @param pam_handle_t *pamh
 *   A pointer to the pam data structure handle.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
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
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
      return PAM_MYSQL_ERR_ALLOC;
    }

    /* give the data back to PAM for management */
    if (pam_set_data(pamh, PAM_MODULE_NAME, (void*)*pretval, pam_mysql_cleanup_hdlr)) {
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "failed to set context to PAM at " __FILE__ ":%d", __LINE__);
      xfree(*pretval);
      *pretval = NULL;
      return PAM_MYSQL_ERR_UNKNOWN;
    }

    if ((err = pam_mysql_init_ctx(*pretval))) {
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "cannot initialize context at " __FILE__ ":%d", __LINE__);
      pam_mysql_destroy_ctx(*pretval);
      xfree(*pretval);
      *pretval = NULL;
      return err;
    }
  }

  return PAM_MYSQL_ERR_SUCCESS;
}

