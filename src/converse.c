#include "converse.h"
#include "logging.h"
#include "alloc.h"
#include "strings.h"

/**
 * Have a conversation with an application via PAM.
 *
 * (This is not the PAM conversation callback).
 *
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 * @param char **pretval
 *   The address of a pointer to the return value.
 * @param pam_handle_t *pamh
 *   A pointer to the PAM handle.
 * @param size_t nargs
 *   The number of messages to be sent.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
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
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_mysql_converse() called.");
  }

  va_start(ap, nargs);

  /* obtain conversation interface */
  if ((perr = pam_get_item(pamh, PAM_CONV,
          (PAM_GET_ITEM_CONST void **)&conv))) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR,
        "could not obtain coversation interface (reason: %s)", pam_strerror(pamh, perr));
    err = PAM_MYSQL_ERR_UNKNOWN;
    goto out;
  }

  /* build message array */
  if (NULL == (msgs = xcalloc(nargs, sizeof(struct pam_message *)))) {

    pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
    err = PAM_MYSQL_ERR_ALLOC;
    goto out;
  }

  for (i = 0; i < nargs; i++) {
    msgs[i] = NULL;
  }

  if (NULL == (bulk_msg_buf = xcalloc(nargs, sizeof(struct pam_message)))) {

    pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
    err = PAM_MYSQL_ERR_ALLOC;
    goto out;
  }

  for (i = 0; i < nargs; i++) {
    msgs[i] = &bulk_msg_buf[i];
    msgs[i]->msg_style = va_arg(ap, int);
    msgs[i]->msg = va_arg(ap, char *);
  }

  if (NULL == (retval = xcalloc(nargs + 1, sizeof(char **)))) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
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
      pam_mysql_syslog(LOG_DEBUG, "conversation failure (reason: %s)",
          pam_strerror(pamh, perr));
      err = PAM_MYSQL_ERR_UNKNOWN;
      goto out;
  }

  for (i = 0; i < nargs; i++) {
    if (resps && resps[i].resp != NULL &&
        NULL == (retval[i] = xstrdup(resps[i].resp))) {
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
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

