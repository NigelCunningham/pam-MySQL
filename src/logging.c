#include "os_dep.h"
#include "logging.h"
#include "context.h"
#include "strings.h"
#include "alloc.h"
#include "configuration.h"

/*
 * Definitions for the externally accessible functions in this file (these
 * definitions are required for static modules but strongly encouraged
 * generally) they are used to instruct the modules include file to define their
 * prototypes.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#ifdef HAVE_GETADDRINFO
static char *_try_get_addr_info(char *hostname) {
  char *retval;
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
      retval = xcalloc(INET_ADDRSTRLEN, sizeof(char));

      if (!retval) {
        pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
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
      retval = xcalloc(INET6_ADDRSTRLEN,sizeof(char));
      
      if (!retval) {
        pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
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
  return retval;
}

#define try_get_addr_info(hostname) {
  retval = _try_get_addr_info(hostname);

  if (IS_ERR(retval)) {
    return retval;
  }

}
#else
#define try_get_addr_info(hostname) { }
#endif

/**
 * Try get host by name if getaddrinfo isn't available.
 *
 */
#if defined(HAVE_SUNOS_GETHOSTBYNAME_R) || defined(HAVE_GNU_GETHOSTBYNAME_R)
static pam_mysql_err_t try_gethostbyname() {
  struct hostent *hent = NULL;
  struct hostent *tmp;
  size_t hent_size = sizeof(struct hostent) + 64;
  int herr = 0;

  for (;;) {
    tmp = xrealloc(hent, hent_size, sizeof(char));
    if (!tmp) {
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);

      if (hent) {
        xfree(hent);
      }

      return PAM_MYSQL_ERR_ALLOC;
    }

    hent = tmp;

#if defined(HAVE_SUNOS_GETHOSTBYNAME_R)
    if (gethostbyname_r(hostname, hent,
          (char *)hent + sizeof(struct hostent),
          hent_size - sizeof(struct hostent), &herr)) {
      break;
    }
#elif defined(HAVE_GNU_GETHOSTBYNAME_R)
    if (!gethostbyname_r(hostname, hent,
          (char *)hent + sizeof(struct hostent),
          hent_size - sizeof(struct hostent), &tmp, &herr)) {
      break;
    }
#endif

    if (errno != ERANGE) {
      xfree(hent);
      return PAM_MYSQL_ERR_UNKNOWN;
    }

    if (hent_size + 32 < hent_size) {
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
      xfree(hent);
      return PAM_MYSQL_ERR_ALLOC;
    }

    hent_size += 32;
  }

  switch (hent->h_addrtype) {
    case AF_INET:
      retval = xcalloc(INET_ADDRSTRLEN, sizeof(char));
      if (!retval) {
        pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
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
      retval = xcalloc(INET6_ADDRSTRLEN,sizeof(char));
      if (!retval) {
        pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
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

  return retval;
}
#else
#define try_gethostbyname() { return PAM_MYSQL_ERR_NOTIMPL; }
#endif

/**
 * Convert a host name to an IP address.
 *
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 * @param const char **pretval
 *   A pointer to the address of a string.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
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
    
    try_get_addr_info(hostname);
    try_gethostbyname();

    *pretval = ctx->my_host_info = retval;

    return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * Log a message.
 *
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 * @param const char *msg
 *   A pointer to the message to be logged.
 * @param const char *user
 *   A pointer to the string containing the relevant user name.
 * @param const char *rhost
 *   A pointer to a string containing the name of the remote host.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
pam_mysql_err_t pam_mysql_sql_log(pam_mysql_ctx_t *ctx, const char *msg, const char *user, const char *rhost)
{
    pam_mysql_err_t err;
    pam_mysql_str_t query;
    const char *host;

    if (ctx->verbose) {
        pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_mysql_sql_log() called.");
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
        pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "%s", "sqllog set but logtable not set");
        return PAM_MYSQL_ERR_INVAL;
    }

    if (ctx->logmsgcolumn == NULL) {
        pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "%s", "sqllog set but logmsgcolumn not set");
        return PAM_MYSQL_ERR_INVAL;
    }

    if (ctx->logusercolumn == NULL) {
        pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "%s", "sqllog set but logusercolumn not set");
        return PAM_MYSQL_ERR_INVAL;
    }

    if (ctx->loghostcolumn == NULL) {
        pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "%s", "sqllog set but loghostcolumn not set");
        return PAM_MYSQL_ERR_INVAL;
    }

    if (ctx->logtimecolumn == NULL) {
        pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "%s", "sqllog set but logtimecolumn not set");
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
        pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "%s", query.p);
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
            pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "MySQL error (%s)", mysql_error(ctx->mysql_hdl));
        }

        pam_mysql_str_destroy(&query);

        if (ctx->verbose) {
            pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_mysql_sql_log() returning %d.", err);
        }

        return err;
    }

