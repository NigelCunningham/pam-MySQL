#include "context.h"
#include "strings.h"
#include "alloc.h"
#include "logging.h"
#include "stream.h"

typedef int(*pam_mysql_option_getter_t)(void *val, const char **pretval, int *to_release);

typedef int(*pam_mysql_option_setter_t)(void *val, const char *newval_str);

typedef struct _pam_mysql_option_accessor_t {
  pam_mysql_option_getter_t get_op;
  pam_mysql_option_setter_t set_op;
} pam_mysql_option_accessor_t;

typedef struct _pam_mysql_option_t {
  const char *name;
  size_t name_len;
  size_t offset;
  pam_mysql_option_accessor_t *accessor;
} pam_mysql_option_t;

struct _pam_mysql_entry_handler_t;

typedef pam_mysql_err_t (*pam_mysql_handle_entry_fn_t)(
    struct _pam_mysql_entry_handler_t *, int, const char *, size_t,
    const char *, size_t);

typedef struct _pam_mysql_entry_handler_t {
  pam_mysql_ctx_t *ctx;
  pam_mysql_handle_entry_fn_t handle_entry_fn;
  pam_mysql_option_t *options;
} pam_mysql_entry_handler_t;

typedef struct _pam_mysql_config_parser_t {
  pam_mysql_ctx_t *ctx;
  pam_mysql_entry_handler_t *hdlr;
} pam_mysql_config_parser_t;

/**
 * Getter for a string option.
 *
 * @param void *val
 *   The pointer to be set to the address of the option.
 * @param const char **pretval.
 *   Pointer to the start of the requested string.
 * @param int *to_release.
 *   Pointer to a flag indicating whether the caller should free val.
 *
 * @return pam_mysql_err_t
 *   Indication of whether the operation succeeded.
 */
static pam_mysql_err_t pam_mysql_string_opt_getter(void *val, const char **pretval, int *to_release)
{
  *pretval = *(char **)val;
  *to_release = 0;

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * Setter for a string option.
 *
 * @param void *val
 *   A pointer to the string. Any existing value will be freed.
 * @param const char *newval_str
 *   Pointer to the new string value.
 *
 * @return pam_mysql_err_t
 *   Indication of whether the operation succeeded.
 */
static pam_mysql_err_t pam_mysql_string_opt_setter(void *val, const char *newval_str)
{
  if (*(char **)val != NULL) {
    xfree(*(char **)val);
  }

  if (NULL == (*(char **)val = xstrdup(newval_str))) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
    return PAM_MYSQL_ERR_ALLOC;
  }

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * Getter for a boolean option.
 *
 * @param void *val
 *   The pointer to be set to the address of the option.
 * @param const char **pretval.
 *   Pointer to the start of the requested option.
 * @param int *to_release.
 *   Pointer to a flag indicating whether the caller should free val.
 *
 * @return pam_mysql_err_t
 *   Indication of whether the operation succeeded.
 */
static pam_mysql_err_t pam_mysql_boolean_opt_getter(void *val, const char **pretval, int *to_release)
{
  *pretval = (*(int *)val ? "true": "false");
  *to_release = 0;

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * Setter for a boolean option.
 *
 * @param void *val
 *   A pointer to the boolean.
 * @param const char *newval_str
 *   Pointer to the new value.
 *
 * @return int
 *   Indication of whether the operation succeeded.
 */
static pam_mysql_err_t pam_mysql_boolean_opt_setter(void *val, const char *newval_str)
{
  *(int *)val = (strcmp(newval_str, "0") != 0 &&
      strcasecmp(newval_str, "N") != 0 &&
      strcasecmp(newval_str, "false") != 0 &&
      strcasecmp(newval_str, "no") != 0);

  return PAM_MYSQL_ERR_SUCCESS;
}

/* {{{ pam_mysql_numeric_opt_getter
*/
static pam_mysql_err_t pam_mysql_numeric_opt_getter(void *val, const char **pretval, int *to_release)
{
  char buf[20];
  snprintf(buf, sizeof(buf), "%d", *(int *)val);
  *pretval = buf;
  *to_release = 0;

  return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_numeric_opt_setter */
static pam_mysql_err_t pam_mysql_numeric_opt_setter(void *val, const char *newval_str)
{
  *(long int *)val = strtol(newval_str, NULL, 10);

  return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/**
 * Get the name matching a numeric key for a crypt method.
 *
 * @param void *val
 *   The index of the method.
 * @param const char **pretval
 *   A pointer that should be set to the address of the matching string.
 * @param int *
 *   Pointer to an integer indicating whether the caller should free val.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
static pam_mysql_err_t pam_mysql_crypt_opt_getter(void *val, const char **pretval, int *to_release)
{
  switch (*(int *)val) {
    case 0:
      *pretval = "plain";
      break;

    case 1:
      *pretval = "Y";
      break;

    case 2:
      *pretval = "mysql";
      break;

    case 3:
      *pretval = "md5";
      break;

    case 4:
      *pretval = "sha1";
      break;

    case 5:
      *pretval = "drupal7";
      break;

    case 6:
      *pretval = "joomla15";
      break;

    case 7:
      *pretval = "ssha";
      break;

    case 8:
      *pretval = "sha512";
      break;

    case 9:
      *pretval = "sha256";
      break;

    default:
      *pretval = NULL;
  }

  *to_release = 0;

  return PAM_MYSQL_ERR_SUCCESS;
}

/* pam_mysql_crypt_opt_setter */
/**
 * Get the number matching a crypt method name.
 *
 * @param void *val
 *   Pointer to the integer value to be returned.
 * @param const char *newval_str
 *   Pointer to a string to be matched against method names.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
static pam_mysql_err_t pam_mysql_crypt_opt_setter(void *val, const char *newval_str)
{
  if (strcmp(newval_str, "0") == 0 || strcasecmp(newval_str, "plain") == 0) {
    *(int *)val = 0;
    return PAM_MYSQL_ERR_SUCCESS;
  }

  if (strcmp(newval_str, "1") == 0 || strcasecmp(newval_str, "Y") == 0) {
    *(int *)val = 1;
    return PAM_MYSQL_ERR_SUCCESS;
  }

  if (strcmp(newval_str, "2") == 0 || strcasecmp(newval_str, "mysql") == 0) {
    *(int *)val = 2;
    return PAM_MYSQL_ERR_SUCCESS;
  }
  if (strcmp(newval_str, "3") == 0 || strcasecmp(newval_str, "md5") == 0) {
    *(int *)val = 3;
    return PAM_MYSQL_ERR_SUCCESS;
  }
  if (strcmp(newval_str, "4") == 0 || strcasecmp(newval_str, "sha1") == 0) {
    *(int *)val = 4;
    return PAM_MYSQL_ERR_SUCCESS;
  }

  if (strcmp(newval_str, "5") == 0 || strcasecmp(newval_str, "drupal7") == 0) {
    *(int *)val = 5;
    return PAM_MYSQL_ERR_SUCCESS;
  }

  if (strcmp(newval_str, "6") == 0 || strcasecmp(newval_str, "joomla15") == 0) {
    *(int *)val = 6;
    return PAM_MYSQL_ERR_SUCCESS;
  }

  if (strcmp(newval_str, "7") == 0 || strcasecmp(newval_str, "ssha") == 0) {
    *(int *)val = 7;
    return PAM_MYSQL_ERR_SUCCESS;
  }

  if (strcmp(newval_str, "8") == 0 || strcasecmp(newval_str, "sha512") == 0) {
    *(int *)val = 8;
    return PAM_MYSQL_ERR_SUCCESS;
  }

  if (strcmp(newval_str, "9") == 0 || strcasecmp(newval_str, "sha256") == 0) {
    *(int *)val = 9;
    return PAM_MYSQL_ERR_SUCCESS;
  }

  *(int *)val = 0;

  return PAM_MYSQL_ERR_INVAL;
}

/* option definitions */
#define PAM_MYSQL_OFFSETOF(type, x) ((size_t)&((type *)0)->x)

#define PAM_MYSQL_DEF_OPTION(name, accr) PAM_MYSQL_DEF_OPTION2(name, name, accr)


#define PAM_MYSQL_DEF_OPTION2(name, sname, accr) \
{ #name, sizeof(#name) - 1, PAM_MYSQL_OFFSETOF(pam_mysql_ctx_t, sname), accr }

static pam_mysql_option_accessor_t pam_mysql_string_opt_accr = {
  pam_mysql_string_opt_getter,
  pam_mysql_string_opt_setter
};

static pam_mysql_option_accessor_t pam_mysql_boolean_opt_accr = {
  pam_mysql_boolean_opt_getter,
  pam_mysql_boolean_opt_setter
};

static pam_mysql_option_accessor_t pam_mysql_numeric_opt_accr = {
  pam_mysql_numeric_opt_getter,
  pam_mysql_numeric_opt_setter
};

static pam_mysql_option_accessor_t pam_mysql_crypt_opt_accr = {
  pam_mysql_crypt_opt_getter,
  pam_mysql_crypt_opt_setter
};

static pam_mysql_option_t options[] = {
  PAM_MYSQL_DEF_OPTION(host, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(where, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(db, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(user, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(passwd, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(table, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(update_table, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(usercolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(passwdcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(statcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(select, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(crypt, crypt_type, &pam_mysql_crypt_opt_accr),
  PAM_MYSQL_DEF_OPTION(md5, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION(sha256, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION(sha512, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION(blowfish, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION(rounds, &pam_mysql_numeric_opt_accr),
  PAM_MYSQL_DEF_OPTION(sqllog, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION(verbose, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION(logtable, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(logmsgcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(logpidcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(logusercolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(loghostcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(logrhostcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(logtimecolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(config_file, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(use_323_passwd, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION(use_first_pass, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION(try_first_pass, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION(disconnect_every_op, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION2(debug, verbose, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION(ssl_mode, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(ssl_cert, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(ssl_key, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(ssl_ca, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(ssl_capath, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION(ssl_cipher, &pam_mysql_string_opt_accr),
  { NULL, 0, 0, NULL }
};

/**
 * Find an option with the specified name.
 *
 * @param pam_mysql_option_t *options
 *   The list of defined options.
 * @param const char *name
 *   A pointer to the string being sought.
 * @param size_t name_len
 *   The length of the string being matched.
 *
 * @return mixed
 *   A pointer to the option data structure or NULL if no match is found.
 */
pam_mysql_option_t *pam_mysql_find_option(pam_mysql_option_t *options,
    const char *name, size_t name_len)
{
  /* set the various ctx */
  pam_mysql_option_t *retval;

  for (retval = options; retval->name != NULL; retval++) {
    if (retval->name_len == name_len &&
        memcmp(retval->name, name, name_len) == 0) {
      return retval;
    }
  }

  return NULL;
}

/* entry handler */
static pam_mysql_option_t pam_mysql_entry_handler_options[] = {
  PAM_MYSQL_DEF_OPTION2(users.host, host, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.database, db, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.db_user, user, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.db_passwd, passwd, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.where_clause, where, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.table, table, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.update_table, update_table, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.user_column, usercolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.password_column, passwdcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.status_column, statcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.select, select, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.password_crypt, crypt_type, &pam_mysql_crypt_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.use_md5, md5, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.use_sha256, sha256, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.use_sha512, sha512, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.use_blowfish, blowfish, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.rounds, rounds, &pam_mysql_numeric_opt_accr),
  PAM_MYSQL_DEF_OPTION2(verbose, verbose, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION2(log.enabled, sqllog, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION2(log.table, logtable, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(log.message_column, logmsgcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(log.pid_column, logpidcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(log.user_column, logusercolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(log.host_column, loghostcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(log.rhost_column, logrhostcolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(log.time_column, logtimecolumn, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.use_323_password, use_323_passwd, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.disconnect_every_operation, disconnect_every_op, &pam_mysql_boolean_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.ssl_mode, ssl_mode, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.ssl_cert, ssl_cert, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.ssl_key, ssl_key, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.ssl_ca, ssl_ca, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.ssl_capath, ssl_capath, &pam_mysql_string_opt_accr),
  PAM_MYSQL_DEF_OPTION2(users.ssl_cipher, ssl_cipher, &pam_mysql_string_opt_accr),
  { NULL, 0, 0, NULL }
};

/**
 * Get an option.
 *
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 * @param const char **pretval
 *   A pointer to the string (will be updated to point to the value)
 * @param int *to_release
 *   A pointer to an int controlling whether the caller releases *pretval.
 * @param const char *name
 *   A pointer to the name of the option being set.
 * @param size_t name_len
 *   The length of the name being set.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
pam_mysql_err_t pam_mysql_get_option(pam_mysql_ctx_t *ctx, const char **pretval, int *to_release, const char *name, size_t name_len)
{
  pam_mysql_option_t *opt = pam_mysql_find_option(options, name, name_len);

  if (opt == NULL) {
    if (ctx->verbose) {
      char buf[1024];
      strnncpy(buf, sizeof(buf), name, name_len);
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "unknown option: %s", buf);
    }

    return PAM_MYSQL_ERR_NO_ENTRY;
  }

  return opt->accessor->get_op((void *)((char *)ctx + opt->offset), pretval, to_release);
}

/**
 * Set an option.
 *
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 * @param const char *name
 *   A pointer to the name of the option being set.
 * @param size_t name_len
 *   The length of the name being set.
 * @param const char *val
 *   A pointer to the new value of the option.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
pam_mysql_err_t pam_mysql_set_option(pam_mysql_ctx_t *ctx, const char *name, size_t name_len, const char *val)
{
  pam_mysql_option_t *opt = pam_mysql_find_option(options, name, name_len);

  if (opt == NULL) {
    if (ctx->verbose) {
      char buf[1024];
      strnncpy(buf, sizeof(buf), name, name_len);
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "unknown option: %s", buf);
    }

    return PAM_MYSQL_ERR_NO_ENTRY;
  }

  return opt->accessor->set_op((void *)((char *)ctx + opt->offset), val);
}

/**
 * Format a string.
 *
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 * @param pam_mysql_str_t *pretval
 *   A pointer to the output string.
 * @param const char *template
 *   The template to which arguments should be applied.
 * @param int mangle
 *   Unused parameter - va_start just wants to know where args start.
 * @param mixed
 *   Additional parameters used to replace % macros in the template.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
pam_mysql_err_t pam_mysql_format_string(pam_mysql_ctx_t *ctx,
    pam_mysql_str_t *pretval, const char *template, int mangle, ...)
{
  pam_mysql_err_t err = PAM_MYSQL_ERR_SUCCESS;
  const char *p;
  const char *name = NULL;
  const char *commit_ptr;
  int state;
  va_list ap;

  if (ctx->verbose) {
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "pam_mysql_format_string() called");
  }

  va_start(ap, mangle);

  state = 0;
  for (commit_ptr = p = template; *p != '\0'; p++) {
    switch (state) {
      case 0:
        if (*p == '%') {
          if ((err = pam_mysql_str_append(pretval, commit_ptr, (size_t)(p - commit_ptr)))) {
            goto out;
          }

          commit_ptr = p;
          state = 1;
        }
        break;

      case 1:
        switch (*p) {
          case '{':
            state = 2;
            break;

          case '[':
            state = 4;
            break;

          case 's': {
                      const char *val = va_arg(ap, char *);

                      if ((err = pam_mysql_quick_escape(ctx, pretval, val, strlen(val)))) {
                        goto out;
                      }

                      state = 0;
                      commit_ptr = p + 1;
                    } break;

          case 'S': {
                      const char *val = va_arg(ap, char *);

                      if ((err = pam_mysql_str_append(pretval, val, strlen(val)))) {
                        goto out;
                      }

                      state = 0;
                      commit_ptr = p + 1;
                    } break;

          case 'u': {
                      char buf[128];
                      unsigned int val = va_arg(ap, unsigned int);
                      char *q = buf + sizeof(buf);

                      while (--q >= buf) {
                        *q = "0123456789"[val % 10];
                        val /= 10;
                        if (val == 0) break;
                      }

                      if ((err = pam_mysql_str_append(pretval, q, sizeof(buf) - (size_t)(q - buf)))) {
                        goto out;
                      }

                      state = 0;
                      commit_ptr = p + 1;
                    } break;

          default:
                    if ((err = pam_mysql_str_append_char(pretval, '%'))) {
                      goto out;
                    }

                    if ((err = pam_mysql_str_append_char(pretval, *p))) {
                      goto out;
                    }

                    state = 0;
                    commit_ptr = p + 1;
                    break;
        }
        break;

      case 2:
        name = p;
        state = 3;
        break;

      case 3:
        if (*p == '}') {
          const char *val;
          int to_release;

          if ((err = pam_mysql_get_option(ctx, &val, &to_release, name, (size_t)(p - name)))) {
            goto out;
          }

          if (val == NULL) {
            val = xstrdup("");
          }

          if ((err = pam_mysql_quick_escape(ctx, pretval, val, strlen(val)))) {
            if (to_release) {
              xfree((char *)val);
            }
            goto out;
          }

          if (to_release) {
            xfree((char *)val);
          }

          state = 0;
          commit_ptr = p + 1;
        }
        break;

      case 4:
        name = p;
        state = 5;
        break;

      case 5:
        if (*p == ']') {
          const char *val;
          int to_release;

          if ((err = pam_mysql_get_option(ctx, &val, &to_release, name, (size_t)(p - name)))) {
            goto out;
          }

          if (val == NULL) {
            val = xstrdup("");
          }

          if ((err = pam_mysql_str_append(pretval, val, strlen(val)))) {
            if (to_release) {
              xfree((char *)val);
            }
            goto out;
          }

          if (to_release) {
            xfree((char *)val);
          }

          state = 0;
          commit_ptr = p + 1;
        }
        break;
    }
  }

  if (commit_ptr < p) {
    if ((err = pam_mysql_str_append(pretval, commit_ptr, (size_t)(p - commit_ptr)))) {
      goto out;
    }
  }

out:
  if (err) {
    pam_mysql_str_destroy(pretval);
  }

  va_end(ap);

  return err;
}

/**
 * Initialise the config parser data structure.
 *
 * pam_mysql_config_parser_t *parser
 *   A pointer to the parser data structure.
 * pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 * pam_mysql_entry_handler_t *hdlr
 *   A pointer to the handler data structure.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
static pam_mysql_err_t pam_mysql_config_parser_init(
    pam_mysql_config_parser_t *parser, pam_mysql_ctx_t *ctx,
    pam_mysql_entry_handler_t *hdlr)
{
  parser->ctx = ctx;
  parser->hdlr = hdlr;

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * Handle one option in the configuration file.
 *
 * @param pam_mysql_entry_handler_t *hdlr
 *   A pointer to the handler data structure.
 * @param int line_num
 *   The current line number in the configuration file.
 * @param const char *name
 *   The name of the option being sought.
 * @param size_t name_len
 *   The length of the name string.
 * @param const char *value
 *   A pointer to the value being given for the option.
 * @param size_t value_len
 *   The length of the value string.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
static pam_mysql_err_t pam_mysql_handle_entry(
    pam_mysql_entry_handler_t *hdlr, int line_num, const char *name,
    size_t name_len, const char *value, size_t value_len)
{
  (void) value_len;

  pam_mysql_err_t err;
  pam_mysql_option_t *opt = pam_mysql_find_option(hdlr->options, name,
      name_len);

  if (opt == NULL) {
    if (hdlr->ctx->verbose) {
      char buf[1024];
      strnncpy(buf, sizeof(buf), name, name_len);
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "unknown option %s on line %d", buf, line_num);
    }

    return PAM_MYSQL_ERR_SUCCESS;
  }

  err = opt->accessor->set_op((void*)((char *)hdlr->ctx + opt->offset), value);
  if (!err && hdlr->ctx->verbose) {
    char buf[1024];
    strnncpy(buf, sizeof(buf), name, name_len);
    pam_mysql_syslog(LOG_AUTHPRIV | LOG_INFO, "option %s is set to \"%s\"", buf, value);
  }

  return err;
}

/**
 * Destroy the config parser data structure.
 *
 * @param pam_mysql_config_parser_t *parser
 *   A pointer to the parser data structure.
 */
static void pam_mysql_config_parser_destroy(pam_mysql_config_parser_t *parser)
{
  (void) parser;
  // Do nothing as it's a stack variable in the caller.
}

/**
 * Initialise the handler data structure.
 *
 * @param pam_mysql_entry_handler_t *hdlr
 *   A pointer to the handler data structure.
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
static pam_mysql_err_t pam_mysql_entry_handler_init(
    pam_mysql_entry_handler_t *hdlr, pam_mysql_ctx_t *ctx)
{
  hdlr->handle_entry_fn = pam_mysql_handle_entry;
  hdlr->ctx = ctx;
  hdlr->options = pam_mysql_entry_handler_options;

  return PAM_MYSQL_ERR_SUCCESS;
}
/**
 * Destroy the handler data structure.
 *
 * @param pam_mysql_entry_handler_t *hdlr
 *   A pointer to the handler data structure.
 */
static void pam_mysql_entry_handler_destroy(
    pam_mysql_entry_handler_t *hdlr)
{
  (void) hdlr;
  // Do nothing - stack variable.
}

/**
 * Initialise the scanner data structure.
 *
 * @param pam_mysql_config_scanner_t *scanner
 *   A pointer to the scanner data structure.
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to the context data structure.
 * @param pam_mysql_stream_t *stream
 *   A pointer to the stream data structure.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
static pam_mysql_err_t pam_mysql_config_scanner_init(
    pam_mysql_config_scanner_t *scanner, pam_mysql_ctx_t *ctx,
    pam_mysql_stream_t *stream)
{
  pam_mysql_err_t err;

  if ((err = pam_mysql_str_init(&scanner->image, 1))) {
    return err;
  }

  scanner->ctx = ctx;
  scanner->stream = stream;
  scanner->state = 0;

  return PAM_MYSQL_ERR_SUCCESS;
}

/**
 * Destroy a scanner data structure.
 *
 * @param pam_mysql_config_scanner_t *scanner
 *   A pointer to the scanner data structure.
 */
static void pam_mysql_config_scanner_destroy(
    pam_mysql_config_scanner_t *scanner)
{
  pam_mysql_str_destroy(&scanner->image);
}

/**
 * Get the next token in a stream.
 *
 * @param pam_mysql_config_scanner_t *scanner
 *   A pointer to the scanner data structure.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
static pam_mysql_err_t pam_mysql_config_scanner_next_token(
    pam_mysql_config_scanner_t *scanner)
{
  pam_mysql_err_t err;
  int c;

  switch (scanner->state) {
    case 0:
      if ((err = pam_mysql_str_truncate(&scanner->image, 0))) {
        return err;
      }

      if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
        return err;
      }

      if (c == '#') {
        if ((err = pam_mysql_str_append_char(&scanner->image, c))) {
          return err;
        }

        if ((err = pam_mysql_stream_read_cspn(scanner->stream,
                &scanner->image, &c, "\n\r", sizeof("\n\r") - 1))) {
          return err;
        }

        scanner->token = PAM_MYSQL_CONFIG_TOKEN_COMMENT;

        if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
          return err;
        }

        if (c == '\r') {
          if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
            return err;
          }

          if (c != '\n') {
            if ((err = pam_mysql_stream_ungetc(scanner->stream, c))) {
              return err;
            }
          }
        }
        break;
      } else {
        if ((err = pam_mysql_stream_ungetc(scanner->stream, c))) {
          return err;
        }
      }
      [[fallthrough]];

    case 1:
      if ((err = pam_mysql_stream_skip_spn(scanner->stream,
              " \t", sizeof(" \t") - 1))) {
        return err;
      }

      if ((err = pam_mysql_str_truncate(&scanner->image, 0))) {
        return err;
      }

      if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
        return err;
      }

      if ((err = pam_mysql_str_append_char(&scanner->image, c))) {
        return err;
      }

      switch (scanner->image.p[0]) {
        case '=':
          scanner->token = PAM_MYSQL_CONFIG_TOKEN_EQUAL;
          scanner->state = 2;
          break;

        case ';':
          scanner->token = PAM_MYSQL_CONFIG_TOKEN_SEMICOLON;
          scanner->state = 1;
          break;

        default:
          if ((err = pam_mysql_stream_read_cspn(scanner->stream,
                  &scanner->image, &c, "=; \t\n\r", sizeof("=; \t\n\r") - 1))) {
            return err;
          }
          scanner->token = PAM_MYSQL_CONFIG_TOKEN_STRING;
          scanner->state = 1;
          break;

        case '\r':
          if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
            return err;
          }

          if (c != '\n') {
            if ((err = pam_mysql_stream_ungetc(scanner->stream, c))) {
              return err;
            }
          } else {
            if ((err = pam_mysql_str_append_char(&scanner->image, c))) {
              return err;
            }
          }

          scanner->token = PAM_MYSQL_CONFIG_TOKEN_NEWLINE;
          scanner->state = 0;
          break;

        case '\n':
          scanner->token = PAM_MYSQL_CONFIG_TOKEN_NEWLINE;
          scanner->state = 0;
          break;
      }
      break;

    case 2:
      if ((err = pam_mysql_stream_skip_spn(scanner->stream,
              " \t", sizeof(" \t") - 1))) {
        return err;
      }

      if ((err = pam_mysql_str_truncate(&scanner->image, 0))) {
        return err;
      }

      if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
        return err;
      }

      if ((err = pam_mysql_str_append_char(&scanner->image, c))) {
        return err;
      }

      switch (scanner->image.p[0]) {
        case ';':
          scanner->token = PAM_MYSQL_CONFIG_TOKEN_SEMICOLON;
          scanner->state = 1;
          break;

        default:
          if ((err = pam_mysql_stream_read_cspn(scanner->stream,
                  &scanner->image, &c, ";\n\r", sizeof(";\n\r") - 1))) {
            return err;
          }
          scanner->token = PAM_MYSQL_CONFIG_TOKEN_STRING;
          break;

        case '\r':
          if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
            return err;
          }

          if (c != '\n') {
            if ((err = pam_mysql_stream_ungetc(scanner->stream, c))) {
              return err;
            }
          } else {
            if ((err = pam_mysql_str_append_char(&scanner->image, c))) {
              return err;
            }
          }

          scanner->token = PAM_MYSQL_CONFIG_TOKEN_NEWLINE;
          scanner->state = 0;
          break;

        case '\n':
          scanner->token = PAM_MYSQL_CONFIG_TOKEN_NEWLINE;
          scanner->state = 0;
          break;
      }
      break;
  }

  return PAM_MYSQL_ERR_SUCCESS;
}

static const char * pam_mysql_config_token_name[] = {
  "=",
  "<NEWLINE>",
  "<STRING_LITERAL>",
  ";",
  "<COMMENT>",
  NULL
};

/**
 * Parse a configuration file.
 *
 * @param pam_mysql_config_parser_t *parser
 *   A pointer to the parser data structure.
 * @param pam_mysql_stream_t *stream
 *   A pointer to the stream data structure.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
static pam_mysql_err_t pam_mysql_config_parser_parse(
    pam_mysql_config_parser_t *parser, pam_mysql_stream_t *stream)
{
  pam_mysql_err_t err;
  pam_mysql_config_scanner_t scanner;
  char *name = NULL;
  size_t name_len = 0;
  char *value = NULL;
  size_t value_len = 0;

  int state = 0;
  int line_num = 1;

  if ((err = pam_mysql_config_scanner_init(&scanner, parser->ctx, stream))) {
    return err;
  }

  while (!(err = pam_mysql_config_scanner_next_token(&scanner))) {
    switch (state) {
      case 0:
        switch (scanner.token) {
          case PAM_MYSQL_CONFIG_TOKEN_STRING:
            if (name == NULL || name_len < scanner.image.len) {
              char *new_buf;

              if (NULL == (new_buf = xrealloc(name,
                      scanner.image.len + 1, sizeof(char)))) {
                pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
                err = PAM_MYSQL_ERR_ALLOC;
                goto out;
              }

              name = new_buf;
            }

            memcpy(name, scanner.image.p, scanner.image.len + 1);
            name_len = scanner.image.len;

            state = 1;
            break;

          case PAM_MYSQL_CONFIG_TOKEN_NEWLINE:
            line_num++;
            break;

          case PAM_MYSQL_CONFIG_TOKEN_COMMENT:
            line_num++;
            break;

          default:
            err = PAM_MYSQL_ERR_SYNTAX;
            goto out;
        }
        break;

      case 1:
        switch (scanner.token) {
          case PAM_MYSQL_CONFIG_TOKEN_EQUAL:
            state = 2;
            break;

          default:
            err = PAM_MYSQL_ERR_SYNTAX;
            goto out;
        }
        break;

      case 2:
        switch (scanner.token) {
          case PAM_MYSQL_CONFIG_TOKEN_SEMICOLON:
            if (parser->hdlr &&
                (err = parser->hdlr->handle_entry_fn(
                                                     parser->hdlr, line_num, name, name_len,
                                                     "", 0))) {
              goto out;
            }
            state = 4;
            break;

          case PAM_MYSQL_CONFIG_TOKEN_NEWLINE:
            if (parser->hdlr &&
                (err = parser->hdlr->handle_entry_fn(
                                                     parser->hdlr, line_num, name, name_len,
                                                     "", 0))) {
              goto out;
            }
            line_num++;
            state = 0;
            break;

          case PAM_MYSQL_CONFIG_TOKEN_STRING:
            if (value == NULL || value_len < scanner.image.len) {
              char *new_buf;

              if (NULL == (new_buf = xrealloc(value,
                      scanner.image.len + 1, sizeof(char)))) {
                pam_mysql_syslog(LOG_AUTHPRIV | LOG_CRIT, "allocation failure at " __FILE__ ":%d", __LINE__);
                err = PAM_MYSQL_ERR_ALLOC;
                goto out;
              }

              value = new_buf;
            }

            memcpy(value, scanner.image.p, scanner.image.len + 1);
            value_len = scanner.image.len;

            if (parser->hdlr &&
                (err = parser->hdlr->handle_entry_fn(
                                                     parser->hdlr, line_num, name, name_len,
                                                     value, value_len))) {
              goto out;
            }
            state = 3;
            break;

          default:
            err = PAM_MYSQL_ERR_SYNTAX;
            goto out;
        }
        break;

      case 3:
        switch (scanner.token) {
          case PAM_MYSQL_CONFIG_TOKEN_SEMICOLON:
            state = 4;
            break;

          case PAM_MYSQL_CONFIG_TOKEN_NEWLINE:
            line_num++;
            state = 0;
            break;

          default:
            err = PAM_MYSQL_ERR_SYNTAX;
            goto out;
        }
        break;

      case 4:
        switch (scanner.token) {
          case PAM_MYSQL_CONFIG_TOKEN_NEWLINE:
            line_num++;
            state = 0;
            break;

          default:
            err = PAM_MYSQL_ERR_SYNTAX;
            goto out;
        }
        break;
    }
  }

  if (err == PAM_MYSQL_ERR_EOF) {
    err = PAM_MYSQL_ERR_SUCCESS;
  }

out:
  if (err == PAM_MYSQL_ERR_SYNTAX) {
    if (parser->ctx->verbose) {
      pam_mysql_syslog(LOG_AUTHPRIV | LOG_ERR, "unexpected token %s on line %d\n",
          pam_mysql_config_token_name[scanner.token],
          line_num);
    }
  }

  if (name != NULL) {
    xfree(name);
  }

  if (value != NULL) {
    xfree(value);
  }

  pam_mysql_config_scanner_destroy(&scanner);

  return err;
}

/**
 * Read a configuration file.
 *
 * @param pam_mysql_ctx_t *ctx
 *   A pointer to a context data structure.
 * @param const char *path
 *   The path to the configuration file.
 *
 * @return pam_mysql_err_t
 *   Indication of success or failure.
 */
pam_mysql_err_t pam_mysql_read_config_file(pam_mysql_ctx_t *ctx,
    const char *path)
{
  pam_mysql_err_t err;
  pam_mysql_entry_handler_t handler;
  pam_mysql_config_parser_t parser;
  pam_mysql_stream_t stream;


  if ((err = pam_mysql_entry_handler_init(&handler, ctx))) {
    return err;
  }

  if ((err = pam_mysql_stream_open(&stream, ctx, path))) {
    pam_mysql_entry_handler_destroy(&handler);
    return err;
  }

  if ((err = pam_mysql_config_parser_init(&parser, ctx, &handler))) {
    pam_mysql_stream_close(&stream);
    pam_mysql_entry_handler_destroy(&handler);
    return err;
  }

  err = pam_mysql_config_parser_parse(&parser, &stream);

  pam_mysql_config_parser_destroy(&parser);
  pam_mysql_stream_close(&stream);
  pam_mysql_entry_handler_destroy(&handler);

  return err;
}

