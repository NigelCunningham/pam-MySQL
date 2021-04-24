
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
}
