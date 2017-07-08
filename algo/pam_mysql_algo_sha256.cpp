/**
 * @file pam_mysql_algo_sha256.cpp
 *
 * Encrypt a password using SHA256.
 */
#include <string>
#include <pam_mysql.h>
#include "pam_mysql_algo_interface.cpp"

class PamMySQLAlgo_SHA256 {

private:
	static const char OPTION_NAME[];

	/**
	 * Calculate the SHA256 hash of input and return as a hex string.
	 *
	 * @param const unsigned char *d
	 *   The input buffer location.
	 * @param unsigned int sz
	 *   The size of the input.
	 * @param char *md
	 *   A pointer to the output buffer (NULL or at least 65 bytes).
	 *
	 * @return char *
	 *   A pointer to the output buffer.
	 */
	static unsigned char *pam_mysql_sha256_data(const unsigned char *d, unsigned int sz, unsigned char *md)
	{
		size_t i, j;
		unsigned char buf[32];

		if (!md) {
			md = (unsigned char *) xcalloc(64 + 1, sizeof(char));
            if (!md) {
				return NULL;
			}
		}

		SHA256(d, (unsigned long)sz, (unsigned char *) &buf);

		for (i = 0, j = 0; i < 32; i++, j += 2) {
			md[j + 0] = "0123456789abcdef"[(int)(buf[i] >> 4)];
			md[j + 1] = "0123456789abcdef"[(int)(buf[i] & 0x0f)];
		}
		md[j] = '\0';

		return md;
	}

	/**
	 * Check a password.
	 *
	 * @param pam_mysql_ctx_t *ctx
	 *   A pointer to the context data structure.
	 * @ param const char *user
	 *   A pointer to the user name string.
	 * @param const char *password
	 *   A pointer to the unencrypted password string.
	 * @param int null_inhibited
	 *   Whether null authentication tokens should be disallowed.
	 *
	 * @return pam_mysql_err_t
	 *   Indication of success or failure.
	 */
public:
	pam_mysql_err_t check_password(const unsigned char *passwd, const char *dbpwd)
	{
		unsigned char buf[65];
		pam_mysql_err_t result;

        pam_mysql_sha256_data(passwd, strlen((const char *) passwd), (unsigned char *) &buf);

		result = (pam_mysql_err_t) strcmp(dbpwd, (const char *) buf);

		memset(buf, 0, 65);

		return result;
	}


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
	pam_mysql_err_t encryt_passwd(const char *new_passwd)
	{
		unsigned char *encrypted_passwd = (unsigned char *) xcalloc(64 + 1, sizeof(char));

		if (!encrypted_passwd) {
			syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
			return PAM_MYSQL_ERR_ALLOC;
		}
		pam_mysql_sha256_data((const unsigned char*) new_passwd, strlen(new_passwd), encrypted_passwd);
	}
};

const char PamMySQLAlgo_SHA256::OPTION_NAME[] = "SHA256";

/* vim: set expandtab sw=4 ts=4 textwidth=80 : */
