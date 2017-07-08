/**
 * @file pam_mysql_algo_interface.cpp
 *
 * Interface for defining a method of encrypting a password.
 */
#include <string>
#include <pam_mysql.h>

class PamMySQLAlgo
{
private:
	static const char OPTION_NAME[];

	/**
	 * Check a password.
	 *
	 * @param const char *password
	 *   A pointer to the unencrypted password string.
	 * @param const char *dbpwd
	 *   A pointer to the encrypted password string.
	 *
	 * @return pam_mysql_err_t
	 *   Indication of success or failure.
	 */
public:
	pam_mysql_err_t check_passwd(const char *passwd, const char *dbpwd);


	/**
	 * Update the password in MySQL.
	 *
	 * To reduce the number of calls to the DB, I'm now assuming that the old
	 * password has been verified elsewhere, so I only check for null/not null
	 * and is_root.
	 *
	 * @param const char *new_passwd
	 *   A pointer to the string containing the new password.
	 *
	 * @return pam_mysql_err_t
	 *   Indication of success or failure.
	 */
	pam_mysql_err_t pam_mysql_update_passwd(const char *new_passwd);
};
