#include <stdio.h>
#include "src/os_dep.h"
#include "src/context.h"
#include "src/alloc.h"
#include "src/logging.h"
#include "src/configuration.h"
#include "src/mysql.h"
#include "src/converse.h"
#include "src/password.h"
#include "src/pam_calls.h"
#include "tests/test.h"
#include "mocks/mock.h"

#define PAM_MYSQL_TEST

int verbose = 0;

struct pam_handle {
};

PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags,
    int argc, const char **argv);

extern void pam_mysql_set_mock_context(pam_mysql_ctx_t *context);
extern int assert_expected_messages(const char *prefix, char** expected, int num);
extern int assert_expected_syslog_messages(const char *prefix, const char** expected, int num);
extern void dump_syslog_messages();
extern void pam_mysql_set_mock_converse_result(char **result);
extern void pam_mysql_set_user_name(char *user);
extern void pam_mysql_set_item(int index, char *result, int retval);

/**
 * Check the outcome of executing pam_mysql_query_user_stat.
 *
 * @param char *prefix
 *   The prefix to add to messages.
 * @param int result
 *   The result of the tested function.
 * @param int expected_result
 *   The expected return code from the system under test.
 * @param const char **expected
 *   The expected logged messages.
 * @param int num_expected
 *   The number of messages expected to be logged.
 *
 * @return int
 *   Whether the test passes.
 */
int pam_mysql_query_stat_check_result(char *prefix, int result, int expected_result, const char **expected, int num_expected) {
  int ret;

  if (expected_result != result) {
    fprintf(stdout, "%s: pam_mysql_query_user_stat returned %d when we expected %d.\n",
        prefix, result, expected_result);
    ret = 1;
  }
  else {
    ret = assert_expected_syslog_messages(prefix, expected, num_expected);
  }

  return ret;
}

/**
 * Test helper.
 *
 * @param int method
 *   The encryption method to use.
 * @param char *actual
 *   The 'stored' encrypted password.
 * @param char *check
 *   The plain text password to check.
 *
 * @return int
 *   Whether the test passes.
 */
int pam_mysql_test_check_password(int method, char *actual, char *check) {
  pam_handle_t pamh;
  int flags = 0, argc = 0, result;
  const char *argv[] = {}, *prefix = "";
  char **converse_result = NULL;

  pam_mysql_ctx_t ctx = {
    NULL,
    "localhost",
    NULL,
    "mock_db",
    "mock_user",
    "first_pass",
    "mock_table",
    "update_table",
    "user_col",
    "pwd_col",
    "stat_col",
    NULL,
    method, /* crypt_type */
    0, /* use_323_passwd */
    0, /* md5 */
    0, /* sha256 */
    0, /* sha512 */
    0, /* blowfish */
    0, /* rounds */
    0, /* sqllog */
    0, /* verbose */
    0, /* use_first_pass */
    0, /* try_first_pass */
    0, /* disconnect_every_op */
    NULL, /* logtable */
    NULL, /* logmsgcolumn */
    NULL, /* logpidcolumn */
    NULL, /* logusercolumn */
    NULL, /* loghostcolumn */
    NULL, /* logrhostcolumn */
    NULL, /* logtimecolumn */
    NULL, /* config_file */
    NULL, /* my_host_info */
    NULL, /* ssl_mode */
    NULL, /* ssl_cert */
    NULL, /* ssl_key */
    NULL, /* ssl_ca */
    NULL, /* ssl_capath */
    NULL, /* ssl_cipher */
  };

  pam_mysql_set_mock_context(&ctx);

  // Needed for the mySQL escape string calls.
  mysql_init(NULL);

  // The equivalent of asking the user for their password.
  converse_result = xcalloc(1, sizeof(char *));
  converse_result[0] = xstrdup(check);
  pam_mysql_set_mock_converse_result(converse_result);

  pam_mysql_set_user_name("mock_user");
  pam_mysql_set_item(PAM_RHOST, NULL, PAM_PERM_DENIED);

  // MySQL returns a resource pointer which we don't use
  // but it must be non zero.
  set_mock_result_mysql_store_result((MYSQL_RES *) 1);

  // One row in our mock query result.
  set_mock_result_mysql_num_rows(1);

  // This is our mock result.
  char *mock_row[1] = { actual };
  set_mock_result_mysql_fetch_row(mock_row);

  // And now we can test...
  result = pam_sm_authenticate(&pamh, flags, argc, argv);

  const char* expected[] = {
  };
  if (assert_expected_syslog_messages(prefix, expected, 0)) {
    dump_syslog_messages();
  }
  return result;
}


/**
 * Entry point.
 *
 * Argument is the name of the test to run (as given in pam_mysql_password_plugins.
 *
 * @param int argc
 *   The number of arguments provided to the binary.
 * @param char **argv
 *   The array of arguments.
 *
 * @return int
 *   Whether tests ran successfully.
 */
int main(int argc, char **argv) {
  (void) argc;
  (void) argv;

  if (argc != 2) {
    return 1;
  }

  fprintf(stdout, "Running test '%s'\n", argv[1]);

  for (long unsigned int i=0; i < pam_mysql_num_plugins(); i++) {
    pam_mysql_password_encryption_t *plugin = &pam_mysql_password_plugins[i];

    if (!strcmp(argv[1], plugin->name)) {
      char **passwords = pam_mysql_password_plugin_test_passwords(i);
      int pwd = 0;
      int failed_any = 0;
      while (passwords[pwd]) {
	int succeed = pam_mysql_test_check_password(plugin->index, passwords[pwd], "this is a passwd");
	int fail = pam_mysql_test_check_password(plugin->index, passwords[pwd], "wrong");
	if (succeed || !fail) {
	  fprintf(stderr, "Test for password '%s' fails.\n", passwords[pwd]);
	  failed_any++;
	}
	pwd++;
      }
      xfree(passwords);
      fprintf(stderr, "Passed %d/%d passwords.\n", pwd - failed_any, pwd);
      // A successful password check returns 0. Anything else is a failure.
      // We return an error is we don't pass the expected success (succeed != 0) or we don't fail when we should (!fail).
      return failed_any;
    }
  }

  fprintf(stdout, "Test '%s' is unrecognised.\n", argv[1]);
  return 1;
}
