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
 * @param char *config_file
 *   The configuration file.
 *
 * @return int
 *   Whether the test passes.
 */
int pam_mysql_test_check_password(int method, char *config_file) {
  int result;
  const char *prefix = "";

  pam_mysql_ctx_t ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
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
    xstrdup(config_file), /* config_file */
    NULL, /* my_host_info */
    NULL, /* ssl_mode */
    NULL, /* ssl_cert */
    NULL, /* ssl_key */
    NULL, /* ssl_ca */
    NULL, /* ssl_capath */
    NULL, /* ssl_cipher */
  };

  result = pam_mysql_read_config_file(&ctx, ctx.config_file);

  const char* expected[] = {
  };
  if (assert_expected_syslog_messages(prefix, expected, 1)) {
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
  int result, to_release;
  const char *prefix = "", *pretval = NULL;

  if (argc != 4) {
    return 1;
  }

  fprintf(stdout, "Running config file parser test with config file %s and looking for %s to be set to %s'\n", argv[1], argv[2], argv[3]);

  pam_mysql_ctx_t ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    0, /* crypt_type */
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
    xstrdup(argv[1]), /* config_file */
    NULL, /* my_host_info */
    NULL, /* ssl_mode */
    NULL, /* ssl_cert */
    NULL, /* ssl_key */
    NULL, /* ssl_ca */
    NULL, /* ssl_capath */
    NULL, /* ssl_cipher */
  };

  result = pam_mysql_read_config_file(&ctx, ctx.config_file);
  if (!result) {
    pam_mysql_option_t* options = pam_mysql_get_options();
    pam_mysql_option_t* option = pam_mysql_find_option(options, argv[2], strlen(argv[2]));
    result = pam_mysql_get_option(&ctx, &pretval, &to_release, argv[2], strlen(argv[2]));
    if (pretval && result != PAM_MYSQL_ERR_NO_ENTRY) {
      result = !!strcmp(pretval, argv[3]);
      if (result) {
        fprintf(stdout, "Expected %s but got %s.\n", argv[3], pretval);
      }
    }
    else {
      fprintf(stdout, "No option named %s was found.\n", argv[2]);
      result = 1;
    }
  }
  else {
    fprintf(stdout, "pam_mysql_read_config_file returned %d.\n", result);
    result = 1;
  }

  const char* expected[] = {
  };
  if (assert_expected_syslog_messages(prefix, expected, 1)) {
    dump_syslog_messages();
  }

  return result;
}
