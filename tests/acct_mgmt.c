#include <stdio.h>
#include "tests/test.h"
#include "mocks/mock.h"
#include "src/context.h"
#include "src/strings.h"

int verbose = 0;

extern pam_mysql_err_t pam_mysql_query_user_stat(pam_mysql_ctx_t *ctx,
    int *pretval, const char *user);

extern void set_mock_result_pam_mysql_str_init(pam_mysql_err_t result);
extern void set_mock_alloc_pam_mysql_str_init(char *result);

extern int assert_expected_messages(const char *prefix, char** expected, int num);
extern int assert_expected_syslog_messages(const char *prefix, const char** expected, int num);

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
 * Test 1. Logging is working?
 *
 * @return int
 *   Whether the test passes.
 */
int pam_mysql_query_user_stat_can_log_use() {
  pam_mysql_ctx_t ctx;
  int pretval, result;
  const char *user = "";
  const char *prefix = "pam_mysql_query_user_stat_can_log_use";

  ctx.verbose = 1;
  set_mock_result_pam_mysql_str_init(PAM_MYSQL_ERR_ALLOC);

  result = pam_mysql_query_user_stat(&ctx, &pretval, user);

  const char* expected[] = {
    "pam_mysql_query_user_stat() called.",
  };
  result = assert_expected_syslog_messages(prefix, expected, 1);
  return result;
}

/**
 * Test 2. Logging disabled also works?
 *
 * @return int
 *   Whether the test passes.
 */
int pam_mysql_query_user_stat_doesnt_log_use_if_verbose_disabled() {
  pam_mysql_ctx_t ctx;
  int pretval, result;
  const char *user = "";
  const char *prefix = "pam_mysql_query_user_stat_doesnt_log_use_if_verbose_disabled";

  ctx.verbose = 0;
  set_mock_result_pam_mysql_str_init(PAM_MYSQL_ERR_ALLOC);

  result = pam_mysql_query_user_stat(&ctx, &pretval, user);

  const char* expected[] = {};
  result = assert_expected_syslog_messages(prefix, expected, 1);
  return result;
}

/**
 * Test 3. Handles str_init allocation failure.
 *
 * @return int
 *   Whether the test passes.
 */
int pam_mysql_query_stat_handles_str_init_alloc_failure() {
  const char *expected[] = {
    "pam_mysql_query_user_stat() called."
  };
  pam_mysql_ctx_t ctx;
  int pretval, result;
  const char *user = "username";
  char *prefix = "pam_mysql_query_stat_handles_str_init_alloc_failure";

  ctx.verbose = 1;
  ctx.mysql_hdl = 0;
  ctx.where = NULL;

  set_mock_result_pam_mysql_str_init(PAM_MYSQL_ERR_ALLOC);
  result = pam_mysql_query_user_stat(&ctx, &pretval, user);

  return pam_mysql_query_stat_check_result(prefix, result, PAM_MYSQL_ERR_ALLOC, expected, 1);
}

/**
 * Test 4. Handles allocation failure in mysql_format.
 *
 * @return int
 *   Whether the test passes.
 */
int pam_mysql_query_stat_handles_mysql_format_alloc_failure() {
  const char *expected[2] = {
    "pam_mysql_query_user_stat() called.",
    "pam_mysql_query_user_stat() returning 2."
  };
  pam_mysql_ctx_t ctx;
  int pretval, result;
  const char *user = "username";
  char *prefix = "pam_mysql_query_stat_handles_mysql_format_alloc_failure";

  ctx.verbose = 1;
  ctx.mysql_hdl = 0;
  ctx.where = NULL;

  set_mock_result_pam_mysql_format_string(PAM_MYSQL_ERR_ALLOC);

  result = pam_mysql_query_user_stat(&ctx, &pretval, user);

  return pam_mysql_query_stat_check_result(prefix, result, PAM_MYSQL_ERR_ALLOC, expected, 2);
}

/**
 * Test 5. Prepares a query where there's no extra clause.
 *
 * @return int
 *   Whether the test passes.
 */
int pam_mysql_query_prepares_query_without_extra_where() {
  const char *expected[4] = {
    "pam_mysql_query_user_stat() called.",
    "Query",
    "MySQL error ()",
    "pam_mysql_query_user_stat() returning 5.",
  };
  pam_mysql_ctx_t ctx;
  int pretval, result;
  const char *user = "username";
  char *prefix = "pam_mysql_query_prepares_query_without_extra_where";
  pam_mysql_str_t query_buf;
  char buf[1024];

  query_buf.len = 0;
  query_buf.alloc_size = 1024;
  query_buf.p = buf;

  ctx.verbose = 1;
  ctx.mysql_hdl = 0;
  ctx.where = NULL;

  set_mock_alloc_pam_mysql_str_init(&query_buf);

  result = pam_mysql_query_user_stat(&ctx, &pretval, user);

  return pam_mysql_query_stat_check_result(prefix, result, PAM_MYSQL_ERR_DB, expected, 4);
}

/**
 * The array of tests to be run.
 */
struct test_definition tests[] = {
  { "verbose logging", pam_mysql_query_user_stat_can_log_use },
  { "non verbose logging", pam_mysql_query_user_stat_doesnt_log_use_if_verbose_disabled },
  { "str init alloc failure", pam_mysql_query_stat_handles_str_init_alloc_failure },
  { "mysql format alloc failure", pam_mysql_query_stat_handles_mysql_format_alloc_failure },
  { "mysql format - no extra where", pam_mysql_query_prepares_query_without_extra_where },
};

#define num_tests (sizeof(tests) / sizeof(struct test_definition))

/**
 * Entry point.
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

  if (argc == 1) {
    return 1;
  }

  reset();
  fprintf(stdout, "Running test '%s'\n", argv[1]);

  for (long unsigned int i=0; i < num_tests; i++) {
    if (!strcmp(argv[1], tests[i].name)) {
      return tests[i].fn();
    }
  }

  fprintf(stdout, "Test '%s' is unrecognised.\n", argv[1]);
  return 1;
}
