#include "src/os_dep.h"
#include "src/logging.h"
#include "src/context.h"
#include "src/strings.h"
#include "src/alloc.h"
#include "src/configuration.h"
#include "src/mysql.h"
#include "tests/test.h"

char **messages = NULL, **syslog_messages = NULL;
int num_messages = 0, num_syslog = 0;

extern int verbose;
void dump_syslog_messages(void);

pam_mysql_err_t pam_mysql_sql_log(pam_mysql_ctx_t *ctx, const char *msg, const char *user, const char *rhost) {
  (void) ctx;
  (void) msg;
  (void) user;
  (void) rhost;

  num_messages++;
  messages = xrealloc(messages, num_messages, sizeof(char **));
  messages[num_messages - 1] = xstrdup(msg);

  return PAM_MYSQL_ERR_SUCCESS;
}

int assert_expected_messages(const char** expected)
{
  int i;

  fprintf(stdout, "Checking expected messages were logged...\n");
  fprintf(stdout, "Actual number of logged messages: %d.\n", num_messages);

  for (i = 0; i < num_messages; i++) {
    fprintf(stdout, "Actual message %d.\n", i);

    if (!expected[i]) {
      return 1;
    }

    if (strcmp(expected[i], messages[i])) {
      return 1;
    }
  }

  return 0;
}

int assert_expected_syslog_messages(char *prefix, const char** expected, int num_expected)
{
  int i, result = 0;

  if (verbose) {
    fprintf(stdout, "%s: Checking expected syslog messages were logged...\n", prefix);
    fprintf(stdout, "%s: Actual number of logged messages: %d.\n", prefix, num_syslog);
    fprintf(stdout, "%s: Expected number of logged messages: %d.\n", prefix, num_expected);
  }

  for (i = 0; i < num_syslog; i++) {
    if (verbose) {
      fprintf(stdout, "%s: Actual message %d: ", prefix, i);
    }

    if (num_expected <= i) {
      fprintf(stdout, "%s: Unexpected syslog message: %s\n", prefix, syslog_messages[i]);
      result = 1;
      continue;
    }

    if (strcmp(expected[i], syslog_messages[i])) {
      fprintf(stdout, "%s: Expected '%s', got '%s'\n", prefix, expected[i], syslog_messages[i]);
      result = 1;
      continue;
    }

    if (verbose) {
      fprintf(stdout, "%s: %s\n", prefix, expected[i]);
    }
  }

  return result;
}

void dump_syslog_messages(void)
{
  int i;

  fprintf(stdout, "Dumping syslog messages...\n");
  fprintf(stdout, "Actual number of logged messages: %d.\n", num_syslog);

  for (i = 0; i < num_syslog; i++) {
    fprintf(stdout, "Actual message %d:%s\n", i, syslog_messages[i]);
  }
}

void pam_mysql_syslog(int level, const char *message, ...)
{
  (void) level;
  va_list args;
  char buf[4096];


  num_syslog++;
  syslog_messages = xrealloc(syslog_messages, num_syslog, sizeof(char *));

  va_start(args, message);
  vsnprintf(buf, 4096, message, args);
  va_end(args);

  syslog_messages[num_syslog - 1] = xstrdup(buf);
}

void reset_logging(void) 
{
  if (syslog_messages) {
    if (verbose) {
      fprintf(stdout, "Clearing %d syslog messages.\n", num_syslog);
    }

    for (int i=0; i < num_syslog; i++) {
      xfree(syslog_messages[i]);
    }
    xfree(syslog_messages);
    syslog_messages = NULL;
    num_syslog = 0;
  }

  if (messages) {
    if (verbose) {
      fprintf(stdout, "Clearing %d messages.\n", num_messages);
    }

    for (int i=0; i < num_messages; i++) {
      xfree(messages[i]);
    }
    xfree(messages);
    messages = NULL;
    num_messages = 0;
  }
}
