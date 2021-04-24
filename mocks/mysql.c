#include "src/os_dep.h"
#include "src/mysql.h"
#include "src/strings.h"
#include "src/logging.h"
#include "src/alloc.h"

int pam_mysql_query(char *query) {
  (void) query;
  return 0;
}

pam_mysql_err_t pam_mysql_open_db(pam_mysql_ctx_t *ctx) {
  (void) ctx;

  return PAM_MYSQL_ERR_SUCCESS;
}

void pam_mysql_close_db(pam_mysql_ctx_t *ctx) {
  (void) ctx;
}

/**
 * mysql_store_result mock
 */
struct st_mysql_res *mock_mysql_store_result_result;

void set_mock_result_mysql_store_result(struct st_mysql_res *result)
{
  mock_mysql_store_result_result = result;
}

struct st_mysql_res * STDCALL mysql_store_result(MYSQL *mysql)
{
  (void) mysql;

  return mock_mysql_store_result_result;
}

/**
 * mysql_query
 */
pam_mysql_err_t mock_mysql_query_result;
int mock_mysql_query_invocation_count = 0;

void set_mock_result_mysql_query(pam_mysql_err_t result) {
  mock_mysql_query_result = result;
}

int STDCALL mysql_query(MYSQL *ctx, const char *query)
{
  (void) ctx;
  (void) query;

  return mock_mysql_query_result;
}

/**
 * mysql_num_rows
 */
my_ulonglong mock_mysql_num_rows_result;
int mock_mysql_num_rows_invocation_count = 0;

void set_mock_result_mysql_num_rows(my_ulonglong result) {
  mock_mysql_num_rows_result = result;
}

my_ulonglong STDCALL mysql_num_rows(MYSQL_RES *res) {
  (void) res;

  return mock_mysql_num_rows_result;
}

/**
 * mysql_fetch_row
 */
MYSQL_ROW mock_mysql_fetch_row_result;
int mock_mysql_fetch_row_invocation_count = 0;

void set_mock_result_mysql_fetch_row(MYSQL_ROW result) {
  mock_mysql_fetch_row_result = result;
}

MYSQL_ROW STDCALL mysql_fetch_row(MYSQL_RES *result) {
  (void) result;

  return mock_mysql_fetch_row_result;
}

void STDCALL mysql_free_result(MYSQL_RES *result) {
  (void) result;
}

/**
 * Reset
 */
void reset_mysql()
{
  mock_mysql_query_result = PAM_MYSQL_ERR_SUCCESS;
  mock_mysql_query_invocation_count = 0;

  mock_mysql_store_result_result = (MYSQL_RES *) 1;
  mock_mysql_num_rows_result = 0;
  mock_mysql_num_rows_invocation_count = 0;
}
