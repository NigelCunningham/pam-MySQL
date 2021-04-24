#include "src/context.h"

extern void set_mock_result_pam_mysql_parse_args(pam_mysql_err_t result);
extern void set_mock_result_pam_mysql_format_string(pam_mysql_err_t result);
extern void set_mock_result_pam_mysql_read_config_file(pam_mysql_err_t result);
extern void set_mock_result_mysql_store_result(MYSQL_RES *result);
extern void set_mock_result_mysql_query(pam_mysql_err_t result);
extern void set_mock_result_mock_mysql_query_result(pam_mysql_err_t result);
extern void set_mock_result_mysql_num_rows(my_ulonglong result);
extern void set_mock_result_mysql_fetch_row(MYSQL_ROW result);
extern void set_mock_result_pam_mysql_str_init(pam_mysql_err_t result);

extern void reset(void);
