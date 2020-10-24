#ifndef MYSQL_H
#define MYSQL_H
#include "context.h"
extern pam_mysql_err_t pam_mysql_open_db(pam_mysql_ctx_t *);
extern void pam_mysql_close_db(pam_mysql_ctx_t *ctx);
#endif
