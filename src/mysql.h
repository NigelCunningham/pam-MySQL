#ifndef MYSQL_H
#define MYSQL_H
#include "os_dep.h"
#include "context.h"

#ifdef TEST
extern int pam_mysql_query(char *query);
#define MYSQL_QUERY(ctx, query) pam_mysql_query(query.p)
#else
#ifdef HAVE_MYSQL_REAL_QUERY
#define MYSQL_QUERY(ctx, query) mysql_real_query(ctx->mysql_hdl, query.p, query.len)
#else
#define MYSQL_QUERY(ctx, query) mysql_query(ctx->mysql_hdl, query.p)
#endif
#endif

extern pam_mysql_err_t pam_mysql_open_db(pam_mysql_ctx_t *);
extern void pam_mysql_close_db(pam_mysql_ctx_t *ctx);
#endif
