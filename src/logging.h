#ifndef LOGGING_H
#define LOGGING_H

#include "context.h"

extern pam_mysql_err_t pam_mysql_sql_log(pam_mysql_ctx_t *, const char *msg,
        const char *user, const char *host);
void _pam_mysql_syslog(int __pri, const char *__fmt, ...);

#define PAM_MODULE_NAME "pam_mysql"
#define APPLY_LOG_PREFIX(lit) PAM_MODULE_NAME " - " lit

#define pam_mysql_syslog(level, message, ...) { syslog(level, APPLY_LOG_PREFIX(message), ##__VA_ARGS__); }
#endif
