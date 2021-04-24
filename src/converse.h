#include "context.h"

#define PLEASE_ENTER_PASSWORD "Password:"
#define PLEASE_ENTER_OLD_PASSWORD "Current Password:"
#define PLEASE_ENTER_NEW_PASSWORD "New Password:"
#define PLEASE_REENTER_NEW_PASSWORD "Retype New Password:"

#define PAM_MYSQL_USER_STAT_EXPIRED         0x0001
#define PAM_MYSQL_USER_STAT_AUTHTOK_EXPIRED 0x0002
#define PAM_MYSQL_USER_STAT_NULL_PASSWD     0x0004

#define PAM_MYSQL_CAP_CHAUTHTOK_SELF    0x0001
#define PAM_MYSQL_CAP_CHAUTHTOK_OTHERS    0x0002

extern pam_mysql_err_t pam_mysql_converse(pam_mysql_ctx_t *ctx, char ***pretval,
    pam_handle_t *pamh, size_t nargs, ...);
