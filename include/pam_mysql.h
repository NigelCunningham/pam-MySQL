/**
 * @file pam_mysql.h
 *
 * Internal header file for pam_mysql.
 */

#ifndef PAM_MYSQL_H
#define PAM_MYSQL_H

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include <time.h>

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#ifndef HAVE_OPENSSL
#ifdef HAVE_MD5_H
#include <md5.h>
#endif

#if defined(HAVE_SASL_MD5_H) && (defined(HAVE_CYRUS_SASL_V1) || defined(HAVE_CYRUS_SASL_V2))
#define USE_SASL_MD5
#include <md5global.h>
#include <md5.h>
#endif
#endif

#ifdef HAVE_OPENSSL
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <assert.h>
#endif

/*
 * Definitions for the externally accessible functions in this file (these
 * definitions are required for static modules but strongly encouraged
 * generally) they are used to instruct the modules include file to define their
 * prototypes.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#ifndef LOG_AUTHPRIV
#define LOG_AUTHPRIV LOG_AUTH
#endif

#ifdef LINUX_PAM_CONST_BUG
#define PAM_AUTHTOK_RECOVERY_ERR PAM_AUTHTOK_RECOVER_ERR
#endif

enum _pam_mysql_err_t {
    PAM_MYSQL_ERR_SUCCESS = 0,
    PAM_MYSQL_ERR_UNKNOWN = -1,
    PAM_MYSQL_ERR_NO_ENTRY = 1,
    PAM_MYSQL_ERR_ALLOC = 2,
    PAM_MYSQL_ERR_INVAL = 3,
    PAM_MYSQL_ERR_BUSY = 4,
    PAM_MYSQL_ERR_DB = 5,
    PAM_MYSQL_ERR_MISMATCH = 6,
    PAM_MYSQL_ERR_IO = 7,
    PAM_MYSQL_ERR_SYNTAX = 8,
    PAM_MYSQL_ERR_EOF = 9,
    PAM_MYSQL_ERR_NOTIMPL = 10
};

#define PAM_MODULE_NAME "pam_mysql"
#define PAM_MYSQL_LOG_PREFIX PAM_MODULE_NAME " - "
#define PLEASE_ENTER_PASSWORD "Password:"
#define PLEASE_ENTER_OLD_PASSWORD "Current Password:"
#define PLEASE_ENTER_NEW_PASSWORD "New Password:"
#define PLEASE_REENTER_NEW_PASSWORD "Retype New Password:"

typedef enum _pam_mysql_err_t pam_mysql_err_t;

void *xcalloc(size_t nmemb, size_t size);
#endif
