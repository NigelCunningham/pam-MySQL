/*
 * PAM module for MySQL
 *
 * Copyright (C) 1998-2005 Gunay Arslan and the contributors.
 * Copyright (C) 2015-2017 Nigel Cunningham and contributors.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Original Version written by: Gunay ARSLAN <arslan@gunes.medyatext.com.tr>
 * This version by: James O'Kane <jo2y@midnightlinux.com>
 * Modifications by Steve Brown, <steve@electronic.co.uk>
 * B.J. Black, <bj@taos.com>
 * Kyle Smith, <kyle@13th-floor.org>
 * Patch integration by Moriyoshi Koizumi, <moriyoshi@at.wakwak.com>,
 * based on the patches by the following contributors:
 * Paul Bryan (check_acct_mgmt service support)
 * Kev Green (Documentation, UNIX socket option)
 * Kees Cook (Misc. clean-ups and more)
 * Fredrik Rambris (RPM spec file)
 * Peter E. Stokke (chauthtok service support)
 * Sergey Matveychuk (OpenPAM support)
 * Package unmaintained for some years; now taken care of by Nigel Cunningham
 * https://github.com/NigelCunningham/pam-MySQL
 */

#ifndef PAM_MYSQL_COMMON_H
#define PAM_MYSQL_COMMON_H 1

#define _GNU_SOURCE

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#ifndef LOG_AUTHPRIV
#define LOG_AUTHPRIV LOG_AUTH
#endif

#ifdef LINUX_PAM_CONST_BUG
#define PAM_AUTHTOK_RECOVERY_ERR PAM_AUTHTOK_RECOVER_ERR
#endif

#define PAM_MODULE_NAME "pam_mysql"
#define PAM_MYSQL_LOG_PREFIX PAM_MODULE_NAME " - "

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
#endif

#ifdef HAVE_MYSQL_H
#include <mysql.h>
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

typedef struct _pam_mysql_ctx_t {
  MYSQL *mysql_hdl;
  char *host;
  char *where;
  char *db;
  char *user;
  char *passwd;
  char *table;
  char *update_table;
  char *usercolumn;
  char *passwdcolumn;
  char *statcolumn;
  int crypt_type;
  int use_323_passwd;
  int md5;
  int sqllog;
  int verbose;
  int use_first_pass;
  int try_first_pass;
  int disconnect_every_op;
  char *logtable;
  char *logmsgcolumn;
  char *logpidcolumn;
  char *logusercolumn;
  char *loghostcolumn;
  char *logrhostcolumn;
  char *logtimecolumn;
  char *config_file;
  char *my_host_info;
} pam_mysql_ctx_t; /*Max length for most MySQL fields is 16 */

typedef enum _pam_mysql_err_t pam_mysql_err_t;

#include <security/_pam_types.h>
#include "pam_mysql_string.h"
#endif
