/*
 * PAM module for MySQL
 *
 * Copyright (C) 1998-2005 Gunay Arslan and the contributors.
 * All rights reserved.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * Original Version written by: Gunay ARSLAN <arslan@gunes.medyatext.com.tr>
 * This version by: James O'Kane <jo2y@midnightlinux.com>
 * Modifications by Steve Brown, <steve@electronic.co.uk>
 *		  B.J. Black, <bj@taos.com>
 *		  Kyle Smith, <kyle@13th-floor.org>
 * Patch integration by Moriyoshi Koizumi, <moriyoshi@at.wakwak.com>,
 * based on the patches by the following contributors:
 *        Paul Bryan (check_acct_mgmt service support)
 *        Kev Green (Documentation, UNIX socket option)
 *        Kees Cook (Misc. clean-ups and more)
 *        Fredrik Rambris (RPM spec file)
 *        Peter E. Stokke (chauthtok service support)
 *        Sergey Matveychuk (OpenPAM support)
 *
 * $Id: pam_mysql.c,v 1.10.2.15 2006/01/09 10:35:59 moriyoshi Exp $
 */

#define _GNU_SOURCE

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* {{{ includes */

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

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

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

/*
 * here, we make definitions for the externally accessible functions
 * in this file (these definitions are required for static modules
 * but strongly encouraged generally) they are used to instruct the
 * modules include file to define their prototypes.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <pam_appl.h>
#include <pam_modules.h>

/* }}} */

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#ifndef LOG_AUTHPRIV
#define LOG_AUTHPRIV LOG_AUTH
#endif

#ifdef LINUX_PAM_CONST_BUG
#define PAM_AUTHTOK_RECOVERY_ERR PAM_AUTHTOK_RECOVER_ERR
#endif

#define PAM_MODULE_NAME  "pam_mysql"
#define PAM_MYSQL_LOG_PREFIX PAM_MODULE_NAME " - "
#define PLEASE_ENTER_PASSWORD "Password:"
#define PLEASE_ENTER_OLD_PASSWORD "(Current) Password:"
#define PLEASE_ENTER_NEW_PASSWORD "(New) Password:"
#define PLEASE_REENTER_NEW_PASSWORD "Retype (New) Password:"

/* {{{ consts  */
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

enum _pam_mysql_config_token_t {
	PAM_MYSQL_CONFIG_TOKEN_EQUAL = 0,
	PAM_MYSQL_CONFIG_TOKEN_NEWLINE,
	PAM_MYSQL_CONFIG_TOKEN_STRING,
	PAM_MYSQL_CONFIG_TOKEN_SEMICOLON,
	PAM_MYSQL_CONFIG_TOKEN_COMMENT,
	PAM_MYSQL_CONFIG_TOKEN__LAST
};

#define PAM_MYSQL_USER_STAT_EXPIRED         0x0001
#define PAM_MYSQL_USER_STAT_AUTHTOK_EXPIRED 0x0002
#define PAM_MYSQL_USER_STAT_NULL_PASSWD     0x0004

#define PAM_MYSQL_CAP_CHAUTHTOK_SELF		0x0001
#define PAM_MYSQL_CAP_CHAUTHTOK_OTHERS		0x0002
/* }}} */
 
/* {{{ typedefs */
/* {{{ typedef struct pam_mysql_ctx_t */
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
/* }}} */

/* {{{ typedef enum pam_mysql_err_t */
typedef enum _pam_mysql_err_t pam_mysql_err_t;
/* }}} */

/* {{{ typedef enum pam_mysql_config_token_t */
typedef enum _pam_mysql_config_token_t pam_mysql_config_token_t;
/* }}} */

/* {{{ typedef (func) pam_mysql_option_getter_t */
typedef int(*pam_mysql_option_getter_t)(void *val, const char **pretval, int *to_release);
/* }}} */

/* {{{ typedef (func) pam_mysql_option_setter_t */
typedef int(*pam_mysql_option_setter_t)(void *val, const char *newval_str);
/* }}} */

/* {{{ typedef struct pam_mysql_option_accessor_t */
typedef struct _pam_mysql_option_accessor_t {
	pam_mysql_option_getter_t get_op;
	pam_mysql_option_setter_t set_op;
} pam_mysql_option_accessor_t;
/* }}} */

/* {{{ typedef struct pam_mysql_option_t */
typedef struct _pam_mysql_option_t {
	const char *name;
	size_t name_len;
	size_t offset;
	pam_mysql_option_accessor_t *accessor;
} pam_mysql_option_t;
/* }}} */

/* {{{ typedef struct pam_mysql_str_t */
typedef struct _pam_mysql_str_t {
	char *p;
	size_t len;
	size_t alloc_size;
	int mangle;
} pam_mysql_str_t;
/* }}} */

/* {{{ typedef (func) pam_mysql_handle_entry_fn_t */
struct _pam_mysql_entry_handler_t;

typedef pam_mysql_err_t (*pam_mysql_handle_entry_fn_t)(
		struct _pam_mysql_entry_handler_t *, int, const char *, size_t,
		const char *, size_t);
/* }}} */

/* {{{ typedef struct pam_mysql_entry_handler_t */
typedef struct _pam_mysql_entry_handler_t {
	pam_mysql_ctx_t *ctx;
	pam_mysql_handle_entry_fn_t handle_entry_fn;
	pam_mysql_option_t *options;
} pam_mysql_entry_handler_t;
/* }}} */

/* {{{ typedef struct pam_mysql_config_parser_t */
typedef struct _pam_mysql_config_parser_t {
	pam_mysql_ctx_t *ctx;
	pam_mysql_entry_handler_t *hdlr;
} pam_mysql_config_parser_t;
/* }}} */

/* {{{ typedef struct pam_mysql_stream_t */
typedef struct _pam_mysql_stream_t {
	int fd;
	unsigned char buf[2][2048];
	unsigned char *buf_start;
	unsigned char *buf_ptr;
	unsigned char *buf_end;
	unsigned char *pushback;
	size_t buf_in_use;
	int eof;
} pam_mysql_stream_t;
/* }}} */

/* {{{ typedef struct _pam_mysql_config_scanner_t */
typedef struct _pam_mysql_config_scanner_t {
	pam_mysql_ctx_t *ctx;
	pam_mysql_str_t image;
	pam_mysql_config_token_t token;
	pam_mysql_stream_t *stream;
	int state;
} pam_mysql_config_scanner_t;
/* }}} */
/* }}} */

/* {{{ prototypes */
/* {{{ General PAM Prototypes */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
		int flags, int argc, const char **argv);
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
		const char **argv);
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
		const char **argv);
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
		const char **argv);
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
		const char **argv);
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
		const char **argv);
/* }}} */

/* {{{ static prototypes */ 
static void pam_mysql_cleanup_hdlr(pam_handle_t *pamh, void * voiddata, int status);

/* {{{ pam_mysql methods */
static pam_mysql_err_t pam_mysql_retrieve_ctx(pam_mysql_ctx_t **pretval, pam_handle_t *pamh);

static pam_mysql_err_t pam_mysql_init_ctx(pam_mysql_ctx_t *);
static void pam_mysql_destroy_ctx(pam_mysql_ctx_t *);
static void pam_mysql_saltify(pam_mysql_ctx_t *, char *salt, const char *salter );
static pam_mysql_err_t pam_mysql_parse_args(pam_mysql_ctx_t *, int argc, const char **argv);
static pam_mysql_err_t pam_mysql_open_db(pam_mysql_ctx_t *);
static void pam_mysql_close_db(pam_mysql_ctx_t *);
static pam_mysql_err_t pam_mysql_check_passwd(pam_mysql_ctx_t *ctx,
		const char *user, const char *passwd, int null_inhibited);
static pam_mysql_err_t pam_mysql_update_passwd(pam_mysql_ctx_t *,
		const char *user, const char *new_passwd);
static pam_mysql_err_t pam_mysql_query_user_stat(pam_mysql_ctx_t *,
		int *pretval, const char *user);
static pam_mysql_err_t pam_mysql_query_user_caps(pam_mysql_ctx_t *,
		int *pretval, const char *user);
static pam_mysql_err_t pam_mysql_sql_log(pam_mysql_ctx_t *, const char *msg,
		const char *user, const char *host);
static pam_mysql_err_t pam_mysql_get_host_info(pam_mysql_ctx_t *,
		const char **pretval);
/* }}} */

static size_t strnncpy(char *dest, size_t dest_size, const char *src, size_t src_len);
static void *xcalloc(size_t nmemb, size_t size);
static char *xstrdup(const char *ptr);
static void xfree(void *ptr);
static void xfree_overwrite(char *ptr);
/* }}} */
/* }}} */

/* {{{ strnncpy */
static size_t strnncpy(char *dest, size_t dest_size, const char *src, size_t src_len)
{
	size_t cpy_len;
	dest_size--;
	cpy_len = (dest_size < src_len ? dest_size: src_len);

	memcpy(dest, src, cpy_len);

	dest[cpy_len] = '\0';

	return cpy_len;
}
/* }}} */

/* {{{ xcalloc */
static void *xcalloc(size_t nmemb, size_t size)
{
	void *retval;
	double v = ((double)size) * (int)(nmemb & (((size_t)-1) >> 1));

	if (v != nmemb * size) {
		return NULL;
	}

	retval = calloc(nmemb, size);

	return retval;
}
/* }}} */

/* {{{ xrealloc */
static void *xrealloc(void *ptr, size_t nmemb, size_t size)
{
	void *retval;
	size_t total = nmemb * size;

	if (((double)size) * (int)(nmemb & (((size_t)-1) >> 1)) != total) {
		return NULL;
	}

	retval = realloc(ptr, total);

	return retval;
}
/* }}} */

/* {{{ xstrdup */
static char *xstrdup(const char *ptr)
{
	size_t len = strlen(ptr) + sizeof(char);
	char *retval = xcalloc(sizeof(char), len);

	if (retval == NULL) {
		return NULL;
	}

	memcpy(retval, ptr, len);

	return retval;
}
/* }}} */

/* {{{ xfree */
static void xfree(void *ptr)
{
	if (ptr != NULL) {
		free(ptr);
	}
}
/* }}} */

/* {{{ xfree_overwrite */
static void xfree_overwrite(char *ptr)
{
	if (ptr != NULL) {
		char *p;
		for (p = ptr; *p != '\0'; p++) {
			*p = '\0';
		}
		free(ptr);
	}
}
/* }}} */

/* {{{ memspn */
static void *memspn(void *buf, size_t buf_len, const unsigned char *delims,
		size_t ndelims)
{
	unsigned char *buf_end = ((unsigned char *)buf) + buf_len;
	unsigned char *p;

	switch (ndelims) {
		case 0:
			return buf_end;

		case 1: {
			unsigned char c = delims[0];

			for (p = (unsigned char *)buf; p < buf_end; p++) {
				if (*p != c) {
					return (void *)p;
				}
			}
		} break;

		case 2: {
			unsigned char c1 = delims[0], c2 = delims[1];

			for (p = (unsigned char *)buf; p < buf_end; p++) {
				if (*p != c1 && *p != c2) {
					return (void *)p;
				}
			}
		} break;

		default: {
			const unsigned char *delims_end = delims + ndelims;
			unsigned char and_mask = ~0, or_mask = 0;
			const unsigned char *q;

			for (q = delims; q < delims_end; q++) {
				and_mask &= *q;
				or_mask |= *q;
			}

			for (p = (unsigned char *)buf; p < buf_end; p++) {
				if ((*p & and_mask) == and_mask && (*p & or_mask) != 0) {
					for (q = delims; *p != *q; q++) {
						if (q >= delims_end) {
							return (void *)p;
						}
					}
				}
			}
		} break;
	}

	return NULL;
}
/* }}} */

/* {{{ memcspn */
static void *memcspn(void *buf, size_t buf_len, const unsigned char *delims,
		size_t ndelims)
{
	if (ndelims == 1) {
		return memchr(buf, delims[0], buf_len);
	} else {
		unsigned char *buf_end = ((unsigned char *)buf) + buf_len;
		const unsigned char *delims_end = delims + ndelims;
		unsigned char *p;

		for (p = (unsigned char *)buf; p < buf_end; p++) {
			const unsigned char *q;

			for (q = delims; q < delims_end; q++) {
				if (*p == *q) {
					return (void *)p;
				}
			}
		}

		return NULL;
	}
}
/* }}} */

/* {{{ pam_mysql_md5_data
 * 
 * AFAIK, only FreeBSD has MD5Data() defined in md5.h
 * better MD5 support will appear in 0.5
 */
#ifdef HAVE_MD5DATA
#define HAVE_PAM_MYSQL_MD5_DATA
#define pam_mysql_md5_data MD5Data
#elif defined(HAVE_OPENSSL) || (defined(HAVE_SASL_MD5_H) && defined(USE_SASL_MD5)) || (!defined(HAVE_OPENSSL) && defined(HAVE_SOLARIS_MD5))
#if defined(USE_SASL_MD5)
static unsigned char *MD5(const unsigned char *d, unsigned int n,
		unsigned char *md)
{
	MD5_CTX ctx;

	_sasl_MD5Init(&ctx);

	_sasl_MD5Update(&ctx, (unsigned char *)d, n);

	_sasl_MD5Final(md, &ctx);

	return md;
}
#elif defined(USE_SOLARIS_MD5)
#define MD5(d, n, md) md5_calc(d, md, n)
#endif
#define HAVE_PAM_MYSQL_MD5_DATA
static char *pam_mysql_md5_data(const unsigned char *d, unsigned int sz, char *md)
{
	size_t i, j;
	unsigned char buf[16];

	if (md == NULL) {
		if ((md = xcalloc(32 + 1, sizeof(char))) == NULL) {
			return NULL;
		}
	}

	MD5(d, (unsigned long)sz, buf);

	for (i = 0, j = 0; i < 16; i++, j += 2) {
		md[j + 0] = "0123456789abcdef"[(int)(buf[i] >> 4)];
		md[j + 1] = "0123456789abcdef"[(int)(buf[i] & 0x0f)];
	}
	md[j] = '\0';

	return md;
}
#endif
/* }}} */

/* {{{ pam_mysql_sha1_data */
#if defined(HAVE_OPENSSL)
#define HAVE_PAM_MYSQL_SHA1_DATA
static char *pam_mysql_sha1_data(const unsigned char *d, unsigned int sz, char *md)
{
	size_t i, j;
	unsigned char buf[20];

	if (md == NULL) {
		if ((md = xcalloc(40 + 1, sizeof(char))) == NULL) {
			return NULL;
		}
	}

	SHA1(d, (unsigned long)sz, buf);

	for (i = 0, j = 0; i < 20; i++, j += 2) {
		md[j + 0] = "0123456789abcdef"[(int)(buf[i] >> 4)];
		md[j + 1] = "0123456789abcdef"[(int)(buf[i] & 0x0f)];
	}
	md[j] = '\0';

	return md;
}
#endif
/* }}} */

/* {{{ option handlers */
/* {{{ pam_mysql_string_opt_getter */
static pam_mysql_err_t pam_mysql_string_opt_getter(void *val, const char **pretval, int *to_release)
{
	*pretval = *(char **)val;
	*to_release = 0;

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_string_opt_setter */
static pam_mysql_err_t pam_mysql_string_opt_setter(void *val, const char *newval_str)
{
	if (*(char **)val != NULL) {
		xfree(*(char **)val);
	}

	if (NULL == (*(char **)val = xstrdup(newval_str))) {
		syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
		return PAM_MYSQL_ERR_ALLOC;
	}

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_boolean_opt_getter
 */
static pam_mysql_err_t pam_mysql_boolean_opt_getter(void *val, const char **pretval, int *to_release)
{
	*pretval = (*(int *)val ? "true": "false");
	*to_release = 0;

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_boolean_opt_setter */
static pam_mysql_err_t pam_mysql_boolean_opt_setter(void *val, const char *newval_str)
{
	*(int *)val = (strcmp(newval_str, "0") != 0 &&
			strcasecmp(newval_str, "N") != 0 &&
			strcasecmp(newval_str, "false") != 0 &&
			strcasecmp(newval_str, "no") != 0);
		
	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_crypt_opt_getter */
static pam_mysql_err_t pam_mysql_crypt_opt_getter(void *val, const char **pretval, int *to_release)
{
	switch (*(int *)val) {
		case 0:
			*pretval = "plain";
			break;

		case 1:
			*pretval = "Y";
			break;

		case 2:
			*pretval = "mysql";
			break;

		case 3:
			*pretval = "md5";
			break;

		case 4:
			*pretval = "sha1";
			break;

		default:
			*pretval = NULL;
	}

	*to_release = 0;

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_crypt_opt_setter */
static pam_mysql_err_t pam_mysql_crypt_opt_setter(void *val, const char *newval_str)
{
	if (strcmp(newval_str, "0") == 0 || strcasecmp(newval_str, "plain") == 0) {
		*(int *)val = 0;
		return PAM_MYSQL_ERR_SUCCESS;
	}

	if (strcmp(newval_str, "1") == 0 || strcasecmp(newval_str, "Y") == 0) {
		*(int *)val = 1;
		return PAM_MYSQL_ERR_SUCCESS;
	}

	if (strcmp(newval_str, "2") == 0 || strcasecmp(newval_str, "mysql") == 0) {
		*(int *)val = 2;
		return PAM_MYSQL_ERR_SUCCESS;
	}
	if (strcmp(newval_str, "3") == 0 || strcasecmp(newval_str, "md5") == 0) {
		*(int *)val = 3;
		return PAM_MYSQL_ERR_SUCCESS;
	}
	if (strcmp(newval_str, "4") == 0 || strcasecmp(newval_str, "sha1") == 0) {
		*(int *)val = 4;
		return PAM_MYSQL_ERR_SUCCESS;
	}

	*(int *)val = 0;

	return PAM_MYSQL_ERR_INVAL;
}
/* }}} */
/* }}} */

/* {{{ option definitions */
#define PAM_MYSQL_OFFSETOF(type, x) ((size_t)&((type *)0)->x)

#define PAM_MYSQL_DEF_OPTION(name, accr) PAM_MYSQL_DEF_OPTION2(name, name, accr)


#define PAM_MYSQL_DEF_OPTION2(name, sname, accr) \
	{ #name, sizeof(#name) - 1, PAM_MYSQL_OFFSETOF(pam_mysql_ctx_t, sname), accr }

static pam_mysql_option_accessor_t pam_mysql_string_opt_accr = {
	pam_mysql_string_opt_getter,
	pam_mysql_string_opt_setter
};

static pam_mysql_option_accessor_t pam_mysql_boolean_opt_accr = {
	pam_mysql_boolean_opt_getter,
	pam_mysql_boolean_opt_setter
};

static pam_mysql_option_accessor_t pam_mysql_crypt_opt_accr = {
	pam_mysql_crypt_opt_getter,
	pam_mysql_crypt_opt_setter
};

static pam_mysql_option_t options[] = {
	PAM_MYSQL_DEF_OPTION(host, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION(where, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION(db, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION(user, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION(passwd, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION(table, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION(update_table, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION(usercolumn, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION(passwdcolumn, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION(statcolumn, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION2(crypt, crypt_type, &pam_mysql_crypt_opt_accr),
	PAM_MYSQL_DEF_OPTION(md5, &pam_mysql_boolean_opt_accr),
	PAM_MYSQL_DEF_OPTION(sqllog, &pam_mysql_boolean_opt_accr),
	PAM_MYSQL_DEF_OPTION(verbose, &pam_mysql_boolean_opt_accr),
	PAM_MYSQL_DEF_OPTION(logtable, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION(logmsgcolumn, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION(logpidcolumn, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION(logusercolumn, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION(loghostcolumn, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION(logrhostcolumn, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION(logtimecolumn, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION(config_file, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION(use_323_passwd, &pam_mysql_boolean_opt_accr),
	PAM_MYSQL_DEF_OPTION(use_first_pass, &pam_mysql_boolean_opt_accr),
	PAM_MYSQL_DEF_OPTION(try_first_pass, &pam_mysql_boolean_opt_accr),
	PAM_MYSQL_DEF_OPTION(disconnect_every_op, &pam_mysql_boolean_opt_accr),
	PAM_MYSQL_DEF_OPTION2(debug, verbose, &pam_mysql_boolean_opt_accr),
	{ NULL, 0, 0, NULL }
};
/* }}} */

/* {{{ string functions */
/* {{{ pam_mysql_str_init() */
static pam_mysql_err_t pam_mysql_str_init(pam_mysql_str_t *str, int mangle)
{
	str->p = "";
	str->len = 0;
	str->alloc_size = 0;
	str->mangle = mangle;

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_str_destroy() */
static void pam_mysql_str_destroy(pam_mysql_str_t *str)
{
	if (str->alloc_size > 0) {
		if (str->mangle) {
			memset(str->p, 0, str->len);
		}
		xfree(str->p);
	}
}
/* }}} */

/* {{{ pam_mysql_str_reserve() */
static pam_mysql_err_t pam_mysql_str_reserve(pam_mysql_str_t *str, size_t len)
{
	size_t len_req;

	{
		len_req = str->len + len;
		if (len_req < str->len) {
			syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "integer overflow at " __FILE__ ":%d", __LINE__);
			return PAM_MYSQL_ERR_INVAL;
		}

		len_req += sizeof(char); // space for a string terminator
	}

	if (len_req >= str->alloc_size) {
		size_t cv = 0;
		size_t new_size = (str->alloc_size == 0 ? 1: str->alloc_size);
		char *new_buf;

		do {
			new_size *= 2;
			if (cv > new_size) {
				syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
				return PAM_MYSQL_ERR_ALLOC;		
			}
			cv = new_size;
		} while (new_size < len_req);

		if (str->mangle) {
			if (NULL == (new_buf = xcalloc(new_size, sizeof(char)))) {
				syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
				return PAM_MYSQL_ERR_ALLOC;		
			}

			memcpy(new_buf, str->p, str->len);
			memset(str->p, 0, str->len);
			if (str->alloc_size > 0) {
				xfree(str->p);
			}
		} else {
			if (str->alloc_size == 0) {
				if (NULL == (new_buf = xcalloc(new_size, sizeof(char)))) {
					syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
					return PAM_MYSQL_ERR_ALLOC;		
				}
			} else {
				if (NULL == (new_buf = xrealloc(str->p, new_size, sizeof(char)))) {
					syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
					return PAM_MYSQL_ERR_ALLOC;		
				}
			}
		}
		str->p = new_buf;
		str->alloc_size = new_size;
	}

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_str_append() */
static pam_mysql_err_t pam_mysql_str_append(pam_mysql_str_t *str,
		const char *s, size_t len)
{
	pam_mysql_err_t err;

	if ((err = pam_mysql_str_reserve(str, len))) {
		return err;
	}

	memcpy(str->p + str->len, s, len);
	str->len += len;
	str->p[str->len] = '\0';

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_str_append_char() */
static pam_mysql_err_t pam_mysql_str_append_char(pam_mysql_str_t *str, char c)
{
	return pam_mysql_str_append(str, &c, sizeof(c));
}
/* }}} */

/* {{{ pam_mysql_str_truncate() */
static pam_mysql_err_t pam_mysql_str_truncate(pam_mysql_str_t *str, size_t len)
{
	if (len > str->len) {
		return PAM_MYSQL_ERR_INVAL;
	}

	str->len = len;

	if (str->alloc_size != 0) {
		str->p[len] = '\0';
	}

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */
/* }}} */

/* {{{ stream functions */
/* {{{ pam_mysql_stream_open */
static pam_mysql_err_t pam_mysql_stream_open(pam_mysql_stream_t *stream,
		pam_mysql_ctx_t *ctx, const char *file)
{
	stream->buf_end = stream->buf_start = stream->buf_ptr = stream->buf[0];
	stream->pushback = NULL;
	stream->buf_in_use = 0;
	stream->eof = 0;

	if ((stream->fd = open(file, O_RDONLY)) == -1) {
		if (ctx->verbose) {
			switch (errno) {
				case EACCES:
				case EPERM:
					syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "access to %s not permitted", file);
					break;

				case EISDIR:
					syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "%s is directory", file);
					break;

#ifdef HAVE_ELOOP
				case ELOOP:
					syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "%s refers to an inresolvable symbolic link", file);
					break;
#endif

				case EMFILE:
					syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "too many opened files");
					break;

				case ENFILE:
					syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "too many opened files within this system");
					break;

				case ENOENT:
					syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "%s does not exist", file);
					break;

				case ENOMEM:
					syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "kernel resource exhausted");
					break;

#ifdef HAVE_EOVERFLOW
				case EOVERFLOW:
					syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "%s is too big", file);
					break;
#endif

				default:
					syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "unknown error while opening %s", file);
					break;
			}
		}

		return PAM_MYSQL_ERR_IO;
	}

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_stream_close */
static void pam_mysql_stream_close(pam_mysql_stream_t *stream)
{
	if (stream->fd != -1) {
		close(stream->fd);
	}
}
/* }}} */

/* {{{ pam_mysql_stream_getc */
static pam_mysql_err_t pam_mysql_stream_getc(pam_mysql_stream_t *stream,
		int *retval)
{
	if (stream->buf_ptr >= stream->buf_end) {
		ssize_t new_buf_len;
		unsigned char *new_buf = stream->buf[1 - stream->buf_in_use];

		if (stream->pushback != NULL) {
			stream->buf_end = stream->pushback;
			stream->pushback = NULL;
		} else {
			if (stream->eof) {
				return PAM_MYSQL_ERR_EOF;
			}

			if ((new_buf_len = read(stream->fd, new_buf, sizeof(stream->buf[0]))) == -1) {
				syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "I/O error");
				return PAM_MYSQL_ERR_IO;
			}

			if (new_buf_len == 0) {
				stream->eof = 1;
				return PAM_MYSQL_ERR_EOF;
			}

			stream->buf_end = new_buf + new_buf_len;
		}

		stream->buf_start = stream->buf_ptr = new_buf;
		stream->buf_in_use = 1 - stream->buf_in_use;
	}

	*retval = *(stream->buf_ptr++);

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_stream_ungetc */
static pam_mysql_err_t pam_mysql_stream_ungetc(pam_mysql_stream_t *stream, int c)
{
	if (stream->buf_ptr == stream->buf_start) {
		if (stream->pushback != NULL) {
			return PAM_MYSQL_ERR_IO;
		}

		stream->pushback = stream->buf_end;
		stream->buf_in_use = 1 - stream->buf_in_use;
		stream->buf_start = stream->buf[stream->buf_in_use];
		stream->buf_ptr = stream->buf_start + sizeof(stream->buf[0]);
	}

	*(--stream->buf_ptr) = c;

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_stream_skip_spn */
static pam_mysql_err_t pam_mysql_stream_skip_spn(pam_mysql_stream_t *stream,
		const char *accept_cset, size_t naccepts)
{
	unsigned char *p;

	if (stream->eof) {
		return PAM_MYSQL_ERR_EOF;
	}

	if ((p = (unsigned char *)memspn(stream->buf_ptr,
			stream->buf_end - stream->buf_ptr, (const unsigned char *)accept_cset,
			naccepts)) != NULL) {
		stream->buf_ptr = p;

		return PAM_MYSQL_ERR_SUCCESS;
	}

	if (stream->pushback != NULL) {
		stream->buf_in_use = 1 - stream->buf_in_use;
		stream->buf_start = stream->buf_ptr = stream->buf[stream->buf_in_use];
		stream->buf_end = stream->pushback;
		stream->pushback = NULL;

		if ((p = (unsigned char *)memspn(stream->buf_ptr,
				stream->buf_end - stream->buf_ptr, (const unsigned char *)accept_cset,
				naccepts)) != NULL) {
			stream->buf_ptr = p;

			return PAM_MYSQL_ERR_SUCCESS;
		}
	}

	for (;;) {
		ssize_t new_buf_len;

		if ((new_buf_len = read(stream->fd, stream->buf_start, sizeof(stream->buf[0]))) == -1) {
			syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "I/O error");
			return PAM_MYSQL_ERR_IO;
		}

		if (new_buf_len == 0) {
			stream->eof = 1;
			return PAM_MYSQL_ERR_EOF;
		}

		stream->buf_end = stream->buf_start + new_buf_len;

		if ((p = (unsigned char *)memspn(stream->buf_start, new_buf_len,
				(const unsigned char *)accept_cset, naccepts)) != NULL) {
			stream->buf_ptr = p;

			break;
		}
	}

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_stream_read_cspn */
static pam_mysql_err_t pam_mysql_stream_read_cspn(pam_mysql_stream_t *stream,
		pam_mysql_str_t *append_to, int *found_delim, const char *delims,
		size_t ndelims)
{
	pam_mysql_err_t err;
	unsigned char *p;
	ssize_t len;
	size_t rem_len;

	if (stream->eof) {
		return PAM_MYSQL_ERR_EOF;
	}

	if ((p = (unsigned char *)memcspn(stream->buf_ptr,
			stream->buf_end - stream->buf_ptr, (const unsigned char *)delims,
			ndelims)) != NULL) {
		if ((err = pam_mysql_str_append(append_to, (char *)stream->buf_ptr,
				p - stream->buf_ptr))) {
			return err;
		}

		*found_delim = *p;
		stream->buf_ptr = p;

		return PAM_MYSQL_ERR_SUCCESS;
	}

	if ((err = pam_mysql_str_append(append_to, (char *)stream->buf_ptr,
			stream->buf_end - stream->buf_ptr))) {
		return err;
	}

	if (stream->pushback != NULL) {
		stream->buf_in_use = 1 - stream->buf_in_use;
		stream->buf_start = stream->buf_ptr = stream->buf[stream->buf_in_use];
		stream->buf_end = stream->pushback;
		stream->pushback = NULL;

		if ((p = (unsigned char *)memcspn(stream->buf_ptr,
				stream->buf_end - stream->buf_ptr,
				(const unsigned char *)delims, ndelims)) != NULL) {
			if ((err = pam_mysql_str_append(append_to, (char *)stream->buf_ptr,
					p - stream->buf_ptr))) {
				return err;
			}

			*found_delim = *p;
			stream->buf_ptr = p;

			return PAM_MYSQL_ERR_SUCCESS;
		}

		if ((err = pam_mysql_str_append(append_to, (char *)stream->buf_ptr,
					stream->buf_end - stream->buf_ptr))) {
			return err;
		}
	}

	rem_len = 0;

	for (;;) {
		unsigned char *block;

		if ((err = pam_mysql_str_reserve(append_to,
				sizeof(stream->buf[0]) - rem_len))) {
			return err;
		}

		block = (unsigned char*)append_to->p + append_to->len;

		if ((len = read(stream->fd, block, sizeof(stream->buf[0]))) == -1) {
			syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "I/O error");
			return PAM_MYSQL_ERR_IO;
		}

		if (len == 0) {
			stream->eof = 1;
			return PAM_MYSQL_ERR_EOF;
		}

		if ((p = (unsigned char *)memcspn(block, len,
				(const unsigned char *)delims, ndelims)) != NULL) {
			size_t new_buf_len;

			append_to->len += p - block;
			new_buf_len = len - (p - block);

			memcpy(stream->buf_start, p, new_buf_len);

			stream->buf_ptr = stream->buf_start;
			stream->buf_end = stream->buf_start + new_buf_len;

			break;
		}

		append_to->len += len;
		rem_len = sizeof(stream->buf[0]) - len;
	}

	*found_delim = *p;
	append_to->p[append_to->len] = '\0';

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */
/* }}} */

/* {{{ config file scanner / parser */
static const char * pam_mysql_config_token_name[] = {
	"=",
	"<NEWLINE>",
	"<STRING_LITERAL>",
	";",
	"<COMMENT>",
	NULL
};

/* {{{ pam_mysql_config_scanner_init */
static pam_mysql_err_t pam_mysql_config_scanner_init(
		pam_mysql_config_scanner_t *scanner, pam_mysql_ctx_t *ctx,
		pam_mysql_stream_t *stream)
{
	pam_mysql_err_t err;

	if ((err = pam_mysql_str_init(&scanner->image, 1))) {
		return err;
	}

	scanner->ctx = ctx;
	scanner->stream = stream;
	scanner->state = 0;

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_config_scanner_destroy */
static void pam_mysql_config_scanner_destroy(
		pam_mysql_config_scanner_t *scanner)
{
	pam_mysql_str_destroy(&scanner->image);
}
/* }}} */

/* {{{ pam_mysql_config_scanner_next_token */
static pam_mysql_err_t pam_mysql_config_scanner_next_token(
		pam_mysql_config_scanner_t *scanner)
{
	pam_mysql_err_t err;
	int c;

	switch (scanner->state) {
		case 0:
			if ((err = pam_mysql_str_truncate(&scanner->image, 0))) {
				return err;
			}

			if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
				return err;
			}

			if (c == '#') {
				if ((err = pam_mysql_str_append_char(&scanner->image, c))) {
					return err;
				}

				if ((err = pam_mysql_stream_read_cspn(scanner->stream,
						&scanner->image, &c, "\n\r", sizeof("\n\r") - 1))) {
					return err;
				}

				scanner->token = PAM_MYSQL_CONFIG_TOKEN_COMMENT;

				if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
					return err;
				}

				if (c == '\r') {
					if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
						return err;
					}
	
					if (c != '\n') {
						if ((err = pam_mysql_stream_ungetc(scanner->stream, c))) {
							return err;
						}
					}
				}
				break;
			} else {
				if ((err = pam_mysql_stream_ungetc(scanner->stream, c))) {
					return err;
				}
			}

		case 1:
			if ((err = pam_mysql_stream_skip_spn(scanner->stream,
					" \t", sizeof(" \t") - 1))) {
				return err;
			}

			if ((err = pam_mysql_str_truncate(&scanner->image, 0))) {
				return err;
			}

			if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
				return err;
			}

			if ((err = pam_mysql_str_append_char(&scanner->image, c))) {
				return err;
			}

			switch (scanner->image.p[0]) {
				case '=':
					scanner->token = PAM_MYSQL_CONFIG_TOKEN_EQUAL;
					scanner->state = 2;
					break;

				case ';':
					scanner->token = PAM_MYSQL_CONFIG_TOKEN_SEMICOLON;
					scanner->state = 1;
					break;

				default:
					if ((err = pam_mysql_stream_read_cspn(scanner->stream,
							&scanner->image, &c, "=; \t\n\r", sizeof("=; \t\n\r") - 1))) {
						return err;
					}
					scanner->token = PAM_MYSQL_CONFIG_TOKEN_STRING;
					scanner->state = 1;
					break;

				case '\r':
					if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
						return err;
					}

					if (c != '\n') {
						if ((err = pam_mysql_stream_ungetc(scanner->stream, c))) {
							return err;
						}
					} else {
						if ((err = pam_mysql_str_append_char(&scanner->image, c))) {
							return err;
						}
					}

					scanner->token = PAM_MYSQL_CONFIG_TOKEN_NEWLINE;
					scanner->state = 0;
					break;

				case '\n':
					scanner->token = PAM_MYSQL_CONFIG_TOKEN_NEWLINE;
					scanner->state = 0;
					break;
			}
			break;

		case 2:
			if ((err = pam_mysql_stream_skip_spn(scanner->stream,
					" \t", sizeof(" \t") - 1))) {
				return err;
			}

			if ((err = pam_mysql_str_truncate(&scanner->image, 0))) {
				return err;
			}

			if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
				return err;
			}

			if ((err = pam_mysql_str_append_char(&scanner->image, c))) {
				return err;
			}

			switch (scanner->image.p[0]) {
				case ';':
					scanner->token = PAM_MYSQL_CONFIG_TOKEN_SEMICOLON;
					scanner->state = 1;
					break;

				default:
					if ((err = pam_mysql_stream_read_cspn(scanner->stream,
							&scanner->image, &c, ";\n\r", sizeof(";\n\r") - 1))) {
						return err;
					}
					scanner->token = PAM_MYSQL_CONFIG_TOKEN_STRING;
					break;

				case '\r':
					if ((err = pam_mysql_stream_getc(scanner->stream, &c))) {
						return err;
					}

					if (c != '\n') {
						if ((err = pam_mysql_stream_ungetc(scanner->stream, c))) {
							return err;
						}
					} else {
						if ((err = pam_mysql_str_append_char(&scanner->image, c))) {
							return err;
						}
					}

					scanner->token = PAM_MYSQL_CONFIG_TOKEN_NEWLINE;
					scanner->state = 0;
					break;

				case '\n':
					scanner->token = PAM_MYSQL_CONFIG_TOKEN_NEWLINE;
					scanner->state = 0;
					break;
			}
			break;
	}

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_config_parser_init */
static pam_mysql_err_t pam_mysql_config_parser_init(
		pam_mysql_config_parser_t *parser, pam_mysql_ctx_t *ctx,
		pam_mysql_entry_handler_t *hdlr)
{
	parser->ctx = ctx;
	parser->hdlr = hdlr;

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_config_parser_destroy */
static void pam_mysql_config_parser_destroy(pam_mysql_config_parser_t *parser)
{
	/* do nothing */
}
/* }}} */

/* {{{ pam_mysql_config_parser_parse */
static pam_mysql_err_t pam_mysql_config_parser_parse(
		pam_mysql_config_parser_t *parser, pam_mysql_stream_t *stream)
{
	pam_mysql_err_t err;
	pam_mysql_config_scanner_t scanner;
	char *name = NULL;
	size_t name_len = 0;
	char *value = NULL;
	size_t value_len = 0;

	int state = 0;
	int line_num = 1;

	if ((err = pam_mysql_config_scanner_init(&scanner, parser->ctx, stream))) {
		return err;
	}

	while (!(err = pam_mysql_config_scanner_next_token(&scanner))) {
		switch (state) {
			case 0:
				switch (scanner.token) {
					case PAM_MYSQL_CONFIG_TOKEN_STRING:
						if (name == NULL || name_len < scanner.image.len) {
							char *new_buf;

							if (NULL == (new_buf = xrealloc(name,
									scanner.image.len + 1, sizeof(char)))) {
								syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
								err = PAM_MYSQL_ERR_ALLOC;
								goto out;
							}

							name = new_buf;
						}

						memcpy(name, scanner.image.p, scanner.image.len + 1);
						name_len = scanner.image.len;

						state = 1;
						break;

					case PAM_MYSQL_CONFIG_TOKEN_NEWLINE:
						line_num++;
						break;

					case PAM_MYSQL_CONFIG_TOKEN_COMMENT:
						line_num++;
						break;

					default:
						err = PAM_MYSQL_ERR_SYNTAX;
						goto out;
				}
				break;

			case 1:
				switch (scanner.token) {
					case PAM_MYSQL_CONFIG_TOKEN_EQUAL:
						state = 2;
						break;

					default:
						err = PAM_MYSQL_ERR_SYNTAX;
						goto out;
				}
				break;

			case 2:
				switch (scanner.token) {
					case PAM_MYSQL_CONFIG_TOKEN_SEMICOLON:
						if (parser->hdlr &&
								(err = parser->hdlr->handle_entry_fn(
										parser->hdlr, line_num, name, name_len,
										"", 0))) {
							goto out;
						}
						state = 4;
						break;

					case PAM_MYSQL_CONFIG_TOKEN_NEWLINE:
						if (parser->hdlr &&
								(err = parser->hdlr->handle_entry_fn(
										parser->hdlr, line_num, name, name_len,
										"", 0))) {
							goto out;
						}
						line_num++;
						state = 0;
						break;

					case PAM_MYSQL_CONFIG_TOKEN_STRING:
						if (value == NULL || value_len < scanner.image.len) {
							char *new_buf;

							if (NULL == (new_buf = xrealloc(value,
									scanner.image.len + 1, sizeof(char)))) {
								syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
								err = PAM_MYSQL_ERR_ALLOC;
								goto out;
							}

							value = new_buf;
						}

						memcpy(value, scanner.image.p, scanner.image.len + 1);
						value_len = scanner.image.len;

						if (parser->hdlr &&
								(err = parser->hdlr->handle_entry_fn(
										parser->hdlr, line_num, name, name_len,
										value, value_len))) {
							goto out;
						}
						state = 3;
						break;

					default:
						err = PAM_MYSQL_ERR_SYNTAX;
						goto out;
				}
				break;

			case 3:
				switch (scanner.token) {
					case PAM_MYSQL_CONFIG_TOKEN_SEMICOLON:
						state = 4;
						break;

					case PAM_MYSQL_CONFIG_TOKEN_NEWLINE:
						line_num++;
						state = 0;
						break;

					default:
						err = PAM_MYSQL_ERR_SYNTAX;
						goto out;
				}
				break;

			case 4:
				switch (scanner.token) {
					case PAM_MYSQL_CONFIG_TOKEN_NEWLINE:
						line_num++;
						state = 0;
						break;

					default:
						err = PAM_MYSQL_ERR_SYNTAX;
						goto out;
				}
				break;
		}
	}

	if (err == PAM_MYSQL_ERR_EOF) {
		err = PAM_MYSQL_ERR_SUCCESS;
	}

out:
	if (err == PAM_MYSQL_ERR_SYNTAX) {
		if (parser->ctx->verbose) {
			syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "unexpected token %s on line %d\n",
					pam_mysql_config_token_name[scanner.token],
					line_num);
		}
	}

	if (name != NULL) {
		xfree(name);
	}

	if (value != NULL) {
		xfree(value);
	}

	pam_mysql_config_scanner_destroy(&scanner);

	return err;
}
/* }}} */
/* }}} */

/* {{{ pam_mysql_find_option()
 */
pam_mysql_option_t *pam_mysql_find_option(pam_mysql_option_t *options,
		const char *name, size_t name_len)
{
	/* set the various ctx */
	pam_mysql_option_t *retval;

	for (retval = options; retval->name != NULL; retval++) {
		if (retval->name_len == name_len &&
				memcmp(retval->name, name, name_len) == 0) {
			return retval;
		}
	}

	return NULL;
}
/* }}} */

/* {{{ entry handler */
static pam_mysql_option_t pam_mysql_entry_handler_options[] = {
	PAM_MYSQL_DEF_OPTION2(users.host, host, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION2(users.database, db, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION2(users.db_user, user, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION2(users.db_passwd, passwd, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION2(users.where_clause, where, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION2(users.table, table, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION2(users.update_table, update_table, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION2(users.user_column, usercolumn, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION2(users.password_column, passwdcolumn, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION2(users.status_column, statcolumn, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION2(users.password_crypt, crypt_type, &pam_mysql_crypt_opt_accr),
	PAM_MYSQL_DEF_OPTION2(users.use_md5, md5, &pam_mysql_boolean_opt_accr),
	PAM_MYSQL_DEF_OPTION2(verbose, verbose, &pam_mysql_boolean_opt_accr),
	PAM_MYSQL_DEF_OPTION2(log.enabled, sqllog, &pam_mysql_boolean_opt_accr),
	PAM_MYSQL_DEF_OPTION2(log.table, logtable, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION2(log.message_column, logmsgcolumn, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION2(log.pid_column, logpidcolumn, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION2(log.user_column, logusercolumn, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION2(log.host_column, loghostcolumn, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION2(log.rhost_column, logrhostcolumn, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION2(log.time_column, logtimecolumn, &pam_mysql_string_opt_accr),
	PAM_MYSQL_DEF_OPTION2(users.use_323_password, use_323_passwd, &pam_mysql_boolean_opt_accr),
	PAM_MYSQL_DEF_OPTION2(users.disconnect_every_operation, disconnect_every_op, &pam_mysql_boolean_opt_accr),
	{ NULL, 0, 0, NULL }
};

/* {{{ pam_mysql_handle_entry */
static pam_mysql_err_t pam_mysql_handle_entry(
		pam_mysql_entry_handler_t *hdlr, int line_num, const char *name,
		size_t name_len, const char *value, size_t value_len)
{
	pam_mysql_err_t err;
	pam_mysql_option_t *opt = pam_mysql_find_option(hdlr->options, name,
			name_len);

	if (opt == NULL) {
		if (hdlr->ctx->verbose) {
			char buf[1024];
			strnncpy(buf, sizeof(buf), name, name_len);
			syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "unknown option %s on line %d", buf, line_num);
		}

		return PAM_MYSQL_ERR_SUCCESS;
	}

	err = opt->accessor->set_op((void*)((char *)hdlr->ctx + opt->offset), value);
	if (!err && hdlr->ctx->verbose) {
		char buf[1024];
		strnncpy(buf, sizeof(buf), name, name_len);
		syslog(LOG_AUTHPRIV | LOG_INFO, PAM_MYSQL_LOG_PREFIX "option %s is set to \"%s\"", buf, value);
	}

	return err;
}
/* }}} */

/* {{{ pam_mysql_entry_handler_init */
static pam_mysql_err_t pam_mysql_entry_handler_init(
		pam_mysql_entry_handler_t *hdlr, pam_mysql_ctx_t *ctx)
{
	hdlr->handle_entry_fn = pam_mysql_handle_entry;
	hdlr->ctx = ctx;
	hdlr->options = pam_mysql_entry_handler_options;

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_entry_handler_destroy */
static void pam_mysql_entry_handler_destroy(
		pam_mysql_entry_handler_t *hdlr)
{
	/* do nothing */
}
/* }}} */
/* }}} */

// {{{ pam_mysql_get_host_info
static pam_mysql_err_t pam_mysql_get_host_info(pam_mysql_ctx_t *ctx,
		const char **pretval)
{
	char hostname[MAXHOSTNAMELEN + 1];
	char *retval;

	if (ctx->my_host_info) {
		*pretval = ctx->my_host_info;
		return PAM_MYSQL_ERR_SUCCESS;
	}

	if (gethostname(hostname, sizeof(hostname))) {
		return PAM_MYSQL_ERR_UNKNOWN;
	}
#ifdef HAVE_GETADDRINFO
	{
		struct addrinfo *ainfo = NULL;
		static const struct addrinfo hint = {
			AI_CANONNAME, PF_INET, 0, 0, 0, NULL, NULL, NULL
		};

		switch (getaddrinfo(hostname, NULL, &hint, &ainfo)) {
			case 0:
				break;

			case EAI_MEMORY:
				return PAM_MYSQL_ERR_ALLOC;

			default:
				return PAM_MYSQL_ERR_UNKNOWN;
		}

		switch (ainfo->ai_family) {
			case AF_INET:
				if (NULL == (retval = xcalloc(INET_ADDRSTRLEN, sizeof(char)))) {
					syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
					freeaddrinfo(ainfo);
					return PAM_MYSQL_ERR_ALLOC;
				}

				if (!inet_ntop(AF_INET,
						&((struct sockaddr_in *)ainfo->ai_addr)->sin_addr,
						retval, INET_ADDRSTRLEN)) {
					xfree(retval);
					freeaddrinfo(ainfo);
					return PAM_MYSQL_ERR_UNKNOWN;
				}
				break;
#ifdef HAVE_IPV6
			case AF_INET6:
				if (NULL == (retval = xcalloc(INET6_ADDRSTRLEN,sizeof(char)))) {
					syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
					freeaddrinfo(ainfo);
					return PAM_MYSQL_ERR_ALLOC;
				}

				if (!inet_ntop(AF_INET6,
						&((struct sockaddr_in6 *)ainfo->ai_addr)->sin6_addr,
						retval, INET6_ADDRSTRLEN)) {
					xfree(retval);
					freeaddrinfo(ainfo);
					return PAM_MYSQL_ERR_UNKNOWN;
				}
				break;
#endif /* HAVE_IPV6 */
			default:
				freeaddrinfo(ainfo);
				return PAM_MYSQL_ERR_NOTIMPL;
		}

		freeaddrinfo(ainfo);
	}
#else
	{
		struct hostent *hent = NULL;
		struct hostent *tmp;
		size_t hent_size = sizeof(struct hostent) + 64;
		int herr = 0;

#if defined(HAVE_SUNOS_GETHOSTBYNAME_R)
		for (;;) {
			if (NULL == (tmp = xrealloc(hent, hent_size, sizeof(char)))) {
				syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);

				if (hent != NULL) {
					xfree(hent);
				}

				return PAM_MYSQL_ERR_ALLOC;
			}

			hent = tmp;

			if (gethostbyname_r(hostname, hent,
					(char *)hent + sizeof(struct hostent),
					hent_size - sizeof(struct hostent), &herr) != NULL) {
				break;
			}

			if (errno != ERANGE) {
				xfree(hent);
				return PAM_MYSQL_ERR_UNKNOWN;
			}

			if (hent_size + 32 < hent_size) {
				syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
				xfree(hent);
				return PAM_MYSQL_ERR_ALLOC;
			}

			hent_size += 32;
		}
#elif defined(HAVE_GNU_GETHOSTBYNAME_R)
		for (;;) {
			if (NULL == (tmp = xrealloc(hent, hent_size, sizeof(char)))) {
				syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);

				if (hent != NULL) {
					xfree(hent);
				}

				return PAM_MYSQL_ERR_ALLOC;
			}

			hent = tmp;

			if (!gethostbyname_r(hostname, hent,
					(char *)hent + sizeof(struct hostent),
					hent_size - sizeof(struct hostent), &tmp, &herr)) {
				break;
			}

			if (errno != ERANGE) {
				xfree(hent);
				return PAM_MYSQL_ERR_UNKNOWN;
			}

			if (hent_size + 32 < hent_size) {
				syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
				xfree(hent);
				return PAM_MYSQL_ERR_ALLOC;
			}

			hent_size += 32;
		}
#else
		return PAM_MYSQL_ERR_NOTIMPL;
#endif

		switch (hent->h_addrtype) {
			case AF_INET:
				if (NULL == (retval = xcalloc(INET_ADDRSTRLEN, sizeof(char)))) {
					syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
					xfree(hent);	
					return PAM_MYSQL_ERR_ALLOC;
				}

				if (!inet_ntop(AF_INET, hent->h_addr_list[0], retval,
							INET_ADDRSTRLEN)) {
					xfree(retval);
					xfree(hent);
					return PAM_MYSQL_ERR_UNKNOWN;
				}
				break;
#ifdef HAVE_IPV6
			case AF_INET6:
				if (NULL == (retval = xcalloc(INET6_ADDRSTRLEN,sizeof(char)))) {
					syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
					xfree(hent);
					return PAM_MYSQL_ERR_ALLOC;
				}

				if (!inet_ntop(AF_INET6, hent->h_addr_list[0], retval,
							INET6_ADDRSTRLEN)) {
					xfree(retval);
					xfree(hent);
					return PAM_MYSQL_ERR_UNKNOWN;
				}
				break;
#endif /* HAVE_IPV6 */
			default:
				xfree(hent);
				return PAM_MYSQL_ERR_NOTIMPL;
		}

		xfree(hent);
	}
#endif /* HAVE_GETADDRINFO */

	*pretval = ctx->my_host_info = retval;

	return PAM_MYSQL_ERR_SUCCESS;
}

/* {{{ pam_mysql_init_ctx()
 */
static pam_mysql_err_t pam_mysql_init_ctx(pam_mysql_ctx_t *ctx)
{
	ctx->mysql_hdl = NULL;
	ctx->host = NULL;
	ctx->where = NULL;
	ctx->db = NULL;
	ctx->user = NULL;
	ctx->passwd = NULL;
	ctx->table = NULL;
	ctx->update_table =NULL;
	ctx->usercolumn = NULL;
	ctx->passwdcolumn = NULL;
	ctx->statcolumn = xstrdup("0");
	ctx->crypt_type = 0;
	ctx->use_323_passwd = 0;
	ctx->md5 = -1;
	ctx->sqllog = 0;
	ctx->verbose = 0;
	ctx->use_first_pass = 0;
	ctx->try_first_pass = 1;
	ctx->disconnect_every_op = 0;
	ctx->logtable = NULL;
	ctx->logmsgcolumn = NULL;
	ctx->logpidcolumn = NULL;
	ctx->logusercolumn = NULL;
	ctx->loghostcolumn = NULL;
	ctx->logrhostcolumn = NULL;
	ctx->logtimecolumn = NULL;
	ctx->config_file = NULL;
	ctx->my_host_info = NULL;

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_destroy_ctx() */
static void pam_mysql_destroy_ctx(pam_mysql_ctx_t *ctx)
{
	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_destroy_ctx() called.");
	}

	pam_mysql_close_db(ctx);

	xfree(ctx->host);
	ctx->host = NULL;

	xfree(ctx->where);
	ctx->where = NULL;

	xfree(ctx->db);
	ctx->db = NULL;

	xfree(ctx->user);
	ctx->user = NULL;

	xfree(ctx->passwd);
	ctx->passwd = NULL;

	xfree(ctx->table);
	ctx->table = NULL;

	xfree(ctx->update_table);
	ctx->update_table = NULL;

	xfree(ctx->usercolumn);
	ctx->usercolumn = NULL;

	xfree(ctx->passwdcolumn);
	ctx->passwdcolumn = NULL;

	xfree(ctx->statcolumn);
	ctx->statcolumn = NULL;

	xfree(ctx->logtable);
	ctx->logtable = NULL;

	xfree(ctx->logmsgcolumn);
	ctx->logmsgcolumn = NULL;

	xfree(ctx->logpidcolumn);
	ctx->logpidcolumn = NULL;

	xfree(ctx->logusercolumn);
	ctx->logusercolumn = NULL;

	xfree(ctx->loghostcolumn);
	ctx->loghostcolumn = NULL;

	xfree(ctx->logrhostcolumn);
	ctx->logrhostcolumn = NULL;

	xfree(ctx->logtimecolumn);
	ctx->logtimecolumn = NULL;

	xfree(ctx->config_file);
	ctx->config_file = NULL;

	xfree(ctx->my_host_info);
	ctx->my_host_info = NULL;
}
/* }}} */

/* {{{ pam_mysql_release_ctx() */
static void pam_mysql_release_ctx(pam_mysql_ctx_t *ctx)
{
	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_release_ctx() called.");
	}

	if (ctx != NULL) {
		pam_mysql_destroy_ctx(ctx);
		xfree(ctx);
	}
}
/* }}} */

/* {{{ pam_mysql_cleanup_hdlr() */
static void pam_mysql_cleanup_hdlr(pam_handle_t *pamh, void * voiddata, int status)
{
    pam_mysql_release_ctx((pam_mysql_ctx_t*)voiddata);
}
/* }}} */

/* {{{ pam_mysql_retrieve_ctx()
*/
pam_mysql_err_t pam_mysql_retrieve_ctx(pam_mysql_ctx_t **pretval, pam_handle_t *pamh)
{
	pam_mysql_err_t err;

	switch (pam_get_data(pamh, PAM_MODULE_NAME,
				(PAM_GET_DATA_CONST void**)pretval)) {
		case PAM_NO_MODULE_DATA:
			*pretval = NULL;
			break;

		case PAM_SUCCESS:
			break;

		default:
			return PAM_MYSQL_ERR_UNKNOWN;
	}

	if (*pretval == NULL) {
		/* allocate global data space */
		if (NULL == (*pretval = (pam_mysql_ctx_t*)xcalloc(1, sizeof(pam_mysql_ctx_t)))) {
			syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
			return PAM_MYSQL_ERR_ALLOC;
		}
		
		/* give the data back to PAM for management */
		if (pam_set_data(pamh, PAM_MODULE_NAME, (void*)*pretval, pam_mysql_cleanup_hdlr)) {
			syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "failed to set context to PAM at " __FILE__ ":%d", __LINE__);
			xfree(*pretval);
			*pretval = NULL;
			return PAM_MYSQL_ERR_UNKNOWN;
		}

		if ((err = pam_mysql_init_ctx(*pretval))) {
			syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "cannot initialize context at " __FILE__ ":%d", __LINE__);
			pam_mysql_destroy_ctx(*pretval);
			xfree(*pretval);
			*pretval = NULL;
			return err;
		}
	}

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_set_option()
 */
pam_mysql_err_t pam_mysql_set_option(pam_mysql_ctx_t *ctx, const char *name, size_t name_len, const char *val)
{
	pam_mysql_option_t *opt = pam_mysql_find_option(options, name, name_len);

	if (opt == NULL) {
		if (ctx->verbose) {
			char buf[1024];
			strnncpy(buf, sizeof(buf), name, name_len);
			syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "unknown option: %s", buf);
		}

		return PAM_MYSQL_ERR_NO_ENTRY;
	}

	return opt->accessor->set_op((void *)((char *)ctx + opt->offset), val);
}
/* }}} */

/* {{{ pam_mysql_get_option()
 */
pam_mysql_err_t pam_mysql_get_option(pam_mysql_ctx_t *ctx, const char **pretval, int *to_release, const char *name, size_t name_len)
{
	pam_mysql_option_t *opt = pam_mysql_find_option(options, name, name_len);

	if (opt == NULL) {
		if (ctx->verbose) {
			char buf[1024];
			strnncpy(buf, sizeof(buf), name, name_len);
			syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "unknown option: %s", buf);
		}

		return PAM_MYSQL_ERR_NO_ENTRY;
	}

	return opt->accessor->get_op((void *)((char *)ctx + opt->offset), pretval, to_release);
}
/* }}} */

/* {{{ pam_mysql_parse_args()
 */
pam_mysql_err_t pam_mysql_parse_args(pam_mysql_ctx_t *ctx, int argc, const char **argv)
{
	pam_mysql_err_t err;
	int param_changed = 0;
	char *value = NULL;
	int  i;
 
	/* process all the arguments */
	for (i = 0; i < argc; i++) {
		const char *name = argv[i];
		size_t name_len;

		if ((value = strchr(name, '=')) != NULL) {
			name_len = (size_t)(value - name);
			value++; /* get past the '=' */
		} else {
			name_len = strlen(name);
			value = "";
		}

		err = pam_mysql_set_option(ctx, name, name_len, value);
		if (err == PAM_MYSQL_ERR_NO_ENTRY) {
			continue;
		} else if (err) {
			return err;
		}

		param_changed = 1;

		if (ctx->verbose) {
			char buf[1024];
			strnncpy(buf, sizeof(buf), name, name_len);
			syslog(LOG_AUTHPRIV | LOG_INFO, PAM_MYSQL_LOG_PREFIX "option %s is set to \"%s\"", buf, value);
		}
	}	

	/* close the database in case we get new args */
	if (param_changed) {
		pam_mysql_close_db(ctx);
	}

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_read_config_file() */
static pam_mysql_err_t pam_mysql_read_config_file(pam_mysql_ctx_t *ctx,
		const char *path)
{
	pam_mysql_err_t err;
	pam_mysql_entry_handler_t handler;
	pam_mysql_config_parser_t parser;
	pam_mysql_stream_t stream;
	

	if ((err = pam_mysql_entry_handler_init(&handler, ctx))) {
		return err;
	}

	if ((err = pam_mysql_stream_open(&stream, ctx, path))) {
		pam_mysql_entry_handler_destroy(&handler);
		return err;
	}

	if ((err = pam_mysql_config_parser_init(&parser, ctx, &handler))) {
		pam_mysql_stream_close(&stream);
		pam_mysql_entry_handler_destroy(&handler);
		return err;
	}

	err = pam_mysql_config_parser_parse(&parser, &stream);

	pam_mysql_config_parser_destroy(&parser);
	pam_mysql_stream_close(&stream);
	pam_mysql_entry_handler_destroy(&handler);

	return err;
}
/* }}} */

/* {{{ pam_mysql_open_db()
 */
static pam_mysql_err_t pam_mysql_open_db(pam_mysql_ctx_t *ctx)
{
	pam_mysql_err_t err;
	char *host = NULL;
	char *socket = NULL;
	int port = 0;

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_open_db() called.");
	}

	if (ctx->mysql_hdl != NULL) {
		return PAM_MYSQL_ERR_BUSY;
	}

	if (NULL == (ctx->mysql_hdl = xcalloc(1, sizeof(MYSQL)))) {
		syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
		return PAM_MYSQL_ERR_ALLOC;
	}

	if (ctx->user == NULL) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "required option \"user\" is not set");
		return PAM_MYSQL_ERR_INVAL;
	}

	if (ctx->db == NULL) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "required option \"db\" is not set");
		return PAM_MYSQL_ERR_INVAL;
	}

	if (ctx->host != NULL) {
		if (ctx->host[0] == '/') {
			host = NULL;
			socket = ctx->host;
		} else {
			char *p;

			if ((p = strchr(ctx->host, ':')) != NULL) {
				size_t len = (size_t)(p - ctx->host);

				if (NULL == (host = xcalloc(len + 1, sizeof(char)))) {
					syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
					return PAM_MYSQL_ERR_ALLOC;
				}
				memcpy(host, ctx->host, len);
				host[len] = '\0';
				port = strtol(p + 1, NULL, 10);
			} else {
				host = ctx->host;
			}
			socket = NULL;
		}
	}

	if (NULL == mysql_init(ctx->mysql_hdl)) {
		err = PAM_MYSQL_ERR_ALLOC;
		goto out;
	}

	if (NULL == mysql_real_connect(ctx->mysql_hdl, host,
					ctx->user, (ctx->passwd == NULL ? "": ctx->passwd),
					ctx->db, port, socket, 0)) {
		err = PAM_MYSQL_ERR_DB;
		goto out;
	}

	if (mysql_select_db(ctx->mysql_hdl, ctx->db)) {
		err = PAM_MYSQL_ERR_DB;
		goto out;
	}

	err = PAM_MYSQL_ERR_SUCCESS;

out:
	if (err == PAM_MYSQL_ERR_DB) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "MySQL error (%s)\n", mysql_error(ctx->mysql_hdl));
	}

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_open_db() returning %d.", err);
	}

	if (host != ctx->host) {
		xfree(host);
	}

	return err;
}
/* }}} */

/* {{{ pam_mysql_close_db()
 */
static void pam_mysql_close_db(pam_mysql_ctx_t *ctx)
{
	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_close_db() called.");
	}

	if (ctx->mysql_hdl == NULL) {
		return; /* closed already */
	}

	mysql_close(ctx->mysql_hdl);

	xfree(ctx->mysql_hdl);
	ctx->mysql_hdl = NULL;
}
/* }}} */

/* {{{ pam_mysql_quick_escape()
 */
static pam_mysql_err_t pam_mysql_quick_escape(pam_mysql_ctx_t *ctx, pam_mysql_str_t *append_to, const char *val, size_t val_len)
{
	size_t len;

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_quick_escape() called.");
	}

	if (val_len >= (((size_t)-1)>>1) || pam_mysql_str_reserve(append_to, val_len * 2)) {
		syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
		return PAM_MYSQL_ERR_ALLOC;
	}

#ifdef HAVE_MYSQL_REAL_ESCAPE_STRING
	len = mysql_real_escape_string(ctx->mysql_hdl, &append_to->p[append_to->len], val, val_len);
#else
	len = mysql_escape_string(&append_to->p[append_to->len], val, val_len);
#endif
	append_to->p[append_to->len += len] = '\0';

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ pam_mysql_format_string() */
static pam_mysql_err_t pam_mysql_format_string(pam_mysql_ctx_t *ctx,
		pam_mysql_str_t *pretval, const char *template, int mangle, ...)
{
	pam_mysql_err_t err = PAM_MYSQL_ERR_SUCCESS;
	const char *p;
	const char *name = NULL;
	const char *commit_ptr;
	int state;
	va_list ap;

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_format_string() called");
	}

	va_start(ap, mangle);

	state = 0;
	for (commit_ptr = p = template; *p != '\0'; p++) {
		switch (state) {
			case 0:
				if (*p == '%') {
					if ((err = pam_mysql_str_append(pretval, commit_ptr, (size_t)(p - commit_ptr)))) {
						goto out;
					}

					commit_ptr = p;
					state = 1;
				}
				break;

			case 1:
				switch (*p) {
					case '{':
						state = 2;
						break;

					case '[':
						state = 4;
						break;

					case 's': {
						const char *val = va_arg(ap, char *);

						if ((err = pam_mysql_quick_escape(ctx, pretval, val, strlen(val)))) {
							goto out;
						}

						state = 0;
						commit_ptr = p + 1;
					} break;

					case 'S': {
						const char *val = va_arg(ap, char *);

						if ((err = pam_mysql_str_append(pretval, val, strlen(val)))) {
							goto out;
						}

						state = 0;
						commit_ptr = p + 1;
					} break;

					case 'u': {
						char buf[128];
						unsigned int val = va_arg(ap, unsigned int);
						char *q = buf + sizeof(buf);

						while (--q >= buf) {
							*q = "0123456789"[val % 10];
							val /= 10;
							if (val == 0) break;
						}

						if ((err = pam_mysql_str_append(pretval, q, sizeof(buf) - (size_t)(q - buf)))) {
							goto out;
						}

						state = 0;
						commit_ptr = p + 1;
					} break;

					default:
						if ((err = pam_mysql_str_append_char(pretval, '%'))) {
							goto out;
						}

						if ((err = pam_mysql_str_append_char(pretval, *p))) {
							goto out;
						}
		
						state = 0;
						commit_ptr = p + 1;
						break;
				}
				break;

			case 2:
				name = p;
				state = 3;
				break;

			case 3:
				if (*p == '}') {
					const char *val;
					int to_release;

					if ((err = pam_mysql_get_option(ctx, &val, &to_release, name, (size_t)(p - name)))) {
						goto out;
					}

					if (val == NULL) {
						val = xstrdup("");
					}

					if ((err = pam_mysql_quick_escape(ctx, pretval, val, strlen(val)))) {
						if (to_release) {
							xfree((char *)val);
						}
						goto out;
					}

					if (to_release) {
						xfree((char *)val);
					}

					state = 0;
					commit_ptr = p + 1;
				}
				break;

			case 4:
				name = p;
				state = 5;
				break;

			case 5:
				if (*p == ']') {
					const char *val;
					int to_release;

					if ((err = pam_mysql_get_option(ctx, &val, &to_release, name, (size_t)(p - name)))) {
						goto out;
					}

					if (val == NULL) {
						val = xstrdup("");
					}

					if ((err = pam_mysql_str_append(pretval, val, strlen(val)))) {
						if (to_release) {
							xfree((char *)val);
						}
						goto out;
					}

					if (to_release) {
						xfree((char *)val);
					}

					state = 0;
					commit_ptr = p + 1;
				}
				break;
		}
	}

	if (commit_ptr < p) {
		if ((err = pam_mysql_str_append(pretval, commit_ptr, (size_t)(p - commit_ptr)))) {
			goto out;
		}
	}

out:
	if (err) {
		pam_mysql_str_destroy(pretval);
	}

	va_end(ap);

	return err;
}
/* }}} */

/* {{{ pam_mysql_check_passwd
 */
static pam_mysql_err_t pam_mysql_check_passwd(pam_mysql_ctx_t *ctx,
		const char *user, const char *passwd, int null_inhibited)
{
	pam_mysql_err_t err;
	pam_mysql_str_t query;
	MYSQL_RES *result = NULL;
	MYSQL_ROW row;
	int vresult;

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_check_passwd() called.");
	}

	/* To avoid putting a plain password in the MySQL log file and on
	 * the wire more than needed we will request the encrypted password
	 * from MySQL. We will check encrypt the passed password against the
	 * one returned from MySQL.
	 */
	if ((err = pam_mysql_str_init(&query, 1))) {
		return err;
	}

	err = pam_mysql_format_string(ctx, &query,
		(ctx->where == NULL ?
			"SELECT %[passwdcolumn] FROM %[table] WHERE %[usercolumn] = '%s'":
			"SELECT %[passwdcolumn] FROM %[table] WHERE %[usercolumn] = '%s' AND (%S)"),
				1, user, ctx->where);

	if (err) {
		goto out;
	}

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "%s", query.p);
	}

#ifdef HAVE_MYSQL_REAL_QUERY
	if (mysql_real_query(ctx->mysql_hdl, query.p, query.len)) {
#else
	if (mysql_query(ctx->mysql_hdl, query.p)) {
#endif
		err = PAM_MYSQL_ERR_DB;
		goto out;
	}

	if (NULL == (result = mysql_store_result(ctx->mysql_hdl))) {
		err = PAM_MYSQL_ERR_DB;
		goto out;
	}

	switch (mysql_num_rows(result)) {
		case 0:
			syslog(LOG_AUTHPRIV | LOG_ERR, "%s", PAM_MYSQL_LOG_PREFIX "SELECT returned no result.");
			err = PAM_MYSQL_ERR_NO_ENTRY;
			goto out;

		case 1:
			break;

		case 2:
			syslog(LOG_AUTHPRIV | LOG_ERR, "%s", PAM_MYSQL_LOG_PREFIX "SELECT returned an indetermined result.");
			err = PAM_MYSQL_ERR_UNKNOWN;
			goto out;
	}

	/* Grab the password from RESULT_SET. */
	if (NULL == (row = mysql_fetch_row(result))) {
		err = PAM_MYSQL_ERR_DB;
		goto out;
	}

	vresult = -1;

	if (row[0] != NULL) {
		if (passwd != NULL) {
			switch (ctx->crypt_type) {
				/* PLAIN */
				case 0:
					vresult = strcmp(row[0], passwd);
					break;

				/* ENCRYPT */
				case 1:
					vresult = strcmp(row[0], crypt(passwd, row[0]));
					if (errno) {
						syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "something went wrong when invoking crypt() - %s", strerror(errno));
					}
					break;

				/* PASSWORD */
				case 2: {
					char buf[42];
#ifdef HAVE_MAKE_SCRAMBLED_PASSWORD_323
					if (ctx->use_323_passwd) {
						make_scrambled_password_323(buf, passwd);
					} else {
						make_scrambled_password(buf, passwd);
					}
#else
					make_scrambled_password(buf, passwd);
#endif

					vresult = strcmp(row[0], buf);
					{
						char *p = buf - 1;
						while (*(++p)) *p = '\0';
					}
				} break;

				/* MD5 hash (not MD5 crypt()) */
				case 3: {
#ifdef HAVE_PAM_MYSQL_MD5_DATA
					char buf[33];
					pam_mysql_md5_data((unsigned char*)passwd, strlen(passwd),
							buf);
					vresult = strcmp(row[0], buf);
					{
						char *p = buf - 1;
						while (*(++p)) *p = '\0';
					}
#else
					syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "non-crypt()ish MD5 hash is not supported in this build.");
#endif
				} break;

				case 4: {
#ifdef HAVE_PAM_MYSQL_SHA1_DATA
					char buf[41];
					pam_mysql_sha1_data((unsigned char*)passwd, strlen(passwd),
							buf);
					vresult = strcmp(row[0], buf);
					{
						char *p = buf - 1;
						while (*(++p)) *p = '\0';
					}
#else
					syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "non-crypt()ish SHA1 hash is not supported in this build.");
#endif
				} break;

				default: {
				}
			}
		}
	} else {
		vresult = null_inhibited;
	}

	if (vresult == 0) {
		err = PAM_MYSQL_ERR_SUCCESS;
	} else {
		err = PAM_MYSQL_ERR_MISMATCH;
	}

out:
	if (err == PAM_MYSQL_ERR_DB) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "MySQL error(%s)", mysql_error(ctx->mysql_hdl));
	}

	if (result != NULL) {
		mysql_free_result(result);
	}

	pam_mysql_str_destroy(&query);

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_check_passwd() returning %i.", err);
	}

	return err;
}
/* }}} */

/* {{{ pam_mysql_saltify()
 * Create a random salt for use with CRYPT() when changing passwords */
static void pam_mysql_saltify(pam_mysql_ctx_t *ctx, char *salt, const char *salter)
{
	unsigned int i = 0;
	char *q;
	unsigned int seed = 0;
	static const char saltstr[] = 
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "saltify called.");
	}

	if (salter != NULL) {
		const char *p;
		for (p = salter; *p != '\0'; p++) {
			seed += salter[i];
		}
	}

#ifdef HAVE_GETTIMEOFDAY
	{
		struct timeval *tv;
		if (gettimeofday(&tv, NULL)) {
			tv.tv_usec = 0;
		}
		seed = (unsigned int)((tv.tv_usec + j) % 65535);
	}
#endif

	q = salt;
	if (ctx->md5) {
		strcpy(salt, "$1$");
		q += sizeof("$1$") - 1;
		i = 8;
	} else {
		i = 2;
	}

	while (i-- > 0) {
		*(q++) = saltstr[seed % 64];
		seed = (((seed ^ 0x967e3c5a) << 3) ^ (~(seed >> 2) + i));
	}

	if (ctx->md5) {
		*(q++) = '$';
	}	
	*q = '\0';

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_saltify() returning salt = %s.", salt);
	}
}
/* }}} */

/* {{{ pam_mysql_update_passwd 
 * Update the password in MySQL
 * To reduce the number of calls to the DB, I'm now assuming that the old
 * password has been verified elsewhere, so I only check for null/not null
 * and is_root. */
static pam_mysql_err_t pam_mysql_update_passwd(pam_mysql_ctx_t *ctx, const char *user, const char *new_passwd)
{
	pam_mysql_err_t err = PAM_MYSQL_ERR_SUCCESS;
	pam_mysql_str_t query;
	char *encrypted_passwd = NULL;

	if ((err = pam_mysql_str_init(&query, 1))) {
		return err;
	}

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_update_passwd() called.");
	}

	if (user == NULL) {
		if (ctx->verbose) {
			syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "user is NULL.");
		}

		syslog(LOG_NOTICE, PAM_MYSQL_LOG_PREFIX "unable to change password");
		return PAM_MYSQL_ERR_INVAL;
	}

	if (new_passwd != NULL) {
		switch (ctx->crypt_type) {
			case 0:
				if (NULL == (encrypted_passwd = xstrdup(new_passwd))) {
					syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
					err = PAM_MYSQL_ERR_ALLOC;
					goto out;
				}
				break;

			case 1: {
				char salt[18];
				pam_mysql_saltify(ctx, salt, new_passwd);
				if (NULL == (encrypted_passwd = xstrdup(crypt(new_passwd, salt)))) {
					syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
					err = PAM_MYSQL_ERR_ALLOC;
					goto out;
				}
			} break;

			case 2:
				if (NULL == (encrypted_passwd = xcalloc(41 + 1, sizeof(char)))) {
					syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
					err = PAM_MYSQL_ERR_ALLOC;
					goto out;
				}
#ifdef HAVE_MAKE_SCRAMBLED_PASSWORD_323
				if (ctx->use_323_passwd) {
					make_scrambled_password_323(encrypted_passwd, new_passwd);
				} else {
					make_scrambled_password(encrypted_passwd, new_passwd);
				}
#else
				make_scrambled_password(encrypted_passwd, new_passwd);
#endif
				break;

			case 3:
#ifdef HAVE_PAM_MYSQL_MD5_DATA
				if (NULL == (encrypted_passwd = xcalloc(32 + 1, sizeof(char)))) {
					syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
					err = PAM_MYSQL_ERR_ALLOC;
					goto out;
				}
				pam_mysql_md5_data((unsigned char*)new_passwd,
						strlen(new_passwd), encrypted_passwd);
#else
				syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "non-crypt()ish MD5 hash is not supported in this build.");
				err = PAM_MYSQL_ERR_NOTIMPL;
				goto out;
#endif
				break;

			case 4:
#ifdef HAVE_PAM_MYSQL_SHA1_DATA
				if (NULL == (encrypted_passwd = xcalloc(40 + 1, sizeof(char)))) {
					syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
					err = PAM_MYSQL_ERR_ALLOC;
					goto out;
				}
				pam_mysql_sha1_data((unsigned char*)new_passwd,
						strlen(new_passwd), encrypted_passwd);
#else
				syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "non-crypt()ish SHA1 hash is not supported in this build.");
				err = PAM_MYSQL_ERR_NOTIMPL;
				goto out;
#endif
				break;

			default:
				encrypted_passwd = NULL;
				break;
		}
	}

	err = pam_mysql_format_string(ctx, &query,
		(ctx->where == NULL ?
			"UPDATE %[table] SET %[passwdcolumn] = '%s' WHERE %[usercolumn] = '%s'":
			"UPDATE %[table] SET %[passwdcolumn] = '%s' WHERE %[usercolumn] = '%s' AND (%S)"),
				1, (encrypted_passwd == NULL ? "": encrypted_passwd), user, ctx->where);
	if (err) {
		goto out;
	}

#ifdef HAVE_MYSQL_REAL_QUERY
	if (mysql_real_query(ctx->mysql_hdl, query.p, query.len)) {
#else
	if (mysql_query(ctx->mysql_hdl, query.p)) {
#endif
		err = PAM_MYSQL_ERR_DB;
		goto out;
	}

out:
	if (err == PAM_MYSQL_ERR_DB) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "MySQL error (%s)", mysql_error(ctx->mysql_hdl));
	}

	if (encrypted_passwd != NULL) {
		char *p;
		for (p = encrypted_passwd; *p != '\0'; p++) {
			*p = '\0';
		}
		xfree(encrypted_passwd);
	}

	pam_mysql_str_destroy(&query);

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_update_passwd() returning %i.", err);
	}

	return err;
}
/* }}} */

/* {{{ pam_mysql_query_user_stat */
static pam_mysql_err_t pam_mysql_query_user_stat(pam_mysql_ctx_t *ctx,
		int *pretval, const char *user)
{
	pam_mysql_err_t err = PAM_MYSQL_ERR_SUCCESS;
	pam_mysql_str_t query;
	MYSQL_RES *result = NULL;
	MYSQL_ROW row;

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_query_user_stat() called.");
	}

	if ((err = pam_mysql_str_init(&query, 0))) {
		return err;
	}

	err = pam_mysql_format_string(ctx, &query,
		(ctx->where == NULL ?
			"SELECT %[statcolumn], %[passwdcolumn] FROM %[table] WHERE %[usercolumn] = '%s'":
			"SELECT %[statcolumn], %[passwdcolumn] FROM %[table] WHERE %[usercolumn] = '%s' AND (%S)"),
				1, user, ctx->where);

	if (err) {
		goto out;
	}

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "%s", query.p);
	}

#ifdef HAVE_MYSQL_REAL_QUERY
	if (mysql_real_query(ctx->mysql_hdl, query.p, query.len)) {
#else
	if (mysql_query(ctx->mysql_hdl, query.p)) {
#endif
		err = PAM_MYSQL_ERR_DB;
		goto out;
	}

	if (NULL == (result = mysql_store_result(ctx->mysql_hdl))) {
		err = PAM_MYSQL_ERR_DB;
		goto out;
	}

	switch (mysql_num_rows(result)) {
		case 0:
			syslog(LOG_AUTHPRIV | LOG_ERR, "%s", PAM_MYSQL_LOG_PREFIX "SELECT returned no result.");
			err = PAM_MYSQL_ERR_NO_ENTRY;
			goto out;

		case 1:
			break;

		case 2:
			syslog(LOG_AUTHPRIV | LOG_ERR, "%s", PAM_MYSQL_LOG_PREFIX "SELECT returned an indetermined result.");
			err = PAM_MYSQL_ERR_UNKNOWN;
			goto out;
	}

	if (NULL == (row = mysql_fetch_row(result))) {
		err = PAM_MYSQL_ERR_DB;
		goto out;
	}

	if (row[0] == NULL) {
		*pretval = PAM_MYSQL_USER_STAT_EXPIRED;
	} else {
		*pretval = strtol(row[0], NULL, 10) & ~PAM_MYSQL_USER_STAT_NULL_PASSWD;
	}

	if (row[1] == NULL) {
		*pretval |= PAM_MYSQL_USER_STAT_NULL_PASSWD;
	}

out:
	if (err == PAM_MYSQL_ERR_DB) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "MySQL error (%s)", mysql_error(ctx->mysql_hdl));
	}

	if (result != NULL) {
		mysql_free_result(result);
	}

	pam_mysql_str_destroy(&query);

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_query_user_stat() returning %i.", err);
	}

	return err;
}
/* }}} */

/* {{{ pam_mysql_sql_log()
 */
static pam_mysql_err_t pam_mysql_sql_log(pam_mysql_ctx_t *ctx, const char *msg, const char *user, const char *rhost)
{
	pam_mysql_err_t err;
	pam_mysql_str_t query;
	const char *host;

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_sql_log() called.");
	}

	if ((err = pam_mysql_str_init(&query, 1))) {
		return err;
	}

	if (!ctx->sqllog) {
		err = PAM_MYSQL_ERR_SUCCESS;
		goto out;
	}

	if (pam_mysql_get_host_info(ctx, &host)) {
		host = "(unknown)";
	}

	if (ctx->logtable == NULL) {
		syslog(LOG_AUTHPRIV | LOG_ERR, "%s",
				PAM_MYSQL_LOG_PREFIX "sqllog set but logtable not set");
		return PAM_MYSQL_ERR_INVAL;
	}

	if (ctx->logmsgcolumn == NULL) {
		syslog(LOG_AUTHPRIV | LOG_ERR, "%s",
				PAM_MYSQL_LOG_PREFIX "sqllog set but logmsgcolumn not set");
		return PAM_MYSQL_ERR_INVAL;
	}

	if (ctx->logusercolumn == NULL) {
		syslog(LOG_AUTHPRIV | LOG_ERR, "%s",
				PAM_MYSQL_LOG_PREFIX "sqllog set but logusercolumn not set");
		return PAM_MYSQL_ERR_INVAL;
	}

	if (ctx->loghostcolumn == NULL) {
		syslog(LOG_AUTHPRIV | LOG_ERR, "%s",
				PAM_MYSQL_LOG_PREFIX "sqllog set but loghostcolumn not set");
		return PAM_MYSQL_ERR_INVAL;
	}

	if (ctx->logtimecolumn == NULL) {
		syslog(LOG_AUTHPRIV | LOG_ERR, "%s",
				PAM_MYSQL_LOG_PREFIX "sqllog set but logtimecolumn not set");
		return PAM_MYSQL_ERR_INVAL;
	}

	if (ctx->logrhostcolumn) {
		err = pam_mysql_format_string(ctx, &query,
				"INSERT INTO %[logtable] (%[logmsgcolumn], %[logusercolumn], %[loghostcolumn], %[logrhostcolumn], %[logpidcolumn], %[logtimecolumn]) VALUES ('%s', '%s', '%s', '%s', '%u', NOW())", 1,
				msg, user, host, rhost == NULL ? "(unknown)": rhost, getpid());
	} else {
		err = pam_mysql_format_string(ctx, &query,
				"INSERT INTO %[logtable] (%[logmsgcolumn], %[logusercolumn], %[loghostcolumn], %[logpidcolumn], %[logtimecolumn]) VALUES ('%s', '%s', '%s', '%u', NOW())", 1,
				msg, user, host, getpid());
	}

	if (err) {
		goto out;
	}

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "%s", query.p);
	}

#ifdef HAVE_MYSQL_REAL_QUERY
	if (mysql_real_query(ctx->mysql_hdl, query.p, query.len)) {
#else
	if (mysql_query(ctx->mysql_hdl, query.p)) {
#endif
		err = PAM_MYSQL_ERR_DB;
		goto out;
	}

	err = PAM_MYSQL_ERR_SUCCESS;

out:
	if (err == PAM_MYSQL_ERR_DB) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "MySQL error (%s)", mysql_error(ctx->mysql_hdl));
	}

	pam_mysql_str_destroy(&query);

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_sql_log() returning %d.", err);
	}

	return err;
}
/* }}} */

/* {{{ pam_mysql_converse()
 */
static pam_mysql_err_t pam_mysql_converse(pam_mysql_ctx_t *ctx, char ***pretval,
		pam_handle_t *pamh, size_t nargs, ...) 
{
	pam_mysql_err_t err = PAM_MYSQL_ERR_SUCCESS;
	int perr;
	struct pam_message **msgs = NULL;
	struct pam_message *bulk_msg_buf = NULL;
	struct pam_response *resps = NULL;
	struct pam_conv *conv = NULL;
	va_list ap;
	size_t i;
	char **retval = NULL;

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_mysql_converse() called.");
	}

	va_start(ap, nargs);

	/* obtain conversation interface */
	if ((perr = pam_get_item(pamh, PAM_CONV,
			(PAM_GET_ITEM_CONST void **)&conv))) {
		syslog(LOG_AUTHPRIV | LOG_ERR,
				PAM_MYSQL_LOG_PREFIX "could not obtain coversation interface (reason: %s)", pam_strerror(pamh, perr));
		err = PAM_MYSQL_ERR_UNKNOWN;
		goto out;
	}

	/* build message array */
	if (NULL == (msgs = xcalloc(nargs, sizeof(struct pam_message *)))) {

		syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
		err = PAM_MYSQL_ERR_ALLOC;
		goto out;
	}

	for (i = 0; i < nargs; i++) {
		msgs[i] = NULL;
	}

	if (NULL == (bulk_msg_buf = xcalloc(nargs, sizeof(struct pam_message)))) {

		syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
		err = PAM_MYSQL_ERR_ALLOC;
		goto out;
	}

	for (i = 0; i < nargs; i++) {
		msgs[i] = &bulk_msg_buf[i];
		msgs[i]->msg_style = va_arg(ap, int);
		msgs[i]->msg = va_arg(ap, char *);
	}

	if (NULL == (retval = xcalloc(nargs + 1, sizeof(char **)))) {
		syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
		err = PAM_MYSQL_ERR_ALLOC;
		goto out;
	}

	for (i = 0; i < nargs; i++) {
		retval[i] = NULL;
	}

	switch ((perr = conv->conv(nargs,
			(PAM_CONV_CONST struct pam_message **)msgs, &resps,
			conv->appdata_ptr))) {
		case PAM_SUCCESS:
			break;

#ifdef HAVE_PAM_CONV_AGAIN
		case PAM_CONV_AGAIN:
			break;
#endif
		default:
			syslog(LOG_DEBUG, PAM_MYSQL_LOG_PREFIX "conversation failure (reason: %s)",
					pam_strerror(pamh, perr));
			err = PAM_MYSQL_ERR_UNKNOWN;
			goto out;
	}

	for (i = 0; i < nargs; i++) {
		if (resps[i].resp != NULL &&
				NULL == (retval[i] = xstrdup(resps[i].resp))) {
			syslog(LOG_AUTHPRIV | LOG_CRIT, PAM_MYSQL_LOG_PREFIX "allocation failure at " __FILE__ ":%d", __LINE__);
			err = PAM_MYSQL_ERR_ALLOC;
			goto out;
		}
	}

	retval[i] = NULL;

out:
	if (resps != NULL) {
		size_t i;
		for (i = 0; i < nargs; i++) {
			xfree_overwrite(resps[i].resp);
		}
		xfree(resps);
	}

	if (bulk_msg_buf != NULL) {
		memset(bulk_msg_buf, 0, sizeof(*bulk_msg_buf) * nargs);
		xfree(bulk_msg_buf);
	}

	xfree(msgs);

	if (err) {
		if (retval != NULL) {
			for (i = 0; i < nargs; i++) {
				xfree_overwrite(retval[i]);
				retval[i] = NULL;
			}
			xfree(retval);
		}
	} else {
		*pretval = retval;
	}

	va_end(ap);

	return err;
}
/* }}} */
/* }}} */

/* {{{ pam_mysql_query_user_caps */
static pam_mysql_err_t pam_mysql_query_user_caps(pam_mysql_ctx_t *ctx,
		int *pretval, const char *user)
{
	*pretval = 0;

	if (geteuid() == 0) {
		*pretval |= PAM_MYSQL_CAP_CHAUTHTOK_SELF;

		if (getuid() == 0) {
			*pretval |= PAM_MYSQL_CAP_CHAUTHTOK_OTHERS;
		}
	}

	return PAM_MYSQL_ERR_SUCCESS;
}
/* }}} */

/* {{{ PAM Authentication services */
/* {{{ pam_sm_authenticate
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags,
		int argc, const char **argv)
{
	int retval;
	int err;
	const char *user;
	const char *rhost;
	char *passwd = NULL;
	pam_mysql_ctx_t *ctx = NULL;
	char **resps = NULL; 
	int passwd_is_local = 0;

	switch (pam_mysql_retrieve_ctx(&ctx, pamh)) {
		case PAM_MYSQL_ERR_SUCCESS:
			break;

		case PAM_MYSQL_ERR_ALLOC:
			return PAM_BUF_ERR;

		default:
			return PAM_SERVICE_ERR;
	}

	switch (pam_mysql_parse_args(ctx, argc, argv)) {
		case PAM_MYSQL_ERR_SUCCESS:
			break;

		case PAM_MYSQL_ERR_ALLOC:
			retval = PAM_BUF_ERR;
			goto out;

		default:
			retval = PAM_SERVICE_ERR;
			goto out;
	}

	if (ctx->config_file != NULL) {
		switch (pam_mysql_read_config_file(ctx, ctx->config_file)) {
			case PAM_MYSQL_ERR_ALLOC:
				retval = PAM_BUF_ERR;
				goto out;

			default:
				break;
		}
	}

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_authenticate() called.");
	}

	/* Get User */
	if ((retval = pam_get_user(pamh, (PAM_GET_USER_CONST char **)&user,
			NULL))) {
		goto out;
	}

	if (user == NULL) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "no user specified.");
		retval = PAM_USER_UNKNOWN;
		goto out;
	} 

	switch (pam_get_item(pamh, PAM_RHOST,
			(PAM_GET_ITEM_CONST void **)&rhost)) {
		case PAM_SUCCESS:
			break;

		default:
			rhost = NULL;
	}

	if (ctx->use_first_pass || ctx->try_first_pass) {
		retval = pam_get_item(pamh, PAM_AUTHTOK,
				(PAM_GET_ITEM_CONST void **)&passwd);

		switch (retval) {
			case PAM_SUCCESS:
				break;

			case PAM_NO_MODULE_DATA:
				passwd = NULL;
				break;

			default:
				retval = PAM_AUTH_ERR;
				goto out;
		}

		switch (pam_mysql_open_db(ctx)) {
			case PAM_MYSQL_ERR_BUSY:
			case PAM_MYSQL_ERR_SUCCESS:
				break;

			case PAM_MYSQL_ERR_ALLOC:
				retval = PAM_BUF_ERR;
				goto out;

			case PAM_MYSQL_ERR_DB:
				retval = PAM_AUTHINFO_UNAVAIL;
				goto out;

			default:
				retval = PAM_SERVICE_ERR;
				goto out;
		}

		err = pam_mysql_check_passwd(ctx, user, passwd,
				!(flags & PAM_DISALLOW_NULL_AUTHTOK));

		if (err == PAM_MYSQL_ERR_SUCCESS) {
			pam_mysql_sql_log(ctx, "AUTHENTICATION SUCCESS (FIRST_PASS)", user, rhost);
		} else {
			pam_mysql_sql_log(ctx, "AUTHENTICATION FALURE (FIRST_PASS)", user, rhost);
		}

		switch (err) {
			case PAM_MYSQL_ERR_SUCCESS:
				if (ctx->use_first_pass || ctx->try_first_pass) {
					retval = PAM_SUCCESS;
					goto out;
				}
				break;

			case PAM_MYSQL_ERR_NO_ENTRY:
				if (ctx->use_first_pass) {
					retval = PAM_USER_UNKNOWN;
					goto out;
				}
				break;

			case PAM_MYSQL_ERR_MISMATCH:
				if (ctx->use_first_pass) {
					retval = PAM_AUTH_ERR;
					goto out;
				}
				break;

			case PAM_MYSQL_ERR_ALLOC:
				retval = PAM_BUF_ERR;
				goto out;

			default:
				retval = PAM_SERVICE_ERR;
				goto out;
		}
	}

	switch (pam_mysql_converse(ctx, &resps, pamh, 1,
			PAM_PROMPT_ECHO_OFF, PLEASE_ENTER_PASSWORD)) {
		case PAM_MYSQL_ERR_SUCCESS:
			break;

		case PAM_MYSQL_ERR_ALLOC:
			retval = PAM_BUF_ERR;
			goto out;

		default:
			retval = PAM_SERVICE_ERR;
			goto out;
	}

	passwd = resps[0];
	passwd_is_local = 1;
	resps[0] = NULL;
	xfree(resps);

	if (passwd == NULL) {
		if (ctx->verbose) {
			syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "failed to retrieve authentication token.");
		}
		retval = PAM_AUTH_ERR;
		goto out;
	}

	switch (pam_mysql_open_db(ctx)) {
		case PAM_MYSQL_ERR_BUSY:
		case PAM_MYSQL_ERR_SUCCESS:
			break;

		case PAM_MYSQL_ERR_ALLOC:
			retval = PAM_BUF_ERR;
			goto out;

		case PAM_MYSQL_ERR_DB:
			retval = PAM_AUTHINFO_UNAVAIL;
			goto out;

		default:
			retval = PAM_SERVICE_ERR;
			goto out;
	}

	if (passwd_is_local) {
		(void) pam_set_item(pamh, PAM_AUTHTOK, passwd);
	}

	err = pam_mysql_check_passwd(ctx, user, passwd,
			!(flags & PAM_DISALLOW_NULL_AUTHTOK));

	if (err == PAM_MYSQL_ERR_SUCCESS) {
		pam_mysql_sql_log(ctx, "AUTHENTICATION SUCCESS", user, rhost);
	} else {
		pam_mysql_sql_log(ctx, "AUTHENTICATION FAILURE", user, rhost);
	}

	switch (err) {
		case PAM_MYSQL_ERR_SUCCESS:
			retval = PAM_SUCCESS;
			break;

		case PAM_MYSQL_ERR_NO_ENTRY:
			retval = PAM_USER_UNKNOWN;
			goto out;

		case PAM_MYSQL_ERR_MISMATCH:
			retval = PAM_AUTH_ERR;
			goto out;

		case PAM_MYSQL_ERR_ALLOC:
			retval = PAM_BUF_ERR;
			goto out;

		default:
			retval = PAM_SERVICE_ERR;
			goto out;
	}

out:
	if (ctx->disconnect_every_op) {
		pam_mysql_close_db(ctx);
	}

	if (passwd != NULL && passwd_is_local) {
		xfree_overwrite(passwd);
	}

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_authenticate() returning %d.", retval);
	}

	return retval;
}
/* }}} */

/* {{{ pam_sm_acct_mgmt
 */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t * pamh, int flags, int argc,
		const char **argv)
{
	int retval;
	int err;
	int stat;
	const char *user;
	const char *rhost;
	pam_mysql_ctx_t *ctx = NULL;

	switch (pam_mysql_retrieve_ctx(&ctx, pamh)) {
		case PAM_MYSQL_ERR_SUCCESS:
			break;

		case PAM_MYSQL_ERR_ALLOC:
			return PAM_BUF_ERR;

		default:
			return PAM_SERVICE_ERR;
	}

	switch (pam_mysql_parse_args(ctx, argc, argv)) {
		case PAM_MYSQL_ERR_SUCCESS:
			break;

		case PAM_MYSQL_ERR_ALLOC:
			retval = PAM_BUF_ERR;
			goto out;

		default:
			retval = PAM_SERVICE_ERR;
			goto out;
	}

	if (ctx->config_file != NULL) {
		switch (pam_mysql_read_config_file(ctx, ctx->config_file)) {
			case PAM_MYSQL_ERR_ALLOC:
				retval = PAM_BUF_ERR;
				goto out;

			default:
				break;
		}
	}

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_acct_mgmt() called.");
	}

	/* Get User */
	if ((retval = pam_get_user(pamh, (PAM_GET_USER_CONST char **)&user,
			NULL))) {
		goto out;
	}

	if (user == NULL) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "no user specified.");
		retval = PAM_USER_UNKNOWN;
		goto out;
	} 

	switch (pam_get_item(pamh, PAM_RHOST,
			(PAM_GET_ITEM_CONST void **)&rhost)) {
		case PAM_SUCCESS:
			break;

		default:
			rhost = NULL;
	}

	switch (pam_mysql_open_db(ctx)) {
		case PAM_MYSQL_ERR_BUSY:
		case PAM_MYSQL_ERR_SUCCESS:
			break;

		case PAM_MYSQL_ERR_ALLOC:
			retval = PAM_BUF_ERR;
			goto out;

		case PAM_MYSQL_ERR_DB:
			retval = PAM_AUTHINFO_UNAVAIL;
			goto out;

		default:
			retval = PAM_SERVICE_ERR;
			goto out;
	}

	err = pam_mysql_query_user_stat(ctx, &stat, user);

	if (err == PAM_MYSQL_ERR_SUCCESS) {
		pam_mysql_sql_log(ctx, "QUERYING SUCCESS", user, rhost);
	} else {
		pam_mysql_sql_log(ctx, "QUERYING FAILURE", user, rhost);
	}

	switch (err) {
		case PAM_MYSQL_ERR_SUCCESS:
			retval = PAM_SUCCESS;
			break;

		case PAM_MYSQL_ERR_NO_ENTRY:
			retval = PAM_USER_UNKNOWN;
			goto out;

		case PAM_MYSQL_ERR_ALLOC:
			retval = PAM_BUF_ERR;
			goto out;

		default:
			retval = PAM_SERVICE_ERR;
			goto out;
	}

	if (stat & PAM_MYSQL_USER_STAT_EXPIRED) {
		retval = PAM_ACCT_EXPIRED;
	} else if (stat & PAM_MYSQL_USER_STAT_AUTHTOK_EXPIRED) {
		if (stat & PAM_MYSQL_USER_STAT_NULL_PASSWD) {
#if defined(HAVE_PAM_NEW_AUTHTOK_REQD)
			retval = PAM_NEW_AUTHTOK_REQD;
#else
			retval = PAM_AUTHTOK_EXPIRED;
#endif
		} else {
			retval = PAM_AUTHTOK_EXPIRED;
		}
	}

out:
	if (ctx->disconnect_every_op) {
		pam_mysql_close_db(ctx);
	}

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_acct_mgmt() returning %i.",retval);
	}

	return retval;
}
/* }}} */

/* {{{ pam_sm_setcred
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc,
		const char **argv)
{
#ifdef DEBUG
	syslog(LOG_INFO, "%s", PAM_MYSQL_LOG_PREFIX "setcred called but not implemented.");
#endif
	return PAM_SUCCESS;
}
/* }}} */

/* {{{ pam_sm_chauthtok
 */
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh,int flags,int argc,
		const char **argv)
{
	int retval;
	int err;
	const char *user;
	const char *rhost;
	char *old_passwd = NULL;
	char *first_enter = NULL;
	char *new_passwd = NULL;
	int old_passwd_should_be_freed = 0;
	int new_passwd_is_local = 0;
	int caps = 0;
	int stat = 0;
	pam_mysql_ctx_t *ctx = NULL;

	switch (pam_mysql_retrieve_ctx(&ctx, pamh)) {
		case PAM_MYSQL_ERR_SUCCESS:
			break;

		case PAM_MYSQL_ERR_ALLOC:
			return PAM_BUF_ERR;

		default:
			return PAM_SERVICE_ERR;
	}

	switch (pam_mysql_parse_args(ctx, argc, argv)) {
		case PAM_MYSQL_ERR_SUCCESS:
			break;

		case PAM_MYSQL_ERR_ALLOC:
			retval = PAM_BUF_ERR;
			goto out;

		default:
			retval = PAM_SERVICE_ERR;
			goto out;
	}

	if (ctx->config_file != NULL) {
		switch (pam_mysql_read_config_file(ctx, ctx->config_file)) {
			case PAM_MYSQL_ERR_ALLOC:
				retval = PAM_BUF_ERR;
				goto out;

			default:
				break;
		}
	}

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_chauthtok() called.");
	}

	/* Get User */
	if ((retval = pam_get_user(pamh, (PAM_GET_USER_CONST char **)&user,
			NULL))) {
		goto out;
	}

	if (user == NULL) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "no user specified.");
		retval = PAM_USER_UNKNOWN;
		goto out;
	}

	switch (pam_get_item(pamh, PAM_RHOST,
			(PAM_GET_ITEM_CONST void **)&rhost)) {
		case PAM_SUCCESS:
			break;

		default:
			rhost = NULL;
	}

	err = pam_mysql_open_db(ctx);

	if (flags & PAM_PRELIM_CHECK) {
		switch (err) {
			case PAM_MYSQL_ERR_BUSY:
			case PAM_MYSQL_ERR_SUCCESS:
				break;

			default:
				retval = PAM_TRY_AGAIN;
				goto out;
		}
	} else {
		switch (err) {
			case PAM_MYSQL_ERR_BUSY:
			case PAM_MYSQL_ERR_SUCCESS:
				break;

			case PAM_MYSQL_ERR_ALLOC:
				retval = PAM_BUF_ERR;
				goto out;

			case PAM_MYSQL_ERR_DB:
				retval = PAM_PERM_DENIED;
				goto out;

			default:
				retval = PAM_SERVICE_ERR;
				goto out;
		}
	}

	if (!(flags & PAM_UPDATE_AUTHTOK)) {
		goto out;
	}

	err = pam_mysql_query_user_caps(ctx, &caps, user);

	switch (err) {
		case PAM_MYSQL_ERR_SUCCESS:
			retval = PAM_SUCCESS;
			break;

		case PAM_MYSQL_ERR_NO_ENTRY:
			retval = PAM_SUCCESS;
			caps = 0;
			break;

		default:
			retval = PAM_PERM_DENIED;
			goto out;
	}

	if (!(caps & (PAM_MYSQL_CAP_CHAUTHTOK_SELF
			| PAM_MYSQL_CAP_CHAUTHTOK_OTHERS))) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "User is not allowed to change the authentication token.");
		retval = PAM_PERM_DENIED;
		goto out;
	}

	err = pam_mysql_query_user_stat(ctx, &stat, user);

	if (err == PAM_MYSQL_ERR_SUCCESS) {
		pam_mysql_sql_log(ctx, "QUERYING SUCCESS", user, rhost);
	} else {
		pam_mysql_sql_log(ctx, "QUERYING FAILURE", user, rhost);
	}

	switch (err) {
		case PAM_MYSQL_ERR_SUCCESS:
			retval = PAM_SUCCESS;
			break;

		default:
			retval = PAM_PERM_DENIED;
			goto out;
	}

	if (!(flags & PAM_CHANGE_EXPIRED_AUTHTOK) &&
			(stat & PAM_MYSQL_USER_STAT_EXPIRED)) {
		retval = PAM_AUTHTOK_LOCK_BUSY;
		goto out;
	}

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "update authentication token");
	}

	if (!(caps & PAM_MYSQL_CAP_CHAUTHTOK_OTHERS) &&
			!(stat & PAM_MYSQL_USER_STAT_NULL_PASSWD)) {
		if (ctx->use_first_pass || ctx->try_first_pass) {
			retval = pam_get_item(pamh, PAM_OLDAUTHTOK,
					(PAM_GET_ITEM_CONST void **)&old_passwd);
			switch (retval) {
				case PAM_SUCCESS:
					break;

				case PAM_NO_MODULE_DATA:
					old_passwd = NULL; 
					break;

				default:
					retval = PAM_AUTHTOK_ERR;
					goto out;
			}

			if (old_passwd != NULL) {
				switch (pam_mysql_check_passwd(ctx, user, old_passwd, 0)) {
					case PAM_MYSQL_ERR_SUCCESS:
						retval = PAM_SUCCESS;
						break;

					case PAM_MYSQL_ERR_NO_ENTRY:
						retval = PAM_USER_UNKNOWN;
						goto out;

					case PAM_MYSQL_ERR_MISMATCH:
						if (ctx->use_first_pass) {
							retval = PAM_AUTH_ERR;
							goto out;
						}
						retval = PAM_SUCCESS;
						break;

					case PAM_MYSQL_ERR_ALLOC:
						retval = PAM_BUF_ERR;
						goto out;

					default:
						retval = PAM_SERVICE_ERR;
						goto out;
				}
			}
		}

		if (!ctx->use_first_pass) {
			char **resps;

			if (flags & PAM_SILENT) {
				retval = PAM_AUTHTOK_RECOVERY_ERR;
				goto out;
			}

			switch (pam_mysql_converse(ctx, &resps, pamh, 1,
					PAM_PROMPT_ECHO_OFF, PLEASE_ENTER_OLD_PASSWORD)) {
				case PAM_MYSQL_ERR_SUCCESS:
					break;

				default:
					retval = PAM_SERVICE_ERR;
					goto out;
			}
			old_passwd = resps[0];
			old_passwd_should_be_freed = 1;
			resps[0] = NULL;
			xfree(resps);

			if (old_passwd == NULL) {
				retval = PAM_AUTHTOK_RECOVERY_ERR;
				goto out;
			}

			switch (pam_mysql_check_passwd(ctx, user, old_passwd, 0)) {
				case PAM_MYSQL_ERR_SUCCESS:
					retval = PAM_SUCCESS;
					break;

				case PAM_MYSQL_ERR_NO_ENTRY:
					retval = PAM_USER_UNKNOWN;
					goto out;

				case PAM_MYSQL_ERR_MISMATCH:
					retval = PAM_AUTH_ERR;
					goto out;

				case PAM_MYSQL_ERR_ALLOC:
					retval = PAM_BUF_ERR;
					goto out;

				default:
					retval = PAM_SERVICE_ERR;
					goto out;
			}

			if ((retval = pam_set_item(pamh, PAM_OLDAUTHTOK,
					old_passwd)) != PAM_SUCCESS) {
				goto out;
			}
		}
	}

	retval = pam_get_item(pamh, PAM_AUTHTOK,
			(PAM_GET_ITEM_CONST void **)&new_passwd);

	switch (retval) {
		case PAM_SUCCESS:
			break;

		case PAM_NO_MODULE_DATA:
			new_passwd = NULL; 
			break;

		default:
			retval = PAM_AUTHTOK_ERR;
			goto out;
	}

	if (new_passwd == NULL) {
		char **resps;

		if (ctx->use_first_pass) {
			retval = PAM_AUTHTOK_RECOVERY_ERR;
			goto out;
		}

		if (flags & PAM_SILENT) {
			retval = PAM_AUTHTOK_RECOVERY_ERR;
			goto out;
		}

		if (ctx->verbose) {
			syslog(LOG_AUTHPRIV | LOG_ERR, "Asking for new password (1)");
		}

		switch (pam_mysql_converse(ctx, &resps, pamh, 1,
				PAM_PROMPT_ECHO_OFF, PLEASE_ENTER_NEW_PASSWORD)) {
			case PAM_MYSQL_ERR_SUCCESS:
				break;

			default:
				retval = PAM_SERVICE_ERR;
				goto out;
		}

		first_enter = resps[0];
		resps[0] = NULL;
		xfree(resps);

		switch (pam_mysql_converse(ctx, &resps, pamh, 1,
				PAM_PROMPT_ECHO_OFF, PLEASE_REENTER_NEW_PASSWORD)) {
			case PAM_MYSQL_ERR_SUCCESS:
				break;

			default:
				retval = PAM_SERVICE_ERR;
				goto out;
		}

		new_passwd = resps[0];
		new_passwd_is_local = 1;
		resps[0] = NULL;
		xfree(resps);

		if (new_passwd == NULL || strcmp(first_enter, new_passwd) != 0) {
			retval = PAM_AUTHTOK_RECOVERY_ERR;
			goto out;
		}
	}

	switch (pam_mysql_update_passwd(ctx, user, new_passwd)) {
		case PAM_MYSQL_ERR_SUCCESS:
			if (new_passwd_is_local) {
				(void) pam_set_item(pamh, PAM_AUTHTOK, new_passwd);
			}
			retval = PAM_SUCCESS;
			break;

		default:
			retval = PAM_AUTHTOK_ERR;
			break;
	}

	if (retval == PAM_SUCCESS) {
		pam_mysql_sql_log(ctx, "ALTERATION SUCCESS", user, rhost);
	} else {
		pam_mysql_sql_log(ctx, "ALTERATION FAILURE", user, rhost);
	}

out:
	if (ctx->disconnect_every_op) {
		pam_mysql_close_db(ctx);
	}

	if (new_passwd != NULL && new_passwd_is_local) {
		xfree_overwrite(new_passwd);
	}

	if (first_enter != NULL) {
		xfree_overwrite(first_enter);
	}

	if (old_passwd != NULL && old_passwd_should_be_freed) {
		xfree_overwrite(old_passwd);
	}

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_chauthtok() returning %d.", retval);
	}

	return retval;
}
/* }}} */

/* {{{ pam_sm_open_session
 */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
		const char **argv)
{
	int retval;
	pam_mysql_ctx_t *ctx = NULL;
	const char *user;
	const char *rhost;

	switch (pam_mysql_retrieve_ctx(&ctx, pamh)) {
		case PAM_MYSQL_ERR_SUCCESS:
			break;

		case PAM_MYSQL_ERR_ALLOC:
			return PAM_BUF_ERR;

		default:
			return PAM_SERVICE_ERR;
	}

	switch (pam_mysql_parse_args(ctx, argc, argv)) {
		case PAM_MYSQL_ERR_SUCCESS:
			break;

		case PAM_MYSQL_ERR_ALLOC:
			retval = PAM_BUF_ERR;
			goto out;

		default:
			retval = PAM_SERVICE_ERR;
			goto out;
	}

	if (ctx->config_file != NULL) {
		switch (pam_mysql_read_config_file(ctx, ctx->config_file)) {
			case PAM_MYSQL_ERR_ALLOC:
				retval = PAM_BUF_ERR;
				goto out;

			default:
				break;
		}
	}

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_open_session() called.");
	}

	/* Get User */
	if ((retval = pam_get_user(pamh, (PAM_GET_USER_CONST char **)&user,
			NULL))) {
		goto out;
	}

	if (user == NULL) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "no user specified.");
		retval = PAM_USER_UNKNOWN;
		goto out;
	}

	switch (pam_get_item(pamh, PAM_RHOST,
			(PAM_GET_ITEM_CONST void **)&rhost)) {
		case PAM_SUCCESS:
			break;

		default:
			rhost = NULL;
	}

	switch (pam_mysql_open_db(ctx)) {
		case PAM_MYSQL_ERR_BUSY:
		case PAM_MYSQL_ERR_SUCCESS:
			break;

		case PAM_MYSQL_ERR_ALLOC:
			retval = PAM_BUF_ERR;
			goto out;

		case PAM_MYSQL_ERR_DB:
			retval = PAM_AUTHINFO_UNAVAIL;
			goto out;

		default:
			retval = PAM_SERVICE_ERR;
			goto out;
	}

	pam_mysql_sql_log(ctx, "OPEN SESSION", user, rhost);

out:
	if (ctx->disconnect_every_op) {
		pam_mysql_close_db(ctx);
	}

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_open_session() returning %i.", retval);
	}

	return retval;
}
/* }}} */

/* {{{ pam_sm_close_session
 */
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
		const char **argv)
{
	int retval;
	pam_mysql_ctx_t *ctx = NULL;
	const char *user;
	const char *rhost;

	switch (pam_mysql_retrieve_ctx(&ctx, pamh)) {
		case PAM_MYSQL_ERR_SUCCESS:
			break;

		case PAM_MYSQL_ERR_ALLOC:
			return PAM_BUF_ERR;

		default:
			return PAM_SERVICE_ERR;
	}

	switch (pam_mysql_parse_args(ctx, argc, argv)) {
		case PAM_MYSQL_ERR_SUCCESS:
			break;

		case PAM_MYSQL_ERR_ALLOC:
			retval = PAM_BUF_ERR;
			goto out;

		default:
			retval = PAM_SERVICE_ERR;
			goto out;
	}

	if (ctx->config_file != NULL) {
		switch (pam_mysql_read_config_file(ctx, ctx->config_file)) {
			case PAM_MYSQL_ERR_ALLOC:
				retval = PAM_BUF_ERR;
				goto out;

			default:
				break;
		}
	}

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_close_session() called.");
	}

	/* Get User */
	if ((retval = pam_get_user(pamh, (PAM_GET_USER_CONST char **)&user,
			NULL))) {
		goto out;
	}

	if (user == NULL) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "no user specified.");
		retval = PAM_USER_UNKNOWN;
		goto out;
	} 

	switch (pam_get_item(pamh, PAM_RHOST,
			(PAM_GET_ITEM_CONST void **)&rhost)) {
		case PAM_SUCCESS:
			break;

		default:
			rhost = NULL;
	}

	switch (pam_mysql_open_db(ctx)) {
		case PAM_MYSQL_ERR_BUSY:
		case PAM_MYSQL_ERR_SUCCESS:
			break;

		case PAM_MYSQL_ERR_ALLOC:
			retval = PAM_BUF_ERR;
			goto out;

		case PAM_MYSQL_ERR_DB:
			retval = PAM_AUTHINFO_UNAVAIL;
			goto out;

		default:
			retval = PAM_SERVICE_ERR;
			goto out;
	}

	pam_mysql_sql_log(ctx, "CLOSE SESSION", user, rhost);

out:
	if (ctx->disconnect_every_op) {
		pam_mysql_close_db(ctx);
	}

	if (ctx->verbose) {
		syslog(LOG_AUTHPRIV | LOG_ERR, PAM_MYSQL_LOG_PREFIX "pam_sm_close_session() returning %i.", retval);
	}

	return retval;
}
/* }}} */
/* }}} */

/* end of module definition */

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_mysql_modstruct = {
    PAM_MODULE_NAME,
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok
};

#endif

/*
 * vim600: fdm=marker sw=4 ts=4 sts=4
 */

