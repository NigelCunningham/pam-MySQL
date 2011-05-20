dnl $Id: configure.in,v 1.6.2.7 2006/01/09 10:35:59 moriyoshi Exp $
sinclude([pkg.m4])

AC_PREREQ([2.57])
AC_INIT(pam_mysql, 0.7RC1)
AM_INIT_AUTOMAKE(pam_mysql, 0.7RC1)
AC_CONFIG_SRCDIR(pam_mysql.c)
AM_CONFIG_HEADER(config.h)
AM_MAINTAINER_MODE

AC_SUBST(PACKAGE_VERSION)
AC_SUBST(PACKAGE_NAME)
AC_SUBST(PACKAGE_TARNAME)

enable_static="no"
enable_shared="yes"

AC_PROG_YACC
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_LIBTOOL

AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h netdb.h string.h strings.h sys/socket.h sys/types.h sys/stat.h sys/param.h fcntl.h syslog.h unistd.h stdarg.h errno.h crypt.h])
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_C_VOLATILE
AC_C_STRINGIZE
AC_TYPE_PID_T

AC_FUNC_ALLOCA
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
PAM_MYSQL_CHECK_DEFINES([
#include <errno.h>
], [ELOOP EOVERFLOW])
PAM_MYSQL_CHECK_NETWORK_LIBS
AC_CHECK_FUNCS([inet_ntop getaddrinfo freeaddrinfo strcasecmp strdup])
PAM_MYSQL_CHECK_IPV6
PAM_MYSQL_CHECK_GETHOSTBYNAME_R

AC_CHECK_SIZEOF([char])
AC_CHECK_SIZEOF([short])
AC_CHECK_SIZEOF([int])
AC_CHECK_SIZEOF([long])

AC_ARG_WITH([mysql], [  --with-mysql=PREFIX     specify MySQL installation prefix], [
  PAM_MYSQL_CHECK_LIBMYSQLCLIENT(["$withval"])
], [
dnl try autodetection...
  PAM_MYSQL_CHECK_LIBMYSQLCLIENT([/usr /usr/local /usr/mysql /opt/mysql])
])

AC_ARG_WITH([openssl], [  --with-openssl[[=PREFIX]] specify OpenSSL installation prefix], [
  if test -z "$withval" -o "$withval" = "yes"; then
    dnl try autodetection...
    PKG_CHECK_MODULES([openssl], [openssl], [
      AC_DEFINE([HAVE_OPENSSL], [1], [Define to 1 if OpenSSL library is installed])
    ], [
      PAM_MYSQL_CHECK_OPENSSL([/usr /usr/local /opt/openssl /opt/ssl /usr/ssl /usr/local/ssl], [
        AC_DEFINE([HAVE_OPENSSL], [1], [Define to 1 if OpenSSL library is installed])
      ],[])
    ]) 
  else
    PAM_MYSQL_CHECK_OPENSSL(["$withval"], [
      AC_DEFINE([HAVE_OPENSSL], [1], [Define to 1 if OpenSSL library is installed])
    ], [])
  fi
], [])

CFLAGS="$CFLAGS $openssl_CFLAGS"
LIBS="$LIBS $openssl_LIBS"

sasl_v2_avail=

AC_ARG_WITH([cyrus-sasl2], [  --with-cyrus-sasl2[[=PREFIX]] specify Cyrus-SASL2 installation prefix], [
  if test -z "$withval" -o "$withval" = "yes"; then
    dnl try autodetection...
    PAM_MYSQL_CHECK_CYRUS_SASL_V2([/usr /usr/local /opt/cyrus-sasl /opt/sasl], [
      AC_DEFINE([HAVE_CYRUS_SASL_V2], [1], [Define to 1 if Cyrus-SASL Version 2 is installed])
      sasl_v2_avail=1
    ]) 
  else
    PAM_MYSQL_CHECK_CYRUS_SASL_V2(["$withval"], [
      AC_DEFINE([HAVE_CYRUS_SASL_V2], [1], [Define to 1 if Cyrus-SASL Version 2 is installed])
      sasl_v2_avail=1
    ], [])
  fi
], [])

CFLAGS="$CFLAGS $sasl_v2_CFLAGS"
LIBS="$LIBS $sasl_v2_LIBS"

AC_ARG_WITH([cyrus-sasl], [  --with-cyrus-sasl[[=PREFIX]] specify Cyrus-SASL installation prefix], [
  if test -z "$sasl_v2_avail"; then
    if test -z "$withval" -o "$withval" = "yes"; then
      dnl try autodetection...
      PAM_MYSQL_CHECK_CYRUS_SASL_V1([/usr /usr/local /opt/cyrus-sasl /opt/sasl], [
        AC_DEFINE([HAVE_CYRUS_SASL_V1], [1], [Define to 1 if Cyrus-SASL Version 1 is installed])
      ]) 
    else
      PAM_MYSQL_CHECK_CYRUS_SASL_V1(["$withval"], [
        AC_DEFINE([HAVE_CYRUS_SASL_V1], [1], [Define to 1 if Cyrus-SASL Version 1 is installed])
      ], [])
    fi
  else
    AC_MSG_ERROR([--with-cyrus-sasl and --with-cyrus-sasl2 cannot be specified at the same time.])
  fi
], [])

CFLAGS="$CFLAGS $sasl_v1_CFLAGS"
LIBS="$LIBS $sasl_v1_LIBS"

AC_ARG_WITH([pam], [  --with-pam=PREFIX       specify PAM installation prefix], [
  PAM_MYSQL_CHECK_PAM(["$withval"])
], [
dnl try autodetection...
  PAM_MYSQL_CHECK_PAM([/usr /usr/local])
])

AC_ARG_WITH([pam_mods_dir], [  --with-pam-mods-dir=DIR specify PAM module installation path], [
  PAM_MODS_DIR="$withval"
], [
  PAM_MODS_DIR=
  for dir in "/lib/security" "/lib/pam" "/usr/lib/security" "/usr/lib/pam" \
             "$libdir/pam" "$libdir/security"; do
    if test -d "$dir"; then
      PAM_MODS_DIR="$dir"
    fi
  done
  if test -z "$PAM_MODS_DIR"; then
    AC_MSG_ERROR([Your system doesn't appear to be configured to use PAM. Perhaps you need to specify the correct location where the PAM modules reside.])
  fi
])

PAM_MYSQL_CHECK_MD5_HEADERS
PAM_MYSQL_CHECK_CRYPT

AC_SUBST(INCLUDES)
AC_SUBST(PAM_MODS_DIR)
AC_CONFIG_FILES([Makefile])
AC_OUTPUT([pam_mysql.spec])

dnl vim600: sts=2 sw=2 ts=2 et

