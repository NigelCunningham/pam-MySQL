AC_PREREQ([2.58])
AC_INIT(pam-mysql, 0.8)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Wno-extra-portability dist-xz no-dist-gzip])
AC_CONFIG_SRCDIR(pam_mysql.c)
AC_CONFIG_HEADERS(config.h)

AC_SUBST(PACKAGE_VERSION)
AC_SUBST(PACKAGE_NAME)

LT_INIT([disable-static])

AC_PROG_CC
AC_PROG_INSTALL

dnl Check for sizes
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(long long)
AC_CHECK_SIZEOF(mode_t)

AC_CHECK_HEADERS([arpa/inet.h netinet/in.h netdb.h string.h strings.h sys/socket.h sys/types.h sys/stat.h sys/param.h fcntl.h syslog.h unistd.h stdarg.h errno.h crypt.h security/pam_appl.h])
AC_TYPE_SIZE_T
AC_CHECK_DECLS([ELOOP, EOVERFLOW],,,[[#include <errno.h>]])
AC_SEARCH_LIBS([socket],[socket],,[AC_MSG_ERROR([unable to find the socket() function])])
AC_CHECK_FUNCS([getaddrinfo])

AC_CHECK_LIB(crypt, crypt, , )

PAM_MYSQL_CHECK_IPV6
PAM_MYSQL_CHECK_GETHOSTBYNAME_R

AC_ARG_WITH([mysql], [  --with-mysql=PREFIX     specify MySQL installation prefix], [
  PAM_MYSQL_CHECK_LIBMYSQLCLIENT(["$withval"])
], [
dnl try autodetection...
  PAM_MYSQL_CHECK_LIBMYSQLCLIENT([/usr /usr/local /usr/mysql /opt/mysql])
])

AC_ARG_WITH([openssl],
    [AS_HELP_STRING([--with-openssl],[use the OpenSSL crypto provider @<:@default=check@:>@])],,
    [with_openssl=check])

AS_IF([test x"$with_openssl" != xno],
    [PKG_CHECK_MODULES([openssl],[libcrypto],
         [AC_DEFINE([HAVE_OPENSSL], [1], [Define to 1 if OpenSSL library is installed])],
         [AS_IF([test "x$with_openssl" != xcheck],[AC_MSG_ERROR([Unable to find OpenSSL])])])])

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
AC_SEARCH_LIBS([crypt],[crypt],,[AC_MSG_ERROR([unable to find the crypt() function])])

AC_SUBST(PAM_MODS_DIR)
AC_CONFIG_FILES([Makefile pam_mysql.spec])
AC_SEARCH_LIBS([my_make_scrambled_password],[mysql],[AC_DEFINE([HAVE_MY_MAKE_SCRAMBLED_PASSWORD], [1], [Build own SHA1 support.])])

AC_OUTPUT
