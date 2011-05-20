dnl $Id: acinclude.m4,v 1.6.2.10 2006/01/09 10:35:59 moriyoshi Exp $

AC_DEFUN([PAM_MYSQL_CHECK_CONST], [
  AC_CACHE_CHECK([$1 availability], [ac_cv_const_[]$1], [
    AC_TRY_COMPILE([$4], [
      int dummy = (int)$1;
    ], [
      ac_cv_const_[]$1=yes
    ], [
      ac_cv_const_[]$1=no
    ])
  ])
  if test "$ac_cv_const_[]$1" = "yes"; then
    ifelse([$2],[],[:],[$2])
  else
    ifelse([$3],[],[:],[$3])
  fi
])

AC_DEFUN([PAM_MYSQL_CHECK_PAM_PROTOS], [
  ac_save_CFLAGS="$CFLAGS"
  CFLAGS="$INCLUDES -Werror $CFLAGS"
  AC_MSG_CHECKING([if the second argument of pam_get_user() takes const pointer])
  AC_TRY_COMPILE([
#include <pam_appl.h>
#include <pam_modules.h>
  ], [
    const char *user;
    pam_get_user((void*)0, &user, (void*)0);
  ], [
    AC_MSG_RESULT([yes])
    AC_DEFINE([PAM_GET_USER_CONST], [const], [Define to `const' if the 2nd arg of pam_get_user() takes const pointer])
  ], [
    AC_MSG_RESULT([no])
    AC_DEFINE([PAM_GET_USER_CONST], [], [Define to `const' if the 2nd arg of pam_get_user() takes const pointer])
  ])

  AC_MSG_CHECKING([if the third argument of pam_get_data() takes const pointer])
  AC_TRY_COMPILE([
#include <pam_appl.h>
#include <pam_modules.h>
  ], [
    const void *data;
    pam_get_data((void*)0, (void*)0, &data);
  ], [
    AC_MSG_RESULT([yes])
    AC_DEFINE([PAM_GET_DATA_CONST], [const], [Define to `const' if the 2nd arg of pam_get_data() takes const pointer])
  ], [
    AC_MSG_RESULT([no])
    AC_DEFINE([PAM_GET_DATA_CONST], [], [Define to `const' if the 2nd arg of pam_get_data() takes const pointer])
  ])

  AC_MSG_CHECKING([if the third argument of pam_get_item() takes const pointer])
  AC_TRY_COMPILE([
#include <pam_appl.h>
#include <pam_modules.h>
  ], [
    const void *item;
    pam_get_item((void*)0, 0, &item);
  ], [
    AC_MSG_RESULT([yes])
    AC_DEFINE([PAM_GET_ITEM_CONST], [const], [Define to `const' if the 2nd arg of pam_get_item() takes const pointer])
  ], [
    AC_MSG_RESULT([no])
    AC_DEFINE([PAM_GET_ITEM_CONST], [], [Define to `const' if the 2nd arg of pam_get_item() takes const pointer])
  ])

  AC_MSG_CHECKING([if the second argument of pam_conv.conv() takes const pointer])
  AC_TRY_COMPILE([
#include <pam_appl.h>
#include <pam_modules.h>
  ], [
    int (*conv)(int num_msg, const struct pam_message **msg,
        struct pam_response **resp, void *appdata_ptr) = NULL;
    struct pam_conv c = { conv, NULL };
    c.conv = NULL;
  ], [
    AC_MSG_RESULT(yes)
    AC_DEFINE([PAM_CONV_CONST], [const], [Define to `const' if the 2nd arg of pam_conv.conv takes const pointer.])
  ], [
    AC_MSG_RESULT(no)
    AC_DEFINE([PAM_CONV_CONST], [], [Define to `const' if the 2nd arg of pam_conv.conv takes const pointer.])
  ])
  CFLAGS="$ac_save_CFLAGS"
])

AC_DEFUN([PAM_MYSQL_CHECK_PAM_CONSTS], [
  ac_save_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$INCLUDES $CPPFLAGS"
  PAM_MYSQL_CHECK_CONST([PAM_CONV_AGAIN], [
    AC_DEFINE([HAVE_PAM_CONV_AGAIN], [1], [Define to 1 if PAM defines PAM_CONV_AGAIN constant.])
  ], [], [
#include <pam_appl.h>
#include <pam_modules.h>
  ])

  PAM_MYSQL_CHECK_CONST([PAM_INCOMPLETE], [
    AC_DEFINE([HAVE_PAM_INCOMPLETE], [1], [Define to 1 if PAM defines PAM_INCOMPLETE constant.])
  ], [], [
#include <pam_appl.h>
#include <pam_modules.h>
  ])

  PAM_MYSQL_CHECK_CONST([PAM_NEW_AUTHTOK_REQD], [
    AC_DEFINE([HAVE_PAM_NEW_AUTHTOK_REQD], [1], [Define to 1 if PAM defines PAM_NEW_AUTHTOK_REQD constant.])
  ], [], [
#include <pam_appl.h>
#include <pam_modules.h>
  ])

  PAM_MYSQL_CHECK_CONST([PAM_AUTHTOK_RECOVERY_ERR], [], [
    PAM_MYSQL_CHECK_CONST([PAM_AUTHTOK_RECOVER_ERR], [
      AC_DEFINE([LINUX_PAM_CONST_BUG], [1], [Define to 1 if the implementation does not define PAM_AUTHTOK_RECOVER_ERR])
    ], [], [
#include <pam_appl.h>
#include <pam_modules.h>
    ])
  ], [
#include <pam_appl.h>
#include <pam_modules.h>
  ])

  CPPFLAGS="$ac_save_CFLAGS"
])

AC_DEFUN([PAM_MYSQL_CHECK_PAM], [
  pam_include_path=
  pam_prefix=

  for _pfx in $1; do
    for dir in "$_pfx/include" "$_pfx/include/security" "$_pfx/include/pam"; do
      if test -e "$dir/pam_modules.h"; then
        ac_save_CPPFLAGS="$CPPFLAGS"
        CPPFLAGS="$CPPFLAGS -I$_pfx/include -I$dir"
        AC_CHECK_HEADERS([pam_appl.h], [
          AC_MSG_CHECKING([pam_modules.h usability])
          AC_TRY_COMPILE([
          #include <pam_appl.h>
          #include <pam_modules.h>
          ], [], [
            AC_MSG_RESULT([yes])
            pam_prefix="$_pfx"
            pam_include_path="$dir"
            break
          ], [
            AC_MSG_RESULT([no])
          ])
        ])
        CPPFLAGS="$ac_save_CPPFLAGS"
      fi
    done
  done

  if test -z "$pam_include_path"; then
    AC_MSG_ERROR([Cannot find pam headers. Please check if your system is ready for pam module development.])
  fi

  INCLUDES="$INCLUDES -I$pam_include_path -I$pam_prefix/include"

  PAM_MYSQL_CHECK_PAM_CONSTS
  PAM_MYSQL_CHECK_PAM_PROTOS
])

AC_DEFUN([PAM_MYSQL_CHECK_LIBMYSQLCLIENT], [
  AC_MSG_CHECKING([if] $1 [is a mysql_config script])

  _cfg="$1"
  if test -x "$_cfg" -a -r "$_cfg" -a -f "$_cfg"; then
    dnl $1 may be a path to mysql_config
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_MYSQL_H], [1], [Define to `1' if you have the <mysql.h> header file.])
    mysql_config="$1"
  else
    AC_MSG_RESULT([no])
    mysql_lib_path=
    mysql_include_path=
    mysql_lib_name=mysqlclient

    for _pfx in $1; do
      _cfg="$_pfx/bin/mysql_config"

      AC_MSG_CHECKING([mysql_config availability in $_pfx/bin])

      if test -x "$_cfg" -a -r "$_cfg" -a -f "$_cfg"; then
        AC_MSG_RESULT([yes])
        AC_DEFINE([HAVE_MYSQL_H], [1], [Define to `1' if you have the <mysql.h> header file.])
        mysql_config="$_cfg"
        break
      else
        AC_MSG_RESULT([no])
      fi

      for dir in "$_pfx/lib" "$_pfx/lib/mysql"; do
        AC_MSG_CHECKING([$mysql_lib_name availability in $dir])
        name="$mysql_lib_name"

        if eval test -e "$dir/$libname_spec$shrext_cmds" -o -e "$dir/$libname_spec.$libext"; then
          AC_MSG_RESULT([yes])

          AC_MSG_CHECKING([$dir/$name usability])
          ac_save_LIBS="$LIBS"
          LIBS="$LIBS -L$dir"
          AC_CHECK_LIB([$mysql_lib_name], [mysql_init], [
            AC_MSG_RESULT([yes])
            mysql_lib_path="$dir"
          ], [
            AC_MSG_RESULT([no])
          ])
          LIBS="$ac_save_LIBS"

          if test ! -z "$mysql_lib_path"; then
            break
          fi
        else
          AC_MSG_RESULT([no])
        fi
      done

      for dir in "$_pfx/include" "$_pfx/include/mysql"; do
        AC_MSG_CHECKING([mysql headers availability in $dir])
        if test -e "$dir/mysql.h"; then
          AC_MSG_RESULT([yes])
          AC_MSG_CHECKING([mysql headers usability])
          ac_save_CPPFLAGS="$CPPFLAGS"
          CPPFLAGS="$CPPFLAGS -I$dir"
          AC_CHECK_HEADER([mysql.h], [
            AC_MSG_RESULT([yes])
            AC_DEFINE([HAVE_MYSQL_H], [1], [Define to `1' if you have the <mysql.h> header file.])
            mysql_include_path="$dir"
          ], [
            AC_MSG_RESULT([no])
          ])
          CPPFLAGS="$ac_save_CPPFLAGS"

          if test ! -z "$mysql_include_path"; then
            break
          fi
        else
          AC_MSG_RESULT([no])
        fi
      done
    done
  fi

  if test -z "$mysql_config"; then
    if test -z "$mysql_lib_path" -o -z "$mysql_include_path"; then
      AC_MSG_ERROR([Cannot locate mysql client library. Please check your mysql installation.])
    fi

    INCLUDES="$INCLUDES -I$mysql_include_path"
    LIBS="$LIBS -L$mysql_lib_path -l$mysql_lib_name"
  else
    CFLAGS="$CFLAGS `\"$mysql_config\" --cflags`"
    LIBS="$LIBS `\"$mysql_config\" --libs`"
  fi

  ac_save_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS $INCLUDES"
  AC_CHECK_FUNCS([mysql_real_query mysql_real_escape_string make_scrambled_password_323], [], [])
  CPPFLAGS="$ac_save_CPPFLAGS"
])

AC_DEFUN([PAM_MYSQL_CHECK_OPENSSL], [
  openssl_CFLAGS=
  openssl_LIBS=
  crypto_lib_name="crypto"
  ssl_lib_name="ssl"

  for _pfx in $1; do
    for dir in "$_pfx/include"; do
      if test -e "$dir/openssl/opensslv.h" -a -z "$openssl_CFLAGS"; then
        ac_save_CPPFLAGS="$CPPFLAGS"
        CPPFLAGS="$CPPFLAGS -I$dir/openssl"
        AC_CHECK_HEADERS([opensslv.h], [
          openssl_CFLAGS="-I$dir"
        ], [])
        CPPFLAGS="$ac_save_CPPFLAGS"
      fi
    done
    for dir in "$_pfx/lib" "$_pfx/lib/ssl" "$_pfx/lib/openssl"; do
      if test -z "$openssl_LIBS"; then
        ac_save_LIBS="$LIBS"
        LIBS="$LIBS -L$dir"
        name="$crypto_lib_name"
        if eval test -e "$dir/$libname_spec$shrext_cmds" -o -e "$dir/$libname_spec.$libext"; then
          name="$ssl_lib_name"
          if eval test -e "$dir/$libname_spec$shrext_cmds" -o -e "$dir/$libname_spec.$libext"; then
            LIBS="$LIBS -l$crypto_lib_name -l$ssl_lib_name"

            AC_CHECK_LIB([$crypto_lib_name], [CRYPTO_free], [
              AC_CHECK_LIB([$ssl_lib_name], [SSL_CTX_new], [
                openssl_LIBS="-L$dir -l$crypto_lib_name -l$ssl_lib_name"
              ])
            ],[]) 
          fi
        fi
        LIBS="$ac_save_LIBS"
      fi
    done
  done

  if test -z "$openssl_CFLAGS" -o -z "$openssl_LIBS"; then
    ifelse([$3],[],[:],[$3])
  else
    ifelse([$2],[],[:],[$2])
  fi
])

AC_DEFUN([PAM_MYSQL_CHECK_CRYPT], [
  AC_CHECK_LIB([crypt], [crypt], [ 
    LIBS="$LIBS -lcrypt"
  ], [])
  AC_CHECK_FUNCS([crypt], [], [])
])

AC_DEFUN([PAM_MYSQL_CHECK_CYRUS_SASL_V1], [
  sasl_v1_CFLAGS=
  sasl_v1_LIBS=
  sasl_v1_lib_name="sasl"

  for _pfx in $1; do
    for dir in "$_pfx/include"; do
      if test -e "$dir/sasl.h" -a -z "$sasl_CFLAGS"; then
        ac_save_CPPFLAGS="$CPPFLAGS"
        CPPFLAGS="$CPPFLAGS -I$dir"
        AC_MSG_CHECKING([if sasl.h is one of Cyrus SASL version 1])
        AC_TRY_RUN([
#include <sasl.h>

int main()
{
  return (SASL_VERSION_MAJOR == 1 ? 0: 1);
}
        ], [
          AC_MSG_RESULT([yes])
          sasl_v1_CFLAGS="-I$dir"
        ], [
          AC_MSG_RESULT([no])
        ])
        CPPFLAGS="$ac_save_CPPFLAGS"
      fi
    done
    for dir in "$_pfx/lib"; do
      if test -z "$sasl_v1_LIBS"; then
        ac_save_LIBS="$LIBS"
        LIBS="$LIBS -L$dir"
        name="$sasl_v1_lib_name"
        if eval test -e "$dir/$libname_spec$shrext_cmds" -o -e "$dir/$libname_spec.$libext"; then
          AC_CHECK_LIB([$sasl_v1_lib_name], [sasl_client_init], [
            sasl_v1_LIBS="-L$dir -l$sasl_v1_lib_name"
          ],[]) 
        fi
        LIBS="$ac_save_LIBS"
      fi
    done
  done

  if test -z "$sasl_v1_CFLAGS" -o -z "$sasl_v1_LIBS"; then
    ifelse([$3],[],[:],[$3])
  else
    ifelse([$2],[],[:],[$2])
  fi
])

AC_DEFUN([PAM_MYSQL_CHECK_CYRUS_SASL_V2], [
  sasl_v2_CFLAGS=
  sasl_v2_LIBS=
  sasl_v2_lib_name="sasl2"

  for _pfx in $1; do
    for dir in "$_pfx/include/sasl_v1" "$_pfx/include/sasl_v2" "$_pfx/include"; do
      if test -e "$dir/sasl.h" -a -z "$sasl_v2_CFLAGS"; then
        ac_save_CPPFLAGS="$CPPFLAGS"
        CPPFLAGS="$CPPFLAGS -I$dir"
        AC_MSG_CHECKING([if sasl.h is one of Cyrus SASL version 2])
        AC_TRY_RUN([
#include <sasl.h>

int main()
{
  return (SASL_VERSION_MAJOR == 2 ? 0: 1);
}
        ], [
          AC_MSG_RESULT([yes])
          sasl_v2_CFLAGS="-I$dir"
        ], [
          AC_MSG_RESULT([no])
        ])
        CPPFLAGS="$ac_save_CPPFLAGS"
      fi
    done
    for dir in "$_pfx/lib"; do
      if test -z "$sasl_v2_LIBS"; then
        ac_save_LIBS="$LIBS"
        LIBS="$LIBS -L$dir"
        name="$sasl_v2_lib_name"
        if eval test -e "$dir/$libname_spec$shrext_cmds" -o -e "$dir/$libname_spec.$libext"; then
          AC_CHECK_LIB([$sasl_v2_lib_name], [sasl_v2_client_init], [
            sasl_v2_LIBS="-L$dir -l$sasl_v2_lib_name"
          ],[]) 
        fi
        LIBS="$ac_save_LIBS"
      fi
    done
  done

  if test -z "$sasl_v2_CFLAGS" -o -z "$sasl_v2_LIBS"; then
    ifelse([$3],[],[:],[$3])
  else
    ifelse([$2],[],[:],[$2])
  fi
])

AC_DEFUN([PAM_MYSQL_CHECK_MD5_HEADERS], [
  AC_MSG_CHECKING([if md5.h is derived from Cyrus SASL Version 1])
  AC_TRY_COMPILE([
#include <md5global.h>
#include <md5.h>
  ], [
MD5_CTX ctx;
_sasl_MD5Init(&ctx);
  ], [
    AC_MSG_RESULT([yes])

    AC_DEFINE([HAVE_SASL_MD5_H], [1], [Define to 1 if md5.h in the include path is derived from cyrus-sasl_v1 package])
  ], [
    AC_MSG_RESULT([no])

    AC_CHECK_HEADERS([md5.h])
  ])

  AC_MSG_CHECKING([if md5.h is Solaris's])
  AC_TRY_COMPILE([
#include <md5.h>
  ], [
md5_calc(0, 0, 0);
  ], [
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_SOLARIS_MD5_H], [1], [Define to 1 if md5.h in the include path is Solaris's])
    AC_CHECK_LIB([md5], [md5_calc], [
      AC_DEFINE([HAVE_SOLARIS_LIBMD5], [1], [Define to 1 if Solaris's libmd5 is available])
      LIBS="$LIBS -lmd5"
    ])
  ], [
    AC_MSG_RESULT([no])

    AC_CHECK_HEADERS([md5.h])
    AC_CHECK_FUNCS([MD5Data])
  ])
])

AC_DEFUN([PAM_MYSQL_CHECK_DEFINES], [
  AC_FOREACH([AC_Header], [$2], [
    AH_TEMPLATE(AS_TR_CPP(HAVE_[]AC_Header),
	    [Define to 1 if ]AC_Header[ is an usable constant.])
  ])

  for ac_def in $2; do
    AC_MSG_CHECKING([$ac_def availability])
    AC_TRY_COMPILE([$1], [
int dummy = (int)$ac_def;
    ], [
      AC_MSG_RESULT([yes])
      AC_DEFINE_UNQUOTED(AS_TR_CPP(HAVE_$ac_def), 1)
    ], [
      AC_MSG_RESULT([no])
    ])
  done
])

AC_DEFUN([PAM_MYSQL_CHECK_IPV6], [
  ac_save_CFLAGS="$CFLAGS"
  CFLAGS="$INCLUDES $CFLAGS"
  PAM_MYSQL_CHECK_CONST([PF_INET6], [
    AC_CHECK_TYPES([struct sockaddr_in6,struct in6_addr], [
      AC_DEFINE([HAVE_IPV6], [1], [Define to 1 if IPv6 is available.])
    ], [], [
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
    ])
  ], [], [
#include <sys/types.h>
#include <sys/socket.h>
  ])
  CFLAGS="$ac_save_CFLAGS"
])

AC_DEFUN([PAM_MYSQL_CHECK_GETHOSTBYNAME_R], [
  ac_save_CFLAGS="$CFLAGS"
  CFLAGS="$INCLUDES $CFLAGS"

  AC_CHECK_FUNCS([gethostbyname_r], [
    AC_MSG_CHECKING([if gethostbyname_r() is part of glibc])
    AC_TRY_COMPILE([
#include <netdb.h>
], [
      int x = gethostbyname_r("", (struct hostent *)0, (char *)0, 0, (struct hostent **)0, (int *)0);
    ], [
      AC_MSG_RESULT([yes])
      AC_DEFINE([HAVE_GNU_GETHOSTBYNAME_R], [1], [Define to 1 if gethostbyname_r() is part of glibc])
    ], [
      AC_MSG_RESULT([no])
      AC_MSG_CHECKING([if gethostbyname_r() is part of SUN libc])
      AC_TRY_COMPILE([
#include <netdb.h>
], [
        struct hostent *x = gethostbyname_r("", (struct hostent *)0, (char *)0, 0, (int *)0);
      ], [
        AC_MSG_RESULT([yes])
        AC_DEFINE([HAVE_SUNOS_GETHOSTBYNAME_R], [1], [Define to 1 if gethostbyname_r() is part of SUN libc])
      ], [
        AC_MSG_RESULT([no])
      ])
    ])
  ], [])

   
  CFLAGS="$ac_save_CFLAGS"
])

AC_DEFUN([PAM_MYSQL_CHECK_NETWORK_LIBS], [
  AC_CHECK_LIB([socket], [socket], [
    LIBS="$LIBS -lsocket"
  ], [], [-lnsl])

  AC_CHECK_FUNC([gethostbyname], [
    AC_CHECK_LIB([nsl], [gethostbyname], [
      LIBS="$LIBS -lnsl"
    ], [], [-lsocket])
  ], [])
])

dnl vim600: sts=2 sw=2 ts=2 et
