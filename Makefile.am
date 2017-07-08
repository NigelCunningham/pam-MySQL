# install this platform-dependent module by the 'install-exec' rules
AM_CFLAGS = -I$(top_srcdir)/include
AM_CXXFLAGS = -I$(top_srcdir)/include
AUTOMAKE_OPTIONS = subdir-objects

pamexecdir = @PAM_MODS_DIR@
pamexec_LTLIBRARIES = pam_mysql.la

pam_mysql_la_SOURCES = pam_mysql.c crypto.c crypto-sha1.c crypto-md5.c algo/pam_mysql_algo_sha256.cpp algo/pam_mysql_algo_sha512.cpp
pam_mysql_la_LDFLAGS = -module -avoid-version
pam_mysql_la_CPPFLAGS = $(openssl_CFLAGS)
pam_mysql_la_LIBADD   = $(openssl_LIBS) -lpam

EXTRA_DIST = INSTALL.pam-mysql
ACLOCAL_AMFLAGS = -I m4

AM_DISTCHECK_CONFIGURE_FLAGS = --with-pam-mods-dir=\$${prefix}/lib/security
