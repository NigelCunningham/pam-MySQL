libdir = @PAM_MODS_DIR@
lib_LTLIBRARIES = pam_mysql.la

pam_mysql_la_SOURCES = pam_mysql.c
pam_mysql_la_LDFLAGS = -module -avoid-version

EXTRA_DIST = \
	INSTALL.pam-mysql \
	pam_mysql.spec.in

AM_DISTCHECK_CONFIGURE_FLAGS = --with-pam-mods-dir=\$${prefix}/lib/security
