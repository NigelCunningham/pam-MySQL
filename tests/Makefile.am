TESTS = check_pam_mysql
check_PROGRAMS = check_pam_mysql
check_pam_mysql_SOURCES = check_pam_mysql.c $(top_builddir)/pam_mysql.h
check_pam_mysql_CFLAGS =
check_pam_mysql_LDADD = $(top_builddir)/.libs/libpam_mysql.la -l cmocka
