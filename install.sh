#!/bin/bash

strip /lib/security/libpam_mysql.so
if [ -f /etc/redhat-release ]; then
  mv -f /lib/security/libpam_mysql.so /usr/lib64/security/pam_mysql.so
  rmdir /lib/security
else
  mv -f /lib/security/libpam_mysql.so /lib/security/pam_mysql.so
fi
