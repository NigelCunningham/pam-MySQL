#!/bin/bash

mv -f /lib/security/libpam_mysql.so /lib/security/pam_mysql.so
strip /lib/security/pam_mysql.so
