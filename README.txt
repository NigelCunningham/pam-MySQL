pam-MySQL 1.0.0-alpha1
======================

This is the source code for pam-MySQL, released under the GPL v2 or later.

This release is a huge refactor of the code, switching the build system to
Meson and splitting the monolithic pam-mysql.c into a number of files so that I
can begin to make it unit testable.

I fully expect that a number of tweaks to the build scripts will be needed to
support other environments aside from my ArchLinux system. I intend to test
using VMs in the coming weeks, but will happily accept patches too.

Although the substance of the code is the same as previously, I wouldn't yet
recommend using this release in a production system. Let's bed it down first.

Thanks and hope this effort serves you well!

Nigel Cunningham 24 April 2021

SDG!
