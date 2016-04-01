Summary: A PAM-module for authentication against MySQL
Name: pam_mysql
Version: 0.7RC1
Release: 1
Group: System Environment/Base
URL: http://sourceforge.net/projects/pam-mysql/
License: GPLv2
Source: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Requires: pam
BuildPrereq: mysql-devel pam-devel

%description
A PAM-module for authentication against MySQL

%define security_dir /lib/security/

%prep
%setup -n %{name}-%{version}
%build
%configure --prefix=${_prefix} --with-pam-mods-dir=%{security_dir}
%{__make}

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf "$RPM_BUILD_ROOT"
%{__make} install DESTDIR="$RPM_BUILD_ROOT"
rm -f "$RPM_BUILD_ROOT"%{security_dir}/*.la

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf "$RPM_BUILD_ROOT"
%{__make} clean

%files
%defattr(-,root,root)
/lib/security/pam_mysql.so
%doc NEWS README ChangeLog INSTALL CREDITS
