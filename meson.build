project(
  'pam-mySQL',
  'c',
  version: '0.9-alpha1',
  license: 'GPL v2',
  meson_version: '>=0.53.0',
  default_options: [
    'c_std=c11',
    'warning_level=2',
    'werror=false',
  ],
)

cc = meson.get_compiler('c')
prefix = get_option('prefix')

mysql_config = find_program('mysql_config')

mysql_includes_prefixed = run_command([mysql_config, '--include']).stdout().split()
mysql_includes = []
foreach i : mysql_includes_prefixed
  mysql_includes += i.substring(2)
endforeach

mysql_libs_prefixed = run_command([mysql_config, '--libs']).stdout().split()
mysql_libs = []
foreach i : mysql_libs_prefixed
  mysql_libs += i.substring(2)
endforeach

mysql_dep = declare_dependency(include_directories: mysql_includes)

config_inc = include_directories('.')
deps = [  mysql_dep  ]
extra_args = []

_search = join_paths(meson.current_source_dir(), 'lib')
foreach d : ['mysqlclient', 'crypto', 'crypt' ]
  deps += cc.find_library(d, dirs : _search)
endforeach

deps += cc.find_library('pam',
  has_headers: ['security/pam_modules.h', 'security/pam_appl.h']
)

sizeofshort = cc.sizeof('short')
sizeofint = cc.sizeof('int')
sizeoflong = cc.sizeof('long')

conf_data = configuration_data()
conf_data.set('SIZEOF_SHORT', sizeofshort)
conf_data.set('SIZEOF_INT', sizeofint)
conf_data.set('SIZEOF_LONG', sizeoflong)

check_headers = [
  ['HAVE_ARPA_INET_H', 'arpa/inet.h'],
  ['HAVE_CRYPT_H', 'crypt.h'],
  ['HAVE_DLFCN_H', 'dlfcn.h'],
  ['HAVE_ERRNO_H', 'errno.h'],
  ['HAVE_FCNTL_H', 'fcntl.h'],
  ['HAVE_INTTYPES_H', 'inttypes.h'],
  ['HAVE_MD5_H', 'md5.h'],
  ['HAVE_MEMORY_H', 'memory.h'],
  ['HAVE_MYSQL_H', 'mysql/mysql.h'],
  ['HAVE_NETDB_H', 'netdb.h'],
  ['HAVE_NETINET_IN_H', 'netinet/in.h'],
  ['HAVE_PAM_APPL_H', 'pam/appl.h'],
  ['HAVE_SASL_MD5_H', 'sasl/md5.h'],
  ['HAVE_SECURITY_PAM_APPL_H', 'security/pam_appl.h', 'security'],
  ['HAVE_SOLARIS_MD5_H', 'solaris/md5.h'],
  ['HAVE_STDARG_H', 'stdarg.h'],
  ['HAVE_STDINT_H', 'stdint.h'],
  ['HAVE_STDLIB_H', 'stdlib.h'],
  ['HAVE_STRINGS_H', 'strings.h'],
  ['HAVE_STRING_H', 'string.h'],
  ['HAVE_SYSLOG_H', 'syslog.h'],
  ['HAVE_SYS_PARAM_H', 'sys/param.h'],
  ['HAVE_SYS_SOCKET_H', 'sys/socket.h'],
  ['HAVE_SYS_STAT_H', 'sys/stat.h'],
  ['HAVE_SYS_TYPES_H', 'sys/types.h'],
  ['HAVE_UNISTD_H', 'unistd.h'],
]

foreach h : check_headers
  if cc.has_header(h.get(1))
    conf_data.set(h.get(0), 1)
#     if (h.length() > 2)
#       include_directories(h.get(2))
#     endif
  endif
endforeach

check_functions = [
# check token ['HAVE_BLOWFISH']
# check token ['HAVE_CYRUS_SASL_V1']
# check token ['HAVE_CYRUS_SASL_V2']
# check token ['HAVE_DECL_ELOOP']
# check token ['HAVE_DECL_EOVERFLOW']
  ['HAVE_GETADDRINFO', 'getaddrinfo', '#include <netdb.h>'],
  ['HAVE_GETHOSTBYNAME_R', 'gethostbyname_r', '#include <netdb.h>'],
# check token ['HAVE_GNU_GETHOSTBYNAME_R']
# check token ['HAVE_IPV6']
# check token ['HAVE_MAKE_SCRAMBLED_PASSWORD']
# check token ['HAVE_MAKE_SCRAMBLED_PASSWORD_323']
# check token ['HAVE_MD5DATA']
# ['HAVE_MYSQL_REAL_ESCAPE_STRING']
# check token ['HAVE_MYSQL_REAL_QUERY']
# check token ['HAVE_OPENSSL']
# check token ['HAVE_PAM_CONV_AGAIN']
# check token ['HAVE_PAM_INCOMPLETE']
# check token ['HAVE_PAM_NEW_AUTHTOK_REQD']
# check token ['HAVE_SOLARIS_LIBMD5']
# check token ['HAVE_STRUCT_IN6_ADDR']
# check token ['HAVE_STRUCT_SOCKADDR_IN6']
# check token ['HAVE_SUNOS_GETHOSTBYNAME_R']
]

foreach f : check_functions
  if cc.has_function(f.get(1), prefix : f.get(2))
    conf_data.set(f.get(0), 1)
  endif
endforeach

code = '''#include <security/pam_appl.h>
#include <security/pam_modules.h>

void func() {
    int data = 0;
    pam_get_user((void *)&data, (const char **)&data, (void *)&data);
    }
    '''
if (cc.compiles(code, name : 'PAM_GET_USER_CONST check', args: extra_args))
  conf_data.set('PAM_GET_USER_CONST', 'const')
else
  conf_data.set('PAM_GET_USER_CONST', '')
endif

code = '''#include <security/pam_appl.h>
#include <security/pam_modules.h>
void func() {
int data = 0;
    pam_get_data((void *)&data, (void *)&data, (const void **)&data);
    }
    '''
if (cc.compiles(code, name : 'PAM_GET_DATA_CONST check', args: extra_args))
  conf_data.set('PAM_GET_DATA_CONST', 'const')
else
  conf_data.set('PAM_GET_DATA_CONST', '')
endif

code = '''#include <security/pam_appl.h>
#include <security/pam_modules.h>
void func() {
int data = 0;
    pam_get_item((void *)&data, 0, (const void **)&data);
    }
    '''
if (cc.compiles(code, name : 'PAM_GET_ITEM_CONST check', args: extra_args))
  conf_data.set('PAM_GET_ITEM_CONST', 'const')
else
  conf_data.set('PAM_GET_ITEM_CONST', '')
endif

code = '''#include <security/pam_appl.h>
#include <security/pam_modules.h>

void func() {
        int (*conv)(int num_msg, const struct pam_message **msg,
        struct pam_response **resp, void *appdata_ptr) = 0;
    struct pam_conv c = { conv, 0 };
    c.conv = 0;
    }
    '''

if (cc.compiles(code, name : 'PAM_CONV_CONST check', args: extra_args))
  conf_data.set('PAM_CONV_CONST', 'const')
else
  conf_data.set('PAM_CONV_CONST', '')
endif

configure_file(
  output : 'config.h',
  configuration : conf_data)

configuration_inc = include_directories('.')

add_project_arguments('-DHAVE_CONFIG_H', language: 'c')

buildtarget = library('pam_mysql', [ 'src/pam_mysql.c', 'src/session.c', 'src/args.c', 'src/context.c', 'src/logging.c', 'src/alloc.c', 'src/mysql.c', 'src/strings.c', 'src/configuration.c' ], dependencies: deps, install: true, include_directories: configuration_inc)
