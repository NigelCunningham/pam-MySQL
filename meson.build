project(
  'pam-mySQL',
  'c',
  version: '0.9-alpha1',
  license: 'GPL v2',
  meson_version: '>=0.56.0',
  default_options: [
    'c_std=c11',
    'warning_level=2',
    'werror=false',
  ],
)

defs = [
	'-D_FILE_OFFSET_BITS=64',
	'-D_LARGEFILE_SOURCE',
	'-D_LARGE_FILES',
	'-D_GNU_SOURCE',
]

cc = meson.get_compiler('c')
prefix = get_option('prefix')

mysql_config = find_program('mysql_config')

mysql_includes_prefixed = run_command(mysql_config, '--include', check: true).stdout().split()
mysql_includes = []
foreach i : mysql_includes_prefixed
  mysql_includes += i.substring(2)
endforeach

mysql_libs_prefixed = run_command(mysql_config, '--libs', check: true).stdout().split()
mysql_libs = []
foreach i : mysql_libs_prefixed
  mysql_libs += i.substring(2)
endforeach

mysql_dep = declare_dependency(include_directories: mysql_includes)

config_inc = include_directories('.')
conf_data = configuration_data()
extra_args = []

libpam = [ cc.find_library('pam') ]

deps = [  mysql_dep, libpam  ]

if not(cc.has_function('pam_start',
  args: defs,
  dependencies: libpam,
  prefix: '''
          #include <security/pam_appl.h>
          '''
          ))
        error('Couldn\'t find security/pam_appl.h or pam_start in lib libpam')
endif

_search = join_paths(meson.current_source_dir(), 'lib')

foreach dep: [
    ['openssl', '>= 1.0.0', 'HAVE_OPENSSL'],
  ]
  result = dependency(dep[0], version: dep[1], required: false)
  deps += result
  if  (dep.length() > 2)
    conf_data.set(dep[2], result.found() ? 1 : 0)
  endif
endforeach

foreach dep: ['libmariadb']
  deps += dependency(dep)
endforeach

sizeofshort = cc.sizeof('short')
sizeofint = cc.sizeof('int')
sizeoflong = cc.sizeof('long')

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
  ['HAVE_SECURITY_PAM_APPL_H', 'security/pam_appl.h'],
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
  endif
endforeach

# Based on code from lighttpd.
conf_data.set('HAVE_CRYPT_H', cc.has_header('crypt.h'))
if conf_data.get('HAVE_CRYPT_H')
	# check if we need libcrypt for crypt_r / crypt

	# crypt_r in default libs?
	if cc.has_function('crypt_r', args: defs, prefix: '#include <crypt.h>')
		libcrypt = []
		conf_data.set('HAVE_CRYPT_R', 1)
	# crypt_r in -lcrypt ?
	elif cc.has_function('crypt_r', args: defs + ['-lcrypt'], prefix: '#include <crypt.h>')
		libcrypt = [ cc.find_library('crypt') ]
		conf_data.set('HAVE_CRYPT_R', 1)
	# crypt in default libs?
	elif cc.has_function('crypt', args: defs, prefix: '#include <crypt.h>')
		libcrypt = []
		conf_data.set('HAVE_CRYPT', 1)
	# crypt in -lcrypt ?
	elif cc.has_function('crypt', args: defs + ['-lcrypt'], prefix: '#include <crypt.h>')
		libcrypt = [ cc.find_library('crypt') ]
		conf_data.set('HAVE_CRYPT', 1)
	endif

        deps += libcrypt
endif

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

buildtarget = shared_library('pam_mysql', [
  'src/pam_mysql.c',
  'src/session.c',
  'src/args.c',
  'src/context.c',
  'src/logging.c',
  'src/alloc.c',
  'src/mysql.c',
  'src/strings.c',
  'src/configuration.c',
  'src/stream.c',
  'src/authenticate.c',
  'src/converse.c' ,
  'src/crypto.c',
  'src/crypto-sha1.c',
  'src/crypto-md5.c',
  'src/acct_mgmt.c',
  'src/chauthtok.c' ,
  'src/password_plain.c',
  'src/password_323.c',
  'src/password_crypt.c',
  'src/password_md5.c',
  'src/password_sha1.c',
  'src/password_drupal7.c',
  'src/password_joomla15.c',
  'src/password_ssha.c',
  'src/password_sha512.c',
  'src/password_sha256.c',
  'src/password.c',
  'src/md5.c',
  'src/pam_calls.c',
], dependencies: deps, install: true, include_directories: configuration_inc, name_prefix: '', install_dir: join_paths(get_option('libdir'), 'security'))

test_acct_mgmt = executable('test_acct_mgmt',
  sources: [
    'tests/acct_mgmt.c',
    'mocks/strings.c',
    'mocks/configuration.c',
    'mocks/args.c',
    'mocks/logging.c',
    'mocks/context.c',
    'mocks/mysql.c',
    'mocks/mock.c',
    'src/acct_mgmt.c',
    'src/alloc.c',
    ],
  dependencies: deps,
  c_args : '-DTEST',
  build_by_default: false,
  )

# test('verbose logging', test_acct_mgmt, args: ['verbose logging'])
# test('non verbose logging', test_acct_mgmt, args: ['non verbose logging'])
# test('str init alloc failure', test_acct_mgmt, args: ['str init alloc failure'])
# test('mysql format alloc failure', test_acct_mgmt, args: ['mysql format alloc failure'])
# test('mysql format - no extra where', test_acct_mgmt, args: ['mysql format - no extra where'])

test_config_file = executable('test_config_file',
  sources: [
    'mocks/logging.c',
    'mocks/converse.c' ,
    'mocks/mysql.c' ,
    'mocks/context.c',
    'tests/config_file.c',
    'tests/pam_calls.c',
    'src/session.c',
    'src/args.c',
    'src/alloc.c',
    'src/strings.c',
    'src/configuration.c',
    'src/stream.c',
    'src/authenticate.c',
    'src/crypto.c',
    'src/crypto-sha1.c',
    'src/crypto-md5.c',
    'src/acct_mgmt.c',
    'src/chauthtok.c' ,
    'src/password_plain.c',
    'src/password_323.c',
    'src/password_crypt.c',
    'src/password_md5.c',
    'src/password_sha1.c',
    'src/password_drupal7.c',
    'src/password_joomla15.c',
    'src/password_ssha.c',
    'src/password_sha512.c',
    'src/password_sha256.c',
    'src/password.c',
    'src/md5.c',
    ],
  dependencies: deps,
  c_args : '-DTEST',
  include_directories: configuration_inc,
  build_by_default: false,
  )

test('config file - local', test_config_file, args: [files('tests/config_file'), 'host', 'pukeko'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'db', 'totara'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'user', 'kiwi'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'passwd', 'my_secret'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'where', 'foo="bar"'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'table', 'users'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'update_table', 'update_table'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'usercolumn', 'user'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'passwdcolumn', 'pwd'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'statcolumn', 'status'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'select', 'select'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'crypt', 'Y'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'md5', 'false'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'sha256', 'true'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'sha512', 'true'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'blowfish', 'true'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'rounds', '2'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'disconnect_every_op', 'true'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'verbose', 'false'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'sqllog', 'false'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'logtable', 'logtable'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'logmsgcolumn', 'logmsgcolumn'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'logpidcolumn', 'logpidcolumn'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'logusercolumn', 'logusercolumn'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'loghostcolumn', 'loghostcolumn'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'logrhostcolumn', 'logrhostcolumn'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'logtimecolumn', 'logtimecolumn'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'use_323_passwd', 'false'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'ssl_mode', '1'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'ssl_cert', '/path/to/cert'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'ssl_key', '/path/to/key'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'ssl_ca', 'ca'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'ssl_capath', '/path/to'])
test('config file - local', test_config_file, args: [files('tests/config_file'), 'ssl_cipher', 'cipher'])

test_authenticate = executable('test_authenticate',
  sources: [
    'mocks/logging.c',
    'mocks/converse.c' ,
    'mocks/mysql.c' ,
    'mocks/context.c',
    'tests/authenticate.c',
    'tests/pam_calls.c',
    'src/session.c',
    'src/args.c',
    'src/alloc.c',
    'src/strings.c',
    'src/configuration.c',
    'src/stream.c',
    'src/authenticate.c',
    'src/crypto.c',
    'src/crypto-sha1.c',
    'src/crypto-md5.c',
    'src/acct_mgmt.c',
    'src/chauthtok.c' ,
    'src/password_plain.c',
    'src/password_323.c',
    'src/password_crypt.c',
    'src/password_md5.c',
    'src/password_sha1.c',
    'src/password_drupal7.c',
    'src/password_joomla15.c',
    'src/password_ssha.c',
    'src/password_sha512.c',
    'src/password_sha256.c',
    'src/password.c',
    'src/md5.c',
    ],
  dependencies: deps,
  c_args : '-DTEST',
  include_directories: configuration_inc,
  build_by_default: false,
  )

test('plain text auth', test_authenticate, args: ['plain'])
test('323 auth', test_authenticate, args: ['323'])
test('crypt auth', test_authenticate, args: ['crypt'])
test('md5 auth', test_authenticate, args: ['md5'])
test('sha1 auth', test_authenticate, args: ['sha1'])
test('drupal7 auth', test_authenticate, args: ['drupal7'])
test('joomla15 auth', test_authenticate, args: ['joomla15'])
test('ssha auth', test_authenticate, args: ['ssha'])
test('sha512 auth', test_authenticate, args: ['sha512'])
test('sha256 auth', test_authenticate, args: ['sha256'])
test('blowfish auth', test_authenticate, args: ['blowfish'])
