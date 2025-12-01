project(
	'tpmtest', 
	['cpp'],
	version: '0.0.1',
	default_options : ['cpp_std=c++17'],
	license: 'GPL-3.0-or-later',
)

project_description = 'TPM Test Application'
project_identifier = 'br.com.bb.@0@'.format(meson.project_name())

cxx = meson.get_compiler('cpp')

#
# Compiler flags
#
enable_debug = get_option('debug') or get_option('buildtype').contains('debug')

compiler_flags_common = [
	]

if enable_debug
  compiler_flags_common += [
    '-ggdb3',
	'-DDEBUG=1'
  ]
else
  compiler_flags_common += [
	'-DNDEBUG=1'
  ]
endif

global_cxxflags = cxx.get_supported_arguments(compiler_flags_common)

add_project_arguments(global_cxxflags, language: 'cpp')

#
# Configuration
#
conf_data = configuration_data()
conf_data.set_quoted('PACKAGE_NAME', meson.project_name())
conf_data.set_quoted('PACKAGE_VERSION', meson.project_version())
conf_data.set_quoted('PACKAGE_DESCRIPTION', project_description)

conf_data.set('app_username', meson.project_name())

if cxx.compiles('#include <unistd.h>', name : 'unistd.h')
  conf_data.set('HAVE_UNISTD_H', 1)
endif

if cxx.compiles('#include <getopt.h>', name : 'getopt.h')
  conf_data.set('HAVE_GETOPT', 1)
endif

configure_file(output : 
	'config.h', 
	configuration : conf_data
)

executable(
	meson.project_name(),
	[
		'tpmtest.cc', 
	],
	install: true,
	dependencies: [
		dependency('libnm'),
		dependency('OpenSSL'),
	],
)

