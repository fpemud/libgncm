# -*- meson -*-


#
# General operations
#
project('libgncm', 'c',
          version: '0.1',
          license: 'GPL3',
    meson_version: '>=0.40.1',
  default_options: [ 'warning_level=1', 'buildtype=debugoptimized', 'c_std=gnu11' ]
)

libgncm_version_major = meson.project_version().split('.')[0].to_int()
libgncm_version_minor = meson.project_version().split('.')[1].to_int()

apiversion = '@0@.0'.format(libgncm_version_major)
soversion = libgncm_version_major
libversion = '@0@.@1@'.format(libgncm_version_major, libgncm_version_minor)

config_h = configuration_data()


#
# Add compiler parameters
#
add_project_arguments([
  '-I' + meson.build_root(),
], language: 'c')


#
# Add advanced compiler parameters
#
cc = meson.get_compiler('c')

test_c_args = [
  '-Wcast-align',
  '-Wdeclaration-after-statement',
  '-Wformat-nonliteral',
  '-Wformat-security',
  '-Wmissing-include-dirs',
  '-Wnested-externs',
  '-Wno-missing-field-initializers',
  '-Wno-sign-compare',
  '-Wno-unused-parameter',
  '-Wpointer-arith',
  '-Wredundant-decls',
  '-Wuninitialized',
  ['-Werror=format-security', '-Werror=format=2' ],
  '-Werror=empty-body',
  '-Werror=implicit-function-declaration',
  '-Werror=incompatible-pointer-types',
  '-Werror=pointer-arith',
  '-Werror=init-self',
  '-Werror=int-conversion',
  '-Werror=misleading-indentation',
  '-Werror=missing-include-dirs',
  '-Werror=overflow',
  '-Werror=parenthesis',
  '-Werror=return-type',
  '-Werror=shadow',
  '-Werror=strict-prototypes',
  '-Werror=undef',
]
if get_option('buildtype') != 'plain'
  test_c_args += '-fstack-protector-strong'
endif
if get_option('enable_profiling')
  test_c_args += '-pg'
endif

global_c_args = []
foreach arg: test_c_args
  if cc.has_multi_arguments(arg)
    global_c_args += arg
  endif
endforeach
add_project_arguments(global_c_args, language: 'c')


#
# Detect and set symbol visibility
#
hidden_visibility_args = []
if get_option('default_library') != 'static'
  if cc.has_argument('-fvisibility=hidden')
    config_h.set('LIBGNCM_EXTERN', '__attribute__((visibility("default"))) extern')
    hidden_visibility_args = ['-fvisibility=hidden']
  endif
endif


#
# Generate config.h
#
configure_file(
         output: 'config.h',
  configuration: config_h)


#
# Setup various variables that subdirectory meson.build files need
#
girdir = join_paths(get_option('datadir'), 'gir-1.0')
typelibdir = join_paths(get_option('libdir'), 'girepository-1.0')
libdir = get_option('libdir')
vapidir = join_paths(get_option('datadir'), 'vala', 'vapi')
gnome = import('gnome')
# libversion is needed by subdirectory meson.build files
# gdhcp_version_major and gdhcp_version_minor are needed by subdirectory meson.build files
# hidden_visibility_args is needed by subdirectory meson.build files


#
# call subdirectory meson.build files
#
subdir('src')
#subdir('tests')
if get_option('enable_gtk_doc')
  subdir('doc')
endif
