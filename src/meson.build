# -*- meson -*-

libgncm_header_subdir = 'libgncm-@0@.0'.format(libgncm_version_major)
libgncm_header_dir = join_paths(get_option('includedir'), libgncm_header_subdir)


#
# Generate library file
#
libgncm_public_headers = [
  'libgncm.h',
]

libgncm_headers = [
]

libgncm_sources = [
  'libgncm.c',
]

libgncm_marshaller = gnome.genmarshal('libgncm-marshal',
                      sources: 'libgncm-marshal.list',
                       prefix: 'libgncm_marshal',
                     internal: true
)

libgncm_files = [
  libgncm_public_headers,
  libgncm_headers,
  libgncm_sources,
  libgncm_marshaller,
]

libgncm_deps = [
  dependency('gio-2.0'),
]

libgncm = library('gncm-' + apiversion, libgncm_files,
            c_args: hidden_visibility_args,
      dependencies: libgncm_deps,
         soversion: soversion,
           version: libversion,
           install: true,
)


#
# Generate introspection files
#
if get_option('with_introspection')

  gir = gnome.generate_gir(libgncm,
                sources: libgncm_public_headers,
              nsversion: apiversion,
              namespace: 'gncm',
          symbol_prefix: 'gncm_',
      identifier_prefix: 'GNCM',
              link_with: libgncm,
               includes: [ 'GLib-2.0' ],
                install: true,
        install_dir_gir: girdir,
    install_dir_typelib: typelibdir,
  )

  if get_option('with_vapi')
    gnome.generate_vapi('gncm-' + apiversion,
                sources: gir[0],
               packages: [ 'glib-2.0' ],
                install: true,
            install_dir: vapidir,
    )
  endif
endif


#
# Install header files
#
install_headers(libgncm_public_headers, subdir: libgncm_header_subdir)


#
# Generate dependency item and pkgconfig files
#
libgncm_dep = declare_dependency(
              sources: libgncm_public_headers,
         dependencies: libgncm_deps,
            link_with: libgncm,
  include_directories: include_directories('.'),
)

pkgg = import('pkgconfig')
pkgg.generate(
    libraries: [libgncm],
      subdirs: libgncm_header_subdir,
      version: meson.project_version(),
         name: 'gncm',
     filebase: 'gncm-@0@'.format(apiversion),
  description: 'Global Network Config Management Library',
     requires: [ 'glib-2.0' ],
)

