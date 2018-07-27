# -*- meson -*-

gdhcp_header_subdir = 'gdhcp-@0@.0'.format(gdhcp_version_major)
gdhcp_header_dir = join_paths(get_option('includedir'), gdhcp_header_subdir)


#
# Generate gdhcp-version.h
#
version_data = configuration_data()
version_data.set('MAJOR_VERSION', gdhcp_version_major)
version_data.set('MINOR_VERSION', gdhcp_version_minor)
version_data.set('VERSION', meson.project_version())

gdhcp_version_h = configure_file(
                         input: 'gdhcp-version.h.in',
                        output: 'gdhcp-version.h',
                   install_dir: gdhcp_header_dir,
                       install: true,
                 configuration: version_data
)


#
# Generate library file
#
gdhcp_public_headers = [
  gdhcp_version_h,
  'gdhcp.h',
]

gdhcp_headers = [
  'gdhcp-common.h',
  'gdhcp-ipv4ll.h',
  'gdhcp-unaligned.h',
]

gdhcp_sources = [
  'gdhcp-common.c',
  'gdhcp-ipv4ll.c',
  'gdhcp-unaligned.c',
  'gdhcp-client.c',
  'gdhcp-server.c',
]

gdhcp_marshaller = gnome.genmarshal('gdhcp-marshal',
                      sources: 'gdhcp-marshal.list',
                       prefix: 'gdhcp_marshal',
                     internal: true
)

gdhcp_files = [
  gdhcp_public_headers,
  gdhcp_headers,
  gdhcp_sources,
  gdhcp_marshaller,
]

gdhcp_deps = [
  dependency('gio-2.0'),
]

gdhcp = library('gdhcp-' + apiversion, gdhcp_files,
            c_args: hidden_visibility_args,
      dependencies: gdhcp_deps,
         soversion: soversion,
           version: libversion,
           install: true,
)


#
# Generate introspection files
#
if get_option('with_introspection')

  gir = gnome.generate_gir(gdhcp,
                sources: gdhcp_public_headers,
              nsversion: apiversion,
              namespace: 'gdhcp',
          symbol_prefix: 'gdhcp_',
      identifier_prefix: 'GDHCP',
              link_with: gdhcp,
               includes: [ 'GLib-2.0' ],
                install: true,
        install_dir_gir: girdir,
    install_dir_typelib: typelibdir,
#             extra_args: [ '--c-include=gdhcp.h' ],
  )

  if get_option('with_vapi')
    gnome.generate_vapi('gdhcp-' + apiversion,
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
install_headers(gdhcp_public_headers, subdir: gdhcp_header_subdir)


#
# Generate dependency item and pkgconfig files
#
gdhcp_dep = declare_dependency(
              sources: gdhcp_public_headers,
         dependencies: gdhcp_deps,
            link_with: gdhcp,
  include_directories: include_directories('.'),
)

pkgg = import('pkgconfig')
pkgg.generate(
    libraries: [gdhcp],
      subdirs: gdhcp_header_subdir,
      version: meson.project_version(),
         name: 'gdhcp',
     filebase: 'gdhcp-@0@'.format(apiversion),
  description: 'DHCP library with GLib integration',
     requires: [ 'glib-2.0' ],
)

