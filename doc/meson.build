subdir('xml')

private_headers = [
  'config.h',
  'gdhcp-common.h',
  'gdhcp-ipv4ll.h',
  'gdhcp-unalighed.h',
  'gdhcp-version.h',
]

glib_prefix = dependency('glib-2.0').get_pkgconfig_variable('prefix')
glib_docpath = join_paths(glib_prefix, 'share', 'gtk-doc', 'html')
docpath = join_paths(get_option('datadir'), 'gtk-doc', 'html')

gnome.gtkdoc('gdhcp',
           main_xml: 'gdhcp-docs.sgml',
            src_dir: [
              join_paths(meson.source_root(), 'src'),
              join_paths(meson.build_root(), 'src'),
            ],
       dependencies: gdhcp_dep,
  gobject_typesfile: 'gdhcp.types',
          scan_args: [
            '--rebuild-types',
            '--ignore-decorators=LIBGNCM_EXTERN',
            '--ignore-headers=' + ' '.join(private_headers),
          ],
       fixxref_args: [
         '--html-dir=@0@'.format(docpath),
         '--extra-dir=@0@'.format(join_paths(glib_docpath, 'glib')),
         '--extra-dir=@0@'.format(join_paths(glib_docpath, 'gobject')),
         '--extra-dir=@0@'.format(join_paths(glib_docpath, 'gio')),
       ],
            install: true)

