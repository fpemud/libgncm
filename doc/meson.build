subdir('xml')

private_headers = [
  'config.h',
]

glib_prefix = dependency('glib-2.0').get_pkgconfig_variable('prefix')
glib_docpath = join_paths(glib_prefix, 'share', 'gtk-doc', 'html')
docpath = join_paths(get_option('datadir'), 'gtk-doc', 'html')

gnome.gtkdoc('gncm',
           main_xml: 'libgncm-docs.sgml',
            src_dir: [
              join_paths(meson.source_root(), 'src'),
              join_paths(meson.build_root(), 'src'),
            ],
       dependencies: libgncm_dep,
  gobject_typesfile: 'gncm.types',
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

