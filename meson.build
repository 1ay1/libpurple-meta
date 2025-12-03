# libpurple-meta - Meson Build Configuration
# Meta (Facebook Messenger + Instagram DM) protocol plugin for Pidgin/libpurple

project('libpurple-meta', 'c',
  version: '0.1.0',
  license: 'GPL-3.0-or-later',
  meson_version: '>= 0.56.0',
  default_options: [
    'c_std=c11',
    'warning_level=2',
  ]
)

# Plugin information
plugin_name = 'prpl-meta'
plugin_version = meson.project_version()

# Dependencies
glib_dep = dependency('glib-2.0', version: '>= 2.52.0')
gobject_dep = dependency('gobject-2.0', version: '>= 2.52.0')
gio_dep = dependency('gio-2.0', version: '>= 2.52.0')
json_glib_dep = dependency('json-glib-1.0', version: '>= 1.4.0')
zlib_dep = dependency('zlib')

# Try libpurple 3 first, then fall back to libpurple 2
purple3_dep = dependency('purple-3', required: false)
if purple3_dep.found()
  purple_dep = purple3_dep
  purple_version = 3
  add_project_arguments('-DPURPLE_VERSION=3', language: 'c')
  message('Found libpurple 3.x')
else
  # Try alternate name for purple 3
  purple3_alt_dep = dependency('purple', version: '>= 3.0.0', required: false)
  if purple3_alt_dep.found()
    purple_dep = purple3_alt_dep
    purple_version = 3
    add_project_arguments('-DPURPLE_VERSION=3', language: 'c')
    message('Found libpurple 3.x (alternate)')
  else
    # Fall back to libpurple 2.x
    purple2_dep = dependency('purple', version: '>= 2.10.0', required: false)
    if purple2_dep.found()
      purple_dep = purple2_dep
      purple_version = 2
      add_project_arguments('-DPURPLE_VERSION=2', language: 'c')
      message('Found libpurple 2.x - using compatibility layer')
    else
      error('libpurple not found. Please install pidgin/libpurple development files.')
    endif
  endif
endif

# Optional: libsoup for alternative WebSocket implementation
soup_dep = dependency('libsoup-3.0', required: false)
if not soup_dep.found()
  soup_dep = dependency('libsoup-2.4', required: false)
endif

if soup_dep.found()
  add_project_arguments('-DHAVE_LIBSOUP', language: 'c')
endif

# Source files - Common modules
common_sources = files(
  'src/common/meta-auth.c',
  'src/common/meta-websocket.c',
  'src/common/meta-security.c',
  'src/common/meta-config.c',
  'src/common/meta-http.c',
)

# Source files - Service modules
messenger_sources = files(
  'src/messenger/messenger.c',
)

instagram_sources = files(
  'src/instagram/instagram.c',
)

# Source files - Main plugin
plugin_sources = files(
  'src/prpl-meta.c',
)

all_sources = common_sources + messenger_sources + instagram_sources + plugin_sources

# Include directories
include_dirs = include_directories('src')

# Compiler flags
c_args = [
  '-DHAVE_CONFIG_H',
  '-DG_LOG_DOMAIN="@0@"'.format(plugin_name),
]

if get_option('buildtype') == 'debug'
  c_args += ['-DDEBUG', '-g', '-O0']
endif

# Warnings - be strict but allow some flexibility
warning_flags = [
  '-Wno-unused-parameter',
  '-Wno-missing-field-initializers',
]

c_args += warning_flags

# Build the shared library (plugin)
plugin_deps = [
  glib_dep,
  gobject_dep,
  gio_dep,
  json_glib_dep,
  zlib_dep,
  purple_dep,
]

if soup_dep.found()
  plugin_deps += soup_dep
endif

# Determine plugin install directory
if purple_version == 3
  plugin_install_dir = purple_dep.get_variable(pkgconfig: 'plugindir',
    default_value: get_option('libdir') / 'purple-3' / 'plugins')
else
  plugin_install_dir = purple_dep.get_variable(pkgconfig: 'plugindir',
    default_value: get_option('libdir') / 'purple-2' / 'plugins')
endif

prpl_meta = shared_library(plugin_name,
  all_sources,
  c_args: c_args,
  include_directories: include_dirs,
  dependencies: plugin_deps,
  install: true,
  install_dir: plugin_install_dir,
  name_prefix: '',
  name_suffix: 'so',
)

# Install configuration file
install_data(
  'config/meta-config.json',
  install_dir: get_option('datadir') / 'purple' / 'meta',
)

# Generate pkg-config file (optional, for other plugins to depend on this)
pkg = import('pkgconfig')
pkg.generate(prpl_meta,
  name: meson.project_name(),
  description: 'Meta protocol plugin for Pidgin (Facebook Messenger + Instagram DM)',
  version: meson.project_version(),
  requires: ['glib-2.0', 'json-glib-1.0'],
)

# Configuration header
config_h = configuration_data()
config_h.set_quoted('PACKAGE_NAME', meson.project_name())
config_h.set_quoted('PACKAGE_VERSION', meson.project_version())
config_h.set_quoted('PLUGIN_ID', plugin_name)
config_h.set('PURPLE_VERSION_MAJOR', purple_version)
config_h.set('HAVE_LIBSOUP', soup_dep.found())

configure_file(
  output: 'config.h',
  configuration: config_h,
)

# Summary
summary({
  'Plugin name': plugin_name,
  'Version': plugin_version,
  'libpurple version': purple_version,
  'libsoup support': soup_dep.found(),
  'Build type': get_option('buildtype'),
  'Install directory': plugin_install_dir,
}, section: 'Configuration')

summary({
  'Security module': true,
  'Config module': true,
  'Messenger service': true,
  'Instagram service': true,
}, section: 'Modules')
