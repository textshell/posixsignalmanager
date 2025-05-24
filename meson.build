# SPDX-License-Identifier: BSL-1.0

project('posixsignalmanager', ['cpp'],
  default_options : ['cpp_std=c++17'],
  version: '0.3')

macros = []
cxx = meson.get_compiler('cpp')

clock_gettime_test_code = '''
  #include <time.h>
  struct timespec t;
  int main (int argc, char ** argv) {
    return clock_gettime(CLOCK_REALTIME, &t);
  }'''
librt = []
if cxx.links(clock_gettime_test_code, args : '-lrt', name : 'clock_gettime in librt')
  librt = cxx.find_library('rt')
endif

if not cxx.has_function('pipe2')
  macros += ['-DNO_PIPE2']
endif

qt_version = get_option('qt')
qt = import(qt_version)
qt_dep = dependency(qt_version, modules: 'Core')

lib_name_base = 'posixsignalmanager'

if qt_version == 'qt5'
  lib_name_for_meson = lib_name_base
  pkg_filebase = 'PosixSignalManager'
  pkg_name = 'PosixSignalManager'
  pkg_description = 'Management of POSIX signals for Qt5 event loop'
elif qt_version == 'qt6'
  lib_name_for_meson = lib_name_base + '-qt6'
  pkg_filebase = 'PosixSignalManagerQt6'
  pkg_name = 'PosixSignalManagerQt6'
  pkg_description = 'Management of POSIX signals for Qt6 event loop'
else
  error('Unsupported qt option value: ' + qt_version + '. Must be "qt5" or "qt6".')
endif


main_vscript = 'posixsignalmanager.symver'
if host_machine.system() == 'linux'
  # for now, only do this on linux, expand supported platforms as needed
  main_ld_vscript = '-Wl,--version-script,@0@/@1@'.format(meson.current_source_dir(), main_vscript)
else
  main_ld_vscript = []
endif


posixsignalmanager_lib = library(lib_name_for_meson, 'PosixSignalManager.cpp',
                                 qt.preprocess(moc_headers: 'PosixSignalManager.h'),
                                 dependencies : [qt_dep, librt], cpp_args: macros,
                                 link_args : main_ld_vscript,
                                 link_depends : main_vscript,
                                 soversion: '0a',
                                 darwin_versions: ['1', '1'],
                                 install: true)

posixsignalmanager_dep = declare_dependency(link_with: posixsignalmanager_lib,
                                            include_directories: include_directories('.'),
                                            dependencies: [qt_dep, librt])

install_headers('PosixSignalManager.h')

import('pkgconfig').generate(
  posixsignalmanager_lib,
  description: pkg_description,
  filebase: pkg_filebase,
  name: pkg_name,
  subdirs: ['.']
)

if get_option('tests') and not meson.is_subproject()
  subdir('tests')
endif
