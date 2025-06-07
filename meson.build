# SPDX-License-Identifier: BSL-1.0

project('posixsignalmanager', ['cpp'],
  default_options : ['cpp_std=c++14'],
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

qt5 = import('qt5')
qt5_dep = dependency('qt5', modules: 'Core')

main_vscript = 'posixsignalmanager.symver'
if host_machine.system() == 'linux'
  # for now, only do this on linux, expand supported platforms as needed
  main_ld_vscript = '-Wl,--version-script,@0@/@1@'.format(meson.current_source_dir(), main_vscript)
else
  main_ld_vscript = []
endif


posixsignalmanager_lib = library('posixsignalmanager', 'PosixSignalManager.cpp',
                                 qt5.preprocess(moc_headers: 'PosixSignalManager.h'),
                                 dependencies : [qt5_dep, librt], cpp_args: macros,
                                 link_args : main_ld_vscript,
                                 link_depends : main_vscript,
                                 soversion: '0a',
                                 darwin_versions: ['1', '1'],
                                 install: true)

posixsignalmanager_dep = declare_dependency(link_with: posixsignalmanager_lib,
                                            include_directories: include_directories('.'),
                                            dependencies: [qt5_dep, librt])

install_headers('PosixSignalManager.h')

import('pkgconfig').generate(
  posixsignalmanager_lib,
  description: 'management of posix signals for environments using the qt event loop',
  filebase: 'PosixSignalManager',
  name: 'PosixSignalManager',
  subdirs: ['.']
)

if get_option('tests') and not meson.is_subproject()
  subdir('tests')
endif
