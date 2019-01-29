project('posixsignalmanager', ['cpp'], default_options : ['cpp_std=c++14'])

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

posixsignalmanager_lib = static_library('posixsignalmangager', 'PosixSignalManager.cpp',
                                        qt5.preprocess(moc_headers: 'PosixSignalManager.h'),
                                        dependencies : qt5_dep, cpp_args: macros)

posixsignalmanager_dep = declare_dependency(link_with: posixsignalmanager_lib,
                                            include_directories: include_directories('.'),
                                            dependencies: [qt5_dep, librt])
if not meson.is_subproject()
  testlib = static_library('testlib', 'tests/catch_main.cpp')
  test('tests', executable('tests', 'tests/tests.cpp', link_with: [testlib],
       dependencies: [posixsignalmanager_dep, qt5_dep, librt]))
endif