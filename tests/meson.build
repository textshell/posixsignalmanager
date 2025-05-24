# SPDX-License-Identifier: BSL-1.0

catch2_dep = dependency('catch2', required : get_option('system-catch2'))
if not catch2_dep.found()
  catch2_dep = declare_dependency(compile_args: ['-DBUNDLED_CATCH2'])
else
  if catch2_dep.version().version_compare('>=3.0')
    catch2_dep = [catch2_dep, declare_dependency(compile_args: ['-DCATCH3'])]
  endif
endif

testlib = static_library('testlib', 'catch_main.cpp', dependencies: [catch2_dep])
testdep_socket = []
if host_machine.system() == 'sunos'
  testdep_socket = cxx.find_library('socket')
endif

test_cpp_args = []
feraiseexcept_test_code = '''
#define _GNU_SOURCE
#include <fenv.h>

int main() {
    feenableexcept(FE_DIVBYZERO);
    feraiseexcept(FE_DIVBYZERO);
}
'''
if cxx.links(feraiseexcept_test_code,
     name: 'feraiseexcept')
  test_cpp_args += ['-DTEST_ENABLE_FERAISEEXCEPT']
endif

test_no_opts_cpp_args = []

# The tests are by necessity made using undefined behavior (after all it needs to test what happens in situations that
# are, for good reason, undefined behavior).
# To make this a bit more likely to work, just disable link time optimization if possible.
if cxx.has_argument('-fno-lto')
  test_no_opts_cpp_args += ['-fno-lto', '-O0']
endif

verbose_kwargs = {}
if meson.version().version_compare('>=0.62')
  verbose_kwargs += {'verbose': true}
endif

test('tests', executable('tests', 'tests.cpp', link_with: [testlib],
     dependencies: [posixsignalmanager_dep, qt_dep, librt, catch2_dep, testdep_socket],
     cpp_args: test_cpp_args + test_no_opts_cpp_args),
     kwargs: verbose_kwargs)
