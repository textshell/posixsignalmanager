#define CATCH_CONFIG_RUNNER
#define CATCH_CONFIG_NO_POSIX_SIGNALS
#ifndef BUNDLED_CATCH2
#include "catch2/catch.hpp"
#else
#include "catch.hpp"
#endif

#include <sys/resource.h>

int main( int argc, char* argv[] ) {
    rlimit lim;
    getrlimit(RLIMIT_CORE, &lim);
    lim.rlim_cur = 0;
    setrlimit(RLIMIT_CORE, &lim);
    return Catch::Session().run( argc, argv );
}
