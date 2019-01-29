#define CATCH_CONFIG_RUNNER
#define CATCH_CONFIG_NO_POSIX_SIGNALS
#include "catch.hpp"

#include <sys/resource.h>

int main( int argc, char* argv[] ) {
    rlimit lim;
    getrlimit(RLIMIT_CORE, &lim);
    lim.rlim_cur = 0;
    setrlimit(RLIMIT_CORE, &lim);
    return Catch::Session().run( argc, argv );
}
