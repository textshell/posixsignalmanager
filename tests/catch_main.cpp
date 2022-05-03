#define CATCH_CONFIG_RUNNER
#define CATCH_CONFIG_NO_POSIX_SIGNALS
#ifndef BUNDLED_CATCH2
#include "catch2/catch.hpp"
#else
#include "catch.hpp"
#endif

#include <sys/resource.h>
#include <sys/wait.h>
#include <signal.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif

int main( int argc, char* argv[] ) {
    rlimit lim;
    getrlimit(RLIMIT_CORE, &lim);
    lim.rlim_cur = 0;
    setrlimit(RLIMIT_CORE, &lim);

#ifdef __linux__
    // For linux setting the rlimit is not enough to avoid core dump processing when
    // the /proc/sys/kernel/core_pattern is a pipe. In that case only PR_SET_DUMPABLE
    // reliably disables core dump processing.
    // But debugging is harder with dumpable=0, so check first if this system has the
    // problem.

    bool needPrctl = false;

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return 2;
    }
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        if (r != 0) {
            perror("waitid");
            return 2;
        }
        if (info.si_pid != pid || info.si_status != SIGSEGV) {
            puts("Error in linux coredump check, exiting");
            return 2;
        }
        if (info.si_code == CLD_DUMPED) {
            needPrctl = true;
        }
    } else {
        int *p = (int*)32;
        *p = 42;
        _exit(99);
    }

    if (needPrctl) {
        if (prctl(PR_SET_DUMPABLE, 0) < 0) {
            perror("can't prctl(PR_SET_DUMPABLE)");
            exit(2);
        }
    }
#endif

    printf("NSIG: %d, SIGRTMAX: %d\n", NSIG,
#ifdef SIGRTMAX
           SIGRTMAX
#else
           -1
#endif
           );

    // Reset signal handling state to all default and nothing blocked

    sigset_t newmask, oldmask;
    sigemptyset(&newmask);
    sigprocmask(SIG_SETMASK, &newmask, &oldmask);
    for (int i = 1; i < NSIG; i++) {
        signal(i, SIG_DFL);
        if (sigismember(&oldmask, i)) {
            printf("signal masked %d\n", i);
        }
    }

    // Stash away stderr somewhere to go around redirections in test framework.
    dup2(1, 55);

    return Catch::Session().run( argc, argv );
}
