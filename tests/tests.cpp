#if __has_include(<aio.h>)
#include <aio.h>
#endif
#include <fcntl.h>
#if __has_include(<mqueue.h>)
#include <mqueue.h>
#endif
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <signal.h>
#if defined(__sun)
#include <sys/stropts.h>
#endif

#define CATCH_CONFIG_EXTERNAL_INTERFACES
#define CATCH_CONFIG_NO_POSIX_SIGNALS
#ifndef BUNDLED_CATCH2
#include "catch2/catch.hpp"
#else
#include "catch.hpp"
#endif

#include <QVector>
#include <QCoreApplication>
#include <QSharedPointer>
#include <QTimer>

#include "PosixSignalManager.h"

struct SaneStateListener : Catch::TestEventListenerBase {
    SaneStateListener(Catch::ReporterConfig const& _config) : Catch::TestEventListenerBase(_config) {
        mainPid = getpid();
    }

    using TestEventListenerBase::TestEventListenerBase; // inherit constructor

    virtual void testCaseStarting(Catch::TestCaseInfo const& testInfo) override {
        (void)testInfo;
        if (getpid() != mainPid) {
            puts("FATAL: child process did escape into test runner");
            abort();
        }
        if (PosixSignalManager::isCreated()) {
            puts("FATAL: PosixSignalManager was created in test runner process.");
            abort();
        }
    }

    virtual void testCaseEnded(Catch::TestCaseStats const& testCaseStats) override {
        if (getpid() != mainPid) {
            puts("FATAL: child process did escape into test runner. Test:");
            puts(testCaseStats.testInfo.name.c_str());
            abort();
        }
        if (PosixSignalManager::isCreated()) {
            puts("FATAL: PosixSignalManager was created in test runner process. Test:");
            puts(testCaseStats.testInfo.name.c_str());
            abort();
        }
    }

    pid_t mainPid;
};
CATCH_REGISTER_LISTENER(SaneStateListener)

#ifdef __linux__
bool isLinux() {
    utsname uts;
    uname(&uts);
    return (strcmp(uts.sysname, "Linux") == 0);
}

QVector<int> utsRelease() {
    utsname uts;
    uname(&uts);
    QVector<int> r;
    for (QString part : QString(uts.release).split('.')) {
        bool ok;
        int num = part.toUInt(&ok, 10);
        if (ok) {
            r.append(num);
        } else {
            break;
        }
    }
    return r;
}
#endif

struct shared_page {
    std::atomic<int> caught_signal;
    enum { notcalled, termination, sync, notify } type = notcalled;
    std::atomic<int> sig_count;
    siginfo_t info;
    int misc = 0;

    shared_page() {
        caught_signal.store(0);
        sig_count.store(0);
    }
};

shared_page *shared = nullptr;


void cause_sigsegv() {
    int *p = (int*)32;
    *p = 42;
}

int zero = 0;

void cause_sigfpe() {
    printf("%d\n", 3 / zero);
}

void cause_sigill() {
#if defined(__GNUC__)
#if defined(__i386__)
    __asm__(
        "ud2\n"
    );
#elif defined(__x86_64__)
    __asm__(
        "ud2\n"
    );
#else
#define NO_SIGILL
#endif
#else
#define NO_SIGILL
#endif
}

void cause_sigtrap() {
#if defined(__GNUC__)
#if defined(__i386__)
    __asm__(
        "int $3\n"
    );
#elif defined(__x86_64__)
    __asm__(
        "int $3\n"
    );
#else
#define NO_SIGTRAP
#endif
#else
#define NO_SIGTRAP
#endif
}

void cause_sigbus() {
#if !defined(__sun)
    int fd = open("signalmanager_test_tmpfile", O_CREAT | O_RDWR, 0700);
    unlink("signalmanager_test_tmpfile");
    char *ptr = (char*)mmap(nullptr, 4096, PROT_WRITE, MAP_PRIVATE, fd, 0);
    *ptr = 5;
#else
    int fd = open("faultfs/always_eio", O_RDONLY, 0700);
    char *ptr = (char*)mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    printf("%c\n", *ptr);
#endif
}

void checkdeps_sigbus() {
#if defined(__sun)
    if (access("faultfs/always_eio", R_OK)) {
        // see fusefault.c for implementation of this file system.
        FAIL("Need fault fuse filesystem mounted at \"faultfs/always_eio\".");
    }
#endif
}

void reraise_handler(PosixSignalFlags &flags, const siginfo_t *info, void *context) {
    ++shared->sig_count;
    shared->type = shared_page::sync;
    memcpy(&shared->info, info, sizeof(*info));
    shared->caught_signal.store(info->si_signo);
    flags.reraise();
}

void termination_handler(const siginfo_t *info, void *context) {
    ++shared->sig_count;
    shared->type = shared_page::termination;
    memcpy(&shared->info, info, sizeof(*info));
    shared->caught_signal.store(info->si_signo);
}

void debugout(const char* s) {
    write(55, s, strlen(s));
    write(55, "\n", 1);
}

struct SharedPageAlloc {
    SharedPageAlloc() {
        shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
        REQUIRE(shared != MAP_FAILED);
        new (shared) shared_page();
    }

    ~SharedPageAlloc() {
        if (munmap(shared, sizeof(shared_page)) != 0) {
            debugout("Failed to unmap communication page");
            abort();
        }
        shared = nullptr;
    }
};

#if defined(__OpenBSD__) || defined(__APPLE__)

#define WAIT_CHILD                         \
    int info;                              \
    errno = 0;                             \
    int r = waitpid(WAIT_ANY, &info, WUNTRACED | WCONTINUED);   \
    INFO("info=" << std::hex << info);     \
    REQUIRE(r != -1)

#define WAS_SIGNALED_WITH(signo)        \
    CHECK(r == pid);                    \
    CHECK(WIFSIGNALED(info));           \
    CHECK(WTERMSIG(info) == signo)

#define HAS_EXITED_WITH(retno)          \
    CHECK(r == pid);                    \
    CHECK(WIFEXITED(info));             \
    CHECK(WEXITSTATUS(info) == retno)

#define WAS_STOPPED(signo)              \
    CHECK(r == pid);                    \
    CHECK(WIFSTOPPED(info));

#define WAS_CONTINUED(signo)            \
    CHECK(r == pid);                    \
    CHECK(WIFCONTINUED(info));

#else

#define WAIT_CHILD                                                      \
    siginfo_t info;                                                     \
    errno = 0;                                                          \
    int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);   \
    REQUIRE(r == 0)

#define WAS_SIGNALED_WITH(signo)        \
    CHECK(info.si_pid == pid);          \
    CHECK(info.si_code == CLD_KILLED);  \
    CHECK(info.si_status == signo)

#define HAS_EXITED_WITH(retno)          \
    CHECK(info.si_pid == pid);          \
    CHECK(info.si_code == CLD_EXITED);  \
    CHECK(info.si_status == retno)

#define WAS_STOPPED(signo)              \
    CHECK(info.si_pid == pid);          \
    CHECK(info.si_code == CLD_STOPPED); \
    CHECK(info.si_status == signo)

#define WAS_CONTINUED(signo)              \
    CHECK(info.si_pid == pid);            \
    CHECK(info.si_code == CLD_CONTINUED); \
    CHECK(info.si_status == signo)

#endif

#ifdef NSIG
#if defined(__linux__) || !defined(SIGRTMAX) || defined(__sun)
    #define NUM_SIGNALS NSIG
#else
    #if SIGRTMAX > NSIG
    #define NUM_SIGNALS (SIGRTMAX + 1)
    #else
    #define NUM_SIGNALS NSIG
    #endif
#endif
#else
#error missing signal number macro
#endif

TEST_CASE( "signal classification" ) {
    int signo = GENERATE(range(1, NUM_SIGNALS));
    CAPTURE(signo);
    if (signo == SIGKILL || signo == SIGSTOP || signo == SIGTSTP || signo == SIGTTIN || signo == SIGTTOU) {
        // all these are special, classification does not cover this, so just skip.
        return;
    }
#ifdef SIGRTMIN
    if (signo > NSIG && signo < SIGRTMIN) {
        // There can be a gap between no real time signals and realtime signals. This is e.g. the case with freebsd.
        return;
    }
#endif
    int classification = PosixSignalManager::classifySignal(signo);
    CAPTURE(classification);
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        if (shared->misc == 1) {
            HAS_EXITED_WITH(11);
        } else if (classification > 0) {
            WAS_SIGNALED_WITH(signo);
        } else {
            HAS_EXITED_WITH(99);
        }
    } else {
        if (signal(signo, SIG_DFL) == SIG_ERR) {
            // Certain signal numbers don't really exist or are reserved for libc/OS usage. Skip those.
            shared->misc = 1;
            _exit(11);
        }
        raise(signo);
        _exit(99);
    }
}

TEST_CASE( "baseline sigsegv" ) {
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGSEGV);
    } else {
        cause_sigsegv();
        _exit(99);
    }
}

TEST_CASE( "reraise sigsegv" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGSEGV);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGSEGV);
        CHECK(shared->type == shared_page::sync);
        CHECK(shared->info.si_code == SEGV_MAPERR);
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGSEGV, &reraise_handler);
        cause_sigsegv();
        _exit(99);
    }
}

TEST_CASE( "reraise sigsegv in fork" ) {
    int follow = GENERATE(0, 1, 2);
    CAPTURE(follow);
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        HAS_EXITED_WITH(42);
        if (follow == 0) {
            CHECK(shared->sig_count == 0);
        } else {
            CHECK(shared->sig_count == 1);
            CHECK(shared->caught_signal.load() == SIGSEGV);
            CHECK(shared->type == shared_page::sync);
            CHECK(shared->info.si_code == SEGV_MAPERR);
        }
    } else {
        PosixSignalOptions options;
        if (follow == 0) {
            options = PosixSignalOptions().dontFollowForks();
        } else if (follow == 1) {
            options = PosixSignalOptions().followForks();
        }
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGSEGV, &reraise_handler, options);

        pid_t innerPid = fork();
        if (innerPid == -1) {
            perror("inner fork");
            _exit(99);
        }

        if (innerPid == 0) {
            cause_sigsegv();
            _exit(99);
        }

        int innerStatus;
        waitpid(innerPid, &innerStatus, 0);

        _exit(42);
    }
}

TEST_CASE( "reraise 'raised' sigsegv" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGSEGV);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGSEGV);
        CHECK(shared->type == shared_page::sync);
#if defined(__OpenBSD__) || defined(__APPLE__)
#elif !defined(__FreeBSD__) && !defined(__NetBSD__) && !defined(__sun)
        CHECK(shared->info.si_code == SI_TKILL);
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__sun)
        CHECK(shared->info.si_code == SI_LWP);
#else
        INFO("si_code: " << shared->info.si_code);
        CHECK("Expected si_code for this system unknown" == nullptr);
#endif
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGSEGV, &reraise_handler);
        raise(SIGSEGV);
        _exit(99);
    }
}

TEST_CASE( "reraise 'killed' sigsegv" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGSEGV);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGSEGV);
        CHECK(shared->type == shared_page::sync);
#if defined(__APPLE__)
#else
        CHECK(shared->info.si_code == SI_USER);
#endif
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGSEGV, &reraise_handler);
        kill(getpid(), SIGSEGV);
        _exit(99);
    }
}

#if defined(SIGRTMIN)
// ^^^ sigqueue depends on realtime signals
TEST_CASE( "reraise 'queued' sigsegv" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGSEGV);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGSEGV);
        CHECK(shared->type == shared_page::sync);
        CHECK(shared->info.si_code == SI_QUEUE);
        CHECK(shared->info.si_value.sival_int == 42);
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGSEGV, &reraise_handler);
        sigval sv;
        sv.sival_int = 42;
        sigqueue(getpid(), SIGSEGV, sv);
        _exit(99);
    }
}
#endif

#ifdef __linux__
TEST_CASE( "reraise 'io' sigsegv" ) {
    bool linux_pre_4_14 = false;
    if (isLinux() && utsRelease() < QVector<int>{4,14}) {
        WARN("\"reraise 'io' sigsegv\" test uses degraded handling on linux kernel < 4.14");
        linux_pre_4_14 = true;
    }

    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGSEGV);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGSEGV);
        CHECK(shared->type == shared_page::sync);
        if (!linux_pre_4_14) {
            CHECK(shared->info.si_code == SI_SIGIO);
        } else {
            CHECK(shared->info.si_code == POLL_IN);
        }
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGSEGV, &reraise_handler);
        int sv[2];
        int flags;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
            perror("socketpair");
            goto bad;
        }
        if (fcntl(sv[0], F_SETOWN, getpid()) == -1) {
            perror("setown");
            goto bad;
        }
        if (fcntl(sv[0], F_SETSIG, SIGSEGV)) {
            perror("setsig");
            goto bad;
        }
        flags = fcntl(0, F_GETFL);
        if (fcntl(sv[0], F_SETFL, flags | O_ASYNC) == -1) {
            perror("setfl async");
            goto bad;
        }
        write(sv[1], "b", 1);
        sleep(1);
        _exit(99);
bad:
        _exit(98);
    }
}
#endif

#if defined(SIGRTMIN)
// ^^^ timer_create depends on realtime signals
TEST_CASE( "reraise 'timer' sigsegv" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGSEGV);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGSEGV);
        CHECK(shared->type == shared_page::sync);
        CHECK(shared->info.si_code == SI_TIMER);
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGSEGV, &reraise_handler);
        timer_t timerid;
        sigevent sev;
        sev.sigev_notify = SIGEV_SIGNAL;
        sev.sigev_signo = SIGSEGV;
        sev.sigev_value.sival_ptr = &timerid;
        if (timer_create(CLOCK_REALTIME, &sev, &timerid) == -1) {
            perror("timer_create");
            _exit(98);
        }
        itimerspec its;
        its.it_value.tv_sec = 0;
        its.it_value.tv_nsec = 1;
        its.it_interval.tv_sec = its.it_value.tv_sec;
        its.it_interval.tv_nsec = its.it_value.tv_nsec;
        if (timer_settime(timerid, 0, &its, NULL) == -1) {
            perror("timer_settime");
            _exit(98);
        }
        pause();
        _exit(99);
    }
}
#endif

#if __has_include(<mqueue.h>)
#if defined(__FreeBSD__)
// FreeBSD doesn't implement mq_open (it only returns ENOSYS)
TEST_CASE( "mqueue not implemented" ) {
    const char *name = "/PosixSignalManager-test";
    mq_unlink(name);
    errno = 0;
    mqd_t mqdes = mq_open(name, O_RDWR | O_CREAT, 0600, nullptr);
    auto saved_errno = errno;
    REQUIRE(mqdes == (mqd_t)-1);
    REQUIRE(saved_errno == ENOSYS);
}
#else
#define HAVE_MQ 1
#endif
#endif

#if HAVE_MQ
TEST_CASE( "reraise 'mq' sigsegv" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGSEGV);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGSEGV);
        CHECK(shared->type == shared_page::sync);
        CHECK(shared->info.si_code == SI_MESGQ);
        CHECK(shared->info.si_value.sival_int == 42);
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGSEGV, &reraise_handler);
        const char *name = "/PosixSignalManager-test";
        mq_unlink(name);
        mqd_t mqdes = mq_open(name, O_RDWR | O_CREAT, 0600, nullptr);
        if (mqdes == (mqd_t)-1) {
            perror("mq_open");
            _exit(98);
        }
        //mq_unlink(name);
        sigevent sev;
        sev.sigev_notify = SIGEV_SIGNAL;
        sev.sigev_signo = SIGSEGV;
        sev.sigev_value.sival_int = 42;
        if (mq_notify(mqdes, &sev) == -1) {
            perror("mq_notify");
            _exit(98);
        }
        if (mq_send(mqdes, "test", 4, 0) == -1) {
            perror("mq_send");
            _exit(98);
        }
        pause();
        _exit(99);
    }
}
#endif

#if __has_include(<aio.h>)
TEST_CASE( "reraise 'aio' sigsegv" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGSEGV);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGSEGV);
        CHECK(shared->type == shared_page::sync);
#if defined(__APPLE__)
#else
        CHECK(shared->info.si_code == SI_ASYNCIO);
        CHECK(shared->info.si_value.sival_int == 42);
#endif
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGSEGV, &reraise_handler);
        int fd = open("PosixSignalManager-aiotest", O_CREAT | O_RDWR, 0600);
        if (fd < 0) {
            perror("open");
            _exit(98);
        }
        if (write(fd, "b", 1) != 1) {
            perror("write");
            _exit(98);
        }
        char buff[1];
        aiocb cb;
        cb.aio_fildes = fd;
        cb.aio_offset = 0;
        cb.aio_buf = buff;
        cb.aio_nbytes = 1;
        cb.aio_reqprio = 0;
        cb.aio_sigevent.sigev_notify = SIGEV_SIGNAL;
        cb.aio_sigevent.sigev_signo = SIGSEGV;
        cb.aio_sigevent.sigev_value.sival_int = 42;
        if (aio_read(&cb) == -1) {
            perror("aio_read");
            _exit(98);
        }
        pause();
        _exit(99);
    }
}
#endif

#ifndef NO_SIGBUS
TEST_CASE( "baseline sigbus" ) {
    checkdeps_sigbus();
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGBUS);
    } else {
        cause_sigbus();
        _exit(99);
    }
}
#endif

#ifndef NO_SIGBUS
TEST_CASE( "reraise sigbus" ) {
    checkdeps_sigbus();
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGBUS);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGBUS);
        CHECK(shared->type == shared_page::sync);
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGBUS, &reraise_handler);
        cause_sigbus();
        _exit(99);
    }
}
#endif

TEST_CASE( "reraise 'killed' sigbus" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGBUS);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGBUS);
        CHECK(shared->type == shared_page::sync);
#if defined(__APPLE__) || defined(__OpenBSD__)
#else
        CHECK(shared->info.si_code == SI_USER);
#endif
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGBUS, &reraise_handler);
        kill(getpid(), SIGBUS);
        _exit(99);
    }
}

#if defined(SIGIO)
// ^^^ on some operating systems SIGIO is an alias to SIGPOLL
#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__APPLE__) && !defined(__NetBSD__)
// ^^^ on {freebsd,openbsd,apple,netbsd} sigio is ignored by default, so reraise will not kill the child
TEST_CASE( "reraise sigio" ) {
    REQUIRE(PosixSignalManager::classifySignal(SIGIO) > 0);
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGIO);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGIO);
        CHECK(shared->type == shared_page::sync);
        CHECK(shared->info.si_code == POLL_IN);
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGIO, &reraise_handler);
        int sv[2];
        int flags;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
            perror("socketpair");
            goto bad;
        }
        if (fcntl(sv[0], F_SETOWN, getpid()) == -1) {
            perror("setown");
            goto bad;
        }
#ifdef F_SETSIG
        if (fcntl(sv[0], F_SETSIG, SIGIO)) {
            perror("setsig");
            goto bad;
        }
#endif
        // ioctl FIOASYNC could be an alternative too
#if !defined(__sun)
        flags = fcntl(0, F_GETFL);
        if (fcntl(sv[0], F_SETFL, flags | O_ASYNC) == -1) {
            perror("setfl async");
            goto bad;
        }
#else
        if (ioctl(sv[0], I_SETSIG, S_INPUT)) {
            perror("I_SETSIG");
            goto bad;
        }
#endif
        write(sv[1], "b", 1);
        pause();
        _exit(99);
bad:
        _exit(98);
    }
}
#else
TEST_CASE( "check sigio" ) {
    REQUIRE(PosixSignalManager::classifySignal(SIGIO) == 0);
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        HAS_EXITED_WITH(42);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGIO);
        CHECK(shared->type == shared_page::sync);
#if defined(__FreeBSD__)
        // SIGIO is siginfo less in freebsd
        CHECK(shared->info.si_code == SI_KERNEL);
#elif defined(__OpenBSD__)
        CHECK(shared->info.si_code == SI_USER);
#elif defined(__APPLE__)
        CHECK(shared->info.si_code == 0);
#else
        CHECK(shared->info.si_code == POLL_IN);
#endif
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGIO, &reraise_handler);
        int sv[2];
        int flags;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
            perror("socketpair");
            goto bad;
        }
        if (fcntl(sv[0], F_SETOWN, getpid()) == -1) {
            perror("setown");
            goto bad;
        }
        flags = fcntl(0, F_GETFL);
        if (fcntl(sv[0], F_SETFL, flags | O_ASYNC) == -1) {
            perror("setfl async");
            goto bad;
        }
        sigset_t newmask, oldmask;
        sigemptyset(&newmask);
        sigaddset(&newmask, SIGIO);
        sigprocmask(SIG_BLOCK, &newmask, &oldmask);
        write(sv[1], "b", 1);
        sigsuspend(&oldmask);
        _exit(42);
bad:
        _exit(98);
    }
}
#endif
#endif

TEST_CASE( "reraise 'killed' sigio" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        if (PosixSignalManager::classifySignal(SIGIO) > 0) {
            WAS_SIGNALED_WITH(SIGIO);
        } else {
            HAS_EXITED_WITH(99);
        }
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGIO);
        CHECK(shared->type == shared_page::sync);
#if defined(__APPLE__)
#else
        CHECK(shared->info.si_code == SI_USER);
#endif
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGIO, &reraise_handler);
        kill(getpid(), SIGIO);
        _exit(99);
    }
}

#ifndef NO_SIGILL
TEST_CASE( "baseline sigill" ) {
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGILL);
    } else {
        cause_sigill();
        _exit(99);
    }
}
#endif

#ifndef NO_SIGILL
TEST_CASE( "reraise sigill" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGILL);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGILL);
        CHECK(shared->type == shared_page::sync);
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGILL, &reraise_handler);
        cause_sigill();
        _exit(99);
    }
}
#endif

TEST_CASE( "reraise 'killed' sigill" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGILL);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGILL);
        CHECK(shared->type == shared_page::sync);
#if defined(__APPLE__) || defined(__OpenBSD__)
#else
        CHECK(shared->info.si_code == SI_USER);
#endif
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGILL, &reraise_handler);
        kill(getpid(), SIGILL);
        _exit(99);
    }
}

TEST_CASE( "baseline sigfpe" ) {
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGFPE);
    } else {
        cause_sigfpe();
        _exit(99);
    }
}

TEST_CASE( "reraise sigfpe" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGFPE);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGFPE);
        CHECK(shared->type == shared_page::sync);
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGFPE, &reraise_handler);
        cause_sigfpe();
        _exit(99);
    }
}

TEST_CASE( "reraise 'killed' sigfpe" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGFPE);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGFPE);
        CHECK(shared->type == shared_page::sync);
#if defined(__APPLE__) || defined(__OpenBSD__)
#else
        CHECK(shared->info.si_code == SI_USER);
#endif
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGFPE, &reraise_handler);
        kill(getpid(), SIGFPE);
        _exit(99);
    }
}

#ifndef NO_SIGTRAP
TEST_CASE( "baseline sigtrap" ) {
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGTRAP);
    } else {
        cause_sigtrap();
        _exit(99);
    }
}
#endif

#ifndef NO_SIGTRAP
TEST_CASE( "reraise sigtrap" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGTRAP);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGTRAP);
        CHECK(shared->type == shared_page::sync);
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGTRAP, &reraise_handler);
        cause_sigtrap();
        _exit(99);
    }
}
#endif

TEST_CASE( "reraise 'killed' sigtrap" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGTRAP);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGTRAP);
        CHECK(shared->type == shared_page::sync);
#if defined(__APPLE__) || defined(__OpenBSD__)
#else
        CHECK(shared->info.si_code == SI_USER);
#endif
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGTRAP, &reraise_handler);
        kill(getpid(), SIGTRAP);
        _exit(99);
    }
}

#if defined(SIGIO) && defined(SIGRTMIN) && !defined(__FreeBSD__) && !defined(__OpenBSD__) \
    && !defined(__NetBSD__) && !defined(__sun)
// ^^^ various bsds do not have a way to change the signal for O_ASYNC
TEST_CASE( "reraise 'io' sigrt" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGRTMIN);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGRTMIN);
        CHECK(shared->type == shared_page::sync);
        CHECK(shared->info.si_code == POLL_IN);
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGRTMIN, &reraise_handler);
        int sv[2];
        int flags;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
            perror("socketpair");
            goto bad;
        }
        if (fcntl(sv[0], F_SETOWN, getpid()) == -1) {
            perror("setown");
            goto bad;
        }
        if (fcntl(sv[0], F_SETSIG, SIGRTMIN)) {
            perror("setsig");
            goto bad;
        }
        flags = fcntl(0, F_GETFL);
        if (fcntl(sv[0], F_SETFL, flags | O_ASYNC) == -1) {
            perror("setfl async");
            goto bad;
        }
        write(sv[1], "b", 1);
        pause();
        _exit(99);
bad:
        _exit(98);
    }
}
#endif

TEST_CASE( "term handler (sighup)" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGHUP);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGHUP);
        CHECK(shared->type == shared_page::termination);
#if defined(__OpenBSD__) || defined(__APPLE__)
#elif !defined(__FreeBSD__) && !defined(__NetBSD__) && !defined(__sun)
        CHECK(shared->info.si_code == SI_TKILL);
#else
        CHECK(shared->info.si_code == SI_LWP);
#endif
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncTerminationHandler(&termination_handler);
        raise(SIGHUP);
        _exit(99);
    }
}

TEST_CASE( "term handler (sighup) in fork" ) {
    int follow = GENERATE(0, 1, 2);
    CAPTURE(follow);
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        HAS_EXITED_WITH(42);
        if (follow == 0) {
            CHECK(shared->sig_count == 0);
        } else {
            CHECK(shared->sig_count == 1);
            CHECK(shared->caught_signal.load() == SIGHUP);
            CHECK(shared->type == shared_page::termination);
        }
    } else {
        PosixSignalOptions options;
        if (follow == 0) {
            options = PosixSignalOptions().dontFollowForks();
        } else if (follow == 1) {
            options = PosixSignalOptions().followForks();
        }
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncTerminationHandler(&termination_handler, options);

        pid_t innerPid = fork();
        if (innerPid == -1) {
            perror("inner fork");
            _exit(99);
        }

        if (innerPid == 0) {
            raise(SIGHUP);
            _exit(99);
        }

        int innerStatus;
        waitpid(innerPid, &innerStatus, 0);

        _exit(42);
    }
}

#if defined(SIGRTMIN)
TEST_CASE( "term handler (sigrt)" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGRTMIN+1);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGRTMIN+1);
        CHECK(shared->type == shared_page::termination);
#if defined(__OpenBSD__) || defined(__APPLE__)
#elif !defined(__FreeBSD__) && !defined(__NetBSD__) && !defined(__sun)
        CHECK(shared->info.si_code == SI_TKILL);
#else
        CHECK(shared->info.si_code == SI_LWP);
#endif
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncTerminationHandler(&termination_handler);
        raise(SIGRTMIN+1);
        _exit(99);
    }
}
#endif

TEST_CASE( "ignored term handler (sighup)" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        HAS_EXITED_WITH(99);
        CHECK(shared->sig_count == 0);
        CHECK(shared->caught_signal.load() == 0);
    } else {
        signal(SIGHUP, SIG_IGN);
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncTerminationHandler(&termination_handler);
        raise(SIGHUP);
        _exit(99);
    }
}

TEST_CASE( "removed term handler (sighup)" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        HAS_EXITED_WITH(99);
        CHECK(shared->sig_count == 0);
        CHECK(shared->caught_signal.load() == 0);
    } else {
        signal(SIGHUP, SIG_IGN);
        PosixSignalManager::create();
        int id = PosixSignalManager::instance()->addSyncTerminationHandler(&termination_handler);
        PosixSignalManager::instance()->removeHandler(id);
        raise(SIGHUP);
        _exit(99);
    }
}

TEST_CASE( "crash handler (sigsegv)" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGSEGV);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGSEGV);
        CHECK(shared->type == shared_page::termination);
        CHECK(shared->info.si_code == SEGV_MAPERR);
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncCrashHandler(&termination_handler);
        cause_sigsegv();
        _exit(99);
    }
}

TEST_CASE( "crash handler (sigsegv) in fork" ) {
    int follow = GENERATE(0, 1, 2);
    CAPTURE(follow);
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        HAS_EXITED_WITH(42);
        if (follow == 0) {
            CHECK(shared->sig_count == 0);
        } else {
            CHECK(shared->sig_count == 1);
            CHECK(shared->caught_signal.load() == SIGSEGV);
            CHECK(shared->type == shared_page::termination);
            CHECK(shared->info.si_code == SEGV_MAPERR);
        }
    } else {
        PosixSignalOptions options;
        if (follow == 0) {
            options = PosixSignalOptions().dontFollowForks();
        } else if (follow == 1) {
            options = PosixSignalOptions().followForks();
        }
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncCrashHandler(&termination_handler, options);

        pid_t innerPid = fork();
        if (innerPid == -1) {
            perror("inner fork");
            _exit(99);
        }

        if (innerPid == 0) {
            cause_sigsegv();
            _exit(99);
        }

        int innerStatus;
        waitpid(innerPid, &innerStatus, 0);

        _exit(42);
    }
}

TEST_CASE( "removed crash handler (sigsegv)" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGSEGV);
        CHECK(shared->sig_count == 0);
        CHECK(shared->caught_signal.load() == 0);
    } else {
        signal(SIGHUP, SIG_IGN);
        PosixSignalManager::create();
        int id = PosixSignalManager::instance()->addSyncCrashHandler(&termination_handler);
        PosixSignalManager::instance()->removeHandler(id);
        cause_sigsegv();
        _exit(99);
    }
}

TEST_CASE( "notify (sighup)" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        HAS_EXITED_WITH(42);
        CHECK(shared->sig_count == 1);
        CHECK(shared->caught_signal.load() == SIGHUP);
        CHECK(shared->type == shared_page::notify);
#if defined(__OpenBSD__) || defined(__APPLE__)
#elif !defined(__FreeBSD__) && !defined(__NetBSD__) && !defined(__sun)
        CHECK(shared->info.si_code == SI_TKILL);
#else
        CHECK(shared->info.si_code == SI_LWP);
#endif
    } else {
        int argc = 1;
        char fake_name[] = "test-inner";
        char *argv[] = { fake_name, nullptr };
        QCoreApplication app(argc, argv);

        PosixSignalManager::create();
        PosixSignalNotifier n(SIGHUP);
        QObject::connect(&n, &PosixSignalNotifier::activated, [&] (int signo, QSharedPointer<const siginfo_t> info) {
            ++shared->sig_count;
            shared->type = shared_page::notify;
            memcpy(&shared->info, info.data(), sizeof(*info.data()));
            shared->caught_signal.store(info->si_signo);
            app.exit();
        });

        raise(SIGHUP);
        app.exec();
        _exit(42);
    }
}

TEST_CASE( "removed notify (sighup)" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_SIGNALED_WITH(SIGHUP);
        CHECK(shared->sig_count == 0);
    } else {
        int argc = 1;
        char fake_name[] = "test-inner";
        char *argv[] = { fake_name, nullptr };
        QCoreApplication app(argc, argv);

        PosixSignalManager::create();
        PosixSignalNotifier *notifier = new PosixSignalNotifier(SIGHUP);
        QObject::connect(notifier, &PosixSignalNotifier::activated, [&] (int signo, QSharedPointer<const siginfo_t> info) {
            ++shared->sig_count;
            shared->type = shared_page::notify;
            memcpy(&shared->info, info.data(), sizeof(*info.data()));
            shared->caught_signal.store(info->si_signo);
            app.exit();
        });

        delete notifier;

        raise(SIGHUP);

        QTimer::singleShot(0, [] {
            QCoreApplication::instance()->quit();
        });
        app.exec();
        _exit(42);
    }
}

TEST_CASE( "removed notify (sigchld)" ) {
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        HAS_EXITED_WITH(42);
        CHECK(shared->sig_count == 0);
    } else {
        int argc = 1;
        char fake_name[] = "test-inner";
        char *argv[] = { fake_name, nullptr };
        QCoreApplication app(argc, argv);

        PosixSignalManager::create();
        PosixSignalNotifier *notifier = new PosixSignalNotifier(SIGCHLD);
        QObject::connect(notifier, &PosixSignalNotifier::activated, [&] (int signo, QSharedPointer<const siginfo_t> info) {
            ++shared->sig_count;
            shared->type = shared_page::notify;
            memcpy(&shared->info, info.data(), sizeof(*info.data()));
            shared->caught_signal.store(info->si_signo);
            app.exit();
        });

        delete notifier;

        raise(SIGCHLD);

        QTimer::singleShot(0, [] {
            QCoreApplication::instance()->quit();
        });
        app.exec();
        _exit(42);
    }
}

TEST_CASE( "notify (sighup) in fork" ) {
    int follow = GENERATE(0, 1, 2);
    CAPTURE(follow);
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        HAS_EXITED_WITH(42);
        if (follow == 0) {
            CHECK(shared->sig_count == 1);
        } else {
            CHECK(shared->sig_count == 0);
        }
    } else {
        int argc = 1;
        char fake_name[] = "test-inner";
        char *argv[] = { fake_name, nullptr };
        QCoreApplication app(argc, argv);

        PosixSignalManager::create();
        PosixSignalOptions options;
        if (follow == 0) {
            options = PosixSignalOptions().followForks();
        } else if (follow == 1) {
            options = PosixSignalOptions().dontFollowForks();
        }
        PosixSignalNotifier n(SIGHUP, options);
        QObject::connect(&n, &PosixSignalNotifier::activated, [&] (int signo, QSharedPointer<const siginfo_t> info) {
            ++shared->sig_count;
            shared->type = shared_page::notify;
            memcpy(&shared->info, info.data(), sizeof(*info.data()));
            shared->caught_signal.store(info->si_signo);
            app.exit();
        });

        pid_t innerPid = fork();
        if (innerPid == -1) {
            perror("inner fork");
            _exit(99);
        }

        if (innerPid == 0) {
            raise(SIGHUP);
            _exit(99);
        }

        int innerStatus;
        waitpid(innerPid, &innerStatus, 0);

        QTimer::singleShot(100, [] {
            QCoreApplication::instance()->quit();
        });
        app.exec();
        _exit(42);
    }
}

TEST_CASE( "reraise TSTP/TTIN/TTOU" ) {
    int signo = GENERATE(SIGTSTP, SIGTTIN, SIGTTOU);
    CAPTURE(signo);
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        WAS_STOPPED(signo);
        CHECK(shared->sig_count == 1);
        CHECK(shared->type == shared_page::sync);
        CHECK(shared->caught_signal.load() == signo);
        kill(pid, SIGCONT);
        {
            WAIT_CHILD;
            WAS_CONTINUED(SIGCONT);
            CHECK(shared->sig_count == 1);
        }
        shared->misc = 1;
        {
            WAIT_CHILD;
            HAS_EXITED_WITH(99);
            CHECK(shared->sig_count == 1);
        }
    } else {
        // Make sure that this process is not in a orphaned process group, because that would disable these signal's action.
        setpgid(0, 0);
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(signo, &reraise_handler);
        raise(signo);
        int timelimit = 100;
        while (!shared->misc && timelimit-- > 0) {
            usleep(100000);
        }
        _exit(99);
    }
}

TEST_CASE( "brute force 'killed' reraise" ) {
    int signo = GENERATE(range(1, NUM_SIGNALS));
    CAPTURE(signo);
    if (signo == SIGKILL || signo == SIGSTOP || signo == SIGTSTP || signo == SIGTTIN || signo == SIGTTOU) {
        // all these are special, classification does not cover this, so just skip.
        return;
    }
#ifdef SIGRTMIN
    if (signo > NSIG && signo < SIGRTMIN) {
        // There can be a gap between no real time signals and realtime signals. This is e.g. the case with freebsd.
        return;
    }
#endif
    int classification = PosixSignalManager::classifySignal(signo);
    CAPTURE(classification);
    SharedPageAlloc sharedPageAlloc;
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        WAIT_CHILD;
        if (shared->misc == 1) {
            HAS_EXITED_WITH(11);
        } else if (classification > 0) {
            WAS_SIGNALED_WITH(signo);
        } else {
            HAS_EXITED_WITH(99);
        }
    } else {
        if (signal(signo, SIG_DFL) == SIG_ERR) {
            // Certain signal numbers don't really exist or are reserved for libc/OS usage. Skip those.
            shared->misc = 1;
            _exit(11);
        }
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGTRAP, &reraise_handler);

        kill(getpid(), signo);
        _exit(99);
    }
}
