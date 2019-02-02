#include <aio.h>
#include <fcntl.h>
#include <mqueue.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <signal.h>

#define CATCH_CONFIG_EXTERNAL_INTERFACES
#define CATCH_CONFIG_NO_POSIX_SIGNALS
#include "catch.hpp"

#include <QVector>
#include <QCoreApplication>
#include <QSharedPointer>

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

struct shared_page {
    std::atomic<int> caught_signal;
    enum { notcalled, termination, sync, notify } type = notcalled;
    siginfo_t info;
};

shared_page *shared = nullptr;


void cause_sigsegv() {
    int *p = (int*)32;
    *p = 42;
}

int zero = 0;

void cause_sigfpe() {
    printf("%d\n", 1 / zero);
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
    /* Enable Alignment Checking */
#if defined(__GNUC__)
#if defined(__i386__)
    __asm__(
        "pushf\n"
        "orl $0x40000,(%esp)\n"
        "popf"
    );
#elif defined(__x86_64__)
    __asm__(
        "pushf\n"
        "orl $0x40000,(%rsp)\n"
        "popf"
    );
#else
#define NO_SIGBUS
#endif
#else
#define NO_SIGBUS
#endif
    char *cptr = (char*)malloc(sizeof(int) + 1);

    /* Increment the pointer by one, making it misaligned */
    int *iptr = (int *) ++cptr;

    /* Dereference it as an int pointer, causing an unaligned access */

    *iptr = 42;
}

void reraise_handler(PosixSignalFlags &flags, const siginfo_t *info, void *context) {
    shared->type = shared_page::sync;
    memcpy(&shared->info, info, sizeof(*info));
    shared->caught_signal.store(info->si_signo);
    flags.reraise();
}

void termination_handler(const siginfo_t *info, void *context) {
    shared->type = shared_page::termination;
    memcpy(&shared->info, info, sizeof(*info));
    shared->caught_signal.store(info->si_signo);
}

#define WAS_SIGNALED_WITH(signo)        \
    CHECK(info.si_pid == pid);          \
    CHECK(info.si_code == CLD_KILLED);  \
    CHECK(info.si_status == signo)

#define HAS_EXITED_WITH(retno)        \
    CHECK(info.si_pid == pid);          \
    CHECK(info.si_code == CLD_EXITED);  \
    CHECK(info.si_status == retno)

TEST_CASE( "baseline sigsegv" ) {
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGSEGV);
    } else {
        cause_sigsegv();
        _exit(99);
    }
}

TEST_CASE( "reraise sigsegv" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    shared->caught_signal.store(0);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGSEGV);
        CHECK(shared->caught_signal.load() == SIGSEGV);
        CHECK(shared->type == shared_page::sync);
        CHECK(shared->info.si_code == SEGV_MAPERR);
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGSEGV, &reraise_handler);
        cause_sigsegv();
        _exit(99);
    }
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}

TEST_CASE( "reraise 'raised' sigsegv" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    shared->caught_signal.store(0);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGSEGV);
        CHECK(shared->caught_signal.load() == SIGSEGV);
        CHECK(shared->type == shared_page::sync);
#if !defined(__FreeBSD__)
        CHECK(shared->info.si_code == SI_TKILL);
#elif defined(__FreeBSD__)
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
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}

TEST_CASE( "reraise 'killed' sigsegv" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    shared->caught_signal.store(0);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGSEGV);
        CHECK(shared->caught_signal.load() == SIGSEGV);
        CHECK(shared->type == shared_page::sync);
        CHECK(shared->info.si_code == SI_USER);
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGSEGV, &reraise_handler);
        kill(getpid(), SIGSEGV);
        _exit(99);
    }
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}

TEST_CASE( "reraise 'queued' sigsegv" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    shared->caught_signal.store(0);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGSEGV);
        CHECK(shared->caught_signal.load() == SIGSEGV);
        CHECK(shared->type == shared_page::sync);
        CHECK(shared->info.si_code == SI_QUEUE);
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGSEGV, &reraise_handler);
        sigval sv;
        sv.sival_int = 42;
        sigqueue(getpid(), SIGSEGV, sv);
        _exit(99);
    }
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}

#ifdef __linux__
TEST_CASE( "reraise 'io' sigsegv" ) {
    bool linux_pre_4_14 = false;
    if (isLinux() && utsRelease() < QVector<int>{4,14}) {
        WARN("\"reraise 'io' sigsegv\" test uses degraded handling on linux kernel < 4.14");
        linux_pre_4_14 = true;
    }

    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    shared->caught_signal.store(0);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGSEGV);
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
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}
#endif

TEST_CASE( "reraise 'timer' sigsegv" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    shared->caught_signal.store(0);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGSEGV);
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
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}

TEST_CASE( "reraise 'mq' sigsegv" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    shared->caught_signal.store(0);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGSEGV);
        CHECK(shared->caught_signal.load() == SIGSEGV);
        CHECK(shared->type == shared_page::sync);
        CHECK(shared->info.si_code == SI_MESGQ);
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
        sev.sigev_signo = 11;
        sev.sigev_value.sival_int = 42;
        if (mq_notify(mqdes, &sev) == -1) {
            perror("mq_notify");
            _exit(98);
        }
        sev.sigev_notify = SIGEV_SIGNAL;
        sev.sigev_signo = SIGSEGV;
        sev.sigev_value.sival_int = 42;
        //if (mq_notify(mqdes, &sev) == -1) {
            //perror("mq_notify");
            //_exit(98);
        //}
        if (mq_send(mqdes, "test", 4, 0) == -1) {
            perror("mq_send");
            _exit(98);
        }
        pause();
        _exit(99);
    }
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}

TEST_CASE( "reraise 'aio' sigsegv" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    shared->caught_signal.store(0);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGSEGV);
        CHECK(shared->caught_signal.load() == SIGSEGV);
        CHECK(shared->type == shared_page::sync);
        CHECK(shared->info.si_code == SI_ASYNCIO);
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
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}

#ifndef NO_SIGBUS
TEST_CASE( "baseline sigbus" ) {
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGBUS);
    } else {
        cause_sigbus();
        _exit(99);
    }
}
#endif

#ifndef NO_SIGBUS
TEST_CASE( "reraise sigbus" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGBUS);
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGBUS, &reraise_handler);
        cause_sigbus();
        _exit(99);
    }
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}
#endif

#if defined(SIGIO)
#if !defined(__FreeBSD__)
// ^^^ on freebsd sigio is ignored by default, so reraise will not kill the child
TEST_CASE( "reraise sigio" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    shared->caught_signal.store(0);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGIO);
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
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}
#else
TEST_CASE( "check sigio" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    shared->caught_signal.store(0);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        HAS_EXITED_WITH(42);
        CHECK(shared->caught_signal.load() == SIGIO);
        CHECK(shared->type == shared_page::sync);
        // SIGIO is siginfo less in freebsd
        CHECK(shared->info.si_code == SI_KERNEL);
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
        write(sv[1], "b", 1);
        _exit(42);
bad:
        _exit(98);
    }
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}
#endif
#endif

#ifndef NO_SIGILL
TEST_CASE( "baseline sigill" ) {
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGILL);
    } else {
        cause_sigill();
        _exit(99);
    }
}
#endif

#ifndef NO_SIGILL
TEST_CASE( "reraise sigill" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGILL);
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGBUS, &reraise_handler);
        cause_sigill();
        _exit(99);
    }
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}
#endif

TEST_CASE( "baseline sigfpe" ) {
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGFPE);
    } else {
        cause_sigfpe();
        _exit(99);
    }
}

TEST_CASE( "reraise sigfpe" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGFPE);
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGFPE, &reraise_handler);
        cause_sigfpe();
        _exit(99);
    }
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}

#ifndef NO_SIGTRAP
TEST_CASE( "baseline sigtrap" ) {
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGTRAP);
    } else {
        cause_sigtrap();
        _exit(99);
    }
}
#endif

#ifndef NO_SIGTRAP
TEST_CASE( "reraise sigtrap" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGTRAP);
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncSignalHandler(SIGTRAP, &reraise_handler);
        cause_sigtrap();
        _exit(99);
    }
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}
#endif

#if defined(SIGIO) && !defined(__FreeBSD__)
// ^^^ FreeBSD does not have a way to change the signal for O_ASYNC
TEST_CASE( "reraise 'io' sigrt" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    shared->caught_signal.store(0);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGRTMIN);
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
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}
#endif

TEST_CASE( "term handler (sighup)" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    shared->caught_signal.store(0);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGHUP);
        CHECK(shared->caught_signal.load() == SIGHUP);
        CHECK(shared->type == shared_page::termination);
#if !defined(__FreeBSD__)
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
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}

TEST_CASE( "term handler (sigrt)" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    shared->caught_signal.store(0);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGRTMIN+1);
        CHECK(shared->caught_signal.load() == SIGRTMIN+1);
        CHECK(shared->type == shared_page::termination);
#if !defined(__FreeBSD__)
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
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}

TEST_CASE( "ignored term handler (sighup)" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    shared->caught_signal.store(0);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        HAS_EXITED_WITH(99);
        CHECK(shared->caught_signal.load() == 0);
    } else {
        signal(SIGHUP, SIG_IGN);
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncTerminationHandler(&termination_handler);
        raise(SIGHUP);
        _exit(99);
    }
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}

TEST_CASE( "removed term handler (sighup)" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    shared->caught_signal.store(0);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        HAS_EXITED_WITH(99);
        CHECK(shared->caught_signal.load() == 0);
    } else {
        signal(SIGHUP, SIG_IGN);
        PosixSignalManager::create();
        int id = PosixSignalManager::instance()->addSyncTerminationHandler(&termination_handler);
        PosixSignalManager::instance()->removeHandler(id);
        raise(SIGHUP);
        _exit(99);
    }
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}

TEST_CASE( "crash handler (sigsegv)" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    shared->caught_signal.store(0);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGSEGV);
        CHECK(shared->caught_signal.load() == SIGSEGV);
        CHECK(shared->type == shared_page::termination);
        CHECK(shared->info.si_code == SEGV_MAPERR);
    } else {
        PosixSignalManager::create();
        PosixSignalManager::instance()->addSyncCrashHandler(&termination_handler);
        cause_sigsegv();
        _exit(99);
    }
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}

TEST_CASE( "removed crash handler (sigsegv)" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    shared->caught_signal.store(0);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        WAS_SIGNALED_WITH(SIGSEGV);
        CHECK(shared->caught_signal.load() == 0);
    } else {
        signal(SIGHUP, SIG_IGN);
        PosixSignalManager::create();
        int id = PosixSignalManager::instance()->addSyncCrashHandler(&termination_handler);
        PosixSignalManager::instance()->removeHandler(id);
        cause_sigsegv();
        _exit(99);
    }
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}

TEST_CASE( "notify (sighup)" ) {
    shared = static_cast<shared_page*>(mmap(nullptr, sizeof(shared_page), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shared != MAP_FAILED);
    shared->caught_signal.store(0);
    pid_t pid = fork();
    REQUIRE(pid != -1);
    if (pid) {
        siginfo_t info;
        errno = 0;
        int r = waitid(P_ALL, 0, &info, WEXITED | WSTOPPED | WCONTINUED);
        REQUIRE(r == 0);
        HAS_EXITED_WITH(42);
        CHECK(shared->caught_signal.load() == SIGHUP);
        CHECK(shared->type == shared_page::notify);
#if !defined(__FreeBSD__)
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
            shared->type = shared_page::notify;
            memcpy(&shared->info, info.data(), sizeof(*info.data()));
            shared->caught_signal.store(info->si_signo);
            app.exit();
        });

        raise(SIGHUP);
        app.exec();
        _exit(42);
    }
    REQUIRE(!munmap(shared, sizeof(shared_page)));
}
