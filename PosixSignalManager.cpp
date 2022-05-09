#include "PosixSignalManager.h"

#include <atomic>
#include <limits>

#if 1
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <limits.h>
#endif

#include <QDebug>
#include <QMap>
#include <QMutex>
#include <QMutexLocker>
#include <QSocketNotifier>

#ifdef NSIG
#if defined(__linux__) || !defined(SIGRTMAX) || defined(__sun)
    #define NUM_SIGNALS NSIG
#else
    #if (SIGRTMAX + 1) > NSIG
    #define NUM_SIGNALS (SIGRTMAX + 1)
    #else
    #define NUM_SIGNALS NSIG
    #endif
#endif
#else
#error missing signal number macro
#endif

#ifdef __cpp_lib_atomic_is_always_lock_free
#define STATIC_ASSERT_ALWAYS_LOCKFREE(type) static_assert (type::is_always_lock_free)
#else
#define STATIC_ASSERT_ALWAYS_LOCKFREE(type) /* not supported */
#endif

STATIC_ASSERT_ALWAYS_LOCKFREE(std::atomic<void*>);
STATIC_ASSERT_ALWAYS_LOCKFREE(std::atomic<int>);

// POSIX requires write(2) on a O_NONBLOCK pipe to be atomic with payloads smaller than PIPE_BUF, which we depend
// on for siginfo_t.
static_assert (sizeof(siginfo_t) < PIPE_BUF, "siginfo_t is bigger than limit for atomic pipe writes");

#define LIBNAME "PosixSignalManager: "

class PosixSignalFlagsPrivate {
    friend class PosixSignalFlags;
    bool reraise = true;
    bool stopChain = false;
};

namespace {
    PosixSignalManager *instance = nullptr;

    // all state must be lockfree accessable from async signal context.

    enum class NodeType {
        SyncHandler,
        SyncTerminationHandler,
        SyncCrashHandler,
        NotifyFd
    };

    struct Node {
        int id; // mainline (locked) access only
        int signo; // mainline (locked) access only
        NodeType type; // mainline (locked) access only
        pid_t pidFilter; // only written to in init, readonly after that
    };

    struct SyncHandlerNode : public Node {
        PosixSignalManager::SyncHandler *handler = nullptr;
        void *data = nullptr; // only written to in init, readonly after that
        std::atomic<SyncHandlerNode*> next;
    };

    struct SyncTerminationHandlerNode : public Node {
        PosixSignalManager::SyncTerminationHandler *handler = nullptr;
        void *data = nullptr; // only written to in init, readonly after that
        std::atomic<SyncTerminationHandlerNode*> next;
    };

    struct NotifyFdNode : public Node {
        int write_fd = -1; // only written to in init, readonly after that
        int read_fd = -1; // only written to in init, readonly after that
        std::atomic<NotifyFdNode*> next;
    };

    enum class InternalChainingMode : int { NeverChain, ChainAlways, ChainIfReraiseSet };
    STATIC_ASSERT_ALWAYS_LOCKFREE(std::atomic<InternalChainingMode>);

    struct SignalState {
        std::atomic<SyncHandlerNode*> syncHandlers;
        std::atomic<NotifyFdNode*> notifyFds;
        std::atomic<InternalChainingMode> chainingMode;
        bool handlerInstalled; // mainline (locked) access only
    };

    std::atomic<SyncTerminationHandlerNode*> syncTerminationHandlers;
    std::atomic<SyncTerminationHandlerNode*> syncCrashHandlers;
    SignalState signalStates[NUM_SIGNALS] = { };
    std::atomic<int> asyncSignalHandlerRunning;

    bool signalHandlerInstalled[NUM_SIGNALS] = { false };
    struct sigaction originalSignalActions[NUM_SIGNALS] = { }; // read by signal handler after reading SignalState::InternalChainingMode != Never
                                                               // stored before writing SignalState::InternalChainingMode to != Never

    void PosixSignalManager_init() { // mainline (locked) access only
        asyncSignalHandlerRunning.store(0, std::memory_order_seq_cst);
        for (int i = 0; i < NUM_SIGNALS; i++) {
            signalStates[i].syncHandlers.store(nullptr, std::memory_order_seq_cst);
            signalStates[i].notifyFds.store(nullptr, std::memory_order_seq_cst);
            signalStates[i].chainingMode.store(InternalChainingMode::NeverChain, std::memory_order_seq_cst);
            signalStates[i].handlerInstalled = false;
        }
        syncTerminationHandlers.store(nullptr, std::memory_order_seq_cst);
        syncCrashHandlers.store(nullptr, std::memory_order_seq_cst);
    }

    void PosixSignalManager_classify_signo(int signo, bool *isTermination, bool *isCrash, bool *specialEffect) {
        *isTermination = false;
        *isCrash = false;
        *specialEffect = false;

        switch (signo) {
            case SIGALRM:
            case SIGHUP:
            case SIGINT:
#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__APPLE__) && !defined(__NetBSD__)
            // ^^^ various bsds ignore sigio by default
            case SIGIO:
#endif
            case SIGPIPE:
            case SIGPROF:
#if defined(SIGPWR) && !defined(__NetBSD__) && !defined(__sun)
            case SIGPWR:
#endif
            case SIGQUIT:
#ifdef SIGSTKFLT
            case SIGSTKFLT:
#endif
            case SIGTERM:
            case SIGUSR1:
            case SIGUSR2:
            case SIGVTALRM:
            case SIGXCPU:
            case SIGXFSZ:
#ifdef SIGLOST
            case SIGLOST:
#endif
                *isTermination = true;
                break;
#if defined(SIGEMT)
            case SIGEMT:
#endif
            case SIGBUS:
            case SIGILL:
            case SIGSEGV:
            case SIGABRT:
            case SIGFPE:
            case SIGSYS:
            case SIGTRAP:
                *isCrash = true;
                break;
            case SIGTSTP:
            case SIGTTIN:
            case SIGTTOU:
                *specialEffect = true;
            default:
                break;
        }

#ifdef SIGRTMIN
        if (signo >= SIGRTMIN && signo <= SIGRTMAX) {
            *isTermination = true;
        }
#endif
    }

    void PosixSignalManager_sigdie(const char *msg, int code) {
        write(2, msg, strlen(msg));
        if (code) {
            // open coded int to ascii code, because async signal safety requirements.
            unsigned int tmp;
            if (code < 0) {
                write(2, "-", 1);
                tmp = -(unsigned int)code;
            } else {
                tmp = (unsigned int)code;
            }
            int digitValue = 1;
            while (tmp / digitValue >= 10) {
                digitValue *= 10;
            }
            do {
                char ch = '0' + (tmp / digitValue);
                write(2, &ch, 1);
                tmp /= 10;
                digitValue /= 10;
            } while (digitValue > 0);

        }
        write(2, "\r\n", 2);
        signal(SIGABRT, SIG_DFL);
        abort();
    }

    void PosixSignalManager_handler(int signo, siginfo_t *info, void *context) {
        if (signo >= NUM_SIGNALS) {
            // avoid buffer overlow in code below, should never happen:
            // signo < NUM_SIGNALS should always be true because we don't set this handler for anything higher
            return;
        }
        int savedErrno = errno;

        // At least on linux this assumes a modern libc that does not cache getpid().
        pid_t currentPid = getpid();

        bool isUser = info->si_code == SI_USER || info->si_code == SI_QUEUE
#ifdef SI_FROMUSER
                || SI_FROMUSER(info)
#endif
#ifdef SI_TKILL
                || info->si_code == SI_TKILL
#endif
#ifdef SI_LWP
                || info->si_code == SI_LWP
#endif
                ;
        bool isDynamic = (info->si_code < 0 && !isUser) || info->si_code == SI_TIMER
#ifdef SI_MESGQ
                || info->si_code == SI_MESGQ
#endif
#ifdef SI_ASYNCIO
                || info->si_code == SI_ASYNCIO
#endif
#ifdef SI_SIGIO
                || info->si_code == SI_SIGIO
#endif
                ;

        bool isTermination = false;
        bool isCrash = false;
        bool specialEffect = false;
        PosixSignalManager_classify_signo(signo, &isTermination, &isCrash, &specialEffect);

        asyncSignalHandlerRunning.fetch_add(1, std::memory_order_seq_cst);

        SignalState* signalState = &signalStates[signo];
        // mainline may not delete nodes until asyncSignalHandlerRunning reaches 0 again
        PosixSignalFlagsPrivate cbPriv;
        PosixSignalFlags cb(&cbPriv);

        SyncHandlerNode* syncHandler = signalState->syncHandlers.load(std::memory_order_seq_cst);
        NotifyFdNode* notifyFd = signalState->notifyFds.load(std::memory_order_seq_cst);
        if (syncHandler) {
            while (syncHandler) {
                if (syncHandler->pidFilter == 0 || syncHandler->pidFilter == currentPid) {
                    syncHandler->handler(syncHandler->data, cb, info, context);
                    if (cb.isStopChainSet()) {
                        break;
                    }
                }
                syncHandler = syncHandler->next.load(std::memory_order_seq_cst);
            }
        }

        if (!cb.isStopChainSet()) {
            while (notifyFd) {
                if (notifyFd->pidFilter == 0 || notifyFd->pidFilter == currentPid) {
                    // We depend on this write to be atomic. Posix requires writes smaller than PIPE_BUF to be
                    // atomic and the size requirement is checked above in a static_assert.
                    // If the pipe is full the signal is silently dropped.
                    write(notifyFd->write_fd, info, sizeof(*info));
                    // error of write explicitly not handled.
                    cb.clearReraise();
                }
                notifyFd = notifyFd->next.load(std::memory_order_seq_cst);
            }
        }

        bool shouldChain = false;
        if (signalState->chainingMode != InternalChainingMode::NeverChain
              && originalSignalActions[signo].sa_handler != SIG_IGN
              && originalSignalActions[signo].sa_handler != SIG_DFL) {
            if (signalState->chainingMode == InternalChainingMode::ChainAlways
                  || (signalState->chainingMode == InternalChainingMode::ChainIfReraiseSet && cb.isReraiseSet())) {

                shouldChain = true;
                // when chaining don't reraise signal.
                cb.clearReraise();
            }
        }

        if (cb.isReraiseSet()) {
            if (isTermination) {
                SyncTerminationHandlerNode* thn = syncTerminationHandlers.load(std::memory_order_seq_cst);
                while (thn) {
                    if (thn->pidFilter == 0 || thn->pidFilter == currentPid) {
                        thn->handler(thn->data, info, context);
                    }
                    thn = thn->next.load(std::memory_order_seq_cst);
                }
            } else if (isCrash) {
                SyncTerminationHandlerNode* thn = syncCrashHandlers.load(std::memory_order_seq_cst);
                while (thn) {
                    if (thn->pidFilter == 0 || thn->pidFilter == currentPid) {
                        thn->handler(thn->data, info, context);
                    }
                    thn = thn->next.load(std::memory_order_seq_cst);
                }
            }

            struct sigaction newAction, prevAction;
            sigset_t unblock, prevBlocked;

            if ((signo == SIGSEGV || signo == SIGBUS || signo == SIGILL || signo == SIGFPE)
                    && !isUser && !isDynamic
#if defined(__OpenBSD__) || defined(__APPLE__)
// It seems that OpenBSD does not reliably set si_code when using raise(2).
// Same for MacOS.
                    && false
#endif
                    ) {
                // Fatal, best reraise option is just return from handler with default signal disposition
                // NOTE this will not work on linux < 4.14 if the signal is not a real SIGSEGV, but an io event
                //      masquerading as SIGSEGV etc. Just don't do that.
                newAction.sa_handler = SIG_DFL;
                newAction.sa_flags = 0;
                if (sigemptyset(&newAction.sa_mask) != 0) {
                    PosixSignalManager_sigdie(LIBNAME "Error in signal handler. Can not create empty signal set in crash reraise: ", errno);
                }
                if (sigaction(signo, &newAction, &prevAction) != 0) {
                    PosixSignalManager_sigdie(LIBNAME "Error in signal handler. Can not reset handler to default in crash reraise: ", errno);
                }
            } else if (isCrash || isTermination || specialEffect) {
                // trigger default signal handling.
                newAction.sa_handler = SIG_DFL;
                newAction.sa_flags = 0;
                if (sigaction(signo, &newAction, &prevAction) != 0) {
                    PosixSignalManager_sigdie(LIBNAME "Error in signal handler. Can not reset handler to default in reraise: ", errno);
                }
                if (raise(signo) != 0) {
                    PosixSignalManager_sigdie(LIBNAME "Error in signal handler. Can not raise signal in reraise: ", errno);
                }

                if (sigemptyset(&unblock) != 0) {
                    PosixSignalManager_sigdie(LIBNAME "Error in signal handler. Can not create empty signal set in reraise: ", errno);
                }
                if (sigaddset(&unblock, signo) != 0) {
                    PosixSignalManager_sigdie(LIBNAME "Error in signal handler. Can not add signal to signal set in reraise: ", errno);
                }
                if (sigprocmask(SIG_UNBLOCK, &unblock, &prevBlocked) != 0) {
                    PosixSignalManager_sigdie(LIBNAME "Error in signal handler. Can not unblock signal in reraise: ", errno);
                }
                // signal triggers here after unblock

                // For signals like SIGTSTP this code is reachable

                if (sigprocmask(SIG_SETMASK, &prevBlocked, nullptr) != 0) {
                    PosixSignalManager_sigdie(LIBNAME "Error in signal handler. Can not restore signal mask in reraise: ", errno);
                }
                if (sigaction(signo, &prevAction, nullptr) != 0) {
                    PosixSignalManager_sigdie(LIBNAME "Error in signal handler. Can not restore handler in reraise: ", errno);
                }
            }
        }

        asyncSignalHandlerRunning.fetch_sub(1, std::memory_order_seq_cst);
        errno = savedErrno;

        // do this as the very last action
        if (shouldChain) {
            if (originalSignalActions[signo].sa_flags & SA_SIGINFO) {
                originalSignalActions[signo].sa_sigaction(signo, info, context);
            } else {
                originalSignalActions[signo].sa_handler(signo);
            }
        }
    }

    void PosixSignalManager_install_handler(int signo) { // mainline (locked) access only
        if (!signalHandlerInstalled[signo]) {
            sigaction(signo, nullptr, &originalSignalActions[signo]);
            struct sigaction sa;
            memset(&sa, 0, sizeof(sa));
            sigemptyset(&sa.sa_mask);
            sa.sa_flags = SA_SIGINFO | SA_RESTART;
            sa.sa_sigaction = &PosixSignalManager_handler;
            sigaction(signo, &sa, nullptr); // TODO error handling
            signalHandlerInstalled[signo] = true;
        }
    }
}

PosixSignalFlags::PosixSignalFlags(PosixSignalFlagsPrivate *impl)
    : _impl(impl)
{
}

PosixSignalFlags::~PosixSignalFlags() {
}

void PosixSignalFlags::reraise() {
    _impl->reraise = true;
}

void PosixSignalFlags::clearReraise() {
    _impl->reraise = false;
}

bool PosixSignalFlags::isReraiseSet() {
    return _impl->reraise;
}

void PosixSignalFlags::stopChain() {
    _impl->stopChain = true;
}

bool PosixSignalFlags::isStopChainSet() {
    return _impl->stopChain;
}

class PosixSignalNotifierPrivate {
public:
    PosixSignalNotifierPrivate(int signo) : signo(signo) {

    }

    int signo = 0;
    int registrationId = -1;
};

PosixSignalNotifier::PosixSignalNotifier(int signo, QObject *parent)
    : PosixSignalNotifier(signo, PosixSignalOptions(), parent)
{
}

PosixSignalNotifier::PosixSignalNotifier(int signo, const PosixSignalOptions &options, QObject *parent)
    : QObject(parent), impl(new PosixSignalNotifierPrivate(signo))
{
    impl->registrationId = PosixSignalManager::instance()->addSignalNotifier(signo, options, this);
}

PosixSignalNotifier::~PosixSignalNotifier() {
    PosixSignalManager::instance()->removeHandler(impl->registrationId);
}

void PosixSignalNotifier::_readyRead(int socket) {
    QSharedPointer<siginfo_t> info = QSharedPointer<siginfo_t>::create();
    // We always write a full siginfo_t and nothing else should be reading from this fd. So we should always
    // be able to get a full siginfo_t out.
    int toRead = sizeof(siginfo_t);
    int filled = 0;
    do {
        int len = read(socket, ((char*)info.data()) + filled, toRead);
        if (len == 0) {
            qDebug(LIBNAME "Got end of stream while reading from self pipe");
            break;
        }
        if (len < 0) {
            if (errno == EINTR) {
                continue;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // spurious wakeup of some sort?
                break;
            } else {
                qDebug(LIBNAME "Got error while reading from self pipe");
                break;
            }
        }
        filled += len;
        toRead -= len;
    } while (toRead > 0);
    if (filled == sizeof(siginfo_t)) {
        activated(impl->signo, info);
    }
}

class PosixSignalManagerPrivate {
public:
    static QMutex mutex;
    QMap<int, Node*> idMap;
    int nextId = 1;

    int generateId() {
        // assume less than 2**31 active registrations
        while (true) {
            int id = nextId;
            ++nextId;
            if (nextId == std::numeric_limits<decltype(nextId)>::max()) {
                nextId = 1;
            }
            if (!idMap.contains(id)) {
                return id;
            }
        }
    }
};

QMutex PosixSignalManagerPrivate::mutex;

PosixSignalManager::PosixSignalManager()
    : impl(new PosixSignalManagerPrivate())
{
}

PosixSignalManager *PosixSignalManager::create() {
    QMutexLocker locker(&PosixSignalManagerPrivate::mutex);

    if (::instance) {
        qDebug() << "PosixSignalManager::create: Already created";
        throw std::runtime_error("PosixSignalManager::create: Already created");
    }
    PosixSignalManager_init();
    ::instance = new PosixSignalManager();
    return ::instance;
}

PosixSignalManager *PosixSignalManager::instance() {
    QMutexLocker locker(&PosixSignalManagerPrivate::mutex);

    if (!::instance) {
        qDebug() << "PosixSignalManager::instance: Called before PosixSignalManager::create";
        throw std::runtime_error("PosixSignalManager::instance: Called before PosixSignalManager::create");
    }
    return ::instance;
}

bool PosixSignalManager::isCreated() {
    QMutexLocker locker(&PosixSignalManagerPrivate::mutex);
    return ::instance != nullptr;
}

namespace {
    template<typename T>
    void addToRoot(T* newNode, std::atomic<T*> &root) {  // mainline (locked) access only
        T* node = root.load(std::memory_order_seq_cst);
        if (!node) {
            root.store(newNode, std::memory_order_seq_cst);
        } else {
            while (true) {
                T* nextNode = node->next.load(std::memory_order_seq_cst);
                if (!nextNode) break;
                node = nextNode;
            }
            node->next.store(newNode, std::memory_order_seq_cst);
        }
    }

    void installIfDefault(int signo) { // mainline (locked) access only
        if (!signalStates[signo].handlerInstalled) {
            struct sigaction sa;
            sigaction(signo, nullptr, &sa);
            if (sa.sa_handler == SIG_DFL) {
                PosixSignalManager_install_handler(signo);
            }
        }
    }

    void installIfNeeded(int signo) { // mainline (locked) access only
        if (!signalStates[signo].handlerInstalled) {
            PosixSignalManager_install_handler(signo);
        }
    }
}

int PosixSignalManager::addSyncTerminationHandler(PosixSignalManager::SyncTerminationHandler handler, void *data, const PosixSignalOptions &options) {
    QMutexLocker locker(&PosixSignalManagerPrivate::mutex);
    PosixSignalManagerPrivate *const d = impl.data();

    SyncTerminationHandlerNode* newNode = new SyncTerminationHandlerNode();
    // lifetime is complicated. FIXME document more?
    newNode->handler = handler;
    newNode->data = data;
    newNode->signo = 0;
    newNode->type = NodeType::SyncTerminationHandler;
    newNode->id = d->generateId();
    newNode->pidFilter = (options._forkFilter == PosixSignalOptions::ForkNoFollow) ? getpid() : 0;
    d->idMap[newNode->id] = newNode;
    addToRoot(newNode, syncTerminationHandlers);


    installIfDefault(SIGALRM);
    installIfDefault(SIGHUP);
    installIfDefault(SIGINT);
#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__APPLE__) && !defined(__NetBSD__)
    // ^^^ various bsds ignore sigio by default
    installIfDefault(SIGIO);
#endif
    installIfDefault(SIGPIPE);
    installIfDefault(SIGPROF);
#if defined(SIGPWR) && !defined(__NetBSD__)
    installIfDefault(SIGPWR);
#endif
    installIfDefault(SIGQUIT);
#ifdef SIGSTKFLT
    installIfDefault(SIGSTKFLT);
#endif
    installIfDefault(SIGTERM);
    installIfDefault(SIGUSR1);
    installIfDefault(SIGUSR2);
    installIfDefault(SIGVTALRM);
    installIfDefault(SIGXCPU);
    installIfDefault(SIGXFSZ);

#ifdef SIGRTMAX
    for (int i = SIGRTMIN; i < SIGRTMAX; i++) {
        installIfDefault(i);
    }
#endif

    return newNode->id;
}

int PosixSignalManager::addSyncCrashHandler(PosixSignalManager::SyncTerminationHandler handler, void *data, const PosixSignalOptions &options) {
    QMutexLocker locker(&PosixSignalManagerPrivate::mutex);
    PosixSignalManagerPrivate *const d = impl.data();

    SyncTerminationHandlerNode* newNode = new SyncTerminationHandlerNode();
    // lifetime is complicated. FIXME document more?
    newNode->handler = handler;
    newNode->data = data;
    newNode->signo = 0;
    newNode->type = NodeType::SyncCrashHandler;
    newNode->id = d->generateId();
    newNode->pidFilter = (options._forkFilter == PosixSignalOptions::ForkNoFollow) ? getpid() : 0;
    d->idMap[newNode->id] = newNode;
    addToRoot(newNode, syncCrashHandlers);

#if defined(SIGEMT)
    installIfDefault(SIGEMT);
#endif
    installIfDefault(SIGBUS);
    installIfDefault(SIGILL);
    installIfDefault(SIGSEGV);
    installIfDefault(SIGABRT);
    installIfDefault(SIGFPE);
    installIfDefault(SIGSYS);
    installIfDefault(SIGTRAP);

    return newNode->id;
}

int PosixSignalManager::addSyncSignalHandler(int signo, PosixSignalManager::SyncHandler handler, void *data, const PosixSignalOptions &options) {
    QMutexLocker locker(&PosixSignalManagerPrivate::mutex);
    PosixSignalManagerPrivate *const d = impl.data();
    if (signo >= NUM_SIGNALS || signo < 1) {
        // error
        return -1;
    }

    SyncHandlerNode* newNode = new SyncHandlerNode();
    // lifetime is complicated. FIXME document more?
    newNode->handler = handler;
    newNode->data = data;
    newNode->type = NodeType::SyncHandler;
    newNode->signo = signo;
    newNode->id = d->generateId();
    newNode->pidFilter = (options._forkFilter == PosixSignalOptions::ForkNoFollow) ? getpid() : 0;
    d->idMap[newNode->id] = newNode;
    addToRoot(newNode, signalStates[signo].syncHandlers);

    installIfNeeded(signo);

    return newNode->id;
}

namespace {
    template<typename T>
    void removeAndFreeHandler(Node *n, int id, std::atomic<T*> &root) {  // mainline (locked) access only
        T *nodeToRemove = static_cast<T*>(n);
        T *node = root.load(std::memory_order_seq_cst);
        if (node == nodeToRemove) {
            root.store(nodeToRemove->next.load(std::memory_order_seq_cst), std::memory_order_seq_cst);
        } else {
            while (node) {
                T* nextNode = node->next.load(std::memory_order_seq_cst);
                if (nextNode == nodeToRemove) {
                    node->next.store(nodeToRemove->next.load(std::memory_order_seq_cst), std::memory_order_seq_cst);
                    break;
                }
                node = nextNode;
            }
            if (!node) {
                qDebug() << "PosixSignalManager::removeHandler: Id " << id << " not properly linked";
                throw std::runtime_error("PosixSignalManager::removeHandler: Id not properly linked");
            }
        }
        while (asyncSignalHandlerRunning.load(std::memory_order_seq_cst) != 0) {
            // spin wait until no signal handler is running
        }
        delete nodeToRemove;
    }
}


void PosixSignalManager::removeHandler(int id) {
    QMutexLocker locker(&PosixSignalManagerPrivate::mutex);
    PosixSignalManagerPrivate *const d = impl.data();
    if (!d->idMap.contains(id)) {
        qDebug() << "PosixSignalManager::removeHandler: Id " << id << " does not exist";
        throw std::runtime_error("PosixSignalManager::removeHandler: Id does not exist");
    }
    Node *n = d->idMap[id];
    d->idMap.remove(id);
    int signo = n->signo;

    if (n->type == NodeType::SyncHandler) {
        removeAndFreeHandler(n, id, signalStates[signo].syncHandlers);
    } else if (n->type == NodeType::SyncTerminationHandler) {
        removeAndFreeHandler(n, id, syncTerminationHandlers);
    } else if (n->type == NodeType::SyncCrashHandler) {
        removeAndFreeHandler(n, id, syncCrashHandlers);
    } else if (n->type == NodeType::NotifyFd) {
        int pipe_write = static_cast<NotifyFdNode*>(n)->write_fd;
        int pipe_read = static_cast<NotifyFdNode*>(n)->read_fd;
        removeAndFreeHandler(n, id, signalStates[signo].notifyFds);
        close(pipe_write);
        close(pipe_read);
    }
}

bool PosixSignalManager::setupSignalChaining(int signo, PosixSignalManager::ChainingMode mode) {
    QMutexLocker locker(&PosixSignalManagerPrivate::mutex);

    if (signo >= NUM_SIGNALS || signo < 1) {
        // error
        return false;
    }

    if (mode != ChainingMode::ChainAlways && mode != ChainingMode::ChainIfReraiseSet) {
        return false;
    }

    installIfNeeded(signo);

    if (mode == ChainingMode::ChainAlways) {
        signalStates[signo].chainingMode.store(InternalChainingMode::ChainAlways, std::memory_order_seq_cst);
    }

    if (mode == ChainingMode::ChainIfReraiseSet) {
        signalStates[signo].chainingMode.store(InternalChainingMode::ChainIfReraiseSet, std::memory_order_seq_cst);
    }

    return true;
}

void PosixSignalManager::barrier() {
    while (asyncSignalHandlerRunning.load(std::memory_order_seq_cst) != 0) {
        // spin wait until no signal handler is running
    }
}

int PosixSignalManager::classifySignal(int signo) {
    bool isTermination = false;
    bool isCrash = false;
    bool specialEffect = false;
    PosixSignalManager_classify_signo(signo, &isTermination, &isCrash, &specialEffect);
    return ((isTermination || isCrash) ? 1 : 0) | (isCrash ? 2 : 0);
}

int PosixSignalManager::addSignalNotifier(int signo, const PosixSignalOptions &options, PosixSignalNotifier *notifier) {
    QMutexLocker locker(&PosixSignalManagerPrivate::mutex);
    PosixSignalManagerPrivate *const d = impl.data();

    if (signo >= NUM_SIGNALS || signo < 1) {
        // error
        return -1;
    }

    bool isTermination = false;
    bool isCrash = false;
    bool specialEffect = false;
    PosixSignalManager_classify_signo(signo, &isTermination, &isCrash, &specialEffect);

    if (isCrash) {
        // error
        return -1;
    }

    int pipes[2];
    int r;
#ifndef NO_PIPE2
    std::initializer_list<int> flags = {
#ifdef O_NOSIGPIPE
#ifdef __linux__
        O_CLOEXEC | O_NONBLOCK | O_NOSIGPIPE | O_DIRECT,
#else
        O_CLOEXEC | O_NONBLOCK | O_NOSIGPIPE,
#endif
#endif
#ifdef __linux__
        O_CLOEXEC | O_NONBLOCK | O_DIRECT,
#endif
        O_CLOEXEC | O_NONBLOCK
    };
    for (int f : flags) {
        r = ::pipe2(pipes, f);
        if (r == 0 || errno != EINVAL) break;
    }
#else
    r = ::pipe(pipes);
#endif
    if (r != 0) {
        qDebug() << "PosixSignalNotifier: Can't create internal pipe";
        throw std::runtime_error("PosixSignalNotifier: Can't create internal pipe");
    }
#ifdef NO_PIPE2
    fcntl(pipes[1], F_SETFD, FD_CLOEXEC);
    fcntl(pipes[0], F_SETFD, FD_CLOEXEC);
#endif

    NotifyFdNode* newNode = new NotifyFdNode();
    // lifetime is complicated. FIXME document more?
    newNode->write_fd = pipes[1];
    newNode->read_fd = pipes[0];
    newNode->type = NodeType::NotifyFd;
    newNode->signo = signo;
    newNode->id = d->generateId();
    newNode->pidFilter = (options._forkFilter == PosixSignalOptions::ForkFollow) ? 0 : getpid();
    d->idMap[newNode->id] = newNode;
    addToRoot(newNode, signalStates[signo].notifyFds);

    installIfNeeded(signo);

    QSocketNotifier* qsn = new QSocketNotifier(pipes[0], QSocketNotifier::Read, notifier);
    QObject::connect(qsn, &QSocketNotifier::activated, notifier, &PosixSignalNotifier::_readyRead);

    return newNode->id;
}

PosixSignalOptions PosixSignalOptions::dontFollowForks() {
    PosixSignalOptions ret = *this;
    ret._forkFilter = ForkNoFollow;
    return ret;
}

PosixSignalOptions PosixSignalOptions::followForks() {
    PosixSignalOptions ret = *this;
    ret._forkFilter = ForkFollow;
    return ret;
}
