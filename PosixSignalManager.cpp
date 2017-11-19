#include "PosixSignalManager.h"

#include <atomic>
#include <limits>

#if 1
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#endif

#include <QDebug>
#include <QMap>
#include <QMutex>
#include <QMutexLocker>
#include <QSocketNotifier>

#ifdef _NSIG
    #define NUM_SIGNALS _NSIG
#else
    #define NUM_SIGNALS 65
#endif

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
    };

    struct SyncHandlerNode : public Node {
        PosixSignalManager::SyncHandler *handler = nullptr;
        std::atomic<SyncHandlerNode*> next;
    };

    struct SyncTerminationHandlerNode : public Node {
        PosixSignalManager::SyncTerminationHandler *handler = nullptr;
        std::atomic<SyncTerminationHandlerNode*> next;
    };

    struct NotifyFdNode : public Node {
        int write_fd = -1;
        int read_fd = -1;
        std::atomic<NotifyFdNode*> next;
    };

    struct SignalState {
        std::atomic<SyncHandlerNode*> syncHandlers;
        std::atomic<NotifyFdNode*> notifyFds;
        bool handlerInstalled; // mainline (locked) access only
    };

    std::atomic<SyncTerminationHandlerNode*> syncTerminationHandlers;
    std::atomic<SyncTerminationHandlerNode*> syncCrashHandlers;
    SignalState signalStates[NUM_SIGNALS] = { };
    std::atomic<int> asyncSignalHandlerRunning;

    bool signalHandlerInstalled[NUM_SIGNALS] = { false };
    struct sigaction originalSignalActions[NUM_SIGNALS] = { }; // mainline (locked) access only

    void PosixSignalManager_init() { // mainline (locked) access only
        asyncSignalHandlerRunning.store(0, std::memory_order_seq_cst);
        for (int i = 0; i < NUM_SIGNALS; i++) {
            signalStates[i].syncHandlers.store(nullptr, std::memory_order_seq_cst);
            signalStates[i].notifyFds.store(nullptr, std::memory_order_seq_cst);
            signalStates[i].handlerInstalled = false;
        }
        syncTerminationHandlers.store(nullptr, std::memory_order_seq_cst);
    }

    void PosixSignalManager_handler(int signo, siginfo_t *info, void *context) {
        if (signo > NUM_SIGNALS) {
            // avoid buffer overlow in code below, should never happen:
            // signo < NUM_SIGNALS should always be true because we don't set this handler for anything higher
            return;
        }
        int savedErrno = errno;

        bool isUser = info->si_code == SI_USER || info->si_code == SI_QUEUE
#ifdef    SI_TKILL
                || info->si_code == SI_TKILL
#endif
                ;
        bool isDynamic = (info->si_code < 0 && !isUser) || info->si_code == SI_TIMER || info->si_code == SI_MESGQ
                || info->si_code == SI_ASYNCIO || info->si_code == SI_SIGIO;

        bool isTermination = false;
        bool isCrash = false;

        switch (signo) {
            case SIGABRT:
            case SIGALRM:
            case SIGFPE:
            case SIGHUP:
            case SIGINT:
            case SIGIO:
            case SIGPIPE:
            case SIGPROF:
            case SIGPWR:
            case SIGQUIT:
            case SIGSTKFLT:
            case SIGSYS:
            case SIGTERM:
            case SIGTRAP:
            case SIGUSR1:
            case SIGUSR2:
            case SIGVTALRM:
            case SIGXCPU:
            case SIGXFSZ:
                isTermination = true;
                break;
#if defined(SIGEMT)
            case SIGEMT:
#endif
            case SIGBUS:
            case SIGILL:
            case SIGSEGV:
                isCrash = true;
                break;
            default:
                break;
        }

        asyncSignalHandlerRunning.fetch_add(1, std::memory_order_seq_cst);

        SignalState* signalState = &signalStates[signo];
        // mainline may not delete nodes until asyncRefCount reaches 0 again
        PosixSignalFlags cb;

        SyncHandlerNode* syncHandler = signalState->syncHandlers.load(std::memory_order_seq_cst);
        NotifyFdNode* notifyFd = signalState->notifyFds.load(std::memory_order_seq_cst);
        if (syncHandler) {
            while (syncHandler) {
                syncHandler->handler(cb, info, context);
                if (cb.isStopChainSet()) {
                    break;
                }
                syncHandler = syncHandler->next.load(std::memory_order_seq_cst);
            }
        } else {
            if (!notifyFd) {
                cb.reraise();
            }
        }

        if (!cb.isStopChainSet()) {
            while (notifyFd) {
                write(notifyFd->write_fd, info, sizeof(*info));
                notifyFd = notifyFd->next.load(std::memory_order_seq_cst);
            }
        }

        if (cb.isReraiseSet()) {
            if (isTermination) {
                SyncTerminationHandlerNode* thn = syncTerminationHandlers.load(std::memory_order_seq_cst);
                while (thn) {
                    thn->handler(info, context);
                    thn = thn->next.load(std::memory_order_seq_cst);
                }
            } else if (isCrash) {
                SyncTerminationHandlerNode* thn = syncCrashHandlers.load(std::memory_order_seq_cst);
                while (thn) {
                    thn->handler(info, context);
                    thn = thn->next.load(std::memory_order_seq_cst);
                }
            }

            struct sigaction newAction, prevAction;
            sigset_t unblock, prevBlocked;

            if ((signo == SIGSEGV || signo == SIGBUS || signo == SIGILL || signo == SIGFPE)
                    && !isUser && !isDynamic) {
                // Fatal, best reraise option is just return from handler with default signal disposition
                // NOTE this will not work on linux < 4.14 if the signal is not a real SIGSEGV, but an io event
                //      masquerading as SIGSEGV etc. Just don't do that.
                newAction.sa_handler = SIG_DFL;
                newAction.sa_flags = 0;
                sigemptyset(&newAction.sa_mask);
                sigaction(signo, &newAction, &prevAction); //TODO error handling

#ifdef __linux__
                if (1) {
                    // Workaround for linux io event masquerading as SIGSEGV etc
                    timer_t timerid;
                    sigevent sev;
                    sev.sigev_notify = SIGEV_SIGNAL;
                    sev.sigev_signo = signo;
                    sev.sigev_value.sival_ptr = 0;
                    if (timer_create(CLOCK_REALTIME, &sev, &timerid) != -1) { // FIXME not async safe
                        itimerspec its;
                        its.it_value.tv_sec = 0;
                        its.it_value.tv_nsec = 1000000;
                        its.it_interval.tv_sec = its.it_value.tv_sec;
                        its.it_interval.tv_nsec = its.it_value.tv_nsec;
                        if (timer_settime(timerid, 0, &its, NULL) == -1) {
                            perror("timer_settime");
                            _exit(98);
                        }
                    }
                }
#endif
            } else {
                // trigger default signal handling.
                newAction.sa_handler = SIG_DFL;
                sigaction(signo, &newAction, &prevAction); //TODO error handling
                raise(signo);

                sigemptyset(&unblock);
                sigaddset(&unblock, signo);
                sigprocmask(SIG_UNBLOCK, &unblock, &prevBlocked); // TODO error handling
                // signal triggers here after unblock

                // For signals like SIGTSTP this code is reachable

                sigprocmask(SIG_SETMASK, &prevBlocked, nullptr); // TODO error handling
                sigaction(signo, &prevAction, nullptr); // TODO error handling
            }
        }

        asyncSignalHandlerRunning.fetch_sub(1, std::memory_order_seq_cst);
        errno = savedErrno;
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

void PosixSignalFlags::reraise() {
    _reraise = true;
}

void PosixSignalFlags::clearReraise() {
    _reraise = false;
}

bool PosixSignalFlags::isReraiseSet() {
    return _reraise;
}

void PosixSignalFlags::stopChain() {
    _stopChain = true;
}

bool PosixSignalFlags::isStopChainSet() {
    return _stopChain;
}

class PosixSignalNotifierPrivate {
public:
    PosixSignalNotifierPrivate(int signo) : signo(signo) {

    }

    int signo = 0;
    int registrationId = -1;
};

PosixSignalNotifier::PosixSignalNotifier(int signo, QObject *parent)
    : QObject(parent), impl(new PosixSignalNotifierPrivate(signo))
{
    impl->registrationId = PosixSignalManager::instance()->addSignalNotifier(signo, this);
}

PosixSignalNotifier::~PosixSignalNotifier() {
    PosixSignalManager::instance()->removeHandler(impl->registrationId);
}

void PosixSignalNotifier::_readyRead(int socket) {
    QSharedPointer<siginfo_t> info = QSharedPointer<siginfo_t>::create();
    int len = read(socket, info.data(), sizeof(siginfo_t));
    if (len == sizeof(siginfo_t)) {
        activated(impl->signo, info);
    }
}

class PosixSignalManagerPrivate {
public:
    QMutex mutex;
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

PosixSignalManager::PosixSignalManager()
    : impl(new PosixSignalManagerPrivate())
{
}

PosixSignalManager *PosixSignalManager::create() {
    if (::instance) {
        qDebug() << "PosixSignalManager::create: Already created";
        throw std::runtime_error("PosixSignalManager::create: Already created");
        return ::instance;
    }
    PosixSignalManager_init();
    ::instance = new PosixSignalManager();
    return ::instance;
}

PosixSignalManager *PosixSignalManager::instance() {
    if (!::instance) {
        qDebug() << "PosixSignalManager::instance: Called before PosixSignalManager::create";
        throw std::runtime_error("PosixSignalManager::instance: Called before PosixSignalManager::create");
    }
    return ::instance;
}

bool PosixSignalManager::isCreated() {
    return ::instance != nullptr;
}

namespace {
    template<typename T>
    void addToRoot(T* newNode, std::atomic<T*> &root)
    {
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

    void installIfDefault(int signo) {
        if (!signalStates[signo].handlerInstalled) {
            struct sigaction sa;
            sigaction(signo, nullptr, &sa);
            if (sa.sa_handler == SIG_DFL) {
                PosixSignalManager_install_handler(signo);
            }
        }
    }

    void installIfNeeded(int signo) {
        if (!signalStates[signo].handlerInstalled) {
            PosixSignalManager_install_handler(signo);
        }
    }
}

int PosixSignalManager::addSyncTerminationHandler(PosixSignalManager::SyncTerminationHandler handler) {
    PosixSignalManagerPrivate *const d = impl.data();
    QMutexLocker locker(&d->mutex);

    SyncTerminationHandlerNode* newNode = new SyncTerminationHandlerNode();
    // lifetime is complicated. FIXME document more?
    newNode->handler = handler;
    newNode->signo = 0;
    newNode->type = NodeType::SyncTerminationHandler;
    newNode->id = d->generateId();
    d->idMap[newNode->id] = newNode;
    addToRoot(newNode, syncTerminationHandlers);


    installIfDefault(SIGABRT);
    installIfDefault(SIGALRM);
    installIfDefault(SIGFPE);
    installIfDefault(SIGHUP);
    installIfDefault(SIGINT);
    installIfDefault(SIGIO);
    installIfDefault(SIGPIPE);
    installIfDefault(SIGPROF);
    installIfDefault(SIGPWR);
    installIfDefault(SIGQUIT);
    installIfDefault(SIGSTKFLT);
    installIfDefault(SIGSYS);
    installIfDefault(SIGTERM);
    installIfDefault(SIGTRAP);
    installIfDefault(SIGUSR1);
    installIfDefault(SIGUSR2);
    installIfDefault(SIGVTALRM);
    installIfDefault(SIGXCPU);
    installIfDefault(SIGXFSZ);

    return newNode->id;
}

int PosixSignalManager::addSyncCrashHandler(PosixSignalManager::SyncTerminationHandler handler) {
    PosixSignalManagerPrivate *const d = impl.data();
    QMutexLocker locker(&d->mutex);

    SyncTerminationHandlerNode* newNode = new SyncTerminationHandlerNode();
    // lifetime is complicated. FIXME document more?
    newNode->handler = handler;
    newNode->signo = 0;
    newNode->type = NodeType::SyncCrashHandler;
    newNode->id = d->generateId();
    d->idMap[newNode->id] = newNode;
    addToRoot(newNode, syncCrashHandlers);

#if defined(SIGEMT)
    installIfDefault(SIGEMT);
#endif
    installIfDefault(SIGBUS);
    installIfDefault(SIGILL);
    installIfDefault(SIGSEGV);

    return newNode->id;
}

int PosixSignalManager::addSyncSignalHandler(int signo, PosixSignalManager::SyncHandler handler) {
    PosixSignalManagerPrivate *const d = impl.data();
    QMutexLocker locker(&d->mutex);
    if (signo > NUM_SIGNALS || signo < 1) {
        // error
        return -1;
    }

    SyncHandlerNode* newNode = new SyncHandlerNode();
    // lifetime is complicated. FIXME document more?
    newNode->handler = handler;
    newNode->type = NodeType::SyncHandler;
    newNode->signo = signo;
    newNode->id = d->generateId();
    d->idMap[newNode->id] = newNode;
    addToRoot(newNode, signalStates[signo].syncHandlers);

    installIfNeeded(signo);

    return newNode->id;
}

namespace {
    template<typename T>
    void removeAndFreeHandler(Node *n, int id, std::atomic<T*> &root)
    {
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
    PosixSignalManagerPrivate *const d = impl.data();
    QMutexLocker locker(&d->mutex);
    if (!d->idMap.contains(id)) {
        qDebug() << "PosixSignalManager::removeHandler: Id " << id << " does not exist";
        throw std::runtime_error("PosixSignalManager::removeHandler: Id does not exist");
        return; // bogus id
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

int PosixSignalManager::addSignalNotifier(int signo, PosixSignalNotifier *notifier) {
    PosixSignalManagerPrivate *const d = impl.data();
    QMutexLocker locker(&d->mutex);

    if (signo > NUM_SIGNALS || signo < 1) {
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
    d->idMap[newNode->id] = newNode;
    addToRoot(newNode, signalStates[signo].notifyFds);

    installIfNeeded(signo);

    QSocketNotifier* qsn = new QSocketNotifier(pipes[0], QSocketNotifier::Read, notifier);
    QObject::connect(qsn, &QSocketNotifier::activated, notifier, &PosixSignalNotifier::_readyRead);

    return newNode->id;
}
