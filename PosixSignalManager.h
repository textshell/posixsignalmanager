#ifndef POSIXSIGNALMANAGER_INCLUDED
#define POSIXSIGNALMANAGER_INCLUDED

#include <signal.h>

#include <memory>

#include <QObject>

class PosixSignalFlagsPrivate;
class PosixSignalFlags {
    PosixSignalFlags(const PosixSignalFlags&) = delete;
    PosixSignalFlags &operator=(const PosixSignalFlags&) = delete;

public:
    void reraise();
    void clearReraise();
    bool isReraiseSet();

    void stopChain();
    bool isStopChainSet();

public: // internal interface
    PosixSignalFlags(PosixSignalFlagsPrivate *impl);
    ~PosixSignalFlags();

private:
    PosixSignalFlagsPrivate* _impl;
};

class PosixSignalOptionsPrivate;
class PosixSignalOptions {
    friend class PosixSignalManager;
public:
    PosixSignalOptions();
    PosixSignalOptions(const PosixSignalOptions &other);
    ~PosixSignalOptions();

    PosixSignalOptions &operator=(const PosixSignalOptions &other);

public:
    PosixSignalOptions dontFollowForks();
    PosixSignalOptions followForks();

private:
    std::unique_ptr<PosixSignalOptionsPrivate> _impl;
};

class PosixSignalNotifierPrivate;
class PosixSignalNotifier : public QObject {
    Q_OBJECT
public:
    PosixSignalNotifier(int signo, QObject *parent = nullptr);
    PosixSignalNotifier(int signo, const PosixSignalOptions &options, QObject *parent = nullptr);
    ~PosixSignalNotifier() override;

Q_SIGNALS:
    void activated(int signo, QSharedPointer<const siginfo_t> info);

private Q_SLOTS:
    void _readyRead(int socket);

private:
    QScopedPointer<PosixSignalNotifierPrivate> impl;
    friend class PosixSignalManager;
};

class PosixSignalManagerPrivate;
class PosixSignalManager {
public:
    using SyncHandler = void(void *data, PosixSignalFlags &flags, const siginfo_t *info, void *context);
    using SyncTerminationHandler = void(void *data, const siginfo_t *info, void *context);
    enum class ChainingMode : int { ChainAlways, ChainIfReraiseSet };

public:
    static PosixSignalManager *create();
    static PosixSignalManager *instance();
    static bool isCreated();

public:
    // SIGINT, SIGTERM etc
    int addSyncTerminationHandler(SyncTerminationHandler handler, void *data, const PosixSignalOptions &options = PosixSignalOptions());
    // SIGSEGV etc
    int addSyncCrashHandler(SyncTerminationHandler handler, void *data, const PosixSignalOptions &options = PosixSignalOptions());

    int addSyncSignalHandler(int signo, SyncHandler handler, void *data, const PosixSignalOptions &options = PosixSignalOptions());

    void removeHandler(int id);

    bool setupSignalChaining(int signo, ChainingMode mode);

    void barrier();

public:
    static int classifySignal(int signo);

public: // internal interface
    int addSignalNotifier(int signo, const PosixSignalOptions &options, PosixSignalNotifier* notifier);

private:
    PosixSignalManager();

    QScopedPointer<PosixSignalManagerPrivate> impl;
};

#endif // POSIXSIGNALMANAGER_INCLUDED
