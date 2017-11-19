#ifndef POSIXSIGNALMANAGER_INCLUDED
#define POSIXSIGNALMANAGER_INCLUDED

#include <signal.h>

#include <QObject>

class PosixSignalFlags {
public:
    void reraise();
    void clearReraise();
    bool isReraiseSet();

    void stopChain();
    bool isStopChainSet();

private:
    bool _reraise = false;
    bool _stopChain = false;
};

class PosixSignalNotifierPrivate;
class PosixSignalNotifier : public QObject {
    Q_OBJECT
public:
    PosixSignalNotifier(int signo, QObject *parent = nullptr);
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
    using SyncHandler = void(PosixSignalFlags &flags, const siginfo_t *info, void *context);
    using SyncTerminationHandler = void(const siginfo_t *info, void *context);

public:
    static PosixSignalManager *create();
    static PosixSignalManager *instance();
    static bool isCreated();

public:
    // SIGINT, SIGTERM etc
    int addSyncTerminationHandler(SyncTerminationHandler handler);
    // SIGSEGV etc
    int addSyncCrashHandler(SyncTerminationHandler handler);

    int addSyncSignalHandler(int signo, SyncHandler handler);

    void removeHandler(int id);

    int allocateSignal();
    bool deallocateSignal(int signo);

public: // internal interface
    int addSignalNotifier(int signo, PosixSignalNotifier* notifier);

private:
    PosixSignalManager();

    QScopedPointer<PosixSignalManagerPrivate> impl;
};

#endif // POSIXSIGNALMANAGER_INCLUDED
