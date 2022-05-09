<h1 align="center">
    Posix Signal Manager
</h1>

Library safe, synchronous and asynchronous handling of posix signals for Qt applications and libraries.

## Why?

The interface of libc for posix signals is not library safe, as each signal can only have one handler.
This library offers an interface where multiple parts of an application can share access to signals.

The easiest way is to use `PosixSignalNotifier` to convert posix signals to a Qt signal. The Qt signal is delivered
via the Qt event loop and thus it is safe to use all the usual apis available to the application.

It is also possible to register handlers for crashes (SIGSEGV etc) or signal based termination (SIGINT, SIGTERM, etc)
using `PosixSignalManager::addSyncCrashHandler` and `PosixSignalManager::addSyncTerminationHandler` to add emergency
cleanup. These handlers have to be
[async signal safe](https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html#tag_15_04_03),
which is a quite restrictive environment.

If waiting for a event loop iteration is not acceptable or the signal is of a type that can only be handled directly
from a posix signal handler there is also the possiblity to use `PosixSignalManager::addSyncSignalHandler` to register
handlers that run directly in the async signal context. Again these handlers have to be 
[async signal safe](https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html#tag_15_04_03),
which is a quite restrictive environment. Synchronous handlers can stop processing the signal or mark it to be reraised.

## Alternatives

Often using signals is not the best way to achieve robust code. If possible consider alternatives to signals.

* process management: [pidfd(linux)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html), [pdfork(freebsd)](https://www.freebsd.org/cgi/man.cgi?query=pdfork&sektion=2)
* timers: [QTimer](https://doc.qt.io/qt-5/qtimer.html) [timerfd](https://man7.org/linux/man-pages/man2/timerfd_create.2.html)
* interprocess communication: [dbus](https://doc.qt.io/qt-5/qtdbus-index.html) see also [dbus @ freedesktop](https://www.freedesktop.org/wiki/Software/dbus/)

## Building / Installing

    $ meson setup -Dprefix=$HOME/opt/signalmanager/ _build
    $ ninja -C _build
    $ ninja -C _build install

## Examples

### Reload configuration on SIGHUP

This example handles SIGHUP using a Qt signal on a future event loop iteration.

``` cpp
    if (!PosixSignalManager::isCreated()) PosixSignalManager::create();
    auto* notifier = new PosixSignalNotifier(SIGHUP, parent);
    QObject::connect(notifier, &PosixSignalNotifier::activated, parent, &SomeClass::reloadConfig);
```

### Quit gracefully on SIGTERM

This example handles SIGTERM by terminating the event loop on a future event loop iteration.

``` cpp
    if (!PosixSignalManager::isCreated()) PosixSignalManager::create();
    auto* notifier = new PosixSignalNotifier(SIGTERM, parent);
    QObject::connect(notifier, &PosixSignalNotifier::activated, QCoreApplication::instance(),
                     [](auto signal, auto info) { QCoreApplication::instance()->quit(); });
```

If the program is prone to get stuck without servicing the event loop and a further SIGTERM should be usable to do
an emergency stop it is possible to combine the Qt signal based clean shutdown with an emergency shutdown from the
signal handler

``` cpp
    if (!PosixSignalManager::isCreated()) PosixSignalManager::create();
    auto* notifier = new PosixSignalNotifier(SIGTERM, parent);
    QObject::connect(notifier, &PosixSignalNotifier::activated, QCoreApplication::instance(),
                     [](auto signal, auto info) { QCoreApplication::instance()->quit(); });
    auto* manager = PosixSignalManager::instance();
    manager->addSyncSignalHandler(SIGTERM, [](void *data, PosixSignalFlags &flags, const siginfo_t *info, void *context) {
        static std::atomic<int> count = 0;
        if (count == 0) {
            flags.clearReraise();
        } else {
            // emergency shutdown here
            // maybe remove a pid file or some other externally visible cleanup
            
            // request posix signal manager to terminate application as if no signal handler had been set
            flags.reraise();
            // or as alternative
            // _exit(1);            
        }
        ++count;
    }, nullptr);
```


## Documentation

Before most functionality of this library can be used, its main singleton must be created.
Applications may only create this singleton once.

If a library wants to detect if PosixSignalManager is already in use it can detect this by calling
`PosixSignalManager::isCreated()`. If usage of PosixSignalManager is optional the library can then either use
PosixSignalManager or can fall back to using sigaction.
Otherwise all users should ensure to call `PosixSignalManager::create()` if the singleton was not yet created and
proceed with usage.

The instance of the singleton can be retrieved using `PosixSignalManager::instance`.

After the singleton is created the main interfaces of PosixSignalManager are `PosixSignalNotifier` for message loop
based signal processing and `PosixSignalManager` for low level synchronous signal handling.

### PosixSignalNotifier

`PosixSignalNotifier` is the easiest way to handle the usual signals used for communication.
Just create an instance and pass the signal number to catch as the first constructor argument and connect your handler
to the `activated` signal of the instance.

The `activated` signal passes the number of the caught signal as the first parameter and the full signal details as a
`siginfo_t` structure in the second parameter.

Signals handled with this class are processed in the event loop of the thread that called its constructor as soon as
that event loop reacts the newly available data in PosixSignalNotifier's internal pipe.

If the instance of PosixSignalNotifier is deleted the signal handling reverts back.
Although the low level event handler is not removed, PosixSignalManager will emulate the signals default action when no
PosixSignalNotifier instances or synchronous handlers remain.

This class is not suitable to handle crash signals such as "Segmentation Fault"(SIGSEGV), "Bus Error"(SIGBUS),
"Illegal Instruction"(SIGILL), "Floating Point Error"(SIGFPE) and similar signals.

### PosixSignalManager

If handling the signal via PosixSignalNotifier is not enough PosixSignalManager offers an interface to hook into the
signal's low level handler. All handler functions used with PosixSignalManager must be
[async signal safe](https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html#tag_15_04_03)
([linux](https://man7.org/linux/man-pages/man7/signal-safety.7.html)).
That means most functions and methods one would usually use are not permitted to be called in signal handling functions.
This includes all of Qt, most of the c++ standard library(always lookfree std::atomic should be ok) and even most of the
standard c library. Also calling (sig)longjump from synchronous handlers is not supported in this library.

All handlers are executed in the order of their registration.

One common use case is to register cleanup handlers using `PosixSignalManager::addSyncCrashHandler` and
`PosixSignalManager::addSyncTerminationHandler` to do last moment cleanup before a process dies due to an otherwise
unhandled signal.
The handlers registered using these methods always run after all other handlers and only if the signal is not marked as
handled or handled using `PosixSignalNotifier`.

The crash handlers are called on signals normally associated with process crashes or failed assertations (like SIGSEGV,
SIGBUS, SIGABRT, etc). Crash handlers are also suitable to print or log crash information.

The termination handlers are called on signals that are fatal that are not crash signals.

Termination handler can not stop or modify signal propagation(except calling abort, _exit or similar).

For synchronous handling of signals `PosixSignalManager::addSyncSignalHandler` can be used.
This method registers a handler for a specific signal.
The signal handler can influence the further processing of the signal by calling methods on the `PosixSignalFlags`
object passed as its second parameter.
To prevent the default action of the signal (which is often process termination) the handler should call
`PosixSignalFlags::clearReraise` if it could handle the signal.
Most handlers for communication signals should always call this method, on the other hand handlers that can only handle
a subset of possible signal causes (like SIGSEGV/SIGBUS handlers for specific data or code segments) should call
clearReraise only if they could handle or fix the cause of the signal.
The existance of an instance of `PosixSignalNotifier` implicitly disables reraise of a signal.
In addition handlers can suppress calling of later registered handlers for the same signal by calling
`PosixSignalFlags::stopChain`.

All handler registrations return an `int` registration id that can be used with `PosixSignalManager::removeHandler`
to remove the handler when no longer needed.
Although the low level event handler is not removed PosixSignalManager will emulate the signals default action when
no PosixSignalNotifier instances or synchronous handlers remain.

Variables used from the signal or termination handlers need to be threated with special care as these can be accessed
from the handlers any time while they are manipulated. Even locally blocking the signal will not prevent this in
multithreaded processes. Thus it is safest to always use lock free algorithms that atomically replace old state with
new state. To help with freeing previously used memory after swaping to a new state, PosixSignalManager offers
`PosixSignalManager::barrier` which guarantees that every handler that was running before the call started has
terminated after the call returns.

## Compatiblity and Porting

The main library needs little porting to not yet supported posix-like operating systems. The main concern is updating
the conditions for default fatal signals and possibly updating what method to use to reraise crash signals.

The tests cover many edge cases and are more work to port.

This library currently is known to work and pass its tests on:
Linux (>= 4.14, various distros, glibc and musl), FreeBSD, OpenBSD, NetBSD, Illumos and Apple.

## License

PosixSignalManager is licensed under the [Boost Software License 1.0](COPYING)
