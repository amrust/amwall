#include "dbusclient.h"

#include <QDBusArgument>
#include <QDBusConnection>
#include <QDBusError>
#include <QDBusInterface>
#include <QDBusMessage>
#include <QDBusMetaType>
#include <QDBusPendingCall>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QDBusReply>
#include <QDebug>
#include <QTimer>

QDBusArgument& operator<<(QDBusArgument &arg, const RuleEntry &e) {
    // Wire order MUST match the daemon's interface:
    //   List() returns a(ssqs) — (comm, ip, port, action)
    arg.beginStructure();
    arg << e.comm << e.ip << e.port << e.action;
    arg.endStructure();
    return arg;
}

const QDBusArgument& operator>>(const QDBusArgument &arg, RuleEntry &e) {
    arg.beginStructure();
    arg >> e.comm >> e.ip >> e.port >> e.action;
    arg.endStructure();
    return arg;
}

QDBusArgument& operator<<(QDBusArgument &arg, const SocketProc &e) {
    // Wire order MUST match the daemon's ResolveSockets return type:
    //   a(tuss) — (inode_u64, pid_u32, comm, exe)
    arg.beginStructure();
    arg << e.inode << e.pid << e.comm << e.exe;
    arg.endStructure();
    return arg;
}

const QDBusArgument& operator>>(const QDBusArgument &arg, SocketProc &e) {
    arg.beginStructure();
    arg >> e.inode >> e.pid >> e.comm >> e.exe;
    arg.endStructure();
    return arg;
}

QDBusArgument& operator<<(QDBusArgument &arg, const BlocklistEntry &e) {
    // Wire order MUST match daemon BlocklistList return:
    //   a(ssuub) — (name, description, v4_count, v6_count, enabled)
    arg.beginStructure();
    arg << e.name << e.description << e.v4Count << e.v6Count << e.enabled;
    arg.endStructure();
    return arg;
}

const QDBusArgument& operator>>(const QDBusArgument &arg, BlocklistEntry &e) {
    arg.beginStructure();
    arg >> e.name >> e.description >> e.v4Count >> e.v6Count >> e.enabled;
    arg.endStructure();
    return arg;
}

DbusClient::DbusClient(QObject *parent) : QObject(parent) {
    // Register custom marshallers ONCE per process. qDBusRegisterMetaType
    // is idempotent but cheap-redundant; we still only get one DbusClient
    // per process so this is fine.
    qDBusRegisterMetaType<RuleEntry>();
    qDBusRegisterMetaType<QList<RuleEntry>>();
    qDBusRegisterMetaType<SocketProc>();
    qDBusRegisterMetaType<QList<SocketProc>>();
    qDBusRegisterMetaType<BlocklistEntry>();
    qDBusRegisterMetaType<QList<BlocklistEntry>>();

    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &DbusClient::refresh);
    subscribeSignals();
}

void DbusClient::subscribeSignals() {
    auto bus = QDBusConnection::systemBus();
    if (!bus.isConnected()) {
        qWarning() << "DbusClient: system bus not connected; signal subscription skipped";
        return;
    }
    // Old-style SLOT() macro is required for QDBusConnection::connect():
    // Qt's D-Bus demarshaller introspects the slot signature to map
    // the wire types `usqs` (uint, str, str, ushort, str). The
    // functor (new-style) form does not work for D-Bus signals.
    bool ok = bus.connect(
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("/org/amwall/Daemon1"),
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("ConnectAttempt"),
        this,
        SLOT(onDbusConnectAttempt(uint, QString, QString, ushort, QString)));
    if (!ok) {
        qWarning() << "DbusClient: failed to subscribe to ConnectAttempt:"
                   << bus.lastError().message();
    }
    bool ok2 = bus.connect(
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("/org/amwall/Daemon1"),
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("EnabledChanged"),
        this,
        SLOT(onDbusEnabledChanged(bool)));
    if (!ok2) {
        qWarning() << "DbusClient: failed to subscribe to EnabledChanged:"
                   << bus.lastError().message();
    }
}

void DbusClient::onDbusConnectAttempt(uint pid, const QString &comm,
                                      const QString &ip, ushort port,
                                      const QString &action) {
    emit connectAttempt(pid, comm, ip, port, action);
}

void DbusClient::onDbusEnabledChanged(bool enabled) {
    if (m_enforcementEnabled == enabled) return;
    m_enforcementEnabled = enabled;
    qInfo() << "DbusClient: enforcement →" << (enabled ? "ON" : "OFF (bypass)");
    emit enforcementEnabledChanged(enabled);
    // stateChanged also fires so listeners that re-render on any
    // state delta (status bar, tabs) catch this without subscribing
    // separately.
    emit stateChanged();
}

void DbusClient::startAutoRefresh(int intervalMs) {
    m_timer->start(intervalMs);
}

void DbusClient::stopAutoRefresh() {
    m_timer->stop();
}

void DbusClient::refresh() {
    QString err;
    bool ok = pingDaemon(&err);
    if (ok) {
        QList<RuleEntry> rules;
        ok = listRules(&rules, &err);
        if (ok) {
            m_reachable = true;
            m_rules = std::move(rules);
            m_lastError.clear();

            // Poll IsEnabled every refresh tick so the toolbar /
            // status badge stays accurate even if the EnabledChanged
            // signal got dropped (rare) or another GUI client
            // changed state before we connected. Sync .call() —
            // this is a single-bool reply, sub-millisecond on the
            // local bus. Fire enforcementEnabledChanged on transition
            // so downstream listeners flip without waiting for a
            // signal-broadcast that already happened.
            QDBusMessage msg = QDBusMessage::createMethodCall(
                QStringLiteral("org.amwall.Daemon1"),
                QStringLiteral("/org/amwall/Daemon1"),
                QStringLiteral("org.amwall.Daemon1"),
                QStringLiteral("IsEnabled"));
            QDBusMessage reply = QDBusConnection::systemBus().call(
                msg, QDBus::Block, 2000);
            if (reply.type() == QDBusMessage::ReplyMessage
                && !reply.arguments().isEmpty()) {
                bool newState = reply.arguments().first().toBool();
                if (newState != m_enforcementEnabled) {
                    m_enforcementEnabled = newState;
                    emit enforcementEnabledChanged(newState);
                }
            }
            // If IsEnabled is unreachable (e.g., daemon predates the
            // method), leave m_enforcementEnabled at its last known
            // value — the optimistic-true default at construction
            // matches default-on semantics.
        } else {
            m_reachable = false;
            m_rules.clear();
            m_lastError = err;
        }
    } else {
        m_reachable = false;
        m_rules.clear();
        m_lastError = err;
    }

    m_lastRefresh = QDateTime::currentDateTime();

    // Always emit — status-bar refresh timestamp updates each tick
    // even when the daemon state is unchanged.
    emit stateChanged();
}

bool DbusClient::hasAnyRuleFor(const QString &comm) const {
    for (const RuleEntry &r : m_rules) {
        if (r.comm == comm) return true;
    }
    return false;
}

QHash<quint64, SocketProc>
DbusClient::resolveSockets(const QList<quint64> &inodes) {
    QHash<quint64, SocketProc> out;
    if (inodes.isEmpty()) return out;

    // Use QDBusMessage directly (not QDBusInterface::call) so we can
    // return a QVariant whose held QDBusArgument is in proper read
    // mode — going through QDBusReply<QDBusArgument> hands you a copy
    // that hits the "write from a read-only object" footgun and
    // corrupts libdbus on the next beginStructure call.
    QDBusMessage msg = QDBusMessage::createMethodCall(
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("/org/amwall/Daemon1"),
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("ResolveSockets"));
    msg.setArguments({ QVariant::fromValue(inodes) });

    QDBusMessage reply = QDBusConnection::systemBus().call(
        msg, QDBus::Block, 5000);
    if (reply.type() != QDBusMessage::ReplyMessage) {
        qWarning() << "ResolveSockets failed:" << reply.errorMessage();
        return out;
    }
    const QList<QVariant> outArgs = reply.arguments();
    if (outArgs.isEmpty()) return out;

    // Use the registered SocketProc / QList<SocketProc> streamers
    // (defined above) — they handle const-correct demarshalling and
    // don't trip the read-only-copy bug.
    const QDBusArgument arg = outArgs.first().value<QDBusArgument>();
    QList<SocketProc> list;
    arg >> list;
    for (const SocketProc &sp : list) {
        out.insert(sp.inode, sp);
    }
    return out;
}

QList<BlocklistEntry> DbusClient::blocklistList() {
    QList<BlocklistEntry> out;
    QDBusMessage msg = QDBusMessage::createMethodCall(
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("/org/amwall/Daemon1"),
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("BlocklistList"));
    QDBusMessage reply = QDBusConnection::systemBus().call(
        msg, QDBus::Block, 5000);
    if (reply.type() != QDBusMessage::ReplyMessage) {
        qWarning() << "BlocklistList failed:" << reply.errorMessage();
        return out;
    }
    const QList<QVariant> outArgs = reply.arguments();
    if (outArgs.isEmpty()) return out;
    const QDBusArgument arg = outArgs.first().value<QDBusArgument>();
    arg >> out;
    return out;
}

void DbusClient::setEnforcementEnabled(bool enabled) {
    // Polkit-gated SetEnabled call. Async because polkit auth can
    // take a moment to render and we don't want to freeze the GUI.
    // The daemon emits EnabledChanged on success which our
    // onDbusEnabledChanged subscriber picks up — no need to handle
    // success here, just surface failures.
    QDBusMessage msg = QDBusMessage::createMethodCall(
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("/org/amwall/Daemon1"),
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("SetEnabled"));
    msg.setArguments({ enabled });
    auto pending = QDBusConnection::systemBus().asyncCall(
        msg, /*timeoutMs=*/30000);
    auto *watcher = new QDBusPendingCallWatcher(pending, this);
    connect(watcher, &QDBusPendingCallWatcher::finished,
            this, [this, enabled](QDBusPendingCallWatcher *w) {
        QDBusPendingReply<> r = *w;
        if (r.isError()) {
            qWarning() << "SetEnabled(" << enabled << ") failed:"
                       << r.error().message();
            // Fire enforcementEnabledChanged with the OLD value so
            // any UI that optimistically flipped (e.g., a toolbar
            // toggle) reverts. Force a refresh to be sure.
            emit enforcementEnabledChanged(m_enforcementEnabled);
            refresh();
        }
        // Success: EnabledChanged signal already updated state via
        // onDbusEnabledChanged → enforcementEnabledChanged.
        w->deleteLater();
    });
}

void DbusClient::resetDaemon() {
    // Help → "Reset all rules and config" entry-point. Async because
    // the daemon's Reset method is polkit-gated (same auth as
    // Allow/Deny/Del/BlocklistSetEnabled); a synchronous call would
    // freeze the GUI for however long polkit takes to render its
    // auth prompt. Generous timeout for the same reason.
    QDBusMessage msg = QDBusMessage::createMethodCall(
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("/org/amwall/Daemon1"),
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("Reset"));
    auto pending = QDBusConnection::systemBus().asyncCall(
        msg, /*timeoutMs=*/30000);
    auto *watcher = new QDBusPendingCallWatcher(pending, this);
    connect(watcher, &QDBusPendingCallWatcher::finished,
            this, [this](QDBusPendingCallWatcher *w) {
        QDBusPendingReply<> r = *w;
        if (r.isError()) {
            const QString err = r.error().message();
            qWarning() << "Reset failed:" << err;
            emit resetCompleted(false, err);
        } else {
            qInfo() << "Reset succeeded";
            // Force an immediate cache refresh so the GUI's rule
            // count drops to 0 on the next paint instead of waiting
            // for the 5-second poll.
            refresh();
            emit resetCompleted(true, QString());
        }
        w->deleteLater();
    });
}

void DbusClient::setBlocklistEnabled(const QString &name, bool enabled) {
    // Async via QDBusPendingCall so polkit prompts don't block the
    // event loop. Same pattern as callModify(): we don't wait for the
    // reply — the next refresh tick reflects the new state.
    QDBusMessage msg = QDBusMessage::createMethodCall(
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("/org/amwall/Daemon1"),
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("BlocklistSetEnabled"));
    msg.setArguments({ name, enabled });
    auto pending = QDBusConnection::systemBus().asyncCall(msg);
    auto *watcher = new QDBusPendingCallWatcher(pending, this);
    connect(watcher, &QDBusPendingCallWatcher::finished,
            this, [this](QDBusPendingCallWatcher *w) {
        QDBusPendingReply<> r = *w;
        if (r.isError()) {
            qWarning() << "BlocklistSetEnabled error:"
                       << r.error().message();
        }
        // Trigger a refresh so any listeners (BlocklistTab) re-read.
        emit stateChanged();
        w->deleteLater();
    });
}

void DbusClient::allow(const QString &comm, const QString &ip, ushort port) {
    callModify("Allow", comm, ip, port);
}

void DbusClient::deny(const QString &comm, const QString &ip, ushort port) {
    callModify("Deny", comm, ip, port);
}

void DbusClient::del(const QString &comm, const QString &ip, ushort port) {
    callModify("Del", comm, ip, port);
}

void DbusClient::callModify(const char *method, const QString &comm,
                            const QString &ip, ushort port) {
    auto bus = QDBusConnection::systemBus();
    auto msg = QDBusMessage::createMethodCall(
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("/org/amwall/Daemon1"),
        QStringLiteral("org.amwall.Daemon1"),
        QString::fromLatin1(method));
    msg << comm << ip << QVariant::fromValue<ushort>(port);

    // asyncCall: polkit may pop a prompt or take a bus round-trip;
    // don't freeze the GUI while waiting. The timeout is generous
    // because polkit interaction can be slow.
    auto pending = bus.asyncCall(msg, /*timeoutMs=*/15000);
    auto *watcher = new QDBusPendingCallWatcher(pending, this);
    connect(watcher, &QDBusPendingCallWatcher::finished,
            this, [this, method, comm, ip, port](QDBusPendingCallWatcher *w) {
        QDBusPendingReply<> reply = *w;
        if (reply.isError()) {
            qWarning() << "DbusClient:" << method
                       << "(" << comm << "," << ip << "," << port << ") failed:"
                       << reply.error().message();
        } else {
            // Speed up the cache update so PromptCoordinator's hasRule
            // check sees the new entry on the next signal. The 5-second
            // poll would otherwise lag behind a fast user.
            this->refresh();
        }
        w->deleteLater();
    });
}

bool DbusClient::pingDaemon(QString *errOut) {
    auto bus = QDBusConnection::systemBus();
    if (!bus.isConnected()) {
        if (errOut) *errOut = bus.lastError().message();
        return false;
    }
    auto msg = QDBusMessage::createMethodCall(
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("/org/amwall/Daemon1"),
        QStringLiteral("org.freedesktop.DBus.Peer"),
        QStringLiteral("Ping"));
    auto reply = bus.call(msg, QDBus::Block, /*timeoutMs=*/2000);
    if (reply.type() == QDBusMessage::ErrorMessage) {
        if (errOut) *errOut = reply.errorMessage();
        return false;
    }
    return true;
}

bool DbusClient::listRules(QList<RuleEntry> *out, QString *errOut) {
    // org.amwall.Daemon1.List() returns a(ssqs) — array of
    // (comm, ip, port, action) tuples. Demarshalled via the
    // RuleEntry operator>> registered with qDBusRegisterMetaType
    // in the ctor. The previous manual beginArray/beginStructure
    // pattern on a value-copy of QDBusArgument warned
    // "QDBusArgument: write from a read-only object" on every
    // refresh tick and corrupted libdbus state badly enough to
    // crash with "type struct 114 not a basic type" after enough
    // accumulated bad reads.
    auto bus = QDBusConnection::systemBus();
    auto msg = QDBusMessage::createMethodCall(
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("/org/amwall/Daemon1"),
        QStringLiteral("org.amwall.Daemon1"),
        QStringLiteral("List"));
    auto reply = bus.call(msg, QDBus::Block, /*timeoutMs=*/2000);
    if (reply.type() != QDBusMessage::ReplyMessage) {
        if (errOut) *errOut = reply.errorMessage();
        return false;
    }
    if (reply.arguments().isEmpty()) {
        return true;  // empty list, leave *out as-is
    }
    const QVariant first = reply.arguments().first();

    // Path 1: the bus marshaller already converted the wire to our
    // registered QList<RuleEntry> type — no QDBusArgument needed.
    if (first.canConvert<QList<RuleEntry>>()) {
        *out = first.value<QList<RuleEntry>>();
        return true;
    }

    // Path 2: the value is still a raw QDBusArgument (typical for
    // complex types). Stream into a QList — operator>> on QList
    // uses our registered RuleEntry operator>>.
    if (!first.canConvert<QDBusArgument>()) {
        if (errOut) *errOut = QStringLiteral("List() returned unexpected type");
        return false;
    }
    const QDBusArgument arg = first.value<QDBusArgument>();
    QList<RuleEntry> list;
    arg >> list;
    *out = list;
    return true;
}
