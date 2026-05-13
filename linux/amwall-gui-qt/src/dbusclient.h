// DbusClient — D-Bus client for org.amwall.Daemon1.
//
// Owns the system-bus connection. Polls Peer.Ping + List() on a
// QTimer (or on-demand via refresh()) to keep the rule cache fresh.
// Subscribes to the ConnectAttempt signal and re-emits it as a Qt
// signal so PromptCoordinator can react. Provides allow()/deny()
// helpers that fire-and-forget the corresponding daemon methods
// (polkit gates them server-side; failures land in qWarning).
//
// Synchronous .call() is used for List/Ping (small payload, local
// daemon) — async would just add complexity for sub-millisecond
// responses. allow()/deny() use asyncCall to avoid blocking the GUI
// while polkit prompts (when applicable).

#pragma once

#include <QDateTime>
#include <QDBusArgument>
#include <QList>
#include <QMetaType>
#include <QObject>
#include <QString>

class QTimer;

struct RuleEntry {
    QString comm;
    QString ip;
    QString action;  // "allow" or "deny"
    ushort  port;
};
Q_DECLARE_METATYPE(RuleEntry)

// Returned by DbusClient::resolveSockets — one row per resolved
// inode. Defined outside the class so moc doesn't try to parse it
// as a signal/slot declaration inside a slots: section. The inode
// field carries the key (we deserialize into QList<SocketProc> then
// build the hash on the GUI side); pid/comm/exe are the resolved
// process info. Wire type: (tuss) = (uint64, uint32, str, str).
struct SocketProc {
    quint64 inode = 0;
    uint    pid = 0;
    QString comm;
    QString exe;
};
Q_DECLARE_METATYPE(SocketProc)

QDBusArgument& operator<<(QDBusArgument &arg, const SocketProc &e);
const QDBusArgument& operator>>(const QDBusArgument &arg, SocketProc &e);

// Phase 6.9 — one row per .txt under /usr/share/amwall/blocklists.
// Wire type: (ssuub) — (name, description, v4_count, v6_count, enabled).
struct BlocklistEntry {
    QString name;
    QString description;
    uint    v4Count = 0;
    uint    v6Count = 0;
    bool    enabled = false;
};
Q_DECLARE_METATYPE(BlocklistEntry)

QDBusArgument& operator<<(QDBusArgument &arg, const BlocklistEntry &e);
const QDBusArgument& operator>>(const QDBusArgument &arg, BlocklistEntry &e);

// Free-function streaming operators — registered with the D-Bus
// metatype system in DbusClient's ctor. Once registered, Qt can
// (un)marshal QList<RuleEntry> directly via operator>> on a
// QDBusArgument with no manual beginArray/beginStructure dance.
// The manual dance triggers "QDBusArgument: write from a read-only
// object" warnings (because the value-copy hits non-const overloads)
// and eventually corrupts libdbus state into a struct/basic mismatch.
QDBusArgument& operator<<(QDBusArgument &arg, const RuleEntry &e);
const QDBusArgument& operator>>(const QDBusArgument &arg, RuleEntry &e);

class DbusClient : public QObject {
    Q_OBJECT

public:
    explicit DbusClient(QObject *parent = nullptr);

    bool isReachable() const         { return m_reachable; }
    int  ruleCount()   const         { return m_rules.size(); }
    const QList<RuleEntry>& rules() const { return m_rules; }
    QDateTime lastRefresh() const    { return m_lastRefresh; }
    QString lastError() const        { return m_lastError; }

    // True if rules.toml already contains ANY rule (allow or deny,
    // any IP, any port) for this comm. Once the user has decided
    // about an app — even just one specific destination — we don't
    // re-prompt. Matches simplewall/Win32 amwall semantics: the
    // prompt is per-process, not per-(process, ip, port).
    bool hasAnyRuleFor(const QString &comm) const;

    void startAutoRefresh(int intervalMs);
    void stopAutoRefresh();

public slots:
    // Re-poll the daemon and emit stateChanged().
    void refresh();

    // Persist a rule via the daemon. Async — if polkit denies, a
    // qWarning lands in ~/.local/share/amwall/gui.log. After the next refresh
    // tick the rule shows up in our cache.
    void allow(const QString &comm, const QString &ip, ushort port);
    void deny(const QString &comm, const QString &ip, ushort port);

    // Delete an existing rule. Same async pattern.
    void del(const QString &comm, const QString &ip, ushort port);

    // Synchronous D-Bus call to the daemon's ResolveSockets method.
    // The daemon (root) walks /proc/<pid>/fd/* and returns
    // inode → (pid, comm, exe) for every inode in the input list it
    // can resolve. Used by ConnectionsTab so sockets owned by other
    // users (root daemons like systemd-resolved) get a real Process
    // cell instead of "(unknown)". Inodes the daemon couldn't match
    // are simply absent from the returned map. Returns an empty
    // map on D-Bus failure (timeout, daemon dead). SocketProc itself
    // is defined at file scope above so moc doesn't try to parse it
    // as a slot declaration.
    QHash<quint64, SocketProc> resolveSockets(const QList<quint64> &inodes);

    // Phase 6.9 — blocklist API. blocklistList() returns one
    // BlocklistEntry per .txt file under /usr/share/amwall/blocklists.
    // setBlocklistEnabled() is polkit-gated and triggers an immediate
    // BPF map resync on the daemon side. Both return empty / silently
    // fail when D-Bus is unreachable.
    QList<BlocklistEntry> blocklistList();
    void setBlocklistEnabled(const QString &name, bool enabled);

    // Help → "Reset all rules and config" entry. Calls the polkit-
    // gated daemon Reset method (truncates rules.toml, deletes
    // blocklists.toml, clears BPF maps). Fires resetCompleted(true,
    // {}) on success or resetCompleted(false, err) on failure.
    // GUI-side QSettings cleanup is MainWindow's job — daemon owns
    // root-owned files, GUI owns user-home files. Privilege split
    // intentional.
    void resetDaemon();

signals:
    void stateChanged();

    // Re-emitted from the D-Bus ConnectAttempt signal. Filtering
    // (action / family / dedup) lives in PromptCoordinator.
    void connectAttempt(uint pid, const QString &comm,
                        const QString &ip, ushort port,
                        const QString &action);

    // Fires after the async daemon Reset reply lands. Connected by
    // MainWindow so the user-config cleanup + UI refresh runs.
    void resetCompleted(bool ok, const QString &errOut);

private slots:
    // Private — wired to QDBusConnection::connect() with the OLD-
    // style SLOT() macro because Qt's D-Bus signal demarshaller
    // requires it. Forwards to the public Qt connectAttempt signal.
    void onDbusConnectAttempt(uint pid, const QString &comm,
                              const QString &ip, ushort port,
                              const QString &action);

private:
    bool pingDaemon(QString *errOut);
    bool listRules(QList<RuleEntry> *out, QString *errOut);
    void subscribeSignals();
    void callModify(const char *method, const QString &comm,
                    const QString &ip, ushort port);

    QTimer *m_timer = nullptr;

    bool             m_reachable = false;
    QList<RuleEntry> m_rules;
    QDateTime        m_lastRefresh;
    QString          m_lastError;
};
