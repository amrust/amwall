// ConnectionsTab — Phase 6.5 + 6.5.1. Live view of the system's TCP
// socket table (/proc/net/tcp + /proc/net/tcp6) joined with per-PID
// process info from /proc/<pid>/fd/*. Auto-refreshes every 5 s.
//
// Permission model: as an unprivileged user, we can only enumerate
// /proc/<pid>/fd for our own processes. Sockets owned by other users
// (especially root daemons like systemd-resolved) show "(unknown)"
// in the Process column. Running the GUI as root would resolve all.
//
// Columns: Process | Proto | Local | Remote | State

#pragma once

#include <QWidget>

class DbusClient;
class QLabel;
class QLineEdit;
class QTableWidget;
class QTimer;

class ConnectionsTab : public QWidget {
    Q_OBJECT

public:
    // dbus may be null — we still render the socket table but the
    // Process column reads "(unknown)" for every row.
    explicit ConnectionsTab(DbusClient *dbus, QWidget *parent = nullptr);

public slots:
    void refresh();

private slots:
    void onFilterChanged(const QString &text);

private:
    DbusClient   *m_dbus = nullptr;
    QTimer       *m_timer = nullptr;
    QTableWidget *m_table = nullptr;
    QLineEdit    *m_filter = nullptr;
    QLabel       *m_countLabel = nullptr;
};
