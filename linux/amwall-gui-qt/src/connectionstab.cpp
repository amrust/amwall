#include "connectionstab.h"

#include "dbusclient.h"

#include <QDir>
#include <QFile>
#include <QHash>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QHostAddress>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QSignalBlocker>
#include <QStyle>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextStream>
#include <QTimer>
#include <QVBoxLayout>

namespace {

struct ProcInfo {
    int     pid = 0;
    QString comm;
    QString exe;
};

// Walk /proc once, build a {socket-inode → owning process} map by
// reading every /proc/<pid>/fd/* symlink and matching those that
// point at "socket:[NNNN]". O(processes × fds). On a typical
// desktop this is ~500 dir reads + ~5000 readlinks, ~30-80 ms.
// The 5-second tab refresh tolerates that without UI lag, so no
// background thread for now.
//
// Skips PIDs we can't open (other users' processes when running
// unprivileged) — they leave gaps in the inode map and the matching
// Connections rows render Process="(unknown)".
QHash<quint64, ProcInfo> scanSocketInodes() {
    QHash<quint64, ProcInfo> out;
    QDir procDir(QStringLiteral("/proc"));
    const QStringList entries = procDir.entryList(
        QDir::Dirs | QDir::NoDotAndDotDot, QDir::Unsorted);
    for (const QString &pidStr : entries) {
        bool ok = false;
        int pid = pidStr.toInt(&ok);
        if (!ok) continue;

        QDir fdDir(QStringLiteral("/proc/%1/fd").arg(pid));
        if (!fdDir.exists()) continue;
        const QStringList fds = fdDir.entryList(QDir::NoDotAndDotDot,
                                                QDir::Unsorted);
        if (fds.isEmpty()) continue;  // unreadable for us → skip

        ProcInfo info;
        info.pid = pid;
        bool resolvedMeta = false;
        for (const QString &fd : fds) {
            const QString linkPath = fdDir.absoluteFilePath(fd);
            const QString target   = QFile::symLinkTarget(linkPath);
            if (!target.startsWith(QStringLiteral("socket:["))) continue;
            const int rb = target.indexOf(']');
            if (rb < 0) continue;
            bool inodeOk = false;
            const quint64 inode = target.mid(8, rb - 8).toULongLong(&inodeOk);
            if (!inodeOk) continue;

            if (!resolvedMeta) {
                QFile commF(QStringLiteral("/proc/%1/comm").arg(pid));
                if (commF.open(QIODevice::ReadOnly)) {
                    info.comm = QString::fromUtf8(commF.readAll()).trimmed();
                }
                info.exe = QFile::symLinkTarget(
                    QStringLiteral("/proc/%1/exe").arg(pid));
                resolvedMeta = true;
            }
            out.insert(inode, info);
        }
    }
    return out;
}

QString tcpStateName(int hex) {
    switch (hex) {
    case 0x01: return QStringLiteral("ESTABLISHED");
    case 0x02: return QStringLiteral("SYN_SENT");
    case 0x03: return QStringLiteral("SYN_RECV");
    case 0x04: return QStringLiteral("FIN_WAIT1");
    case 0x05: return QStringLiteral("FIN_WAIT2");
    case 0x06: return QStringLiteral("TIME_WAIT");
    case 0x07: return QStringLiteral("CLOSE");
    case 0x08: return QStringLiteral("CLOSE_WAIT");
    case 0x09: return QStringLiteral("LAST_ACK");
    case 0x0A: return QStringLiteral("LISTEN");
    case 0x0B: return QStringLiteral("CLOSING");
    default:   return QStringLiteral("?(0x%1)").arg(hex, 2, 16, QChar('0'));
    }
}

// /proc/net/tcp address column: HEX_IP:HEX_PORT
// IPv4: 8 hex chars (the kernel's host-endian u32 view of the network-
//       order address bytes) + ':' + 4 hex chars (host-order port).
// Example: "0100007F:0050"  →  127.0.0.1:80   (on x86 LE)
QString formatV4Addr(const QString &s) {
    const QStringList parts = s.split(':');
    if (parts.size() != 2) return s;
    bool ok = false;
    const quint32 ip   = parts[0].toUInt(&ok, 16);   if (!ok) return s;
    const quint16 port = parts[1].toUShort(&ok, 16); if (!ok) return s;
    return QStringLiteral("%1.%2.%3.%4:%5")
        .arg(ip & 0xff)
        .arg((ip >> 8)  & 0xff)
        .arg((ip >> 16) & 0xff)
        .arg((ip >> 24) & 0xff)
        .arg(port);
}

// IPv6: 32 hex chars = four u32 words (each in host-endian, but each
// word's BYTES in increasing memory order = network byte order).
// To reconstruct the 16 network-order bytes, extract little-endian
// bytes of each word and append in order.
QString formatV6Addr(const QString &s) {
    const QStringList parts = s.split(':');
    if (parts.size() != 2 || parts[0].length() != 32) return s;
    Q_IPV6ADDR addr;
    for (int g = 0; g < 4; ++g) {
        bool ok = false;
        const quint32 word = parts[0].mid(g * 8, 8).toUInt(&ok, 16);
        if (!ok) return s;
        addr.c[g * 4 + 0] = char(word & 0xff);
        addr.c[g * 4 + 1] = char((word >> 8)  & 0xff);
        addr.c[g * 4 + 2] = char((word >> 16) & 0xff);
        addr.c[g * 4 + 3] = char((word >> 24) & 0xff);
    }
    bool ok = false;
    const quint16 port = parts[1].toUShort(&ok, 16);
    QHostAddress qaddr(addr);
    return QStringLiteral("[%1]:%2").arg(qaddr.toString()).arg(ok ? port : 0);
}

struct Conn {
    QString proto;
    QString local;
    QString remote;
    QString state;
    quint64 inode = 0;   // /proc/net/tcp column [9] — joins with scanSocketInodes()
};

// /proc/net/tcp column layout (header row of `cat /proc/net/tcp`):
//   sl  local_address  rem_address  st  tx_queue:rx_queue  tr:tm->when
//   retrnsmt  uid  timeout  inode  ...
// Indexes used here: [1]=local [2]=remote [3]=state [9]=inode.
QList<Conn> readProcNetTcp(const QString &path, bool ipv6) {
    QList<Conn> out;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return out;
    QTextStream in(&f);
    in.readLine();   // skip header
    const QRegularExpression splitter("\\s+");
    while (!in.atEnd()) {
        const QString line = in.readLine().trimmed();
        if (line.isEmpty()) continue;
        const QStringList fields = line.split(splitter, Qt::SkipEmptyParts);
        if (fields.size() < 10) continue;
        bool ok = false;
        const int stHex = fields[3].toInt(&ok, 16);
        bool inodeOk = false;
        const quint64 inode = fields[9].toULongLong(&inodeOk);
        out.append(Conn{
            ipv6 ? QStringLiteral("tcp6") : QStringLiteral("tcp4"),
            ipv6 ? formatV6Addr(fields[1]) : formatV4Addr(fields[1]),
            ipv6 ? formatV6Addr(fields[2]) : formatV4Addr(fields[2]),
            ok   ? tcpStateName(stHex) : fields[3],
            inodeOk ? inode : 0,
        });
    }
    return out;
}

}  // namespace

ConnectionsTab::ConnectionsTab(DbusClient *dbus, QWidget *parent)
    : QWidget(parent), m_dbus(dbus) {
    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(8, 8, 8, 8);
    outer->setSpacing(6);

    auto *header = new QHBoxLayout;
    auto *title = new QLabel(tr("<b>Connections</b>"), this);
    title->setTextFormat(Qt::RichText);
    header->addWidget(title);
    m_countLabel = new QLabel(QStringLiteral("(0)"), this);
    header->addWidget(m_countLabel);
    header->addSpacing(12);

    header->addWidget(new QLabel(tr("Filter:"), this));
    m_filter = new QLineEdit(this);
    m_filter->setPlaceholderText(tr("process, IP, or port..."));
    m_filter->setClearButtonEnabled(true);
    connect(m_filter, &QLineEdit::textChanged,
            this, &ConnectionsTab::onFilterChanged);
    header->addWidget(m_filter, 1);

    auto *refreshBtn = new QPushButton(
        style()->standardIcon(QStyle::SP_BrowserReload),
        tr("Refresh"), this);
    connect(refreshBtn, &QPushButton::clicked, this, &ConnectionsTab::refresh);
    header->addWidget(refreshBtn);
    outer->addLayout(header);

    m_table = new QTableWidget(0, 5, this);
    m_table->setHorizontalHeaderLabels({
        tr("Process"), tr("Proto"), tr("Local"), tr("Remote"), tr("State")
    });
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSortingEnabled(true);
    m_table->verticalHeader()->setVisible(false);
    // All Interactive; last column (State) stretches to fill. Click
    // header to sort. Default widths fit ~95% of real content.
    auto *hh = m_table->horizontalHeader();
    hh->setSectionsClickable(true);
    hh->setSortIndicatorShown(true);
    hh->setSectionResizeMode(QHeaderView::Interactive);
    hh->setStretchLastSection(true);
    m_table->setColumnWidth(0, 220);  // Process
    m_table->setColumnWidth(1, 60);   // Proto
    m_table->setColumnWidth(2, 200);  // Local
    m_table->setColumnWidth(3, 200);  // Remote
    // State stretches.
    outer->addWidget(m_table, 1);

    auto *hint = new QLabel(
        tr("<i style='font-size: small;'>"
           "Process column is resolved by the daemon (running as root) "
           "via D-Bus — see every owning PID/comm/exe across all users."
           "</i>"),
        this);
    hint->setTextFormat(Qt::RichText);
    hint->setWordWrap(true);
    outer->addWidget(hint);

    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &ConnectionsTab::refresh);
    m_timer->start(5000);
    refresh();
}

void ConnectionsTab::refresh() {
    QList<Conn> rows = readProcNetTcp(QStringLiteral("/proc/net/tcp"), false);
    rows.append(readProcNetTcp(QStringLiteral("/proc/net/tcp6"), true));

    // Ask the daemon (root) to resolve every inode in one D-Bus call.
    // Falls back to a (limited, our-uid-only) GUI-side /proc walk if
    // D-Bus is unreachable or returns nothing — that way the tab still
    // shows the user's own processes when the daemon is down.
    QList<quint64> wantedInodes;
    wantedInodes.reserve(rows.size());
    for (const Conn &c : rows) {
        if (c.inode != 0) wantedInodes.append(c.inode);
    }
    QHash<quint64, ProcInfo> inodeMap;
    if (m_dbus) {
        const auto daemonMap = m_dbus->resolveSockets(wantedInodes);
        for (auto it = daemonMap.constBegin(); it != daemonMap.constEnd(); ++it) {
            inodeMap.insert(it.key(), ProcInfo{
                static_cast<int>(it.value().pid),
                it.value().comm,
                it.value().exe,
            });
        }
    }
    if (inodeMap.isEmpty()) {
        // Daemon unreachable or replied empty — best-effort local walk
        // so we still show *something* (our own processes).
        inodeMap = scanSocketInodes();
    }

    m_table->setSortingEnabled(false);
    m_table->setRowCount(rows.size());
    int resolved = 0;
    for (int i = 0; i < rows.size(); ++i) {
        const Conn &c = rows[i];
        const auto it = inodeMap.constFind(c.inode);
        QString procCell;
        QString tooltip;
        if (it != inodeMap.constEnd()) {
            const QString comm = it->comm.isEmpty()
                ? tr("(no comm)") : it->comm;
            procCell = QStringLiteral("%1 (pid %2)").arg(comm).arg(it->pid);
            if (!it->exe.isEmpty()) tooltip = it->exe;
            ++resolved;
        } else {
            procCell = tr("(unknown)");
        }
        auto *procItem = new QTableWidgetItem(procCell);
        if (!tooltip.isEmpty()) procItem->setToolTip(tooltip);
        m_table->setItem(i, 0, procItem);
        m_table->setItem(i, 1, new QTableWidgetItem(c.proto));
        m_table->setItem(i, 2, new QTableWidgetItem(c.local));
        m_table->setItem(i, 3, new QTableWidgetItem(c.remote));
        m_table->setItem(i, 4, new QTableWidgetItem(c.state));
    }
    m_table->setSortingEnabled(true);
    m_countLabel->setText(
        tr("(%1 sockets, %2 resolved)").arg(rows.size()).arg(resolved));

    // Re-apply the active filter so newly-arrived sockets don't pop
    // into view ignoring the user's current search needle.
    if (m_filter && !m_filter->text().isEmpty()) {
        onFilterChanged(m_filter->text());
    }
}

void ConnectionsTab::onFilterChanged(const QString &text) {
    // Hide rows whose Process / Proto / Local / Remote / State columns
    // don't contain the needle (case-insensitive substring). Same shape
    // as AppsTab and UserRulesTab. Empty needle = show all.
    const QString needle = text.trimmed();
    QSignalBlocker block(m_table);
    for (int r = 0; r < m_table->rowCount(); ++r) {
        bool hide = false;
        if (!needle.isEmpty()) {
            bool hit = false;
            for (int c = 0; c < m_table->columnCount(); ++c) {
                if (auto *it = m_table->item(r, c)) {
                    if (it->text().contains(needle, Qt::CaseInsensitive)) {
                        hit = true;
                        break;
                    }
                }
            }
            if (!hit) hide = true;
        }
        m_table->setRowHidden(r, hide);
    }
}
