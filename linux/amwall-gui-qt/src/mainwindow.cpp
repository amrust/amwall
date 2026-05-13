#include "mainwindow.h"

#include "appstab.h"
#include "blocklisttab.h"
#include "connectionstab.h"
#include "dashboard.h"
#include "dbusclient.h"
#include "packetslogtab.h"
#include "promptcoordinator.h"
#include "settingsdialog.h"
#include "userrulestab.h"

#include <QAction>
#include <QApplication>
#include <QCloseEvent>
#include <QIcon>
#include <QKeySequence>
#include <QLabel>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QSettings>
#include <QStatusBar>
#include <QStyle>
#include <QTabWidget>
#include <QtGlobal>

#ifndef AMWALL_VERSION
#define AMWALL_VERSION "unknown"
#endif

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    setWindowTitle("amwall");
    resize(900, 600);

    m_dbus = new DbusClient(this);
    connect(m_dbus, &DbusClient::stateChanged,
            this, &MainWindow::onDbusStateChanged);

    // PromptCoordinator must exist BEFORE Dashboard so Dashboard can
    // bind to its pendingCountChanged signal in its constructor.
    m_prompts = new PromptCoordinator(m_dbus, /*windowAnchor=*/this, this);

    setupCentralWidget();
    setupStatusBar();
    setupMenuBar();
    setupTrayIcon();
    loadSettings();

    // Initial poll + start the auto-refresh heartbeat. Dashboard +
    // status bar both render off DbusClient::stateChanged.
    m_dbus->startAutoRefresh(5000);
    m_dbus->refresh();
}

void MainWindow::setupCentralWidget() {
    // Tabbed central. Overview = dashboard (informational). User
    // Rules = rule list + add/edit/delete (Phase 6.4). Connections
    // = live socket table (Phase 6.5/6.5.1). Packets log = rolling
    // ConnectAttempt history (Phase 6.6). 6.7 will append an Apps
    // tab driven off /usr/share/applications/*.desktop.
    m_tabs = new QTabWidget(this);
    m_dashboard   = new Dashboard(m_dbus, m_prompts, this);
    m_userRules   = new UserRulesTab(m_dbus, this);
    m_connections = new ConnectionsTab(m_dbus, this);
    m_packetsLog  = new PacketsLogTab(m_dbus, this);
    m_apps        = new AppsTab(m_dbus, this);
    m_blocklist   = new BlocklistTab(m_dbus, this);
    m_tabs->addTab(m_dashboard,   tr("&Overview"));
    m_tabs->addTab(m_userRules,   tr("&User Rules"));
    m_tabs->addTab(m_apps,        tr("&Apps"));
    m_tabs->addTab(m_blocklist,   tr("&Blocklists"));
    m_tabs->addTab(m_connections, tr("&Connections"));
    m_tabs->addTab(m_packetsLog,  tr("&Packets log"));
    // "Show in User Rules" in the Apps context menu jumps tabs.
    // No filtering of the User Rules table — the user can scroll
    // and the comm is in the first column so it's quick to find.
    connect(m_apps, &AppsTab::showInRulesRequested,
            this, [this](const QString &) {
                if (m_tabs && m_userRules) {
                    m_tabs->setCurrentWidget(m_userRules);
                }
            });
    // Default to User Rules — that's the action surface; the
    // dashboard is informational and a click away.
    m_tabs->setCurrentWidget(m_userRules);
    setCentralWidget(m_tabs);
}

void MainWindow::onAddRuleFromMenu() {
    if (m_tabs && m_userRules) {
        m_tabs->setCurrentWidget(m_userRules);
        m_userRules->onAddRule();
    }
}

void MainWindow::setupMenuBar() {
    // Only menus with real working handlers are added. See header
    // comment for why Edit / Settings / Blocklist are absent.
    auto *file = menuBar()->addMenu(tr("&File"));
    auto *refresh = file->addAction(tr("&Refresh"));
    refresh->setShortcut(QKeySequence(QKeySequence::Refresh));  // F5
    refresh->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));
    connect(refresh, &QAction::triggered, m_dbus, &DbusClient::refresh);
    file->addSeparator();
    auto *settings = file->addAction(tr("&Settings..."));
    settings->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_Comma));
    settings->setIcon(style()->standardIcon(QStyle::SP_FileDialogDetailedView));
    connect(settings, &QAction::triggered, this, &MainWindow::onSettings);
    file->addSeparator();
    auto *quit = file->addAction(tr("&Quit"));
    quit->setShortcut(QKeySequence::Quit);  // Ctrl+Q
    quit->setIcon(style()->standardIcon(QStyle::SP_DialogCloseButton));
    connect(quit, &QAction::triggered, this, &MainWindow::onQuit);

    // Edit menu (re-introduced in Phase 6.4 now that User Rules tab
    // gives the menu items something to act on). Edit / Delete live
    // on the tab itself (selection-driven); only Add Rule is global.
    auto *edit = menuBar()->addMenu(tr("&Edit"));
    auto *addRule = edit->addAction(tr("&Add rule..."));
    addRule->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_N));
    addRule->setIcon(style()->standardIcon(QStyle::SP_FileDialogNewFolder));
    connect(addRule, &QAction::triggered,
            this, &MainWindow::onAddRuleFromMenu);

    auto *view = menuBar()->addMenu(tr("&View"));
    auto *show = view->addAction(tr("&Show window"));
    show->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_W));
    connect(show, &QAction::triggered, this, [this]() {
        // Force-show (vs toggle) so menu item has predictable effect.
        this->show();
        this->raise();
        this->activateWindow();
    });
    m_alwaysOnTopAction = view->addAction(tr("&Always on top"));
    m_alwaysOnTopAction->setCheckable(true);
    connect(m_alwaysOnTopAction, &QAction::toggled,
            this, &MainWindow::onAlwaysOnTopToggled);

    auto *help = menuBar()->addMenu(tr("&Help"));
    auto *about = help->addAction(tr("&About amwall..."));
    about->setIcon(style()->standardIcon(QStyle::SP_MessageBoxInformation));
    connect(about, &QAction::triggered, this, &MainWindow::onAbout);

    // Help → "Reset all rules and config..." — polkit-gated full
    // wipe of /etc/amwall/rules.toml + blocklists state + BPF maps
    // (daemon side) and ~/.config/amwall + QSettings (GUI side).
    // Mirrors Windows amwall's matching Help-menu entry. Placed
    // below About behind a separator so it's not the first thing the
    // user sees when they open Help — same shape as simplewall.
    help->addSeparator();
    auto *resetAct = help->addAction(tr("&Reset all rules and config..."));
    resetAct->setIcon(style()->standardIcon(QStyle::SP_DialogResetButton));
    connect(resetAct, &QAction::triggered, this, &MainWindow::onResetAll);
    if (m_dbus) {
        connect(m_dbus, &DbusClient::resetCompleted,
                this, &MainWindow::onResetCompleted);
    }
}

void MainWindow::setupStatusBar() {
    // Permanent widgets stay pinned (vs the transient showMessage
    // area which is reserved for hover tooltips and short status
    // pulses). Mirrors simplewall's IDC_STATUSBAR layout: state on
    // the left, supplementary info on the right.
    m_statusDaemon = new QLabel(tr("● Daemon: probing..."), this);
    m_statusDaemon->setMargin(4);
    statusBar()->addPermanentWidget(m_statusDaemon, /*stretch=*/1);

    m_statusRefresh = new QLabel(tr("Last refresh: —"), this);
    m_statusRefresh->setMargin(4);
    statusBar()->addPermanentWidget(m_statusRefresh, /*stretch=*/0);
}

void MainWindow::setupTrayIcon() {
    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        qWarning() << "amwall-gui: system tray not available on this desktop";
        return;
    }

    QIcon icon = QIcon::fromTheme(
        "network-firewall",
        style()->standardIcon(QStyle::SP_ComputerIcon));

    m_trayIcon = new QSystemTrayIcon(icon, this);
    m_trayIcon->setToolTip("amwall — application firewall");

    m_trayMenu = new QMenu(this);
    m_showHideAction = m_trayMenu->addAction(tr("&Show / Hide"));
    connect(m_showHideAction, &QAction::triggered, this, &MainWindow::onShowHide);
    m_trayMenu->addSeparator();
    m_quitAction = m_trayMenu->addAction(tr("&Quit"));
    connect(m_quitAction, &QAction::triggered, this, &MainWindow::onQuit);
    m_trayIcon->setContextMenu(m_trayMenu);

    connect(m_trayIcon, &QSystemTrayIcon::activated,
            this, &MainWindow::onTrayActivated);

    m_trayIcon->show();
}

void MainWindow::loadSettings() {
    QSettings s;  // uses Org=amwall, App=amwall (set in main.cpp)
    bool aot = s.value("view/alwaysOnTop", false).toBool();
    if (aot && m_alwaysOnTopAction) {
        m_alwaysOnTopAction->setChecked(true);  // triggers onAlwaysOnTopToggled
    }
}

void MainWindow::onTrayActivated(QSystemTrayIcon::ActivationReason reason) {
    if (reason == QSystemTrayIcon::Trigger) {
        // Single left-click toggles window visibility (matches Win32
        // amwall's tray-click behavior in src/gui/tray.rs).
        onShowHide();
    }
}

void MainWindow::onShowHide() {
    if (isVisible()) {
        hide();
    } else {
        show();
        raise();
        activateWindow();
    }
}

void MainWindow::onQuit() {
    // Settings → general/confirmQuit guards accidental Ctrl+Q.
    // Default off so existing muscle memory still works.
    if (QSettings().value("general/confirmQuit", false).toBool()) {
        const auto ans = QMessageBox::question(
            this, tr("Quit amwall?"),
            tr("Quitting will stop the GUI. The amwall-daemon keeps "
               "enforcing rules in the background regardless — restart "
               "the GUI later with <code>amwall-gui</code> or the desktop "
               "entry."),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (ans != QMessageBox::Yes) return;
    }
    QApplication::quit();
}

void MainWindow::onAbout() {
    QString text = tr(
        "<h3>amwall</h3>"
        "<p>Per-application firewall for Linux.</p>"
        "<p>Version: <b>%1</b><br>"
        "Built with Qt %2</p>"
        "<p>The daemon (amwall-daemon) enforces default-deny on egress "
        "via a BPF LSM hook; this GUI talks to it over the system D-Bus "
        "interface <code>org.amwall.Daemon1</code>.</p>"
        "<p>amwall-cli (<code>amwall-cli --dbus list</code>) is the "
        "matching command-line client.</p>"
        "<p>Source: <a href='https://github.com/amrust/amwall'>"
        "github.com/amrust/amwall</a></p>")
        .arg(QString::fromLatin1(AMWALL_VERSION),
             QString::fromLatin1(qVersion()));
    QMessageBox::about(this, tr("About amwall"), text);
}

void MainWindow::onAlwaysOnTopToggled(bool on) {
    // Toggling WindowStaysOnTopHint requires re-show on X11/Wayland.
    Qt::WindowFlags f = windowFlags();
    if (on) {
        f |= Qt::WindowStaysOnTopHint;
    } else {
        f &= ~Qt::WindowStaysOnTopHint;
    }
    setWindowFlags(f);
    QSettings().setValue("view/alwaysOnTop", on);
    show();  // re-realize the window with the new flags
}

void MainWindow::onSettings() {
    // Modal so we can re-sync the View → Always on top checkmark on
    // close (the dialog writes the QSettings key; we mirror back into
    // the menu state if the user toggled it from inside the dialog).
    SettingsDialog dlg(this);
    if (dlg.exec() == QDialog::Accepted) {
        const bool aot = QSettings().value("view/alwaysOnTop", false).toBool();
        if (m_alwaysOnTopAction && m_alwaysOnTopAction->isChecked() != aot) {
            m_alwaysOnTopAction->setChecked(aot);  // fires onAlwaysOnTopToggled
        }
    }
}

void MainWindow::onResetAll() {
    // Two-step confirmation — Reset is destructive (truncates
    // rules.toml, wipes blocklists state, clears BPF maps, deletes
    // ~/.config/amwall) and not undoable. First dialog states what
    // will happen; second confirms the user really means it.
    const QString detail =
        tr("This will clear every rule, every enabled blocklist, and "
           "every UI preference (window geometry, prompt timeout, "
           "etc.). The daemon stays running but starts fresh on "
           "default-deny.\n\n"
           "Used when you want to undo a misconfiguration without "
           "uninstalling. Not undoable.");

    auto choice = QMessageBox::warning(
        this, tr("Reset all rules and config"),
        detail,
        QMessageBox::Reset | QMessageBox::Cancel,
        QMessageBox::Cancel);
    if (choice != QMessageBox::Reset) return;

    if (!m_dbus || !m_dbus->isReachable()) {
        QMessageBox::critical(
            this, tr("Reset failed"),
            tr("The daemon isn't reachable — can't issue Reset. "
               "Check that amwall-daemon.service is running."));
        return;
    }
    // Async — polkit may pop an auth prompt. onResetCompleted handles
    // the GUI-side cleanup + result dialog on the reply.
    m_dbus->resetDaemon();
}

void MainWindow::onResetCompleted(bool ok, const QString &errOut) {
    if (!ok) {
        QMessageBox::critical(
            this, tr("Reset failed"),
            tr("The daemon refused or failed the Reset call:\n\n%1\n\n"
               "Common causes:\n"
               "• polkit auth was cancelled / denied\n"
               "• /etc/amwall/rules.toml has unexpected permissions\n"
               "• the daemon process is wedged — try "
               "'systemctl restart amwall-daemon'")
                .arg(errOut));
        return;
    }

    // GUI-side cleanup. The daemon already wiped root-owned state
    // (/etc/amwall/rules.toml + /etc/amwall/blocklists.toml +
    // BPF maps). We own the user-side: QSettings (window geometry,
    // alwaysOnTop, autoBlockSec, etc.) plus the on-disk .conf file
    // QSettings writes to. Clearing in-memory state via .clear() +
    // .sync() means re-opening Settings sees defaults instead of
    // stale values.
    {
        QSettings s;
        const QString configFile = s.fileName();  // captured for log
        s.clear();
        s.sync();
        qInfo().noquote()
            << "Reset: cleared QSettings at" << configFile
            << "(status=" << int(s.status()) << ")";
    }
    // Drop the menu's Always-on-top check so the next time the user
    // opens View, it matches the cleared QSettings state. Also
    // strip the flag if currently set.
    if (m_alwaysOnTopAction && m_alwaysOnTopAction->isChecked()) {
        m_alwaysOnTopAction->setChecked(false);  // fires onAlwaysOnTopToggled
    }

    // Forcing a refresh redraws the dashboard rule count → 0 and
    // updates the User Rules table immediately, instead of waiting
    // for the next 5-sec poll.
    if (m_dbus) m_dbus->refresh();

    QMessageBox::information(
        this, tr("Reset complete"),
        tr("All rules, blocklists, and preferences have been cleared. "
           "The daemon is running on default-deny — new outbound "
           "connections will prompt the next time they're attempted."));
}

void MainWindow::onDbusStateChanged() {
    // Render DbusClient state into the permanent status-bar widgets.
    // Dashboard listens to the same signal independently.
    if (m_dbus->isReachable()) {
        m_statusDaemon->setText(
            tr("<span style='color:#2e7d32'>●</span> "
               "Daemon: connected — %n rule(s) loaded", "",
               m_dbus->ruleCount()));
        if (m_trayIcon) {
            m_trayIcon->setToolTip(
                tr("amwall — connected (%1 rules)").arg(m_dbus->ruleCount()));
        }
    } else {
        QString reason = m_dbus->lastError();
        m_statusDaemon->setText(
            tr("<span style='color:#c62828'>○</span> "
               "Daemon: not reachable%1")
                .arg(reason.isEmpty() ? QString()
                                      : QStringLiteral(" — %1").arg(reason)));
        if (m_trayIcon) {
            m_trayIcon->setToolTip(tr("amwall — daemon not reachable"));
        }
    }

    QDateTime ts = m_dbus->lastRefresh();
    m_statusRefresh->setText(
        ts.isValid() ? tr("Last refresh: %1").arg(ts.toString("HH:mm:ss"))
                     : tr("Last refresh: —"));
}

void MainWindow::closeEvent(QCloseEvent *event) {
    // Close-to-tray: hide instead of quit. The tray icon's Quit menu
    // item is the real exit path.
    if (m_trayIcon && m_trayIcon->isVisible()) {
        hide();
        event->ignore();
    } else {
        event->accept();
    }
}
