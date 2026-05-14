// amwall-gui — main window (Phase 6.1 foundation + 6.2 dashboard).
//
// Wires together: DbusClient (live D-Bus state polling), Dashboard
// (central widget that renders DbusClient state + offers refresh),
// menu bar (only menus whose items are real handlers — File / View
// / Help), permanent status-bar widgets, and the system tray icon.
//
// Edit / Settings / Blocklist menus are intentionally absent: they
// reappear when 6.4 (Edit needs tabs) / 6.8 (Settings dialog) /
// 6.x (Blocklist) bring the things they would act on. Empty menus
// would be placeholders, which violates the project's "no
// placeholders" rule.

#pragma once

#include <QMainWindow>
#include <QSystemTrayIcon>

class QAction;
class QCloseEvent;
class QLabel;
class QMenu;
class QTabWidget;
class DbusClient;
class Dashboard;
class PromptCoordinator;
class UserRulesTab;
class ConnectionsTab;
class PacketsLogTab;
class AppsTab;
class BlocklistTab;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void onTrayActivated(QSystemTrayIcon::ActivationReason reason);
    void onShowHide();
    void onQuit();
    void onAbout();
    void onSettings();          // File > Settings — opens preferences dialog
    void onAlwaysOnTopToggled(bool on);
    void onDbusStateChanged();
    void onAddRuleFromMenu();   // Edit > Add Rule — switches to User Rules tab
    void onResetAll();          // Help > Reset all rules and config — polkit-gated wipe
    void onResetCompleted(bool ok, const QString &errOut);
    void onToggleEnforcement(); // File > Disable/Enable filters & toolbar/tray equivalents
    void onEnforcementChanged(bool enabled);  // Daemon-side state changed → re-paint UI

private:
    void setupCentralWidget();
    void setupMenuBar();
    void setupStatusBar();
    void setupTrayIcon();
    void loadSettings();

    DbusClient        *m_dbus = nullptr;
    PromptCoordinator *m_prompts = nullptr;
    QTabWidget        *m_tabs = nullptr;
    Dashboard         *m_dashboard = nullptr;
    UserRulesTab      *m_userRules = nullptr;
    ConnectionsTab    *m_connections = nullptr;
    PacketsLogTab     *m_packetsLog = nullptr;
    AppsTab           *m_apps = nullptr;
    BlocklistTab      *m_blocklist = nullptr;

    QLabel *m_statusDaemon = nullptr;   // permanent left widget
    QLabel *m_statusRefresh = nullptr;  // permanent right widget

    QSystemTrayIcon *m_trayIcon = nullptr;
    QMenu *m_trayMenu = nullptr;
    QAction *m_showHideAction = nullptr;
    QAction *m_quitAction = nullptr;

    QAction *m_alwaysOnTopAction = nullptr;

    // Master enforcement toggle widgets — kept as members so File
    // menu, tray menu, toolbar, and status badge all stay in sync
    // when the daemon emits EnabledChanged. Updated by
    // onEnforcementChanged(); each is allowed to be null if the
    // corresponding setup function hasn't run yet (e.g., tray
    // unavailable on this desktop).
    QAction *m_enforcementMenuAction  = nullptr;  // File menu entry
    QAction *m_enforcementTrayAction  = nullptr;  // tray menu entry
    QAction *m_enforcementToolbarAction = nullptr;  // toolbar button
    QLabel  *m_statusEnforcement = nullptr;        // status-bar badge
};
