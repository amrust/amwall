#include "settingsdialog.h"

#include <QApplication>
#include <QCheckBox>
#include <QDebug>
#include <QDialogButtonBox>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSettings>
#include <QSpinBox>
#include <QStackedWidget>
#include <QStyle>
#include <QVBoxLayout>

#ifndef AMWALL_VERSION
#define AMWALL_VERSION "0.0.0-dev"
#endif

namespace {
constexpr const char *KEY_ALWAYS_ON_TOP    = "view/alwaysOnTop";
constexpr const char *KEY_START_MINIMIZED  = "general/startMinimized";
constexpr const char *KEY_CONFIRM_QUIT     = "general/confirmQuit";
constexpr const char *KEY_AUTOBLOCK_SEC    = "notifications/autoBlockSec";
constexpr const char *KEY_PACKETS_SHOWLOCAL = "packetslog/showLocal";
}  // namespace

SettingsDialog::SettingsDialog(QWidget *parent) : QDialog(parent) {
    setWindowTitle(tr("amwall — Settings"));
    resize(640, 420);
    setModal(true);

    auto *outer = new QVBoxLayout(this);
    auto *body  = new QHBoxLayout;

    // ─── Left pane: page list ─────────────────────────────────────
    m_pageList = new QListWidget(this);
    m_pageList->setFixedWidth(160);
    m_pageList->addItem(tr("General"));
    m_pageList->addItem(tr("Notifications"));
    m_pageList->addItem(tr("About"));
    body->addWidget(m_pageList);

    // ─── Right pane: stacked pages ────────────────────────────────
    m_pages = new QStackedWidget(this);
    buildGeneralPage();
    buildNotificationsPage();
    buildAboutPage();
    body->addWidget(m_pages, 1);

    outer->addLayout(body, 1);

    // ─── Buttons ──────────────────────────────────────────────────
    m_buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel
        | QDialogButtonBox::Apply,
        this);
    outer->addWidget(m_buttons);

    connect(m_pageList, &QListWidget::currentRowChanged,
            this, &SettingsDialog::onPageChanged);
    // OK button: save + close. Apply button: save WITHOUT closing —
    // wiring both to onAccepted (which calls accept()) made Apply
    // behave like OK. We now route Apply through a separate slot
    // that saves and stays open. Cancel discards.
    connect(m_buttons, &QDialogButtonBox::accepted,
            this, &SettingsDialog::onAccepted);
    connect(m_buttons, &QDialogButtonBox::rejected,
            this, &SettingsDialog::reject);
    connect(m_buttons->button(QDialogButtonBox::Apply),
            &QPushButton::clicked,
            this, [this]() { saveToSettings(); });

    loadFromSettings();
    m_pageList->setCurrentRow(0);
}

void SettingsDialog::buildGeneralPage() {
    auto *page = new QWidget(this);
    auto *layout = new QFormLayout(page);
    layout->setHorizontalSpacing(16);
    layout->setVerticalSpacing(10);

    m_alwaysOnTop = new QCheckBox(tr("Keep main window on top"), page);
    m_alwaysOnTop->setToolTip(
        tr("Mirrors the View → Always on top menu item. Setting key:\n"
           "%1").arg(QString::fromLatin1(KEY_ALWAYS_ON_TOP)));
    layout->addRow(m_alwaysOnTop);

    m_startMinimized = new QCheckBox(tr("Start minimized to tray"), page);
    m_startMinimized->setToolTip(
        tr("When amwall-gui starts, hide the main window and only show\n"
           "the tray icon. The window is still reachable via tray-icon\n"
           "click or 'View → Show window'."));
    layout->addRow(m_startMinimized);

    m_confirmQuit = new QCheckBox(tr("Confirm before quitting"), page);
    m_confirmQuit->setToolTip(
        tr("Show a 'Are you sure?' prompt when Quit is invoked.\n"
           "Closing the window via X always goes to tray — Quit is the\n"
           "only path that actually terminates the GUI process."));
    layout->addRow(m_confirmQuit);

    layout->addRow(new QLabel(
        tr("<i><small>Daemon-side settings (default-deny, rule\n"
           "path, BPF features) live in /etc/amwall/ and are\n"
           "edited by hand or via amwall-cli, not this dialog.</small></i>"),
        page));

    m_pages->addWidget(page);
}

void SettingsDialog::buildNotificationsPage() {
    auto *page = new QWidget(this);
    auto *layout = new QFormLayout(page);
    layout->setHorizontalSpacing(16);
    layout->setVerticalSpacing(10);

    m_autoBlockSec = new QSpinBox(page);
    m_autoBlockSec->setRange(0, 600);
    m_autoBlockSec->setSpecialValueText(tr("Never (wait for click)"));
    m_autoBlockSec->setSuffix(tr(" seconds"));
    m_autoBlockSec->setToolTip(
        tr("If a connect-prompt dialog goes un-clicked for this long,\n"
           "auto-Block as the safe default. 0 = wait forever (current\n"
           "behavior). Matches simplewall's 'Notifications timeout'."));
    layout->addRow(tr("Auto-block unattended prompts after:"),
                   m_autoBlockSec);

    m_showLocalByDefault = new QCheckBox(
        tr("Show local (AF_UNIX) events in Packets log on startup"), page);
    m_showLocalByDefault->setToolTip(
        tr("AF_UNIX sockets are the IPC mechanism every desktop\n"
           "process uses; the log will be very noisy. Default off."));
    layout->addRow(m_showLocalByDefault);

    layout->addRow(new QLabel(
        tr("<i><small>Connect-prompt window position and modality\n"
           "are not user-tunable — they're hard-coded to centred\n"
           "and Qt::WindowStaysOnTopHint so the prompt can't get\n"
           "buried under MainWindow.</small></i>"),
        page));

    m_pages->addWidget(page);
}

void SettingsDialog::buildAboutPage() {
    auto *page = new QWidget(this);
    auto *layout = new QVBoxLayout(page);

    auto *icon = new QLabel(page);
    icon->setPixmap(style()->standardIcon(QStyle::SP_ComputerIcon)
                        .pixmap(64, 64));
    icon->setAlignment(Qt::AlignCenter);
    layout->addWidget(icon);

    auto *heading = new QLabel(
        tr("<h2 style='margin: 4px 0;'>amwall</h2>"), page);
    heading->setAlignment(Qt::AlignCenter);
    heading->setTextFormat(Qt::RichText);
    layout->addWidget(heading);

    auto *version = new QLabel(
        tr("<p style='margin: 0;'>Version <code>%1</code><br>"
           "Qt <code>%2</code></p>")
            .arg(QString::fromUtf8(AMWALL_VERSION))
            .arg(QString::fromLatin1(qVersion())),
        page);
    version->setAlignment(Qt::AlignCenter);
    version->setTextFormat(Qt::RichText);
    layout->addWidget(version);

    auto *desc = new QPlainTextEdit(page);
    desc->setReadOnly(true);
    desc->setPlainText(tr(
        "amwall is a per-application firewall built on BPF LSM "
        "enforcement (kernel-side) and a Rust daemon + Qt6 GUI "
        "talking over D-Bus (user-space).\n\n"
        "It is an independent rewrite of what was simplewall v3.8.7 "
        "(henrypp/simplewall, GPL-3.0). amwall is not affiliated "
        "with, endorsed by, or sponsored by Henry++ or the simplewall "
        "project — see the NOTICE file for the full attribution.\n\n"
        "License: GPL-3.0-or-later.\n"
        "Source: https://github.com/amrust/amwall\n\n"
        "Daemon status, rule path, BPF feature flags, and recent\n"
        "ConnectAttempt events: see the Overview tab and the daemon\n"
        "journal (journalctl -u amwall-daemon)."));
    layout->addWidget(desc, 1);

    m_pages->addWidget(page);
}

void SettingsDialog::loadFromSettings() {
    QSettings s;
    const bool aot = s.value(KEY_ALWAYS_ON_TOP,    false).toBool();
    const bool sm  = s.value(KEY_START_MINIMIZED,  false).toBool();
    const bool cq  = s.value(KEY_CONFIRM_QUIT,     false).toBool();
    const int  ab  = s.value(KEY_AUTOBLOCK_SEC,    0).toInt();
    const bool sl  = s.value(KEY_PACKETS_SHOWLOCAL, false).toBool();
    qInfo().noquote()
        << "Settings load from" << s.fileName()
        << "→ aot=" << aot << "startMin=" << sm << "confirmQuit=" << cq
        << "autoBlock=" << ab << "showLocal=" << sl;
    m_alwaysOnTop->setChecked(aot);
    m_startMinimized->setChecked(sm);
    m_confirmQuit->setChecked(cq);
    m_autoBlockSec->setValue(ab);
    m_showLocalByDefault->setChecked(sl);
}

// Returns true on successful sync. Doesn't close the dialog —
// onAccepted does that for the OK path; Apply just saves and stays.
bool SettingsDialog::saveToSettings() {
    QSettings s;
    const bool aot = m_alwaysOnTop->isChecked();
    const bool sm  = m_startMinimized->isChecked();
    const bool cq  = m_confirmQuit->isChecked();
    const int  ab  = m_autoBlockSec->value();
    const bool sl  = m_showLocalByDefault->isChecked();
    s.setValue(KEY_ALWAYS_ON_TOP,    aot);
    s.setValue(KEY_START_MINIMIZED,  sm);
    s.setValue(KEY_CONFIRM_QUIT,     cq);
    s.setValue(KEY_AUTOBLOCK_SEC,    ab);
    s.setValue(KEY_PACKETS_SHOWLOCAL, sl);
    s.sync();

    qInfo().noquote()
        << "Settings save to" << s.fileName()
        << "→ aot=" << aot << "startMin=" << sm << "confirmQuit=" << cq
        << "autoBlock=" << ab << "showLocal=" << sl
        << "(status=" << int(s.status()) << ")";

    // If sync() reported AccessError, the most common cause on Linux
    // is the parent dir not existing or being root-owned (a prior
    // `sudo amwall-gui` run can leave ~/.config/amwall owned by root,
    // and subsequent unprivileged writes get EACCES). Surface it so
    // the user sees the actual failure mode instead of silent loss.
    if (s.status() != QSettings::NoError) {
        qWarning().noquote()
            << "Settings sync FAILED — status=" << int(s.status())
            << ", file=" << s.fileName()
            << ". Check that" << QFileInfo(s.fileName()).path()
            << "is writable by the current user (sudo chown -R "
               "$USER ~/.config/amwall if a prior root run took it).";
        return false;
    }
    return true;
}

void SettingsDialog::onAccepted() {
    saveToSettings();
    accept();
}

void SettingsDialog::onPageChanged(int row) {
    if (row >= 0 && row < m_pages->count()) {
        m_pages->setCurrentIndex(row);
    }
}
