// SettingsDialog — Phase 6.8. Two-pane preferences window. Left:
// QListWidget of page names. Right: QStackedWidget of page bodies.
// Matches simplewall's IDD_SETTINGS modal layout.
//
// Persists via QSettings (already used for window geometry and
// Always-on-top). All keys are documented next to the spinbox /
// checkbox creating them so the QSettings file is greppable.
//
// Apply semantics: changes take effect on OK / Apply. Cancel restores
// nothing — there's no undo stack, but the only side-effect of an
// accidental change is the next prompt timing differently, which is
// recoverable by re-opening Settings.

#pragma once

#include <QDialog>

class QCheckBox;
class QDialogButtonBox;
class QListWidget;
class QSpinBox;
class QStackedWidget;

class SettingsDialog : public QDialog {
    Q_OBJECT

public:
    explicit SettingsDialog(QWidget *parent = nullptr);

private slots:
    void onAccepted();        // OK button → save + close
    void onPageChanged(int row);

private:
    void buildGeneralPage();
    void buildNotificationsPage();
    void buildAboutPage();
    void loadFromSettings();

    // Pure save path — used by both OK (which then closes via accept())
    // and Apply (which stays open). Returns true on successful sync;
    // logs file path + status if not.
    bool saveToSettings();

    QListWidget    *m_pageList = nullptr;
    QStackedWidget *m_pages    = nullptr;
    QDialogButtonBox *m_buttons = nullptr;

    // General page widgets
    QCheckBox *m_alwaysOnTop   = nullptr;
    QCheckBox *m_startMinimized = nullptr;
    QCheckBox *m_confirmQuit   = nullptr;

    // Notifications page widgets
    QSpinBox  *m_autoBlockSec  = nullptr;   // 0 = never auto-block
    QCheckBox *m_showLocalByDefault = nullptr;
};
