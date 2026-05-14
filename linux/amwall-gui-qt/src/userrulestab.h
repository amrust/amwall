// UserRulesTab — central tab listing all rules from rules.toml.
//
// Source of truth: DbusClient::rules(). Auto-rebuilds the table
// whenever DbusClient emits stateChanged. Buttons:
//   • Add Rule    → opens RuleEditorDialog in Add mode → dbus.allow/deny
//   • Edit Rule   → opens RuleEditorDialog in Edit mode (action only)
//   • Delete Rule → confirms → dbus.del
//
// Double-click a row also opens Edit. Delete key on the table
// triggers Delete. Enter triggers Edit.

#pragma once

#include <QWidget>

#include "dbusclient.h"

class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;

class UserRulesTab : public QWidget {
    Q_OBJECT

public:
    explicit UserRulesTab(DbusClient *dbus, QWidget *parent = nullptr);

public slots:
    // Public so the menu's Edit > Add Rule can drive the same path
    // without duplicating dialog wiring in MainWindow.
    void onAddRule();

private slots:
    void onDbusStateChanged();
    void onSelectionChanged();
    void onEditRule();
    void onDeleteRule();
    void onTableActivated();   // double-click / Enter
    void onTableContextMenu(const QPoint &pos);  // right-click → Properties/Allow/Block/Remove/Copy
    void onFilterChanged(const QString &text);   // search bar → hide non-matching rows

private:
    void rebuildTable();
    bool   currentRule(RuleEntry *out) const;

    DbusClient   *m_dbus = nullptr;
    QTableWidget *m_table = nullptr;
    QLineEdit    *m_filter = nullptr;
    QPushButton  *m_addBtn = nullptr;
    QPushButton  *m_editBtn = nullptr;
    QPushButton  *m_deleteBtn = nullptr;
    QLabel       *m_countLabel = nullptr;
};
