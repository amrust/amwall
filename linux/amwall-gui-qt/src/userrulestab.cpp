#include "userrulestab.h"

#include "ruleeditor.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QSignalBlocker>
#include <QStyle>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

UserRulesTab::UserRulesTab(DbusClient *dbus, QWidget *parent)
    : QWidget(parent), m_dbus(dbus) {

    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(8, 8, 8, 8);
    outer->setSpacing(6);

    // ─── Header (count + filter) ─────────────────────────────────
    auto *header = new QHBoxLayout;
    auto *title = new QLabel(tr("<b>User rules</b>"), this);
    title->setTextFormat(Qt::RichText);
    header->addWidget(title);
    m_countLabel = new QLabel(QStringLiteral("(0)"), this);
    header->addWidget(m_countLabel);
    header->addSpacing(12);

    header->addWidget(new QLabel(tr("Filter:"), this));
    m_filter = new QLineEdit(this);
    m_filter->setPlaceholderText(tr("comm, action, or destination..."));
    m_filter->setClearButtonEnabled(true);
    connect(m_filter, &QLineEdit::textChanged,
            this, &UserRulesTab::onFilterChanged);
    header->addWidget(m_filter, 1);

    outer->addLayout(header);

    // ─── Table ───────────────────────────────────────────────────
    m_table = new QTableWidget(0, 4, this);
    m_table->setHorizontalHeaderLabels({
        tr("Process (comm)"), tr("Action"), tr("Destination IP"), tr("Port")
    });
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSortingEnabled(true);
    m_table->verticalHeader()->setVisible(false);
    // Every column Interactive (user can drag any divider). The
    // rightmost section auto-fills remaining viewport width via
    // setStretchLastSection — that re-flows as the user drags the
    // dividers to its left. Click any header cell to sort by that
    // column; Qt persists the sort across rebuilds.
    auto *hh = m_table->horizontalHeader();
    hh->setSectionsClickable(true);
    hh->setSortIndicatorShown(true);
    hh->setSectionResizeMode(QHeaderView::Interactive);
    hh->setStretchLastSection(true);
    m_table->setColumnWidth(0, 240);  // Process (comm)
    m_table->setColumnWidth(1, 90);   // Action
    m_table->setColumnWidth(2, 220);  // Destination IP
    // Port stretches to fill; user can drag column 2's right edge to shrink it.
    outer->addWidget(m_table, /*stretch=*/1);

    connect(m_table, &QTableWidget::itemSelectionChanged,
            this, &UserRulesTab::onSelectionChanged);
    connect(m_table, &QTableWidget::cellDoubleClicked,
            this, &UserRulesTab::onTableActivated);

    // Right-click anywhere in the table → Properties/Allow/Block/Remove/Copy
    // popup (same shape as Win32 amwall's apps_context_menu).
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_table, &QTableWidget::customContextMenuRequested,
            this, &UserRulesTab::onTableContextMenu);

    // ─── Buttons ─────────────────────────────────────────────────
    auto *buttons = new QHBoxLayout;
    buttons->addStretch(1);

    m_addBtn = new QPushButton(
        style()->standardIcon(QStyle::SP_FileDialogNewFolder),
        tr("&Add..."), this);
    m_editBtn = new QPushButton(
        style()->standardIcon(QStyle::SP_FileDialogDetailedView),
        tr("&Edit..."), this);
    m_deleteBtn = new QPushButton(
        style()->standardIcon(QStyle::SP_TrashIcon),
        tr("&Delete"), this);

    m_editBtn->setEnabled(false);
    m_deleteBtn->setEnabled(false);

    connect(m_addBtn,    &QPushButton::clicked, this, &UserRulesTab::onAddRule);
    connect(m_editBtn,   &QPushButton::clicked, this, &UserRulesTab::onEditRule);
    connect(m_deleteBtn, &QPushButton::clicked, this, &UserRulesTab::onDeleteRule);

    buttons->addWidget(m_addBtn);
    buttons->addWidget(m_editBtn);
    buttons->addWidget(m_deleteBtn);
    outer->addLayout(buttons);

    connect(m_dbus, &DbusClient::stateChanged,
            this, &UserRulesTab::onDbusStateChanged);
    rebuildTable();
}

void UserRulesTab::onDbusStateChanged() {
    rebuildTable();
}

void UserRulesTab::rebuildTable() {
    // Capture the (comm, ip, port) of whichever row is selected so we
    // can re-select the same logical rule after the rebuild. Without
    // this the table loses focus on every DbusClient::stateChanged —
    // which fires on every Allow click — and the user sees the
    // highlight jump as new rows are inserted, breaking right-click /
    // Edit / Delete flows in progress.
    QString prevComm, prevIp;
    int prevPort = -1;
    {
        const auto sel = m_table->selectionModel()
                              ? m_table->selectionModel()->selectedRows()
                              : QModelIndexList{};
        if (!sel.isEmpty()) {
            int r = sel.first().row();
            if (auto *it = m_table->item(r, 0)) prevComm = it->text();
            if (auto *it = m_table->item(r, 2)) prevIp = it->text();
            if (auto *it = m_table->item(r, 3)) {
                bool ok = false;
                int p = it->text().toInt(&ok);
                prevPort = ok ? p : 0;  // text "any" → 0 sentinel
            }
        }
    }

    const auto &rules = m_dbus->rules();
    m_table->setSortingEnabled(false);
    // Suppress intermediate currentItemChanged / itemSelectionChanged
    // emissions; the rebuild creates and destroys rows in bulk and any
    // signal that fires mid-way sees half-populated state.
    QSignalBlocker block(m_table);
    // Clear selection AND current-item pointer before the rebuild so
    // a previously-selected row index doesn't carry the highlight
    // into whatever rule lands at that index after sort. We re-apply
    // the selection below via (comm, ip, port) lookup if there really
    // was one — Qt's "current" defaulting to row 0 on first focus is
    // what produced the "random row selected on first show" effect.
    m_table->clearSelection();
    m_table->setCurrentItem(nullptr);
    m_table->setRowCount(rules.size());
    int row = 0;
    for (const RuleEntry &r : rules) {
        auto *commItem = new QTableWidgetItem(r.comm);
        auto *actionItem = new QTableWidgetItem(r.action.toUpper());
        auto *ipItem = new QTableWidgetItem(r.ip);
        auto *portItem = new QTableWidgetItem(
            r.port == 0 ? tr("any") : QString::number(r.port));

        // Color-code action: green for allow, red for deny.
        if (r.action == QStringLiteral("allow")) {
            actionItem->setForeground(QColor("#2e7d32"));
        } else if (r.action == QStringLiteral("deny")) {
            actionItem->setForeground(QColor("#c62828"));
        }

        m_table->setItem(row, 0, commItem);
        m_table->setItem(row, 1, actionItem);
        m_table->setItem(row, 2, ipItem);
        m_table->setItem(row, 3, portItem);
        ++row;
    }
    m_table->setSortingEnabled(true);
    m_countLabel->setText(QStringLiteral("(%1)").arg(rules.size()));

    // Re-apply the active filter so newly-added rules don't pop
    // into view if they don't match the current search needle.
    if (m_filter && !m_filter->text().isEmpty()) {
        onFilterChanged(m_filter->text());
    }

    // Re-select the row whose (comm, ip, port) matches what was
    // selected before. Done AFTER setSortingEnabled re-applies the
    // sort so we find the rule at its final visual row, not the
    // pre-sort index. If the rule was deleted out from under us
    // (e.g. user picked Delete and we're rebuilding for that very
    // delete) we land with no selection — onSelectionChanged disables
    // the Edit/Delete buttons.
    if (!prevComm.isEmpty()) {
        const int rowCount = m_table->rowCount();
        for (int r = 0; r < rowCount; ++r) {
            auto *ci = m_table->item(r, 0);
            auto *ii = m_table->item(r, 2);
            auto *pi = m_table->item(r, 3);
            if (!ci || !ii || !pi) continue;
            if (ci->text() != prevComm) continue;
            if (ii->text() != prevIp) continue;
            bool ok = false;
            int p = pi->text().toInt(&ok);
            int rulePort = ok ? p : 0;
            if (prevPort >= 0 && rulePort != prevPort) continue;
            m_table->selectRow(r);
            m_table->scrollToItem(ci, QAbstractItemView::EnsureVisible);
            break;
        }
    }
    onSelectionChanged();
}

void UserRulesTab::onSelectionChanged() {
    bool any = !m_table->selectedItems().isEmpty();
    m_editBtn->setEnabled(any);
    m_deleteBtn->setEnabled(any);
}

bool UserRulesTab::currentRule(RuleEntry *out) const {
    auto sel = m_table->selectedItems();
    if (sel.isEmpty()) return false;
    int row = sel.first()->row();
    out->comm   = m_table->item(row, 0)->text();
    out->action = m_table->item(row, 1)->text().toLower();
    out->ip     = m_table->item(row, 2)->text();
    QString portText = m_table->item(row, 3)->text();
    out->port   = (portText == tr("any")) ? 0 : portText.toUShort();
    return true;
}

void UserRulesTab::onAddRule() {
    RuleEditorDialog dlg(/*existing=*/nullptr, this);
    if (dlg.exec() != QDialog::Accepted) return;
    if (dlg.action() == QStringLiteral("allow")) {
        m_dbus->allow(dlg.comm(), dlg.ip(), dlg.port());
    } else {
        m_dbus->deny(dlg.comm(), dlg.ip(), dlg.port());
    }
}

void UserRulesTab::onEditRule() {
    RuleEntry r;
    if (!currentRule(&r)) return;
    RuleEditorDialog dlg(&r, this);
    if (dlg.exec() != QDialog::Accepted) return;
    // Edit-mode dialog only allows action to change. (comm, ip, port)
    // is the BPF map key; the daemon's Allow/Deny upserts on key match.
    if (dlg.action() == QStringLiteral("allow")) {
        m_dbus->allow(r.comm, r.ip, r.port);
    } else {
        m_dbus->deny(r.comm, r.ip, r.port);
    }
}

void UserRulesTab::onDeleteRule() {
    RuleEntry r;
    if (!currentRule(&r)) return;
    QString summary = QStringLiteral("%1  %2  %3:%4")
                          .arg(r.action.toUpper(), r.comm, r.ip,
                               r.port == 0 ? tr("any") : QString::number(r.port));
    int rc = QMessageBox::question(
        this, tr("Delete rule"),
        tr("Delete this rule?\n\n  %1\n\nThis takes effect immediately.").arg(summary),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (rc != QMessageBox::Yes) return;
    m_dbus->del(r.comm, r.ip, r.port);
}

void UserRulesTab::onTableActivated() {
    onEditRule();
}

void UserRulesTab::onTableContextMenu(const QPoint &pos) {
    // Match Win32 amwall's apps_context_menu shape:
    //   Properties (default, bold) — opens RuleEditorDialog
    //   ─────
    //   Allow / Block — toggle action, current one is checked
    //   ─────
    //   Remove — delete the rule (same confirmation as Delete button)
    //   ─────
    //   Copy — rule summary as text to the clipboard
    //
    // If the user right-clicks empty space (no row under cursor), we
    // bail out — every item in this menu acts on a specific rule.
    const QModelIndex idx = m_table->indexAt(pos);
    if (!idx.isValid()) return;

    // Selecting the row under the cursor before opening the menu
    // gives a clear visual binding — the user sees which rule the
    // menu items will affect. Matches every other Qt table context
    // menu in this app.
    m_table->selectRow(idx.row());

    RuleEntry r;
    if (!currentRule(&r)) return;

    QMenu menu(this);

    // Properties — opens edit dialog. Default item (bold) so Enter
    // triggers it; mirrors Win32 amwall where Properties is the
    // primary action.
    QAction *propsAct = menu.addAction(
        style()->standardIcon(QStyle::SP_FileDialogDetailedView),
        tr("&Properties..."));
    menu.setDefaultAction(propsAct);

    menu.addSeparator();

    // Allow / Block — toggle action. The current action gets a
    // checkmark; clicking the OTHER one flips the rule. Clicking
    // the already-checked one is harmless (daemon's allow/deny is
    // an upsert keyed on (comm, ip, port)), so we leave both
    // clickable rather than graying the current.
    QAction *allowAct = menu.addAction(tr("&Allow"));
    allowAct->setCheckable(true);
    allowAct->setChecked(r.action == QStringLiteral("allow"));
    if (allowAct->isChecked()) {
        allowAct->setIcon(style()->standardIcon(QStyle::SP_DialogApplyButton));
    }

    QAction *blockAct = menu.addAction(tr("&Block"));
    blockAct->setCheckable(true);
    blockAct->setChecked(r.action == QStringLiteral("deny"));
    if (blockAct->isChecked()) {
        blockAct->setIcon(style()->standardIcon(QStyle::SP_DialogCancelButton));
    }

    menu.addSeparator();

    QAction *removeAct = menu.addAction(
        style()->standardIcon(QStyle::SP_TrashIcon),
        tr("&Remove"));

    menu.addSeparator();

    QAction *copyAct = menu.addAction(
        style()->standardIcon(QStyle::SP_FileIcon),
        tr("&Copy"));

    QAction *chosen = menu.exec(m_table->viewport()->mapToGlobal(pos));
    if (!chosen) return;  // dismissed without picking

    if (chosen == propsAct) {
        onEditRule();
    } else if (chosen == allowAct) {
        m_dbus->allow(r.comm, r.ip, r.port);
    } else if (chosen == blockAct) {
        m_dbus->deny(r.comm, r.ip, r.port);
    } else if (chosen == removeAct) {
        onDeleteRule();
    } else if (chosen == copyAct) {
        // Single-line summary, tab-separated so it pastes usefully
        // into a spreadsheet or log line. Port "any" matches what's
        // shown in the table for the 0 sentinel.
        const QString portText = r.port == 0
            ? QStringLiteral("any")
            : QString::number(r.port);
        const QString summary = QStringLiteral("%1\t%2\t%3\t%4")
            .arg(r.comm, r.action, r.ip, portText);
        QApplication::clipboard()->setText(summary);
    }
}

void UserRulesTab::onFilterChanged(const QString &text) {
    // Hide rows whose comm / action / IP / port columns don't
    // contain the needle (case-insensitive substring). Same shape
    // as AppsTab::onFilterChanged. Empty needle = show all.
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
