#include "ruleeditor.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHostAddress>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QSpinBox>
#include <QVBoxLayout>

RuleEditorDialog::RuleEditorDialog(const RuleEntry *existing, QWidget *parent)
    : QDialog(parent), m_isEdit(existing != nullptr) {
    setWindowTitle(m_isEdit ? tr("Edit rule") : tr("Add rule"));
    setModal(true);
    setMinimumWidth(380);

    auto *outer = new QVBoxLayout(this);
    auto *form  = new QFormLayout;
    form->setLabelAlignment(Qt::AlignRight);

    // Process (comm) — kernel TASK_COMM_NAME, ASCII, max 15 chars.
    m_comm = new QLineEdit(this);
    m_comm->setMaxLength(15);
    m_comm->setPlaceholderText(tr("e.g. firefox  (max 15 chars, kernel comm)"));
    // Allow letters, digits, underscore, hyphen, dot, colon, and
    // space (Firefox's "DNS Resolver #N" has spaces and #).
    m_comm->setValidator(new QRegularExpressionValidator(
        QRegularExpression("[\\w .:#@/+-]+"), this));
    form->addRow(tr("Process (comm):"), m_comm);

    // Action — Allow / Deny.
    m_action = new QComboBox(this);
    m_action->addItem(tr("Allow"), "allow");
    m_action->addItem(tr("Deny"),  "deny");
    form->addRow(tr("Action:"), m_action);

    // IP — "any", an IPv4 literal, or an IPv6 literal.
    m_ip = new QLineEdit(this);
    m_ip->setPlaceholderText(tr("any  or  192.168.1.1  or  2001:db8::1"));
    form->addRow(tr("Destination IP:"), m_ip);

    // Port — 0 = any.
    m_port = new QSpinBox(this);
    m_port->setRange(0, 65535);
    m_port->setSpecialValueText(tr("0  (any port)"));
    form->addRow(tr("Destination port:"), m_port);

    outer->addLayout(form);

    // In Edit mode pre-fill all fields and lock everything except
    // the action combobox. Add mode starts blank with sensible
    // defaults.
    if (existing) {
        m_comm->setText(existing->comm);
        m_ip->setText(existing->ip);
        m_port->setValue(existing->port);
        m_action->setCurrentIndex(existing->action == "deny" ? 1 : 0);
        m_comm->setReadOnly(true);
        m_ip->setReadOnly(true);
        m_port->setReadOnly(true);
        m_port->setButtonSymbols(QAbstractSpinBox::NoButtons);

        auto *note = new QLabel(
            tr("<i style='font-size: small;'>Process / IP / Port are read-only "
               "in Edit. To change those, delete this rule and add a new one.</i>"),
            this);
        note->setTextFormat(Qt::RichText);
        note->setWordWrap(true);
        outer->addWidget(note);
    } else {
        m_ip->setText(QStringLiteral("any"));
    }

    m_buttons = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    outer->addWidget(m_buttons);
    connect(m_buttons, &QDialogButtonBox::accepted,
            this, &RuleEditorDialog::validateAndAccept);
    connect(m_buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
}

QString RuleEditorDialog::comm()   const { return m_comm->text(); }
QString RuleEditorDialog::ip()     const { return m_ip->text().trimmed(); }
ushort  RuleEditorDialog::port()   const { return static_cast<ushort>(m_port->value()); }
QString RuleEditorDialog::action() const { return m_action->currentData().toString(); }

void RuleEditorDialog::validateAndAccept() {
    if (m_isEdit) {
        // Only the action can change; everything else is locked.
        accept();
        return;
    }

    const QString c = comm().trimmed();
    if (c.isEmpty()) {
        QMessageBox::warning(this, tr("Invalid rule"),
            tr("Process name (comm) cannot be empty."));
        m_comm->setFocus();
        return;
    }

    const QString ipv = ip();
    if (ipv.isEmpty()) {
        QMessageBox::warning(this, tr("Invalid rule"),
            tr("Destination IP cannot be empty.\n\nUse 'any' to match all IPs."));
        m_ip->setFocus();
        return;
    }
    if (ipv.compare(QStringLiteral("any"), Qt::CaseInsensitive) != 0) {
        // Not "any" — must be a valid IPv4 or IPv6 literal.
        QHostAddress addr;
        if (!addr.setAddress(ipv)) {
            QMessageBox::warning(this, tr("Invalid rule"),
                tr("Destination IP must be 'any' or a valid IP address "
                   "(e.g. 192.168.1.1 or 2001:db8::1)."));
            m_ip->setFocus();
            return;
        }
    }

    accept();
}
