/*
 * Sippy - zero-configuration fully distributed self-organizing encrypting IM
 * Copyright (C) 2010 Peter Zotov
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <QPushButton>
#include "AddContactDialog.h"
#include "Contact.h"
#include "ContactList.h"

AddContactDialog::AddContactDialog(ContactList &_contactList, QWidget *parent) :
	QDialog(parent), contactList(_contactList)
{
	setupUi(this);

	connect(addressEdit, SIGNAL(textChanged(QString)), SLOT(validate()));
	connect(this, SIGNAL(accepted()), SLOT(close()));
}

void AddContactDialog::show() {
	addressEdit->clear();
	displayNameEdit->clear();
	buttons->button(QDialogButtonBox::Ok)->setEnabled(false);

	QDialog::show();
}

void AddContactDialog::validate() {
	buttons->button(QDialogButtonBox::Ok)->setEnabled(addressEdit->hasAcceptableInput());
}

void AddContactDialog::accept() {
	Contact* contact = new Contact(addressEdit->text());
	contact->setDisplayName(displayNameEdit->text());
	contactList.addContact(contact);

	emit accepted();
}
