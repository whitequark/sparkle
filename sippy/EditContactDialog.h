/*
 * Sippy - zero-configuration fully distributed self-organizing encrypting IM
 * Copyright (C) 2010 Peter Zotov
 *
 * Ths program is free software: you can redistribute it and/or modify
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

#ifndef EDITCONTACTDIALOG_H
#define EDITCONTACTDIALOG_H

#include "ui_EditContactDialog.h"

class Contact;

class EditContactDialog : public QDialog, private Ui_EditContactDialog {
	Q_OBJECT
public:
	EditContactDialog(QWidget *parent = 0);

public slots:
	void showFor(Contact* contact);
	void accept();

private:
	Contact* currentContact;
};

#endif // EDITCONTACTDIALOG_H
