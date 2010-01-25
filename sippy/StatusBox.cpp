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

#include "StatusBox.h"
#include <QKeyEvent>

StatusBox::StatusBox(QWidget *parent) :
	QComboBox(parent)
{
}

QString StatusBox::defaultStatusText(Messaging::Status status) {
	switch(status) {
		default:
		case Messaging::Online:
		return tr("Online");

		case Messaging::Away:
		return tr("Away");

		case Messaging::Busy:
		return tr("Busy");
	}
}

void StatusBox::setStatusText(QString text) {
	setEditText(text);
}

void StatusBox::setStatus(Messaging::Status) {

}

void StatusBox::focusOutEvent(QFocusEvent *e) {
	emit statusTextChanged(currentText());
	QComboBox::focusOutEvent(e);
}

void StatusBox::keyPressEvent(QKeyEvent *e) {
	if(e->key() == Qt::Key_Return) {
		focusNextChild();
	} else {
		QComboBox::keyPressEvent(e);
	}
}
