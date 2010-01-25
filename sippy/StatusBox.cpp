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

#include <QKeyEvent>
#include "StatusBox.h"
#include "pixmaps.h"

StatusBox::StatusBox(QWidget *parent) :
	QComboBox(parent)
{
	addItem(QPixmap(PIXMAP_LARGE_ONLINE), tr("Online"), Messaging::Online);
	addItem(QPixmap(PIXMAP_LARGE_AWAY),   tr("Away"),   Messaging::Away);
	addItem(QPixmap(PIXMAP_LARGE_BUSY),   tr("Busy"),   Messaging::Busy);

	connect(this, SIGNAL(activated(int)), SLOT(updateStatus(int)));
}

void StatusBox::setStatusText(QString text) {
	setEditText(text);
	cachedStatusText = text;
}

void StatusBox::setStatus(Messaging::Status status) {
	setCurrentIndex(findData(status));
	setEditText(cachedStatusText);
}

void StatusBox::updateStatus(int index) {
	if(cachedStatusText != "" && findText(cachedStatusText) == -1)
		setEditText(cachedStatusText);
	focusNextChild();
	emit statusChanged((Messaging::Status) itemData(index).toInt());
}

void StatusBox::focusOutEvent(QFocusEvent *e) {
	if(currentText() == "")
		setEditText(itemText(currentIndex()));
	if(cachedStatusText != currentText()) {
		cachedStatusText = currentText();
		emit statusTextChanged(currentText());
	}
	QComboBox::focusOutEvent(e);
}

void StatusBox::keyPressEvent(QKeyEvent *e) {
	if(e->key() == Qt::Key_Return) {
		focusNextChild();
	} else {
		QComboBox::keyPressEvent(e);
	}
}
