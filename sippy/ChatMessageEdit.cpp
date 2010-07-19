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
#include <QSize>
#include <QAbstractTextDocumentLayout>

#include "ChatMessageEdit.h"

ChatMessageEdit::ChatMessageEdit(QWidget *parent) :
	QTextEdit(parent)
{
	setMinimumHeight(sizeHint().height()); // empty
	setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
}

QSize ChatMessageEdit::sizeHint() const {
	return QSize(0, document()->documentLayout()->documentSize().toSize().height() + 2);
}

QSize ChatMessageEdit::minimumSizeHint() const {
	return sizeHint();
}

void ChatMessageEdit::clear() {
	QTextEdit::clear();
	updateGeometry();
}

void ChatMessageEdit::keyPressEvent(QKeyEvent *e) {
	if(e->key() == Qt::Key_Return && !e->modifiers().testFlag(Qt::ShiftModifier)) {
		emit dispatchRequested();
		return;
	}

	QTextEdit::keyPressEvent(e);

	updateGeometry();
}
