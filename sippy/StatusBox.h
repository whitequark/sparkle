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

#ifndef STATUSBOX_H
#define STATUSBOX_H

#include <QComboBox>
#include "MessagingApplicationLayer.h"

class StatusBox : public QComboBox
{
	Q_OBJECT
public:
	StatusBox(QWidget *parent);

	QString defaultStatusText(Messaging::Status);

public slots:
	void setStatusText(QString);
	void setStatus(Messaging::Status);

signals:
	void statusTextChanged(QString);
	void statusChanged(Messaging::Status);

protected:
	void focusOutEvent(QFocusEvent *e);
	void keyPressEvent(QKeyEvent *e);
};

#endif // STATUSBOX_H
