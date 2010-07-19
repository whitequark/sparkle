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

#ifndef CHATWINDOW_H
#define CHATWINDOW_H

#include <Sparkle/SparkleAddress>

#include <QWidget>
#include "MessagingApplicationLayer.h"

class ChatMessageEdit;
class QTextBrowser;

class ChatWindow : public QWidget {
	Q_OBJECT

public:
	ChatWindow(MessagingApplicationLayer& app, Sparkle::SparkleAddress peer);

public slots:
	virtual void show();
	void handleMessage();

private slots:
	void sendMessage();

private:
	void print(QDateTime timestamp, QString str);

	MessagingApplicationLayer &appLayer;
	Sparkle::SparkleAddress peer;
	Contact* contact;

	QTextBrowser* log;
	ChatMessageEdit* editor;

	QString html;
};

#endif // CHATWINDOW_H
