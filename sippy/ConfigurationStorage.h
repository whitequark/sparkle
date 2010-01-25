/*
 * Sippy - zero-configuration fully distributed self-organizing encrypting IM
 * Copyright (C) 2009 Sergey Gridassov
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

#ifndef __CONFIGURATION_STORAGE__H__
#define __CONFIGURATION_STORAGE__H__

#include <QObject>
#include <QList>
#include "Singleton.h"
#include "MessagingApplicationLayer.h"

class QSettings;
class Contact;

class ConfigurationStorage: public QObject, public Singleton<ConfigurationStorage> {
	Q_OBJECT
public:
	ConfigurationStorage(QObject *parent = 0);
	virtual ~ConfigurationStorage();

public:
	QString getKeyName();

	bool createNetwork();
	QString address();
	quint16 port();
	bool behindNat();
	bool autoLogin();

	QList<Contact*> contacts();

	QString statusText();
	Messaging::Status status();

public slots:
	void setCreateNetwork(bool create);
	void setAddress(QString address);
	void setPort(quint16 port);
	void setBehindNat(bool behind);
	void setAutoLogin(bool login);

	void setContacts(QList<Contact*> list);

	void setStatusText(QString statusText);
	void setStatus(Messaging::Status status);

private:
	QSettings *settings;
};

#endif

