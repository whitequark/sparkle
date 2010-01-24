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
	void setCreateNetwork(bool create);

	QString address();
	void setAddress(QString address);

	quint16 port();
	void setPort(quint16 port);

	bool behindNat();
	void setBehindNat(bool behind);

	bool autoLogin();
	void setAutoLogin(bool login);

	QList<Contact*> contacts();
	void setContacts(QList<Contact*> list);

private:
	QSettings *settings;
};

#endif

