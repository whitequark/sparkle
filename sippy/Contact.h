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

#ifndef CONTACT_H
#define CONTACT_H

#include <QObject>
#include "Roster.h"
#include "SparkleAddress.h"
#include "MessagingApplicationLayer.h"

class Contact : public QObject {
	Q_OBJECT
public:
	Contact(QString address);
	Contact(SparkleAddress address);

	QString fallbackName() const;

	SparkleAddress address() const;
	QString textAddress() const;

	QString displayName() const;
	void setDisplayName(QString);

	Messaging::Status status() const;
	void setStatus(Messaging::Status);

	QString statusText() const;
	void setStatusText(QString);

signals:
	void updated();

private:
	QString _displayName;
	SparkleAddress _address;
	Messaging::Status _status;
	QString _statusText;
};

#endif // CONTACT_H
