/*
 * Sippy - zero-configuration fully distributed self-organizing encrypting IM
 * Copyright (C) 2009 Sergey Gridassov
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

#ifndef __SIPPY_APPLICATION_LAYER__H__
#define __SIPPY_APPLICATION_LAYER__H__

#include <QObject>
#include <ApplicationLayer.h>

class QByteArray;
class QHostAddress;
class LinkLayer;
class Router;
class ContactList;

namespace Messaging {
	enum NodeState { /* an insider joke */
		Present      = 200,
		Unauthorized = 403,
		NotFound     = 404,
	};
}

class MessagingApplicationLayer: public QObject, public ApplicationLayer {
	Q_OBJECT

public:
	MessagingApplicationLayer(ContactList &contactList, LinkLayer &linkLayer);
	virtual ~MessagingApplicationLayer();

	virtual void handleDataPacket(QByteArray &packet, SparkleNode *node);

	Router& router();

	Messaging::NodeState nodeState(QByteArray mac);

signals:
	void nodeStateChanged(SparkleNode* node);

private slots:
	void resolveContacts();

private:
	MessagingApplicationLayer();

	ContactList &contactList;
	LinkLayer &linkLayer;
	Router &_router;
};

#endif

