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
#include <QSet>
#include <ApplicationLayer.h>
#include "SparkleAddress.h"

class QHostAddress;
class LinkLayer;
class Router;
class ContactList;

namespace Messaging {
	enum PeerState { /* an insider joke */
		Present       = 200,
		Unauthorized  = 403,
		NotPresent    = 404,
		InternalError = 500,
		Unavailable   = 503,
	};
}

class MessagingApplicationLayer: public QObject, public ApplicationLayer {
	Q_OBJECT

public:
	MessagingApplicationLayer(ContactList &contactList, LinkLayer &linkLayer);
	virtual ~MessagingApplicationLayer();

	virtual void handleDataPacket(QByteArray &packet, SparkleAddress address);

	Messaging::PeerState peerState(SparkleAddress address);

signals:
	void peerStateChanged(SparkleAddress address);

private slots:
	void pollPresence();
	void cleanup();

	void peerAbsent(SparkleAddress address);

private:
	enum {
		ProtocolVersion = 0,
	};

	enum packet_type_t {
		PresenceRequest	= 1,
		PresenceNotify	= 2,
	};

	struct packet_header_t {
		quint16 type;
		quint16 version;
	};

	void sendPacket(packet_type_t type, QByteArray data, SparkleAddress node, quint16 version = 0);

	void sendPresenceRequest(SparkleAddress addr);
	void handlePresenceRequest(QByteArray& payload, SparkleAddress addr);

	ContactList &contactList;
	LinkLayer &linkLayer;
	Router &_router;

	QSet<SparkleAddress> absentPeers;
};

#endif

