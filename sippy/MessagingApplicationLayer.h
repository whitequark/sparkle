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

#ifndef __SIPPY_APPLICATION_LAYER__H__
#define __SIPPY_APPLICATION_LAYER__H__

#include <QObject>
#include <QSet>
#include <QDateTime>
#include <QTimer>
#include <ApplicationLayer.h>
#include "SparkleAddress.h"
#include "Messaging.h"

class QHostAddress;
class LinkLayer;
class Router;
class ContactList;
class Contact;

class MessagingApplicationLayer: public QObject, public ApplicationLayer {
	Q_OBJECT

public:
	MessagingApplicationLayer(ContactList &contactList, LinkLayer &linkLayer);
	virtual ~MessagingApplicationLayer();

	virtual void handleDataPacket(QByteArray &packet, SparkleAddress address);

	ContactList& contactList() const;

	Messaging::PeerState peerState(SparkleAddress address);

	Messaging::Status status() const;
	QString statusText() const;

	QString nick() const;

	void sendControlPacket(Messaging::ControlPacket* packet);
	template<typename T> T* getControlPacket();

public slots:
	void setStatus(Messaging::Status newStatus);
	void setStatusText(QString newStatusText);

	void setNick(QString newNick);

signals:
	void peerStateChanged(SparkleAddress address);

	void statusChanged(Messaging::Status status);
	void statusTextChanged(QString statusText);

	void nickChanged(QString nick);

	void authorizationAvailable(SparkleAddress peer);
	void messageAvailable(SparkleAddress peer);
	void callRequestAvailable(SparkleAddress peer);
	void callOperateAvailable(SparkleAddress peer);

	void controlTimedOut(quint32 id);

private slots:
	void fetchAllContacts();
	void sendPresence();
	void fetchContact(Contact* contact);

	void peerAbsent(SparkleAddress address);
	void resendControlPackets();

	void cleanup();

private:
	enum {
		ProtocolVersion = 0,
	};

	enum packet_type_t {
		PresenceRequest		= 1,
		PresenceNotify		= 2,

		ControlPacket		= 3,
		ControlBounce		= 4,
	};

	struct packet_header_t {
		quint16 type;
		quint16 version;
	};

	void sendPacket(packet_type_t type, QByteArray data, SparkleAddress node, quint16 version = 0);

	void sendPresenceRequest(SparkleAddress addr);
	void handlePresenceRequest(QByteArray& payload, SparkleAddress addr);

	void sendPresenceNotify(SparkleAddress addr);
	void handlePresenceNotify(QByteArray& payload, SparkleAddress addr);

	/* public sendControlPacket */
	void handleControlPacket(QByteArray& payload, SparkleAddress addr);

	void sendControlBounce(SparkleAddress addr, quint32 id);
	void handleControlBounce(QByteArray& payload, SparkleAddress addr);

	ContactList &_contactList;
	LinkLayer &linkLayer;
	Router &_router;

	QSet<SparkleAddress> absentPeers, authorizedPeers;

	QList<Messaging::ControlPacket*> controlOutputQueue;
	QList<Messaging::ControlPacket*> controlInputQueue;
	QSet<quint32> controlInputCache;

	Messaging::Status _status;
	QString _statusText;
	QString _nick;

	QTimer controlPacketResendTimer;
};

template<typename T>
T* MessagingApplicationLayer::getControlPacket() {
	foreach(Messaging::ControlPacket* packet, controlInputQueue) {
		T* req = qobject_cast<T*>(packet);
		if(req != NULL) {
			controlInputQueue.removeOne(req);
			return req;
		}
	}
	return NULL;
}

#endif

