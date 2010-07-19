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
#include <Sparkle/ApplicationLayer>
#include <Sparkle/SparkleAddress>

#include "Messaging.h"

class QHostAddress;

namespace Sparkle {
	class LinkLayer;
	class Router;
};


class ContactList;
class Contact;

class MessagingApplicationLayer: public QObject, public Sparkle::ApplicationLayer {
	Q_OBJECT

public:
	MessagingApplicationLayer(ContactList &contactList, Sparkle::LinkLayer &linkLayer);
	virtual ~MessagingApplicationLayer();

	virtual void handleDataPacket(QByteArray &packet, Sparkle::SparkleAddress address);

	ContactList& contactList() const;

	Messaging::PeerState peerState(Sparkle::SparkleAddress address);

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
	void peerStateChanged(Sparkle::SparkleAddress address);

	void statusChanged(Messaging::Status status);
	void statusTextChanged(QString statusText);

	void nickChanged(QString nick);

	void authorizationAvailable();
	void messageAvailable(Sparkle::SparkleAddress peer);

	void controlTimedOut(quint32 id);

private slots:
	void fetchAllContacts();
	void sendPresence();
	void fetchContact(Contact* contact);

	void peerAbsent(Sparkle::SparkleAddress address);
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

	void sendPacket(packet_type_t type, QByteArray data, Sparkle::SparkleAddress node, quint16 version = 0);

	void sendPresenceRequest(Sparkle::SparkleAddress addr);
	void handlePresenceRequest(QByteArray& payload, Sparkle::SparkleAddress addr);

	void sendPresenceNotify(Sparkle::SparkleAddress addr);
	void handlePresenceNotify(QByteArray& payload, Sparkle::SparkleAddress addr);

	/* public sendControlPacket */
	void handleControlPacket(QByteArray& payload, Sparkle::SparkleAddress addr);

	void sendControlBounce(Sparkle::SparkleAddress addr, quint32 id);
	void handleControlBounce(QByteArray& payload, Sparkle::SparkleAddress addr);

	ContactList &_contactList;
	Sparkle::LinkLayer &linkLayer;
	Sparkle::Router &_router;

	QSet<Sparkle::SparkleAddress> absentPeers, authorizedPeers;

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

