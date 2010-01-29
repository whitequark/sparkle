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
#include <QTime>
#include <ApplicationLayer.h>
#include "SparkleAddress.h"

class QHostAddress;
class LinkLayer;
class Router;
class ContactList;
class Contact;

namespace Messaging {
	enum PeerState { /* an insider joke */
		Present       = 200,
		Unauthorized  = 403,
		NotPresent    = 404,
		InternalError = 500,
		Unavailable   = 503,
	};

	enum Status {
		Online,
		Away,
		Busy
	};

	class Message
	{
	public:
		Message(QString text, QTime timestamp, SparkleAddress peer, quint32 id = 0) : _id(id), _timestamp(timestamp), _text(text), _peer(peer)
			{ if(_id == 0) _id = qrand(); }

		quint32 id() const		{ return _id; }
		QTime timestamp() const	{ return _timestamp; }
		QString text() const	{ return _text; }
		SparkleAddress peer() const	{ return _peer; }

		bool operator==(Message other) { return _id == other.id(); }

	private:
		quint32 _id;
		QTime _timestamp;
		QString _text;
		SparkleAddress _peer;
	};
}

class MessagingApplicationLayer: public QObject, public ApplicationLayer {
	Q_OBJECT

public:
	MessagingApplicationLayer(ContactList &contactList, LinkLayer &linkLayer);
	virtual ~MessagingApplicationLayer();

	virtual void handleDataPacket(QByteArray &packet, SparkleAddress address);

	Messaging::PeerState peerState(SparkleAddress address);

	Messaging::Status status() const;
	QString statusText() const;

	QString nick() const;

	void sendAuthorizationRequest(SparkleAddress addr, QString reason);
	void sendMessage(Messaging::Message& message);

public slots:
	void setStatus(Messaging::Status newStatus);
	void setStatusText(QString newStatusText);

	void setNick(QString newNick);

signals:
	void peerStateChanged(SparkleAddress address);

	void statusChanged(Messaging::Status status);
	void statusTextChanged(QString statusText);

	void nickChanged(QString nick);

	void authorizationRequested(SparkleAddress address, QString nick, QString reason);

	void messageReceived(Messaging::Message& message);
	void messageTimedOut(quint32 id);

private slots:
	void fetchAllContacts();
	void sendPresence();
	void fetchContact(Contact* contact);

	void peerAbsent(SparkleAddress address);

	void cleanup();

private:
	enum {
		ProtocolVersion = 0,
	};

	enum packet_type_t {
		PresenceRequest	      = 1,
		PresenceNotify	      = 2,
		AuthorizationRequest  = 3,

		MessagePacket         = 4,
		MessageBounce         = 5,
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

	/* public sendAuthorizationRequest */
	void handleAuthorizationRequest(QByteArray& payload, SparkleAddress addr);

	/* public sendMessage */
	void handleMessage(QByteArray& payload, SparkleAddress addr);

	void sendMessageBounce(SparkleAddress addr, quint32 cookie);
	void handleMessageBounce(QByteArray& payload, SparkleAddress addr);

	ContactList &contactList;
	LinkLayer &linkLayer;
	Router &_router;

	QSet<SparkleAddress> absentPeers, authorizedPeers;

	QList<Messaging::Message> messageQueue; // transmitted
	QSet<quint32> messageCache;  // received

	Messaging::Status _status;
	QString _statusText;
	QString _nick;
};

#endif

