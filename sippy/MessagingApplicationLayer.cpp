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

#include <QDataStream>
#include "MessagingApplicationLayer.h"
#include "LinkLayer.h"
#include "Router.h"
#include "ContactList.h"
#include "Contact.h"
#include "Log.h"

using namespace Messaging;

MessagingApplicationLayer::MessagingApplicationLayer(ContactList& _contactList, LinkLayer &_linkLayer) : contactList(_contactList), linkLayer(_linkLayer), _router(_linkLayer.router()), _status(Messaging::Online) {
	linkLayer.attachApplicationLayer(Messaging, this);

	connect(&_router, SIGNAL(peerAdded(SparkleAddress)), SIGNAL(peerStateChanged(SparkleAddress)));
	connect(&_router, SIGNAL(peerRemoved(SparkleAddress)), SIGNAL(peerStateChanged(SparkleAddress)));

	connect(&linkLayer, SIGNAL(joinedNetwork(SparkleNode*)), SLOT(fetchAllContacts()));
	connect(&linkLayer, SIGNAL(routeMissing(SparkleAddress)), SLOT(peerAbsent(SparkleAddress)));
	connect(&linkLayer, SIGNAL(leavedNetwork()), SLOT(cleanup()));

	connect(this, SIGNAL(statusChanged(Messaging::Status)), SLOT(sendPresence()));
	connect(this, SIGNAL(statusTextChanged(QString)), SLOT(sendPresence()));

	connect(&contactList, SIGNAL(contactAdded(Contact*)), SLOT(fetchContact(Contact*)));

}

MessagingApplicationLayer::~MessagingApplicationLayer() {
}

Messaging::Status MessagingApplicationLayer::status() const {
	return _status;
}

QString MessagingApplicationLayer::statusText() const {
	return _statusText;
}

QString MessagingApplicationLayer::nick() const {
	return _nick;
}

void MessagingApplicationLayer::setStatus(Messaging::Status newStatus) {
	_status = newStatus;
	emit statusChanged(_status);
}

void MessagingApplicationLayer::setStatusText(QString newStatusText) {
	_statusText = newStatusText;
	emit statusTextChanged(_statusText);
}

void MessagingApplicationLayer::setNick(QString newNick) {
	_nick = newNick;
	emit nickChanged(_nick);
}

/* ===== NETWORKING ===== */

void MessagingApplicationLayer::fetchAllContacts() {
	Log::debug("mesg: fetching all contacts");
	foreach(Contact* contact, contactList.contacts())
		fetchContact(contact);
}

void MessagingApplicationLayer::sendPresence() {
	if(!linkLayer.isJoined())
		return;

	Log::debug("mesg: sending presence");
	foreach(Contact* contact, contactList.contacts())
		sendPresenceNotify(contact->address());
}

void MessagingApplicationLayer::fetchContact(Contact* contact) {
	if(!linkLayer.isJoined())
		return;

	sendPresenceRequest(contact->address());
	sendPresenceNotify(contact->address());
}

void MessagingApplicationLayer::cleanup() {
	Log::debug("mesg: cleanup");
	absentPeers.clear();
	authorizedPeers.clear();
	foreach(Contact* contact, contactList.contacts())
		emit peerStateChanged(contact->address());
}

Messaging::PeerState MessagingApplicationLayer::peerState(SparkleAddress mac) {
	if(_router.hasRouteTo(mac)) {
		if(authorizedPeers.contains(mac)) {
			return Messaging::Present;
		} else {
			return Messaging::Unauthorized;
		}
	} else if(absentPeers.contains(mac)) {
		return Messaging::NotPresent;
	} else if(!linkLayer.isJoined()) {
		return Messaging::Unavailable;
	}

	sendPresenceRequest(mac);
	return Messaging::InternalError;
}

void MessagingApplicationLayer::peerAbsent(SparkleAddress address) {
	absentPeers.insert(address);
	emit peerStateChanged(address);
}

void MessagingApplicationLayer::handleDataPacket(QByteArray &packet, SparkleAddress address) {
	const packet_header_t *hdr = (packet_header_t *) packet.constData();

	if((size_t) packet.size() < sizeof(packet_header_t)) {
		Log::warn("mesg: malformed packet from %1") << address.pretty();
		return;
	}

	if(hdr->version > ProtocolVersion) {
		Log::debug("mesg: dropping version %1 packet from %2") << hdr->version << address.pretty();
		return;
	}

	QByteArray payload = packet.right(packet.size() - sizeof(packet_header_t));
	switch((packet_type_t) hdr->type) {
		case PresenceRequest:
		handlePresenceRequest(payload, address);
		break;

		case PresenceNotify:
		handlePresenceNotify(payload, address);
		break;

		case AuthorizationRequest:
		handleAuthorizationRequest(payload, address);
		break;

		default:
		Log::warn("mesg: dropping version %1 packet of unknown type %2 from %3") << hdr->version << hdr->type << address.pretty();
	}
}

void MessagingApplicationLayer::sendPacket(packet_type_t type, QByteArray data, SparkleAddress addr, quint16 version) {
	packet_header_t hdr;
	hdr.type = type;
	hdr.version = version;

	data.prepend(QByteArray((const char *) &hdr, sizeof(packet_header_t)));

	linkLayer.sendDataPacket(addr, Messaging, data);
}

/* ===== PACKET RELATED STUFF ===== */

/* PresenceRequest */

void MessagingApplicationLayer::sendPresenceRequest(SparkleAddress addr) {
	sendPacket(PresenceRequest, QByteArray(), addr);
}

void MessagingApplicationLayer::handlePresenceRequest(QByteArray&, SparkleAddress addr) {
	if(contactList.hasAddress(addr))
		sendPresenceNotify(addr);
}

/* PresenceReply */

void MessagingApplicationLayer::sendPresenceNotify(SparkleAddress addr) {
	QByteArray packet;
	QDataStream stream(&packet, QIODevice::WriteOnly);

	stream << (quint16) _status;
	stream << _statusText;

	sendPacket(PresenceNotify, packet, addr);
}

void MessagingApplicationLayer::handlePresenceNotify(QByteArray& packet, SparkleAddress addr) {
	QDataStream stream(&packet, QIODevice::ReadOnly);

	Messaging::Status peerStatus;
	QString peerStatusText;

	stream >> (quint16&) peerStatus;
	stream >> peerStatusText;

	authorizedPeers.insert(addr);

	Contact* contact = contactList.findByAddress(addr);
	if(contact) {
		Log::debug("mesg: received presence for %1: %2[%3]") << addr.pretty() << peerStatus << peerStatusText;
		contact->setStatus(peerStatus);
		contact->setStatusText(peerStatusText);
	} else {
		Log::debug("mesg: received presence for unknown contact %1") << addr.pretty();
	}
}

/* AuthorizationRequest */

void MessagingApplicationLayer::sendAuthorizationRequest(SparkleAddress addr, QString reason) {
	QByteArray packet;
	QDataStream stream(&packet, QIODevice::WriteOnly);

	stream << _nick;
	stream << reason;

	sendPacket(AuthorizationRequest, packet, addr);
}

void MessagingApplicationLayer::handleAuthorizationRequest(QByteArray& packet, SparkleAddress addr) {
	QDataStream stream(&packet, QIODevice::ReadOnly);

	QString peerNick, peerReason;

	stream >> peerNick;
	stream >> peerReason;

	Log::debug("authorization request from %1 (%2): '%3'") << addr.pretty() << peerNick << peerReason;

	emit authorizationRequested(addr, peerNick, peerReason);
}

/* Message */

void MessagingApplicationLayer::sendMessage(Message &message) {
	QByteArray packet;
	QDataStream stream(&packet, QIODevice::WriteOnly);

	messageQueue.append(message);

	stream << message.id();
	stream << message.timestamp();
	stream << message.text();

	sendPacket(MessagePacket, packet, message.peer());
}

void MessagingApplicationLayer::handleMessage(QByteArray& packet, SparkleAddress addr) {
	QDataStream stream(&packet, QIODevice::ReadOnly);

	quint32 id;
	QTime timestamp;
	QString text;

	stream >> id;

	if(!messageCache.contains(id)) {
		stream >> timestamp;
		stream >> text;

		Message message(text, timestamp, addr, id);
		emit messageReceived(message);

		messageCache.insert(id);
	}

	sendMessageBounce(addr, id);
}

/* MessageBounce */

void MessagingApplicationLayer::sendMessageBounce(SparkleAddress addr, quint32 id) {
	QByteArray packet;
	QDataStream stream(&packet, QIODevice::WriteOnly);

	stream << id;

	sendPacket(MessageBounce, packet, addr);
}

void MessagingApplicationLayer::handleMessageBounce(QByteArray& packet, SparkleAddress addr) {
	QDataStream stream(&packet, QIODevice::ReadOnly);

	quint32 id;

	stream >> id;

	foreach(const Message& message, messageQueue) {
		if(message.id() == id) {
			if(message.peer() != addr) {
				Log::warn("mesg: message bounce from node %1 that did not sent it (expected %2); how this can ever happen?") << addr.pretty() << message.peer().pretty();
				return;
			}

			messageQueue.removeOne(message);
		}
	}
}

/*
void MessagingApplicationLayer::send(SparkleAddress addr) {
	QByteArray packet;
	QDataStream stream(&packet, QIODevice::WriteOnly);

	sendPacket(, packet, addr);
}

void MessagingApplicationLayer::handle(QByteArray& packet, SparkleAddress addr) {
	QDataStream stream(&packet, QIODevice::ReadOnly);

}
*/
