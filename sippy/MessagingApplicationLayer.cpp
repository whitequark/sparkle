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

class PresenceRequest;

MessagingApplicationLayer::MessagingApplicationLayer(ContactList& _contactList, LinkLayer &_linkLayer) : contactList(_contactList), linkLayer(_linkLayer), _router(_linkLayer.router()), _status(Messaging::Online) {
	linkLayer.attachApplicationLayer(Messaging, this);

	connect(&_router, SIGNAL(peerAdded(SparkleAddress)), SIGNAL(peerStateChanged(SparkleAddress)));
	connect(&_router, SIGNAL(peerRemoved(SparkleAddress)), SIGNAL(peerStateChanged(SparkleAddress)));

	connect(&linkLayer, SIGNAL(joinedNetwork(SparkleNode*)), SLOT(pollPresence()));
	connect(&linkLayer, SIGNAL(joinedNetwork(SparkleNode*)), SLOT(sendPresence()));
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

void MessagingApplicationLayer::setStatus(Messaging::Status newStatus) {
	_status = newStatus;
	emit statusChanged(_status);
}

void MessagingApplicationLayer::setStatusText(QString newStatusText) {
	_statusText = newStatusText;
	emit statusTextChanged(_statusText);
}

/* ===== NETWORKING ===== */

void MessagingApplicationLayer::pollPresence() {
	Log::debug("mesg: polling for presence");
	foreach(Contact* contact, contactList.contacts())
		sendPresenceRequest(contact->address());
}

void MessagingApplicationLayer::sendPresence() {
	Log::debug("mesg: sending presence update");
	foreach(Contact* contact, contactList.contacts())
		sendPresenceNotify(contact->address());
}

void MessagingApplicationLayer::fetchContact(Contact* contact) {
	if(linkLayer.isJoined()) {
		Log::debug("mesg: fetching contact %1") << contact->address().pretty();
		sendPresenceRequest(contact->address());
	}
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
		Log::warn("mesg: received presence for unknown contact %1") << addr.pretty();
	}
}
