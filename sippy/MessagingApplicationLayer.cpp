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
#include <Sparkle/LinkLayer>
#include <Sparkle/Router>
#include <Sparkle/Log>

#include "MessagingApplicationLayer.h"
#include "ContactList.h"
#include "Contact.h"

using namespace Messaging;
using namespace Sparkle;

MessagingApplicationLayer::MessagingApplicationLayer(ContactList& contactList, LinkLayer &_linkLayer) : _contactList(contactList), linkLayer(_linkLayer), _router(_linkLayer.router()), _status(Messaging::Online) {
	linkLayer.attachApplicationLayer(Messaging, this);

	controlPacketResendTimer.setInterval(5000);
	connect(&controlPacketResendTimer, SIGNAL(timeout()), SLOT(resendControlPackets()));

	connect(&_router, SIGNAL(peerAdded(SparkleAddress)), SIGNAL(peerStateChanged(SparkleAddress)));
	connect(&_router, SIGNAL(peerRemoved(SparkleAddress)), SIGNAL(peerStateChanged(SparkleAddress)));

	connect(&linkLayer, SIGNAL(joinedNetwork(SparkleNode*)), SLOT(fetchAllContacts()));
	connect(&linkLayer, SIGNAL(routeMissing(SparkleAddress)), SLOT(peerAbsent(SparkleAddress)));
	connect(&linkLayer, SIGNAL(leavedNetwork()), SLOT(cleanup()));

	connect(this, SIGNAL(statusChanged(Messaging::Status)), SLOT(sendPresence()));
	connect(this, SIGNAL(statusTextChanged(QString)), SLOT(sendPresence()));

	connect(&_contactList, SIGNAL(contactAdded(Contact*)), SLOT(fetchContact(Contact*)));

	controlPacketResendTimer.start();
}

MessagingApplicationLayer::~MessagingApplicationLayer() {
}

ContactList& MessagingApplicationLayer::contactList() const {
	return _contactList;
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
	foreach(Contact* contact, _contactList.contacts())
		fetchContact(contact);
}

void MessagingApplicationLayer::sendPresence() {
	if(!linkLayer.isJoined())
		return;

	Log::debug("mesg: sending presence");
	foreach(Contact* contact, _contactList.contacts())
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
	foreach(Contact* contact, _contactList.contacts())
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

		case ControlPacket:
		handleControlPacket(payload, address);
		break;

		case ControlBounce:
		handleControlBounce(payload, address);
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
	if(_contactList.hasAddress(addr))
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

	QString peerStatusText;

	quint16 statusWord;

	stream >> statusWord;
	stream >> peerStatusText;

	Messaging::Status peerStatus = (Messaging::Status) statusWord;

	authorizedPeers.insert(addr);

	Contact* contact = _contactList.findByAddress(addr);
	if(contact) {
		Log::debug("mesg: received presence for %1: %2[%3]") << addr.pretty() << peerStatus << peerStatusText;
		contact->setStatus(peerStatus);
		contact->setStatusText(peerStatusText);
	} else {
		Log::debug("mesg: received presence for unknown contact %1") << addr.pretty();
	}
}

/* ControlPacket */

void MessagingApplicationLayer::sendControlPacket(Messaging::ControlPacket* packet) {
	controlOutputQueue.append(packet);
	sendPacket(ControlPacket, packet->marshall(), packet->peer());
}

void MessagingApplicationLayer::handleControlPacket(QByteArray& packet, SparkleAddress addr) {
	Messaging::ControlPacket* controlPacket = Messaging::ControlPacket::demarshall(packet, addr);
	Q_ASSERT(controlPacket != NULL);

	controlInputQueue.append(controlPacket);
	sendControlBounce(controlPacket->peer(), controlPacket->id());

	switch(controlPacket->type()) {
		case Messaging::AuthorizationPacket:
		emit authorizationAvailable();
		return;

		case Messaging::MessagePacket:
		emit messageAvailable(addr);
		return;
	}
}

void MessagingApplicationLayer::resendControlPackets() {
	foreach(Messaging::ControlPacket* packet, controlOutputQueue) {
		Log::debug("mesg: resending control<%1> to %2") << packet->type() << packet->peer().pretty();
		emit controlTimedOut(packet->id());
		sendPacket(ControlPacket, packet->marshall(), packet->peer());
	}
}

/* ControlBounce */

void MessagingApplicationLayer::sendControlBounce(SparkleAddress addr, quint32 id) {
	QByteArray packet;
	QDataStream stream(&packet, QIODevice::WriteOnly);

	stream << id;

	sendPacket(ControlBounce, packet, addr);
}

void MessagingApplicationLayer::handleControlBounce(QByteArray& packet, SparkleAddress addr) {
	QDataStream stream(packet);
	quint32 id;

	stream >> id;

	foreach(Messaging::ControlPacket* packet, controlOutputQueue) {
		if(packet->id() == id) {
			if(packet->peer() != addr) {
				Log::warn("mesg: control bounce from node %1 that did not sent it (expected %2); how this can ever happen?") << addr.pretty() << packet->peer().pretty();
				return;
			}

			controlOutputQueue.removeOne(packet);
			delete packet;
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
