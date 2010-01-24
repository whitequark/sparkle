/*
 * Sippy - zero-configuration fully distributed self-organizing encrypting IM
 * Copyright (C) 2010 Peter Zotov
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

#include "MessagingApplicationLayer.h"
#include "LinkLayer.h"
#include "Router.h"
#include "ContactList.h"

MessagingApplicationLayer::MessagingApplicationLayer(ContactList& _contactList, LinkLayer &_linkLayer) : contactList(_contactList), linkLayer(_linkLayer), _router(_linkLayer.router()) {
	linkLayer.attachApplicationLayer(Messaging, this);

	connect(&_router, SIGNAL(nodeAdded(SparkleNode*)), SIGNAL(nodeStateChanged(SparkleNode*)));
	connect(&_router, SIGNAL(nodeUpdated(SparkleNode*)), SIGNAL(nodeStateChanged(SparkleNode*)));
	connect(&_router, SIGNAL(nodeRemoved(SparkleNode*)), SIGNAL(nodeStateChanged(SparkleNode*)));
}

MessagingApplicationLayer::~MessagingApplicationLayer() {
}

Router& MessagingApplicationLayer::router() {
	return _router;
}

Messaging::NodeState MessagingApplicationLayer::nodeState(QByteArray mac) {
	SparkleNode* node = _router.findSparkleNode(mac);
	if(node != NULL) {
		return Messaging::Unauthorized;
	} else {
		return Messaging::NotFound;
	}
}

void MessagingApplicationLayer::resolveContacts() {

}

void MessagingApplicationLayer::handleDataPacket(QByteArray &packet, SparkleNode *node) {

}
