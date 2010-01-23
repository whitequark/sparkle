/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2009 Sergey Gridassov, Peter Zotov
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

#include <QtGlobal>

#include "Router.h"
#include "SparkleNode.h"
#include "Log.h"

Router::Router() : QObject(NULL), self(NULL)
{
}

void Router::setSelfNode(SparkleNode* node) {
	Q_ASSERT(self == NULL);

	Log::info("router: My MAC is %1, I am %2") << node->getPrettySparkleMAC() << (node->isMaster() ? "master" : "slave");

	self = node;
	updateNode(self);
}

SparkleNode* Router::getSelfNode() const {
	return self;
}

void Router::updateNode(SparkleNode* node) {
	bool newNode = !nodes.contains(node);

	if(newNode)
		nodes.append(node);

	Log::debug("router: %6 node %3 @ [%1]:%2 (%4, %5)") << *node << node->getPrettySparkleMAC()
			<< (node->isMaster() ? "master" : "slave")
			<< (node->isBehindNAT() ? "behind NAT" : "has white IP")
			<< (newNode ? "adding" : "updating");

	emit nodeAdded(node);
}

void Router::removeNode(SparkleNode* node) {
	if(self == node) {
		Log::error("router: attempting to remove myself");
		return;
	}

	if(nodes.contains(node)) {
		nodes.removeOne(node);
		Log::debug("router: removing node %3 @ [%1]:%2") << *node << node->getPrettySparkleMAC();

		emit nodeRemoved(node);

		if(nodes.count() == 1) {
			Log::info("router: you are the One, last node!");
			if(!self->isMaster())
				Log::fatal("router: being the last slave is useless");
		}
	} else {
		Log::warn("router: attempt to remove missing node [%1]:%2") << *node;
	}
}

SparkleNode* Router::searchSparkleNode(QByteArray sparkleMAC) const {
	foreach(SparkleNode *node, nodes) {
		if(node->getSparkleMAC() == sparkleMAC)
			return node;
	}

	return NULL;
}

SparkleNode* Router::searchNode(QHostAddress realIP, quint16 realPort) const {
	foreach(SparkleNode *node, nodes) {
		if(node->getRealIP() == realIP && node->getRealPort() == realPort)
			return node;
	}

	return NULL;
}

SparkleNode* Router::selectMaster() const {
	QList<SparkleNode*> masters = getMasters();

	if(masters.size() == 0) {
		Log::error("router: no masters are present according to my DB. Strange.");

		return NULL;
	}

	if(masters.size() == 1) {
/*		Log::warn ("router: only one master is present in network; this is BAD."
			   " (If you just created a network, ignore this message)");*/

		return masters[0];
	}

	if(getSelfNode() != NULL)
		masters.removeOne(getSelfNode());

	return masters[qrand() % masters.size()];
}

SparkleNode* Router::selectWhiteSlave() const {
	Q_ASSERT(self != NULL && self->isMaster());

	QList<SparkleNode*> nodes = getNodes();

	foreach(SparkleNode* node, nodes) {
		if(node->isMaster() || node->isBehindNAT() || node == self)
			nodes.removeOne(node);
	}

	if(nodes.size() == 0)
		return NULL;

	return nodes[qrand() % nodes.size()];
}

QList<SparkleNode*> Router::getMasters() const {
	QList<SparkleNode*> masters;

	foreach(SparkleNode *node, nodes) {
		if(node->isMaster())
			masters.append(node);
	}

	return masters;
}

QList<SparkleNode*> Router::getOtherMasters() const {
	Q_ASSERT(self != NULL && self->isMaster());

	QList<SparkleNode*> masters;

	foreach(SparkleNode *node, nodes) {
		if(node->isMaster() && node != self)
			masters.append(node);
	}

	return masters;
}

QList<SparkleNode*> Router::getNodes() const {
	return nodes;
}

QList<SparkleNode*> Router::getOtherNodes() const {
	QList<SparkleNode*> selNodes;

	foreach(SparkleNode *node, nodes) {
		if(node != self)
			selNodes.append(node);
	}

	return selNodes;
}

void Router::notifyNodeUpdated(SparkleNode* target) {
	foreach(SparkleNode *node, nodes) {
		if(node == target)
			emit nodeUpdated(target);
	}
}

void Router::clear() {
	nodes.clear();
	self = NULL;
	emit cleared();
}

