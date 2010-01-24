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

Router::Router() : _self(NULL) {
}

void Router::setSelfNode(SparkleNode* node) {
	Q_ASSERT(_self == NULL);

	Log::info("router: My MAC is %1, I am %2") << node->sparkleMAC().pretty() << (node->isMaster() ? "master" : "slave");

	_self = node;
	updateNode(_self);
}

SparkleNode* Router::getSelfNode() const {
	return _self;
}

void Router::updateNode(SparkleNode* node) {
	bool newNode = !_nodes.contains(node);

	if(newNode)
		_nodes.append(node);

	Log::debug("router: %6 node %3 @ [%1]:%2 (%4, %5)") << *node << node->sparkleMAC().pretty()
			<< (node->isMaster() ? "master" : "slave")
			<< (node->isBehindNAT() ? "behind NAT" : "has white IP")
			<< (newNode ? "adding" : "updating");

	emit nodeAdded(node);
	emit peerAdded(node->sparkleMAC());
}

void Router::removeNode(SparkleNode* node) {
	if(_self == node) {
		Log::error("router: attempting to remove myself");
		return;
	}

	if(_nodes.contains(node)) {
		_nodes.removeOne(node);
		Log::debug("router: removing node %3 @ [%1]:%2") << *node << node->sparkleMAC().pretty();

		emit nodeRemoved(node);
		emit peerRemoved(node->sparkleMAC());

		if(_nodes.count() == 1) {
			Log::info("router: you are the One, last node!");
			if(!_self->isMaster())
				Log::fatal("router: being the last slave is useless");
		}
	} else {
		Log::warn("router: attempt to remove missing node [%1]:%2") << *node;
	}
}

SparkleNode* Router::findSparkleNode(SparkleAddress sparkleMAC) const {
	foreach(SparkleNode *node, _nodes) {
		if(node->sparkleMAC() == sparkleMAC)
			return node;
	}

	return NULL;
}

bool Router::hasRouteTo(SparkleAddress sparkleMAC) const {
	return findSparkleNode(sparkleMAC) != NULL;
}


SparkleNode* Router::findNode(QHostAddress realIP, quint16 realPort) const {
	foreach(SparkleNode *node, _nodes) {
		if(node->realIP() == realIP && node->realPort() == realPort)
			return node;
	}

	return NULL;
}

SparkleNode* Router::selectMaster() const {
	QList<SparkleNode*> list = masters();

	if(list.size() == 0) {
		Log::error("router: no masters are present according to my DB. Strange.");

		return NULL;
	}

	if(list.size() == 1) {
/*		Log::warn ("router: only one master is present in network; this is BAD."
			   " (If you just created a network, ignore this message)");*/

		return list[0];
	}

	if(_self != NULL)
		list.removeOne(_self);

	return list[qrand() % list.size()];
}

SparkleNode* Router::selectWhiteSlave() const {
	Q_ASSERT(_self != NULL && _self->isMaster());

	QList<SparkleNode*> list = _nodes;

	foreach(SparkleNode* node, list) {
		if(node->isMaster() || node->isBehindNAT() || node == _self)
			list.removeOne(node);
	}

	if(list.size() == 0)
		return NULL;

	return list[qrand() % list.size()];
}

QList<SparkleNode*> Router::masters() const {
	QList<SparkleNode*> masters;

	foreach(SparkleNode *node, _nodes) {
		if(node->isMaster())
			masters.append(node);
	}

	return masters;
}

QList<SparkleNode*> Router::otherMasters() const {
	Q_ASSERT(_self != NULL && _self->isMaster());

	QList<SparkleNode*> masters;

	foreach(SparkleNode *node, _nodes) {
		if(node->isMaster() && node != _self)
			masters.append(node);
	}

	return masters;
}

QList<SparkleNode*> Router::nodes() const {
	return _nodes;
}

QList<SparkleNode*> Router::getOtherNodes() const {
	QList<SparkleNode*> selNodes;

	foreach(SparkleNode *node, _nodes) {
		if(node != _self)
			selNodes.append(node);
	}

	return selNodes;
}

void Router::notifyNodeUpdated(SparkleNode* target) {
	foreach(SparkleNode *node, _nodes) {
		if(node == target)
			emit nodeUpdated(target);
	}
}

void Router::clear() {
	foreach(SparkleNode* node, _nodes) {
		_nodes.removeOne(node);
		emit peerRemoved(node->sparkleMAC());
		emit nodeRemoved(node);
	}
	_self = NULL;
}

