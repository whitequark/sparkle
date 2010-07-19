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

class RouterPrivate {
public:
	SparkleNode *self;
	QList<SparkleNode *> nodes;
};

Router::Router(QObject *parent) : QObject(parent), d_ptr(new RouterPrivate) {

}

Router::~Router() {
	delete d_ptr;
}

void Router::setSelfNode(SparkleNode* node) {
	Q_D(Router);

	Q_ASSERT(d->self == NULL);

	Log::info("router: My MAC is %1, I am %2") << node->sparkleMAC().pretty() << (node->isMaster() ? "master" : "slave");

	d->self = node;
	updateNode(d->self);
}

SparkleNode* Router::getSelfNode() const {
	Q_D(const Router);

	return d->self;
}

void Router::updateNode(SparkleNode* node) {
	Q_D(Router);

	bool newNode = !d->nodes.contains(node);

	if(newNode)
		d->nodes.append(node);

	Log::debug("router: %6 node %3 @ [%1]:%2 (%4, %5)") << *node << node->sparkleMAC().pretty()
			<< (node->isMaster() ? "master" : "slave")
			<< (node->isBehindNAT() ? "behind NAT" : "has white IP")
			<< (newNode ? "adding" : "updating");

	emit nodeAdded(node);
	emit peerAdded(node->sparkleMAC());
}

void Router::removeNode(SparkleNode* node) {
	Q_D(Router);

	if(d->self == node) {
		Log::error("router: attempting to remove myself");
		return;
	}

	if(d->nodes.contains(node)) {
		d->nodes.removeOne(node);
		Log::debug("router: removing node %3 @ [%1]:%2") << *node << node->sparkleMAC().pretty();

		emit nodeRemoved(node);
		emit peerRemoved(node->sparkleMAC());

		if(d->nodes.count() == 1) {
			Log::info("router: you are the One, last node!");
			if(!d->self->isMaster())
				Log::fatal("router: being the last slave is useless");
		}
	} else {
		Log::warn("router: attempt to remove missing node [%1]:%2") << *node;
	}
}

SparkleNode* Router::findSparkleNode(SparkleAddress sparkleMAC) const {
	Q_D(const Router);

	foreach(SparkleNode *node, d->nodes) {
		if(node->sparkleMAC() == sparkleMAC)
			return node;
	}

	return NULL;
}

bool Router::hasRouteTo(SparkleAddress sparkleMAC) const {
	return findSparkleNode(sparkleMAC) != NULL;
}


SparkleNode* Router::findNode(QHostAddress realIP, quint16 realPort) const {
	Q_D(const Router);
	
	foreach(SparkleNode *node, d->nodes) {
		if(node->realIP() == realIP && node->realPort() == realPort)
			return node;
	}

	return NULL;
}

SparkleNode* Router::selectMaster() const {
	Q_D(const Router);
	
	QList<SparkleNode*> list = masters();

	if(list.size() == 0) {
		Log::error("router: no masters are present according to my DB. Strange.");
		return NULL;
	}

	if(list.size() == 1)
		return list[0];

	if(d->self != NULL)
		list.removeOne(d->self);

	return list[qrand() % list.size()];
}

SparkleNode* Router::selectJoinMaster(QHostAddress excludeIP) const {
	Q_D(const Router);
	
	QList<SparkleNode*> list = masters();

	if(list.size() == 0) {
		Log::error("router: no masters are present according to my DB. Strange.");
		return NULL;
	}

	if(list.size() == 1)
		return list[0];

	foreach(SparkleNode* node, list) {
		if(node->realIP() == excludeIP)
			list.removeOne(node);
	}

	if(list.size() == 0) {
		Log::error("router: all masters belong to the same IP");
		Log::error("router: returning random master because join will fail anyway");
		list = masters();
		return list[qrand() % list.size()];
	}

	if(list.size() == 1)
		return list[0];

	if(d->self != NULL)
		list.removeOne(d->self);

	return list[qrand() % list.size()];
}

SparkleNode* Router::selectWhiteSlave() const {
	Q_D(const Router);

	Q_ASSERT(d->self != NULL && d->self->isMaster());
	
	QList<SparkleNode*> list = d->nodes;

	foreach(SparkleNode* node, list) {
		if(node->isMaster() || node->isBehindNAT() || node == d->self)
			list.removeOne(node);
	}

	if(list.size() == 0)
		return NULL;

	return list[qrand() % list.size()];
}

QList<SparkleNode*> Router::masters() const {
	Q_D(const Router);

	QList<SparkleNode*> masters;

	foreach(SparkleNode *node, d->nodes) {
		if(node->isMaster())
			masters.append(node);
	}

	return masters;
}

QList<SparkleNode*> Router::otherMasters() const {
	Q_D(const Router);

	Q_ASSERT(_self != NULL && d->self->isMaster());

	QList<SparkleNode*> masters;

	foreach(SparkleNode *node, d->nodes) {
		if(node->isMaster() && node != d->self)
			masters.append(node);
	}

	return masters;
}

QList<SparkleNode*> Router::slaves() const {
	Q_D(const Router);

	QList<SparkleNode*> slaves;

	foreach(SparkleNode *node, d->nodes) {
		if(!node->isMaster())
			slaves.append(node);
	}

	return slaves;
}


QList<SparkleNode*> Router::nodes() const {
	Q_D(const Router);
	
	return d->nodes;
}

QList<SparkleNode*> Router::otherNodes() const {
	Q_D(const Router);
	
	QList<SparkleNode*> selNodes;

	foreach(SparkleNode *node, d->nodes) {
		if(node != d->self)
			selNodes.append(node);
	}

	return selNodes;
}

void Router::notifyNodeUpdated(SparkleNode* target) {
	Q_D(const Router);
	
	foreach(SparkleNode *node, d->nodes) {
		if(node == target)
			emit nodeUpdated(target);
	}
}

void Router::clear() {
	Q_D(Router);
	
	foreach(SparkleNode* node, d->nodes) {
		d->nodes.removeOne(node);
		emit peerRemoved(node->sparkleMAC());
		emit nodeRemoved(node);
	}
	d->self = NULL;
}

