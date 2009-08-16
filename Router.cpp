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
	Q_ASSERT(self != NULL);
	
	Log::debug("router: My MAC is %1 and IP is %2") << node->getPrettySparkleMAC()
					<< node->getSparkleIP().toString();
	
	self = node;
	addNode(self);
}

SparkleNode* Router::getSelfNode() const {
	return self;
}

void Router::addNode(SparkleNode* node) {
	Log::debug("router: adding node [%1]:%2 <=> %3 (%4)") << node->getRealIP().toString()
			<< node->getRealPort() << node->getSparkleIP().toString()
			<< (node->isMaster() ? "master" : "slave");
	
	nodes.append(node);
}

SparkleNode* Router::searchSparkleNode(QHostAddress sparkleIP) const {
	foreach(SparkleNode *node, nodes) {
		if(node->getSparkleIP() == sparkleIP)
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

QList<SparkleNode*> Router::getMasters() const {
	QList<SparkleNode*> masters;
	
	foreach(SparkleNode *node, nodes) {
		if(node->isMaster())
			masters.append(node);
	}
	
	return masters;
}

size_t Router::getMasterCount() const {
	size_t count = 0;
	
	foreach(SparkleNode *node, nodes) {
		if(node->isMaster())
			count++;
	}
	
	return count;
}

QList<SparkleNode*> Router::getNodes() const {
	return nodes;
}

