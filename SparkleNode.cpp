/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2009 Sergey Gridassov
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

#include "SparkleNode.h"

SparkleNode::SparkleNode(QHostAddress host, quint16 port, QObject *parent) : QObject(parent) {
	this->host = host;
	this->port = port;

	negotiationDone = false;
}

SparkleNode::~SparkleNode() {

}


QHostAddress SparkleNode::getHost() {
	return host;
}

quint16 SparkleNode::getPort() {
	return port;
}

void SparkleNode::appendQueue(QByteArray data) {
	queue.append(data);
}

bool SparkleNode::isQueueEmpty() {
	return queue.empty();
}

QByteArray SparkleNode::getFromQueue() {
	return queue.takeFirst();
}

