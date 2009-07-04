/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2009 Sergey Gridassov, Peter Zotov
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

#include "SHA1Digest.h"
#include "SparkleNode.h"

SparkleNode::SparkleNode(QHostAddress host, quint16 port, QObject *parent) : QObject(parent) {
	this->host = host;
	this->port = port;

	keyNegotiationDone = false;
}

SparkleNode::~SparkleNode() {

}

QHostAddress SparkleNode::getHost() {
	return host;
}

quint16 SparkleNode::getPort() {
	return port;
}

bool SparkleNode::isQueueEmpty() {
	return queue.empty();
}

void SparkleNode::pushQueue(QByteArray data) {
	queue.append(data);
}

QByteArray SparkleNode::popQueue() {
	return queue.takeFirst();
}

bool SparkleNode::setPublicKey(QByteArray key) {
	if(!keyPair.setPublicKey(key))
		return false;

	fingerprint = SHA1Digest::calculateSHA1(key);

	sparkleIP = calculateSparkleIP(fingerprint);
	sparkleMAC = calculateSparkleMac(fingerprint);

	return true;
}

QHostAddress SparkleNode::calculateSparkleIP(QByteArray fingerprint) {
	char ip[4] = { 0, 0, 0, 14 }; // FIXME byte order

	ip[0] = fingerprint[0];
	ip[1] = fingerprint[1];
	ip[2] = fingerprint[2];

	quint32 *num = (quint32 *) ip;

	return QHostAddress(*num);
}

QByteArray SparkleNode::calculateSparkleMac(QByteArray fingerprint) {
	QByteArray mac = "\x02";

	mac += fingerprint.left(5);

	return mac;
}

QByteArray SparkleNode::getSparkleMAC() {
	return sparkleMAC;
}

QHostAddress SparkleNode::getSparkleIP() {
	return sparkleIP;
}

bool SparkleNode::isKeyNegotiationDone() {
	return keyNegotiationDone;
}

void SparkleNode::setKeyNegotiationDone(bool isDone) {
	keyNegotiationDone = isDone;
}

