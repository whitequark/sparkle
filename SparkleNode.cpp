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
#include "Log.h"

SparkleNode::SparkleNode(QHostAddress _realIP, quint16 _realPort, Router& router)
		 : QObject(NULL), realIP(_realIP), realPort(_realPort) {
	mySessionKey.generate();
}

QString SparkleNode::getPrettySparkleMAC() const {
	QString hexMac = QString(sparkleMAC.toHex()).toUpper();
	return hexMac.replace(QRegExp("(..)"), "\\1:").left(17);
}

void SparkleNode::setHisSessionKey(const QByteArray &keyBytes) {
	hisSessionKey.setBytes(keyBytes);
	keysNegotiated = true;
}

bool SparkleNode::areKeysNegotiated() {
	return keysNegotiated;
}

bool SparkleNode::setAuthKey(const RSAKeyPair &keyPair) {
	return setAuthKey(keyPair.getPublicKey());
}

bool SparkleNode::setAuthKey(const QByteArray &publicKey) {
	if(!authKey.setPublicKey(publicKey))
		return false;
	
	configure();
	
	return true;
}

void SparkleNode::configure() {
	QByteArray fingerprint = SHA1Digest::calculateSHA1(authKey.getPublicKey());

	char ip[4] = { 0, 0, 0, 14 }; // FIXME

	ip[0] = fingerprint[0];
	ip[1] = fingerprint[1];
	ip[2] = fingerprint[2];

	sparkleIP = QHostAddress(*((quint32 *) ip));

	sparkleMAC = "\x02";
	sparkleMAC += fingerprint.left(5);
}

void SparkleNode::setMaster(bool isMaster) {
	master = isMaster;
}

bool SparkleNode::isMaster() {
	return master;
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

