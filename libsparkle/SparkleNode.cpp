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

SparkleNode::SparkleNode(QHostAddress _realIP, quint16 _realPort)
		 : QObject(NULL), realIP(_realIP), realPort(_realPort), authKeyPresent(false),
		 	keysNegotiated(false) {
	mySessionKey.generate();
	
	negotiationTimer.setSingleShot(true);
	negotiationTimer.setInterval(5000);
	connect(&negotiationTimer, SIGNAL(timeout()), SLOT(negotiationTimeout()));
}

bool SparkleNode::operator==(const SparkleNode& another) const {
	return another.getRealIP() == realIP && another.getRealPort() == realPort;
}

bool SparkleNode::operator!=(const SparkleNode& another) const {
	return !(*this == another);
}

QString SparkleNode::getPrettySparkleMAC() const {
	QString hexMac = QString(sparkleMAC.toHex()).toUpper();
	return hexMac.replace(QRegExp("(..)"), "\\1:").left(17);
}

void SparkleNode::setSparkleIP(const QHostAddress& ip) {
	sparkleIP = ip;
}

void SparkleNode::setSparkleMAC(const QByteArray& mac) {
	sparkleMAC = mac;
}

void SparkleNode::setRealIP(const QHostAddress& ip) {
	realIP = ip;
}

void SparkleNode::setRealPort(quint16 port) {
	realPort = port;
}

void SparkleNode::setBehindNAT(bool behindNAT) {
	this->behindNAT = behindNAT;
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
	if(authKeyPresent) {
		if(authKey.getPublicKey() != publicKey) {
			Log::warn("Achtung! Attempt to assign new public key to authenticated node [%1]:%2, DROPPING.")
					<< realIP.toString() << realPort;
			return false;
		} else {
			return true;
		}
	}
	
	if(!authKey.setPublicKey(publicKey))
		return false;
	
	authKeyPresent = true;
	
	return true;
}

void SparkleNode::configureByKey() {
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

void SparkleNode::flushQueue() {
	queue.clear();
}

void SparkleNode::negotiationStart() {
	negotiationTimer.start();
}

void SparkleNode::negotiationFinished() {
	negotiationTimer.stop();
}

void SparkleNode::negotiationTimeout() {
	emit negotiationTimedOut(this);
}
