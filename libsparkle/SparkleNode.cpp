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

SparkleNode::SparkleNode(Router &_router, QHostAddress _realIP, quint16 _realPort) : QObject(&_router), router(_router), realIP(_realIP), realPort(_realPort), authKeyPresent(false),
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
	return makePrettyMAC(sparkleMAC);
}

QString SparkleNode::makePrettyMAC(QByteArray mac) {
	QString hexMac = QString(mac.toHex()).toUpper();
	return hexMac.replace(QRegExp("(..)"), "\\1:").left(17);
}

void SparkleNode::setSparkleMAC(const QByteArray& mac) {
	sparkleMAC = mac;
	router.notifyNodeUpdated(this);
}

void SparkleNode::setRealIP(const QHostAddress& ip) {
	realIP = ip;
	router.notifyNodeUpdated(this);
}

void SparkleNode::setRealPort(quint16 port) {
	realPort = port;
	router.notifyNodeUpdated(this);
}

void SparkleNode::setBehindNAT(bool behindNAT) {
	this->behindNAT = behindNAT;
	router.notifyNodeUpdated(this);
}

void SparkleNode::setHisSessionKey(const QByteArray &keyBytes) {
	hisSessionKey.setBytes(keyBytes);
	keysNegotiated = true;
	router.notifyNodeUpdated(this);
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

	router.notifyNodeUpdated(this);

	return true;
}

void SparkleNode::configureByKey() {
	QByteArray fingerprint = SHA1Digest::calculateSHA1(authKey.getPublicKey());
	sparkleMAC = fingerprint.left(6);
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

