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

SparkleNode::SparkleNode(Router &router, QHostAddress realIP, quint16 realPort) : QObject(&router), _router(router), _realIP(realIP), _realPort(realPort), authKeyPresent(false), keysNegotiated(false) {
	_mySessionKey.generate();

	negotiationTimer.setSingleShot(true);
	negotiationTimer.setInterval(5000);
	connect(&negotiationTimer, SIGNAL(timeout()), SLOT(negotiationTimeout()));
}

bool SparkleNode::operator==(const SparkleNode& another) const {
	return another.realIP() == _realIP && another.realPort() == _realPort;
}

bool SparkleNode::operator!=(const SparkleNode& another) const {
	return !(*this == another);
}

void SparkleNode::setSparkleMAC(const SparkleAddress& mac) {
	_sparkleMAC = mac;
	_router.notifyNodeUpdated(this);
}

void SparkleNode::setRealIP(const QHostAddress& ip) {
	_realIP = ip;
	_router.notifyNodeUpdated(this);
}

void SparkleNode::setRealPort(quint16 port) {
	_realPort = port;
	_router.notifyNodeUpdated(this);
}

void SparkleNode::setBehindNAT(bool behindNAT) {
	this->behindNAT = behindNAT;
	_router.notifyNodeUpdated(this);
}

void SparkleNode::setHisSessionKey(const QByteArray &keyBytes) {
	_hisSessionKey.setBytes(keyBytes);
	keysNegotiated = true;
	_router.notifyNodeUpdated(this);
}

bool SparkleNode::areKeysNegotiated() {
	return keysNegotiated;
}

bool SparkleNode::setAuthKey(const RSAKeyPair &keyPair) {
	return setAuthKey(keyPair.publicKey());
}

bool SparkleNode::setAuthKey(const QByteArray &publicKey) {
	if(authKeyPresent) {
		if(_authKey.publicKey() != publicKey) {
			Log::warn("Achtung! Attempt to assign new public key to authenticated node [%1]:%2, DROPPING.")
					<< _realIP.toString() << _realPort;
			return false;
		} else {
			return true;
		}
	}

	if(!_authKey.setPublicKey(publicKey))
		return false;

	authKeyPresent = true;

	_router.notifyNodeUpdated(this);

	return true;
}

void SparkleNode::configureByKey() {
	QByteArray mac = SHA1Digest::calculateSHA1(_authKey.publicKey()).left(SPARKLE_ADDRESS_SIZE);
	mac[0] = (mac[0] & ~0x03) | 0x02; // make address local and unicast
	_sparkleMAC = mac;
}

void SparkleNode::setMaster(bool isMaster) {
	master = isMaster;
	_router.notifyNodeUpdated(this);
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

