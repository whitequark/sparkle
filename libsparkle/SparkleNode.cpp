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

#include <QTimer>
#include <QCryptographicHash>

#include <Sparkle/SparkleNode>
#include <Sparkle/SparkleAddress>
#include <Sparkle/Router>
#include <Sparkle/BlowfishKey>
#include <Sparkle/Log>
#include <Sparkle/RSAKeyPair>

using namespace Sparkle;

namespace Sparkle {

class SparkleNodePrivate {
public:
	SparkleNodePrivate(Router &router, QHostAddress realIP, quint16 realPort);
	
	Router& router;

	QHostAddress realIP, phantomIP;
	quint16 realPort, phantomPort;

	SparkleAddress sparkleMAC;

	bool master, behindNAT;

	RSAKeyPair authKey;
	bool authKeyPresent;
	BlowfishKey hisSessionKey, mySessionKey;
	bool keysNegotiated;

	QList<QByteArray> queue;

	QTimer negotiationTimer;	
};

}

SparkleNodePrivate::SparkleNodePrivate(Router &router, QHostAddress realIP, quint16 realPort) : router(router), realIP(realIP), realPort(realPort), phantomPort(0), authKeyPresent(false), keysNegotiated(false), master(false), behindNAT(false) {
	mySessionKey.generate();
	
	negotiationTimer.setSingleShot(true);
	negotiationTimer.setInterval(5000);	
}

SparkleNode::SparkleNode(SparkleNodePrivate &dd, QObject *parent) : QObject(parent), d_ptr(&dd) {

}

SparkleNode::SparkleNode(Router &router, QHostAddress realIP, quint16 realPort) : QObject(&router), d_ptr(new SparkleNodePrivate(router, realIP, realPort)) {
	connect(&d_ptr->negotiationTimer, SIGNAL(timeout()), SLOT(negotiationTimeout()));
}

SparkleNode::~SparkleNode() {
	delete d_ptr;
}

bool SparkleNode::operator==(const SparkleNode& another) const {
	Q_D(const SparkleNode);

	return another.realIP() == d->realIP && another.realPort() == d->realPort;
}

bool SparkleNode::operator!=(const SparkleNode& another) const {
	return !(*this == another);
}

void SparkleNode::setSparkleMAC(const SparkleAddress& mac) {
	Q_D(SparkleNode);
	
	d->sparkleMAC = mac;
	d->router.notifyNodeUpdated(this);
}

void SparkleNode::setRealIP(const QHostAddress& ip) {
	Q_D(SparkleNode);
	
	d->realIP = ip;
	d->router.notifyNodeUpdated(this);
}

void SparkleNode::setRealPort(quint16 port) {
	Q_D(SparkleNode);
	
	d->realPort = port;
	d->router.notifyNodeUpdated(this);
}

void SparkleNode::setPhantomIP(const QHostAddress& ip) {
	Q_D(SparkleNode);
	
	d->phantomIP = ip;
}

void SparkleNode::setPhantomPort(quint16 port) {
	Q_D(SparkleNode);
	
	d->phantomPort = port;
}

const QHostAddress &SparkleNode::phantomIP() const {
	Q_D(const SparkleNode);
	
	if(d->phantomIP.isNull())
		return d->realIP;
		
	return d->phantomIP;
}

quint16 SparkleNode::phantomPort() const {
	Q_D(const SparkleNode);
	
	if(d->phantomPort == 0)
		return d->realPort;
		
	return d->phantomPort;
}

void SparkleNode::setBehindNAT(bool behindNAT) {
	Q_D(SparkleNode);
	
	d->behindNAT = behindNAT;
	d->router.notifyNodeUpdated(this);
}

void SparkleNode::setHisSessionKey(const QByteArray &keyBytes) {
	Q_D(SparkleNode);
	
	d->hisSessionKey.setBytes(keyBytes);
	d->keysNegotiated = true;
	
	d->router.notifyNodeUpdated(this);
}

bool SparkleNode::areKeysNegotiated() {
	Q_D(const SparkleNode);

	return d->keysNegotiated;
}

bool SparkleNode::setAuthKey(const RSAKeyPair &keyPair) {
	return setAuthKey(keyPair.publicKey());
}

bool SparkleNode::setAuthKey(const QByteArray &publicKey) {
	Q_D(SparkleNode);

	if(d->authKeyPresent) {
		if(d->authKey.publicKey() != publicKey) {
			Log::warn("link: assigning new pubkey to authenticated node [%1]:%2") << d->realIP.toString() << d->realPort;
		} else {
			return true;
		}
	}

	if(!d->authKey.setPublicKey(publicKey))
		return false;

	d->authKeyPresent = true;

	d->router.notifyNodeUpdated(this);

	return true;
}

void SparkleNode::cloneKeys(SparkleNode *node) {
	Q_D(SparkleNode);
	
	setAuthKey(node->authKey()->publicKey());
	d->mySessionKey.setBytes(node->mySessionKey()->bytes());
	
	if(node->areKeysNegotiated())
		setHisSessionKey(node->hisSessionKey()->bytes());
}

SparkleAddress SparkleNode::addressFromKey(const RSAKeyPair *keyPair) {
	QByteArray mac = QCryptographicHash::hash(keyPair->publicKey(), QCryptographicHash::Sha1).left(SPARKLE_ADDRESS_SIZE);
	
	mac[0] = (mac[0] & ~0x03) | 0x02; // make address local and unicast
	
	return SparkleAddress(mac);
}

void SparkleNode::configure() {
	Q_D(SparkleNode);
	
	d->sparkleMAC = addressFromKey(&d->authKey);
}

void SparkleNode::setMaster(bool isMaster) {
	Q_D(SparkleNode);
	
	d->master = isMaster;
	d->router.notifyNodeUpdated(this);
}

bool SparkleNode::isMaster() {
	Q_D(const SparkleNode);
	
	return d->master;
}

bool SparkleNode::isQueueEmpty() {
	Q_D(const SparkleNode);
	
	return d->queue.empty();
}

void SparkleNode::pushQueue(QByteArray data) {
	Q_D(SparkleNode);

	d->queue.append(data);
}

QByteArray SparkleNode::popQueue() {
	Q_D(SparkleNode);
	
	return d->queue.takeFirst();
}

void SparkleNode::flushQueue() {
	Q_D(SparkleNode);
	
	d->queue.clear();
}

void SparkleNode::negotiationStart() {
	Q_D(SparkleNode);
	
	d->negotiationTimer.start();
}

void SparkleNode::negotiationFinished() {
	Q_D(SparkleNode);
	
	d->negotiationTimer.stop();
}

void SparkleNode::negotiationTimeout() {
	emit negotiationTimedOut(this);
}

const BlowfishKey *SparkleNode::hisSessionKey() const {
	Q_D(const SparkleNode);
	
	return &d->hisSessionKey;
}

const BlowfishKey *SparkleNode::mySessionKey() const {
	Q_D(const SparkleNode);
	
	return &d->mySessionKey;
}

const RSAKeyPair *SparkleNode::authKey() const {
	Q_D(const SparkleNode);
	
	return &d->authKey;
}

const QHostAddress &SparkleNode::realIP() const {
	Q_D(const SparkleNode);
	
	return d->realIP;
}

quint16 SparkleNode::realPort() const {
	Q_D(const SparkleNode);
	
	return d->realPort;
}

const SparkleAddress &SparkleNode::sparkleMAC() const {
	Q_D(const SparkleNode);
	
	return d->sparkleMAC;
}

bool SparkleNode::isBehindNAT() const {
	Q_D(const SparkleNode);
	
	return d->behindNAT;
}
