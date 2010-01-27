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

#include <QCoreApplication>
#include <QStringList>
#include <QHostInfo>
#include <QTimer>
#include <QtGlobal>
#ifdef Q_OS_WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif

#include "LinkLayer.h"
#include "SparkleNode.h"
#include "PacketTransport.h"
#include "SHA1Digest.h"
#include "Router.h"
#include "Log.h"
#include "ApplicationLayer.h"

LinkLayer::LinkLayer(Router &router, PacketTransport &_transport, RSAKeyPair &_hostKeyPair)
		: QObject(NULL), hostKeyPair(_hostKeyPair), _router(router), transport(_transport), joined(false), preparingForShutdown(false)
{
	connect(&transport, SIGNAL(receivedPacket(QByteArray&, QHostAddress, quint16)),
			SLOT(handlePacket(QByteArray&, QHostAddress, quint16)));

	pingTimer = new QTimer(this);
	pingTimer->setSingleShot(true);
	pingTimer->setInterval(10000);
	connect(pingTimer, SIGNAL(timeout()), SLOT(pingTimeout()));

	joinTimer = new QTimer(this);
	joinTimer->setSingleShot(true);
	joinTimer->setInterval(15000);
	connect(joinTimer, SIGNAL(timeout()), SLOT(joinTimeout()));

	natKeepaliveTimer = new QTimer(this);
	natKeepaliveTimer->setSingleShot(false);
	natKeepaliveTimer->setInterval(10000);
	connect(natKeepaliveTimer, SIGNAL(timeout()), SLOT(keepNATAlive()));

	_transport.connect(this, SIGNAL(leavedNetwork()), SLOT(endReceiving()));

	Log::debug("link layer (protocol version %1) is ready") << ProtocolVersion;
}

void LinkLayer::attachApplicationLayer(ApplicationLayer::Encapsulation encap, ApplicationLayer *app) {
	appLayers[encap] = app;
}

Router& LinkLayer::router() {
	return _router;
}

bool LinkLayer::joinNetwork(QHostAddress remoteIP, quint16 remotePort, bool forceBehindNAT) {
	Log::debug("link: joining via [%1]:%2") << remoteIP << remotePort;

	if(!initTransport())
		return false;

	this->forceBehindNAT = forceBehindNAT;

	joinStep = JoinVersionRequest;
	sendProtocolVersionRequest(wrapNode(remoteIP, remotePort));

	joinTimer->start();

	return true;
}

void LinkLayer::joinTimeout() {
	Log::error("link: join timeout");

	cleanup();
	emit joinFailed();
}

bool LinkLayer::createNetwork(QHostAddress localIP, quint8 networkDivisor) {
	SparkleNode *self = new SparkleNode(_router, localIP, transport.port());
	Q_CHECK_PTR(self);
	self->setMaster(true);
	self->setAuthKey(hostKeyPair);
	self->configure();

	_router.setSelfNode(self);

	if(!initTransport()) {
		cleanup();
		return false;
	}

	Log::debug("link: created network, my endpoint is [%1]:%2") << localIP << transport.port();

	this->networkDivisor = networkDivisor;
	Log::debug("link: network divisor is 1/%1") << networkDivisor;

	joinStep = JoinFinished;
	joined = true;
	emit joinedNetwork(self);

	return true;
}

void LinkLayer::exitNetwork() {
	if(joinStep != JoinFinished) {
		Log::debug("link: join isn't finished, skipping finalization");

		cleanup();
		emit leavedNetwork();

		return;
	}

	if(_router.getSelfNode()->isMaster() && _router.masters().count() == 1) {
		Log::debug("link: i'm the last master");
		reincarnateSomeone();
	} else {
		Log::debug("link: sending exit notification");
		sendExitNotification(_router.selectMaster());
	}

	if(awaitingNegotiation.count() > 0) {
		preparingForShutdown = true;
	} else {
		cleanup();
		emit leavedNetwork();
	}
}

bool LinkLayer::isJoined() {
	return joined;
}

bool LinkLayer::initTransport() {
	if(!transport.beginReceiving()) {
		Log::error("link: cannot initiate transport (port is already bound?)");
		return false;
	} else {
		Log::debug("link: transport initiated");
		return true;
	}
}

bool LinkLayer::isMaster() {
	if(_router.getSelfNode() == NULL)
		return false;
	else
		return _router.getSelfNode()->isMaster();
}

SparkleNode* LinkLayer::wrapNode(QHostAddress host, quint16 port) {
	foreach(SparkleNode* node, nodeSpool) {
		if((node->phantomIP() == host && node->phantomPort() == port) ||
				(node->realIP() == host && node->realPort() == port))
			return node;
	}

	Log::debug("link: adding [%1]:%2 to node spool") << host << port;

	SparkleNode* node = new SparkleNode(_router, host, port);
	Q_CHECK_PTR(node);
	nodeSpool.append(node);

	connect(node, SIGNAL(negotiationTimedOut(SparkleNode*)), SLOT(negotiationTimeout(SparkleNode*)));

	return node;
}

void LinkLayer::sendPacket(packet_type_t type, QByteArray data, SparkleNode* node) {
	Q_ASSERT(node != NULL);

	packet_header_t hdr;
	hdr.length = sizeof(packet_header_t) + data.size();
	hdr.type = type;

	data.prepend(QByteArray((const char *) &hdr, sizeof(packet_header_t)));

	if(node == _router.getSelfNode()) {
		Log::error("link: attempting to send packet to myself, dropping");
		return;
	}

	transport.sendPacket(data, node->phantomIP(), node->phantomPort());
}

void LinkLayer::sendEncryptedPacket(packet_type_t type, QByteArray data, SparkleNode *node, bool skipTunnel) {
	packet_header_t hdr;
	hdr.length = sizeof(packet_header_t) + data.size();
	hdr.type = type;

	data.prepend(QByteArray((const char *) &hdr, sizeof(packet_header_t)));

	if(!node->areKeysNegotiated()) {
		node->pushQueue(data);
		if(awaitingNegotiation.contains(node)) {
			Log::warn("link: [%1]:%2 is still awaiting negotiation") << *node;
		} else {
			Log::debug("link: initiating negotiation with [%1]:%2") << *node;

			node->negotiationStart();
			awaitingNegotiation.append(node);
			if(isJoined() && !isMaster() && node->isBehindNAT() && !skipTunnel) {
				Log::debug("link: estabilishing slave-slave link");
				sendPlainKeepalive(node);
				sendBacklinkRedirect(node);
			} else {
				sendPublicKeyExchange(node, &hostKeyPair, true);
			}
		}
	} else {
		encryptAndSend(data, node);
	}
}

void LinkLayer::encryptAndSend(QByteArray data, SparkleNode *node) {
	Q_ASSERT(node->areKeysNegotiated());

	sendPacket(EncryptedPacket, node->mySessionKey()->encrypt(data), node);
}

void LinkLayer::negotiationTimeout(SparkleNode* node) {
	Log::warn("link: negotiation timeout for [%1]:%2, dropping queue") << *node;

	node->flushQueue();
	awaitingNegotiation.removeOne(node);

	if(awaitingNegotiation.count() == 0 && preparingForShutdown) {
		cleanup();
		emit leavedNetwork();
	}
}

void LinkLayer::keepNATAlive() {
	foreach(SparkleNode* node, _router.otherNodes()) {
		sendKeepalive(node);
	}
}

SparkleAddress LinkLayer::findPartialRoute(QByteArray mac) {
	foreach(SparkleNode* node, _router.nodes()) {
		if(node->sparkleMAC().bytes().left(mac.size()) == mac)
			return node->sparkleMAC();
	}

	if(_router.getSelfNode()->isMaster())
		return SparkleAddress();

	route_request_extended_t req;
	memcpy(req.sparkleMAC, mac.constData(), mac.size());
	req.length = mac.size();

	sendEncryptedPacket(RouteRequest, QByteArray((const char*) &req, sizeof(route_request_extended_t)), _router.selectMaster());

	return SparkleAddress();
}

void LinkLayer::handlePacket(QByteArray &data, QHostAddress host, quint16 port) {
	const packet_header_t *hdr = (packet_header_t *) data.constData();

	if((size_t) data.size() < sizeof(packet_header_t) || hdr->length != data.size()) {
		Log::warn("link: malformed packet from [%1]:%2") << host << port;
		return;
	}

	QByteArray payload = data.right(data.size() - sizeof(packet_header_t));
	SparkleNode* node = wrapNode(host, port);

	switch((packet_type_t) hdr->type) {
		case ProtocolVersionRequest:
			handleProtocolVersionRequest(payload, node);
			return;

		case ProtocolVersionReply:
			handleProtocolVersionReply(payload, node);
			return;

		case PublicKeyExchange:
			handlePublicKeyExchange(payload, node);
			return;

		case SessionKeyExchange:
			handleSessionKeyExchange(payload, node);
			return;

		case Ping:
			handlePing(payload, node);
			return;

		case KeepalivePacket:
			//do nothing, it's for NAT on other side
			return;

		case EncryptedPacket:
			break; // will be handled later

		default: {
			Log::warn("link: packet of unknown type %1 from [%2]:%3") <<
					hdr->type << host << port;
			return;
		}
	}

	// at this point we have encrypted packet in payload.
	if(!node->areKeysNegotiated()) {
		Log::warn("link: no keys for encrypted packet from [%1]:%2") <<
				host << port;
		return;
	}

	// don't call handlePacket again to prevent receiving of unencrypted packet
	//   of types that imply encryption

	QByteArray decData = node->hisSessionKey()->decrypt(payload);
	const packet_header_t *decHdr = (packet_header_t *) decData.constData();

	if((size_t) decData.size() < sizeof(packet_header_t) ||
			decHdr->length < sizeof(packet_header_t) ||
			decHdr->length > decData.size()) {
		Log::warn("link: malformed encrypted payload from [%1]:%2") << host << port;
		return;
	}

	// Blowfish requires 64-bit chunks, here we truncate alignment zeroes at end
	if(decData.size() > decHdr->length && decData.size() < decHdr->length + 8)
		decData.resize(decHdr->length);

	QByteArray decPayload = decData.right(decData.size() - sizeof(packet_header_t));
	switch((packet_type_t) decHdr->type) {
		case LocalRewritePacket:
			handleLocalRewritePacket(decPayload, node);
			return;

		case MasterNodeRequest:
			handleMasterNodeRequest(decPayload, node);
			return;

		case MasterNodeReply:
			handleMasterNodeReply(decPayload, node);
			return;

		case PingRequest:
			handlePingRequest(decPayload, node);
			return;

		case PingInitiate:
			handlePingInitiate(decPayload, node);
			return;

		case RegisterRequest:
			handleRegisterRequest(decPayload, node);
			return;

		case RegisterReply:
			handleRegisterReply(decPayload, node);
			return;

		case Route:
			handleRoute(decPayload, node);
			return;

		case RouteRequest:
			handleRouteRequest(decPayload, node);
			return;

		case RouteMissing:
			handleRouteMissing(decPayload, node);
			return;

		case RouteInvalidate:
			handleRouteInvalidate(decPayload, node);
			return;

		case RoleUpdate:
			handleRoleUpdate(decPayload, node);
			return;

		case KeepalivePacket:
			handleKeepalive(decPayload, node);
			return;

		case BacklinkRedirect:
			handleBacklinkRedirect(decPayload, node);
			return;

		case ExitNotification:
			handleExitNotification(decPayload, node);
			return;

		case DataPacket:
			handleDataPacket(decPayload, node);
			return;

		default: {
			Log::warn("link: encrypted packet of unknown type %1 from [%2]:%3") <<
					decHdr->type << host << port;
		}
	}
}

bool LinkLayer::checkPacketSize(QByteArray& payload, quint16 requiredSize,
					 SparkleNode* node, const char* packetName,
						 packet_size_class_t sizeClass) {
	if((payload.size() != requiredSize && sizeClass == PacketSizeEqual) ||
		(payload.size() <= requiredSize && sizeClass == PacketSizeGreater)) {
		Log::warn("link: malformed %3 packet from [%1]:%2") << *node << packetName;
		return false;
	}

	return true;
}

bool LinkLayer::checkPacketExpection(SparkleNode* node, const char* packetName, join_step_t neededStep) {
	if(joinStep != neededStep) {
		Log::warn("link: unexpected %3 packet from [%1]:%2") << *node << packetName;
		return false;
	}

	return true;
}

/* ======= PACKET HANDLERS ======= */

/* ProtocolVersionRequest */

void LinkLayer::sendProtocolVersionRequest(SparkleNode* node) {
	sendPacket(ProtocolVersionRequest, QByteArray(), node);
}

void LinkLayer::handleProtocolVersionRequest(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, 0, node, "ProtocolVersionRequest"))
		return;

	sendProtocolVersionReply(node);
}

/* ProtocolVersionReply */

void LinkLayer::sendProtocolVersionReply(SparkleNode* node) {
	protocol_version_reply_t ver;
	ver.version = ProtocolVersion;

	sendPacket(ProtocolVersionReply, QByteArray((const char*) &ver, sizeof(ver)), node);
}

void LinkLayer::handleProtocolVersionReply(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(protocol_version_reply_t), node, "ProtocolVersionReply"))
		return;

	if(!checkPacketExpection(node, "ProtocolVersionReply", JoinVersionRequest))
		return;

	const protocol_version_reply_t *ver = (const protocol_version_reply_t *) payload.data();
	Log::debug("link: remote protocol version: %1") << ver->version;

	if(ver->version != ProtocolVersion) {
		Log::error("link: protocol version mismatch: got %1, expected %2") << ver->version << ProtocolVersion;

		cleanup();
		emit joinFailed();
	}

	joinStep = JoinMasterNodeRequest;
	sendMasterNodeRequest(node);

	joinTimer->start();
}

/* PublicKeyExchange */

void LinkLayer::sendPublicKeyExchange(SparkleNode* node, const RSAKeyPair* key, bool needHisKey, quint32 cookie) {
	key_exchange_t ke;
	ke.needOthersKey = needHisKey;

	if(needHisKey) {
		ke.cookie = qrand();
		cookies[ke.cookie] = node;
	} else {
		ke.cookie = cookie;
	}

	QByteArray request;
	if(key)	request.append(key->publicKey());
	else 	request.append(hostKeyPair.publicKey());
	request.prepend(QByteArray((const char*) &ke, sizeof(ke)));

	sendPacket(PublicKeyExchange, request, node);
}

void LinkLayer::handlePublicKeyExchange(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(key_exchange_t), node, "PublicKeyExchange", PacketSizeGreater))
		return;

	const key_exchange_t *ke = (const key_exchange_t*) payload.constData();

	QByteArray key = payload.mid(sizeof(key_exchange_t));
	if(!ke->needOthersKey && !cookies.contains(ke->cookie)) {
		cookies.remove(ke->cookie);
		Log::warn("link: unexpected pubkey from [%1]:%2") << *node;
		return;
	}

	if(!node->setAuthKey(key)) {
		Log::warn("link: received malformed public key from [%1]:%2") << *node;
		awaitingNegotiation.removeOne(node);
		return;
	} else {
		Log::debug("link: received public key for [%1]:%2") << *node;
	}

	if(ke->needOthersKey) {
		sendPublicKeyExchange(node, NULL, false, ke->cookie);
	} else {
		SparkleNode* origNode = cookies[ke->cookie];
		cookies.remove(ke->cookie);

		if(!(origNode->phantomIP() == node->phantomIP() && origNode->phantomPort() == origNode->phantomPort())) {
			Log::info("link: node [%1]:%2 is [%3]:%4 behind the NAT, rewriting") << *origNode << *node;

			origNode->setPhantomIP(node->phantomIP());
			origNode->setPhantomPort(node->phantomPort());
			origNode->setAuthKey(node->authKey()->publicKey());

			Log::debug("link: removing [%1]:%2 from node spool [nat]") << *node;
			nodeSpool.removeOne(node);
			delete node;

			node = origNode;

			sendLocalRewritePacket(node);
		}

		sendSessionKeyExchange(node, true);
	}
}

/* SessionKeyExchange */

void LinkLayer::sendSessionKeyExchange(SparkleNode* node, bool needHisKey) {
	key_exchange_t ke;
	ke.needOthersKey = needHisKey;

	QByteArray request;
	request.append(node->mySessionKey()->bytes());
	request.prepend(QByteArray((const char*) &ke, sizeof(ke)));

	sendPacket(SessionKeyExchange, request, node);
}

void LinkLayer::handleSessionKeyExchange(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(key_exchange_t), node, "SessionKeyExchange", PacketSizeGreater))
		return;

	const key_exchange_t *ke = (const key_exchange_t*) payload.constData();

	QByteArray key = payload.mid(sizeof(key_exchange_t));
	node->setHisSessionKey(key);

	Log::debug("link: stored session key for [%1]:%2") << *node;

	if(ke->needOthersKey) {
		sendSessionKeyExchange(node, false);
	}

	node->negotiationFinished();
	awaitingNegotiation.removeOne(node);

	while(!node->isQueueEmpty())
		encryptAndSend(node->popQueue(), node);

	if(awaitingNegotiation.count() == 0 && preparingForShutdown) {
		cleanup();
		emit leavedNetwork();
	}
}

/* LocalRewrite */

void LinkLayer::sendLocalRewritePacket(SparkleNode* node) {
	sendEncryptedPacket(LocalRewritePacket, QByteArray(), node);
}

void LinkLayer::handleLocalRewritePacket(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, 0, node, "LocalRewritePacket"))
		return;

	SparkleNode* target = NULL;
	foreach(SparkleNode* slave, _router.slaves()) {
		if(SparkleNode::addressFromKey(node->authKey()) == slave->sparkleMAC())
			target = slave;
	}

	if(target == NULL) {
		Log::warn("link: cannot associate LocalRewrite source [%1]:%2") << *node;
		return;
	}

	target->setPhantomIP(node->phantomIP());
	target->setPhantomPort(node->phantomPort());
	target->cloneKeys(node);

	SparkleNode* orphan = NULL;

	foreach(SparkleNode* i, nodeSpool) {
		if(i->realIP() == target->phantomIP() && i->realPort() == target->phantomPort() && i != target) {
			orphan = i;
			break;
		}
	}

	if(orphan != NULL && !_router.nodes().contains(orphan)) {
		Log::debug("link: removing [%1]:%2 from node spool [orphan]") << *orphan;
		nodeSpool.removeOne(orphan);
		delete orphan;
	}

	if(node != orphan && !_router.nodes().contains(node)) {
		Log::debug("link: removing [%1]:%2 from node spool [rewrite]") << *node;
		nodeSpool.removeOne(node);
		delete node;
	}

	Log::debug("link: associated [%1]:%2 to link-local [%3]:%4") << *target << target->phantomIP() << target->phantomPort();
}

/* MasterNodeRequest */

void LinkLayer::sendMasterNodeRequest(SparkleNode* node) {
	sendEncryptedPacket(MasterNodeRequest, QByteArray(), node);
}

void LinkLayer::handleMasterNodeRequest(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, 0, node, "MasterNodeRequest"))
		return;

	// scatter load over the whole network
	SparkleNode* master = _router.selectJoinMaster(node->realIP());

	if(master == NULL)
		Log::fatal("link: cannot choose master, this is probably a bug");

	sendMasterNodeReply(node, master);
}

/* MasterNodeReply */

void LinkLayer::sendMasterNodeReply(SparkleNode* node, SparkleNode* masterNode) {
	master_node_reply_t reply;
	reply.addr = masterNode->realIP().toIPv4Address();
	reply.port = masterNode->realPort();

	sendEncryptedPacket(MasterNodeReply, QByteArray((const char*) &reply, sizeof(master_node_reply_t)), node);
}

void LinkLayer::handleMasterNodeReply(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(master_node_reply_t), node, "MasterNodeReply"))
		return;

	if(!checkPacketExpection(node, "MasterNodeReply", JoinMasterNodeRequest))
		return;

	const master_node_reply_t *reply = (const master_node_reply_t*) payload.constData();

	SparkleNode* master = wrapNode(QHostAddress(reply->addr), reply->port);
	joinMaster = master;

	Log::debug("link: determined master node: [%1]:%2") << *master;

	if(!forceBehindNAT) {
		joinStep = JoinAwaitingPings;
		joinPing.addr = 0;
		joinPingsEmitted = 4;
		joinPingsArrived = 0;
		pingTimer->start();
		sendPingRequest(node, master, 4);
	} else {
		Log::debug("link: skipping NAT detection");

		joinStep = JoinRegistration;
		sendRegisterRequest(master, true);
	}

	joinTimer->start();
}

/* PingRequest */

void LinkLayer::sendPingRequest(SparkleNode* node, SparkleNode* target, int count) {
	ping_request_t req;
	req.count = count;
	req.addr = target->realIP().toIPv4Address();
	req.port = target->realPort();

	sendEncryptedPacket(PingRequest, QByteArray((const char*) &req, sizeof(ping_request_t)), node);
}

void LinkLayer::handlePingRequest(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(ping_request_t), node, "PingRequest"))
		return;

	const ping_request_t *req = (const ping_request_t*) payload.constData();

	SparkleNode* target = wrapNode(QHostAddress(req->addr), req->port);

	if(*_router.getSelfNode() == *target) {
		doPing(node, req->count);
		return;
	}

	sendPingInitiate(target, node, req->count);
}

/* PingInitiate */

void LinkLayer::sendPingInitiate(SparkleNode* node, SparkleNode* target, int count) {
	ping_request_t req;
	req.count = count;
	req.addr = target->realIP().toIPv4Address();
	req.port = target->realPort();

	sendEncryptedPacket(PingInitiate, QByteArray((const char*) &req, sizeof(ping_request_t)), node);
}

void LinkLayer::handlePingInitiate(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(ping_request_t), node, "PingInitiate"))
		return;

	const ping_request_t *req = (const ping_request_t*) payload.constData();

	doPing(wrapNode(QHostAddress(req->addr), req->port), req->count);
}

void LinkLayer::doPing(SparkleNode* node, quint8 count) {
	if(count > 16) {
		Log::warn("link: request for many (%1) ping's for [%2]:%3. DoS attempt? Dropping.") << count << *node;
		return;
	}

	for(int i = 0; i < count; i++)
		sendPing(node);
}

/* Ping */

void LinkLayer::sendPing(SparkleNode* node) {
	ping_t ping;
	ping.addr = node->realIP().toIPv4Address();
	ping.port = node->realPort();

	sendPacket(Ping, QByteArray((const char*) &ping, sizeof(ping_t)), node);
}

void LinkLayer::handlePing(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(ping_t), node, "Ping"))
		return;

	if(!checkPacketExpection(node, "Ping", JoinAwaitingPings))
		return;

	if(node != joinMaster) {
		Log::warn("link: unexpected ping from node [%1]:%2") << *node;
		return;
	}

	const ping_t* ping = (const ping_t*) payload.constData();

	joinPingsArrived++;
	if(joinPing.addr == 0) {
		joinPing = *ping;
	} else if(joinPing.addr != ping->addr || joinPing.port != ping->port) {
		Log::error("link: got nonidentical pings");

		cleanup();
		emit joinFailed();
	}

	if(joinPingsArrived == joinPingsEmitted)
		joinGotPinged();
}

void LinkLayer::pingTimeout() {
	if(joinPingsArrived == 0) {
		Log::debug("link: no pings arrived, NAT is detected");

		joinStep = JoinRegistration;

		Log::debug("link: registering on [%1]:%2") << *joinMaster;
		sendRegisterRequest(joinMaster, true);
	} else {
		joinGotPinged();
	}
}

void LinkLayer::joinGotPinged() {
	Log::debug("link: %1% of pings arrived") << (joinPingsArrived * 100 / joinPingsEmitted);

	pingTimer->stop();

	joinStep = JoinRegistration;

	Log::debug("link: no NAT detected, my real address is [%1]:%2")
				<< QHostAddress(joinPing.addr) << joinPing.port;

	Log::debug("link: registering on [%1]:%2") << *joinMaster;
	sendRegisterRequest(joinMaster, false);

	joinTimer->start();
}

/* RegisterRequest */

void LinkLayer::sendRegisterRequest(SparkleNode* node, bool isBehindNAT) {
	register_request_t req;
	req.isBehindNAT = isBehindNAT;

	sendEncryptedPacket(RegisterRequest, QByteArray((const char*) &req, sizeof(register_request_t)), node);
}

void LinkLayer::handleRegisterRequest(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(register_request_t), node, "RegisterRequest"))
		return;

	if(!_router.getSelfNode()->isMaster()) {
		Log::warn("link: got RegisterRequest while not master");
		return;
	}

	const register_request_t* req = (const register_request_t*) payload.constData();

	node->configure();
	node->setBehindNAT(req->isBehindNAT);

	if(!node->isBehindNAT()) {
		if(_router.masters().count() == 1) {
			node->setMaster(true);
		} else {
			double ik = 1. / networkDivisor;
			double rk = ((double) _router.masters().count()) / (_router.nodes().count() + 1);
			if(rk < ik) {
				Log::debug("link: insufficient masters (I %1; R %2), adding one") << ik << rk;
				node->setMaster(true);
			} else {
				node->setMaster(false);
			}
		}
	} else {
		node->setMaster(false);
	}

	QList<SparkleNode*> updates;
	if(node->isMaster())	updates = _router.otherNodes();
	else			updates = _router.otherMasters();

	foreach(SparkleNode* update, updates) {
		sendRoute(node, update);
		sendRoute(update, node);
	}

	sendRoute(node, _router.getSelfNode());

	_router.updateNode(node);

	sendRegisterReply(node);
}

/* RegisterReply */

void LinkLayer::sendRegisterReply(SparkleNode* node) {
	register_reply_t reply;
	reply.isMaster = node->isMaster();
	reply.networkDivisor = networkDivisor;
	if(node->isBehindNAT()) {
		reply.realIP = node->realIP().toIPv4Address();
		reply.realPort = node->realPort();
	} else {
		reply.realIP = reply.realPort = 0;
	}

	Q_ASSERT(!node->sparkleMAC().isNull());
	memcpy(reply.sparkleMAC, node->sparkleMAC().rawBytes(), SPARKLE_ADDRESS_SIZE);

	sendEncryptedPacket(RegisterReply, QByteArray((const char*) &reply, sizeof(register_reply_t)), node);
}

void LinkLayer::handleRegisterReply(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(register_reply_t), node, "RegisterReply"))
		return;

	if(!checkPacketExpection(node, "RegisterReply", JoinRegistration))
		return;

	const register_reply_t* reply = (const register_reply_t*) payload.constData();

	SparkleNode* self;
	if(reply->realIP != 0) { // i am behind NAT
		Log::debug("link: external endpoint was assigned by NAT passthrough");
		self = wrapNode(QHostAddress(reply->realIP), reply->realPort);
		self->setBehindNAT(true);

		Log::debug("link: enabling NAT keepalive polling (each %1s)") << natKeepaliveTimer->interval() / 1000;
		natKeepaliveTimer->start();
	} else {
		self = wrapNode(QHostAddress(joinPing.addr), joinPing.port);
		self->setBehindNAT(false);
	}
	self->setSparkleMAC(reply->sparkleMAC);
	self->setAuthKey(hostKeyPair);
	self->setMaster(reply->isMaster);
	_router.setSelfNode(self);

	networkDivisor = reply->networkDivisor;
	Log::debug("link: network divisor is 1/%1") << networkDivisor;

	joinTimer->stop();

	joined = true;
	joinStep = JoinFinished;
	emit joinedNetwork(self);
}

/* Route */

void LinkLayer::sendRoute(SparkleNode* node, SparkleNode* target, bool tunnelRequest)
{
	route_t route;
	route.realIP = target->realIP().toIPv4Address();
	route.realPort = target->realPort();
	route.isMaster = target->isMaster();
	route.isBehindNAT = target->isBehindNAT();
	route.tunnelRequest = tunnelRequest;

	Q_ASSERT(!node->sparkleMAC().isNull());
	memcpy(route.sparkleMAC, target->sparkleMAC().rawBytes(), SPARKLE_ADDRESS_SIZE);

	sendEncryptedPacket(Route, QByteArray((const char*) &route, sizeof(route_t)), node);
}

void LinkLayer::handleRoute(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(route_t), node, "Route"))
		return;

	if(!node->isMaster() && _router.getSelfNode() != NULL) {
		Log::warn("link: route packet from unauthoritative source [%1]:%2") << *node;
		return;
	}

	const route_t* route = (const route_t*) payload.constData();

	Log::debug("link: route received from [%1]:%2") << *node;

	SparkleNode* target = NULL;
	QHostAddress newIP(route->realIP);
	quint16 newPort = route->realPort;

	foreach(SparkleNode* node, _router.nodes()) {
		if(node->sparkleMAC() == route->sparkleMAC && !(node->realIP() == newIP && node->realPort() == newPort)) {
			Log::debug("link: endpoint [%1]:%2 is obsolete in favor of [%3]:%4") << *node << newIP << newPort;
			target = node;
		}
	}

	if(target == NULL) {
		target = wrapNode(QHostAddress(route->realIP), route->realPort);
		target->setSparkleMAC(route->sparkleMAC);
	}

	target->setRealIP(newIP);
	target->setRealPort(newPort);
	target->setMaster(route->isMaster);
	target->setBehindNAT(route->isBehindNAT);

	_router.updateNode(target);

	SparkleAddress addr(target->sparkleMAC());

	if(isJoined() && _router.getSelfNode()->isBehindNAT() && target->isBehindNAT() && route->tunnelRequest) {
		// estabilishing a tunnel through NAT
		sendKeepalive(target, true);
	}

	// two checks to prevent automatic list creation
	if(queuedData.contains(addr) && queuedData[addr].count() > 0) {
		Log::debug("link: sending %1 packets in %2 queue") << queuedData[addr].count() << addr.pretty();

		foreach(const QByteArray& packet, queuedData[addr])
			sendEncryptedPacket(DataPacket, packet, target);
		queuedData.remove(addr); // route is estabilished
	}
}

/* RouteRequest */

//TODO: add timeouts on route requests

void LinkLayer::sendRouteRequest(SparkleAddress mac) {
	Q_ASSERT(!mac.isNull());

	if(_router.hasRouteTo(mac)) {
		Log::error("link: route request for known address %1") << mac.pretty();
		return;
	}

	SparkleNode* master = _router.selectMaster();
	if(master == _router.getSelfNode()) {
		// i'm the one master & i don't know route
		Log::debug("link: no route to %1") << mac.pretty();

		emit routeMissing(mac);

		return;
	}

	route_request_t req;
	memcpy(req.sparkleMAC, mac.rawBytes(), SPARKLE_ADDRESS_SIZE);

	sendEncryptedPacket(RouteRequest, QByteArray((const char*) &req, sizeof(route_request_t)), master);
}

void LinkLayer::handleRouteRequest(QByteArray &payload, SparkleNode* node) {
	if(!_router.getSelfNode()->isMaster()) {
		Log::warn("link: i'm slave and got route request from [%1]:%2") << *node;
		return;
	}

	if(payload.size() == sizeof(route_request_extended_t)) {
		const route_request_extended_t* req = (const route_request_extended_t*) payload.constData();

		if(req->length > 6) {
			Log::warn("link: got malformed extended RouteRequest from [%1]:%2") << *node;
			return;
		}

		QByteArray mac((const char*) req->sparkleMAC, req->length);
		SparkleAddress fullMAC = findPartialRoute(mac);

		if(!fullMAC.isNull())
			sendRoute(node, _router.findSparkleNode(fullMAC));

		return;
	}

	if(!checkPacketSize(payload, sizeof(route_request_t), node, "RouteRequest"))
		return;

	const route_request_t* req = (const route_request_t*) payload.constData();

	SparkleNode* target = _router.findSparkleNode(req->sparkleMAC);
	if(target) {
		sendRoute(node, target);
	} else {
		sendRouteMissing(node, req->sparkleMAC);
	}
}

/* RouteMissing */

void LinkLayer::sendRouteMissing(SparkleNode* node, SparkleAddress mac) {
	route_missing_t req;
	memcpy(req.sparkleMAC, mac.rawBytes(), SPARKLE_ADDRESS_SIZE);

	sendEncryptedPacket(RouteMissing, QByteArray((const char*) &req, sizeof(route_request_t)), node);
}

void LinkLayer::handleRouteMissing(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(route_missing_t), node, "RouteMissing"))
		return;

	const route_missing_t* req = (const route_missing_t*) payload.constData();
	SparkleAddress addr(req->sparkleMAC);

	Log::debug("link: no route to %1") << addr.pretty();

	// two checks to prevent automatic list creation
	if(queuedData.contains(addr) && queuedData[addr].count()) {
		Log::debug("link: dropping %1 packets to %2") << queuedData[addr].count() << addr.pretty();
		queuedData[addr].clear();
	}

	emit routeMissing(addr);
}

/* RouteInvalidate */

void LinkLayer::sendRouteInvalidate(SparkleNode* node, SparkleNode* target) {
	route_invalidate_t inv;
	inv.realIP = target->realIP().toIPv4Address();
	inv.realPort = target->realPort();

	sendEncryptedPacket(RouteInvalidate, QByteArray((const char*) &inv, sizeof(route_invalidate_t)), node);
}

void LinkLayer::handleRouteInvalidate(QByteArray& payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(route_invalidate_t), node, "RouteInvalidate"))
		return;

	const route_invalidate_t* inv = (const route_invalidate_t*) payload.constData();
	SparkleNode* target = NULL;
	foreach(SparkleNode* node, _router.otherNodes()) {
		if(node->realIP() == QHostAddress(inv->realIP) && node->realPort() == inv->realPort) {
			target = node;
			break;
		}
	}

	if(target != NULL) {
		Log::debug("link: invalidating route %5 @ [%1]:%2 because of command from [%3]:%4")
			<< *target << *node << node->sparkleMAC().pretty();

		_router.removeNode(target);

		Log::debug("link: removing [%1]:%2 from node spool [iroute]") << *target;

		nodeSpool.removeOne(target);
		delete target;
	} else {
		Log::warn("link: request of invalidating unexistent route [%1]:%2 because of command from [%3]:%4")
			<< QHostAddress(inv->realIP) << inv->realPort << *node;
	}
}

/* BacklinkRedirect */

void LinkLayer::sendBacklinkRedirect(SparkleNode* node) {
	backlink_redirect_t redirect;
	redirect.realIP = node->realIP().toIPv4Address();
	redirect.realPort = node->realPort();

	sendEncryptedPacket(BacklinkRedirect, QByteArray((const char*) &redirect, sizeof(backlink_redirect_t)), _router.selectMaster());
}

void LinkLayer::handleBacklinkRedirect(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(backlink_redirect_t), node, "BacklinkRedirect"))
		return;

	if(!_router.getSelfNode()->isMaster()) {
		Log::warn("link: got backlink redirect from [%1]:%2 while slave") << *node;
		return;
	}

	if(node->isMaster()) {
		Log::warn("link: got backlink redirect from master [%1]:%2") << *node;
		return;
	}

	const backlink_redirect_t* redirect = (const backlink_redirect_t*) payload.constData();

	SparkleNode* target = wrapNode(QHostAddress(redirect->realIP), redirect->realPort);

	if(!_router.nodes().contains(target)) {
		Log::debug("link: got backlink redirect from [%1]:%2 for non-peered [%1]:%2; probably network error") << *node << *target;
		return;
	}

	if(!target->isBehindNAT()) {
		Log::warn("link: got backlink redirect from [%1]:%2 for white node [%3]:%4; this is useless") << *node << *target;
	}

	if(!target->areKeysNegotiated()) {
		Log::error("link: got backlink redirect from [%1]:%2 for non-negotiated slave [%3]:%4") << *node << *target;
		return;
	}

	sendRoute(target, node, true);
}

/* RoleUpdate */

void LinkLayer::sendRoleUpdate(SparkleNode* node, bool isMasterNow) {
	role_update_t update;
	update.isMasterNow = isMasterNow;

	sendEncryptedPacket(RoleUpdate, QByteArray((const char*) &update, sizeof(role_update_t)), node);
}

void LinkLayer::handleRoleUpdate(QByteArray& payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(role_update_t), node, "RoleUpdate"))
		return;

	if(!node->isMaster()) {
		Log::warn("link: RoleUpdate packet was received from slave [%1]:%2, dropping") << *node;
		return;
	}

	const role_update_t* update = (const role_update_t*) payload.constData();

	Log::info("link: switching to %3 role caused by [%1]:%2") << *node
		<< (update->isMasterNow ? "Master" : "Slave");

	_router.getSelfNode()->setMaster(update->isMasterNow);
}

/* Keepalive */

void LinkLayer::sendPlainKeepalive(SparkleNode* node) {
	sendPacket(KeepalivePacket, QByteArray(), node);
}

void LinkLayer::sendKeepalive(SparkleNode* node, bool skipTunnel) {
	sendEncryptedPacket(KeepalivePacket, QByteArray(), node, skipTunnel);
}

void LinkLayer::handleKeepalive(QByteArray& payload, SparkleNode* node) {
	if(!checkPacketSize(payload, 0, node, "Keepalive"))
		return;

	// nothing currently
}

/* ExitNotification */

void LinkLayer::sendExitNotification(SparkleNode* node) {
	sendEncryptedPacket(ExitNotification, QByteArray(), node);
}

void LinkLayer::handleExitNotification(QByteArray& payload, SparkleNode* node) {
	if(!checkPacketSize(payload, 0, node, "ExitNotification"))
		return;

	if(!_router.getSelfNode()->isMaster()) {
		Log::warn("link: ExitNotification was received from [%1]:%2, but I am slave") << *node;
		return;
	}

	_router.removeNode(node);

	foreach(SparkleNode* target, _router.otherNodes())
		sendRouteInvalidate(target, node);

	Log::debug("link: removing [%1]:%2 from node spool [exit]") << *node;

	nodeSpool.removeOne(node);
	delete node;

	double ik = 1. / networkDivisor;
	double rk = ((double) _router.masters().count()) / (_router.nodes().count());
	if(rk < ik || _router.masters().count() == 1) {
		Log::debug("link: insufficient masters (I %1; R %2)") << ik << rk;

		reincarnateSomeone();
	}
}

void LinkLayer::reincarnateSomeone() {
	SparkleNode* target = _router.selectWhiteSlave();

	if(target == NULL) {
		Log::warn("link: there're no nodes to reincarnate");
		return;
	}

	Log::debug("link: %1 @ [%2]:%3 is selected as target") << target->sparkleMAC().pretty() << *target;

	target->setMaster(true);

	_router.updateNode(target);

	foreach(SparkleNode* node, _router.otherNodes()) {
		if(!node->isMaster() && node != target) {
			sendRoute(node, target);
			sendRoute(target, node);
		}
	}

	sendRoleUpdate(target, true);
}

/* DataPacket */

void LinkLayer::sendDataPacket(SparkleAddress address, ApplicationLayer::Encapsulation encap, QByteArray &payload) {
	data_packet_t info;
	info.encapsulation = encap;

	QByteArray packet = QByteArray((const char*) &info, sizeof(data_packet_t)).append(payload);

	SparkleNode* node = _router.findSparkleNode(address);
	if(node) {
		sendEncryptedPacket(DataPacket, packet, node);
	} else {
		Log::debug("link: queueing data<%2> packet for %1") << address.pretty() << encap;
		queuedData[address].append(packet);
		sendRouteRequest(address);
	}
}

void LinkLayer::handleDataPacket(QByteArray& packet, SparkleNode* node) {
	if(!checkPacketSize(packet, sizeof(data_packet_t), node, "DataPacket", PacketSizeGreater))
		return;

	const data_packet_t* info = (const data_packet_t*) packet.constData();

	QByteArray payload = packet.right(packet.size() - sizeof(data_packet_t));

	ApplicationLayer::Encapsulation encap = (ApplicationLayer::Encapsulation) info->encapsulation;

	if(appLayers.contains(encap)) {
		appLayers[encap]->handleDataPacket(payload, node->sparkleMAC());
	} else {
		Log::warn("link: received packet from [%1]:%2 with unknown encapsulation %3") << *node << encap;
	}
}


/* ======= END ======= */

void LinkLayer::cleanup() {
	Log::debug("link: cleanup");

	foreach(SparkleNode *node, nodeSpool)
		delete node;

	_router.clear();
	nodeSpool.clear();
	awaitingNegotiation.clear();
	cookies.clear();
	joinTimer->stop();
	pingTimer->stop();
	natKeepaliveTimer->stop();
	joined = false;
}


