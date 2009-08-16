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
#include <arpa/inet.h>

#include "LinkLayer.h"
#include "SparkleNode.h"
#include "PacketTransport.h"
#include "SHA1Digest.h"
#include "Router.h"
#include "Log.h"

LinkLayer::LinkLayer(Router &_router, PacketTransport &_transport, RSAKeyPair &_hostKeyPair)
		: QObject(NULL), hostKeyPair(_hostKeyPair), router(_router), transport(_transport)
{
	connect(&transport, SIGNAL(receivedPacket(QByteArray&, QHostAddress, quint16)),
			SLOT(handlePacket(QByteArray&, QHostAddress, quint16)));
	connect(this, SIGNAL(networkPacketReady(QByteArray&, QHostAddress, quint16)),
		&transport, SLOT(sendPacket(QByteArray&, QHostAddress, quint16)));
	
	pingTimer = new QTimer(this);
	pingTimer->setSingleShot(true);
	pingTimer->setInterval(5000); // FIXME
	connect(pingTimer, SIGNAL(timeout()), SLOT(pingTimeout()));
	
	Log::debug("link layer (protocol version %1) is ready") << ProtocolVersion;
}

bool LinkLayer::joinNetwork(QHostAddress remoteIP, quint16 remotePort) {
	Log::debug("link: joining via [%1]:%2") << remoteIP << remotePort;

	if(!initTransport())
		return false;
	
	joinStep = JoinVersionRequest;
	sendProtocolVersionRequest(wrapNode(remoteIP, remotePort));

	return true;
}

bool LinkLayer::createNetwork(QHostAddress localIP, quint8 networkDivisor) {
	SparkleNode *self = new SparkleNode(localIP, transport.getPort());
	Q_CHECK_PTR(self);
	self->setMaster(true);
	self->setAuthKey(hostKeyPair);
	self->configureByKey();
	
	router.setSelfNode(self);
	
	if(!initTransport())
		return false;
	
	Log::debug("link: created network, my endpoint is [%1]:%2") << localIP << transport.getPort();
	
	this->networkDivisor = networkDivisor;
	Log::debug("link: network divisor is 1/%1") << networkDivisor;
	
	joinStep = JoinFinished;
	emit joined(self);

	return true;
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
	if(router.getSelfNode() == NULL)
		return false;
	else
		return router.getSelfNode()->isMaster();
}

SparkleNode* LinkLayer::wrapNode(QHostAddress host, quint16 port) {
	foreach(SparkleNode* node, nodeSpool) {	
		if(node->getRealIP() == host && node->getRealPort() == port)
			return node;
	}
	
	SparkleNode* node = new SparkleNode(host, port);
	Q_CHECK_PTR(node);
	nodeSpool.append(node);
	
	Log::debug("link: added [%1]:%2 to node spool") << host << port;
	
	return node;
}

void LinkLayer::sendPacket(packet_type_t type, QByteArray data, SparkleNode* node) {
	packet_header_t hdr;
	hdr.length = sizeof(packet_header_t) + data.size();
	hdr.type = type;

	data.prepend(QByteArray((const char *) &hdr, sizeof(packet_header_t)));

	emit networkPacketReady(data, node->getRealIP(), node->getRealPort());
}

void LinkLayer::sendEncryptedPacket(packet_type_t type, QByteArray data, SparkleNode *node) {
	packet_header_t hdr;
	hdr.length = sizeof(packet_header_t) + data.size();
	hdr.type = type;

	data.prepend(QByteArray((const char *) &hdr, sizeof(packet_header_t)));
	
	if(!node->areKeysNegotiated()) {
		node->pushQueue(data);
		if(awaitingNegotiation.contains(node)) {
			Log::warn("link: [%1]:%2 still awaiting negotiation") << *node;
		} else {
			Log::debug("link: initiating negotiation with [%1]:%2") << *node;
			
			awaitingNegotiation.append(node);
			sendPublicKeyExchange(node, &hostKeyPair, true);
		}
	} else {
		encryptAndSend(data, node);
	}
}

void LinkLayer::encryptAndSend(QByteArray data, SparkleNode *node) {
	Q_ASSERT(node->areKeysNegotiated());
	
	sendPacket(EncryptedPacket, node->getMySessionKey()->encrypt(data), node);
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
	
	QByteArray decData = node->getHisSessionKey()->decrypt(payload);
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
		case IntroducePacket:
			handleIntroducePacket(decPayload, node);
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
	
	if(ver->version != ProtocolVersion)
		Log::fatal("link: protocol version mismatch: got %1, expected %2") << ver->version << ProtocolVersion;
	
	joinStep = JoinMasterNodeRequest;
	sendMasterNodeRequest(node);
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
	if(key)	request.append(key->getPublicKey());
	else 	request.append(router.getSelfNode()->getAuthKey()->getPublicKey());
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
		
		if(*origNode != *node) {
			Log::info("link: node [%1]:%2 is apparently behind the same NAT, rewriting")
				<< *origNode;
			origNode->setRealIP(node->getRealIP());
			origNode->setRealPort(node->getRealPort());
			origNode->setAuthKey(key);
			node = origNode;
		}
		
		if(router.getSelfNode() != NULL && !router.getSelfNode()->isMaster())
			sendIntroducePacket(node);
		
		sendSessionKeyExchange(node, true);
	}
}

/* SessionKeyExchange */

void LinkLayer::sendSessionKeyExchange(SparkleNode* node, bool needHisKey) {
	key_exchange_t ke;
	ke.needOthersKey = needHisKey;
	
	QByteArray request;
	request.append(node->getMySessionKey()->getBytes());
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
	} else {
		awaitingNegotiation.removeOne(node);
		while(!node->isQueueEmpty())
			encryptAndSend(node->popQueue(), node);
	}
}

/* IntroducePacket */

void LinkLayer::sendIntroducePacket(SparkleNode* node) {
	introduce_packet_t intr;
	intr.sparkleIP = router.getSelfNode()->getSparkleIP().toIPv4Address();
	memcpy(intr.sparkleMAC, router.getSelfNode()->getSparkleMAC().constData(), 6);

	sendEncryptedPacket(IntroducePacket, QByteArray((const char*) &intr, sizeof(introduce_packet_t)), node);
}

void LinkLayer::handleIntroducePacket(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(introduce_packet_t), node, "IntroducePacket"))
		return;
	
	if(node->getSparkleMAC().length() > 0) {
		Log::warn("link: node [%2]:%3 is already introduced as %1") << node->getSparkleIP() << *node;
		return;
	}
	
	const introduce_packet_t *intr = (const introduce_packet_t*) payload.constData();

	node->setSparkleIP(QHostAddress(intr->sparkleIP));
	node->setSparkleMAC(QByteArray((const char*) intr->sparkleMAC, 6));
	node->setMaster(false);
	
	router.addNode(node);

	Log::debug("link: node [%1]:%2 introduced itself as %3") << *node << node->getSparkleIP();
}

/* MasterNodeRequest */

void LinkLayer::sendMasterNodeRequest(SparkleNode* node) {
	sendEncryptedPacket(MasterNodeRequest, QByteArray(), node);
}

void LinkLayer::handleMasterNodeRequest(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, 0, node, "MasterNodeRequest"))
		return;
	
	// scatter load over the whole network
	SparkleNode* master = router.selectMaster();
	
	if(master == NULL)
		Log::fatal("link: cannot choose master, this is probably a bug");
	
	sendMasterNodeReply(node, master);
}

/* MasterNodeReply */

void LinkLayer::sendMasterNodeReply(SparkleNode* node, SparkleNode* masterNode) {
	master_node_reply_t reply;
	reply.addr = masterNode->getRealIP().toIPv4Address();
	reply.port = masterNode->getRealPort();
	
	sendEncryptedPacket(MasterNodeReply, QByteArray((const char*) &reply, sizeof(master_node_reply_t)), node);
}

void LinkLayer::handleMasterNodeReply(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(master_node_reply_t), node, "MasterNodeReply"))
		return;

	if(!checkPacketExpection(node, "MasterNodeReply", JoinMasterNodeRequest))
		return;
	
	const master_node_reply_t *reply = (const master_node_reply_t*) payload.constData();
	
	SparkleNode* master = wrapNode(QHostAddress(reply->addr), reply->port);
	
	Log::debug("link: determined master node: [%1]:%2") << *master;
	
	joinStep = JoinAwaitingPings;
	joinPing.addr = 0;
	joinPingsEmitted = 4;
	joinPingsArrived = 0;
	joinMaster = master;
	pingTimer->start();
	sendPingRequest(node, master, 4);
}

/* PingRequest */

void LinkLayer::sendPingRequest(SparkleNode* node, SparkleNode* target, int count) {
	ping_request_t req;
	req.count = count;
	req.addr = target->getRealIP().toIPv4Address();
	req.port = target->getRealPort();
	
	sendEncryptedPacket(PingRequest, QByteArray((const char*) &req, sizeof(ping_request_t)), node);
}

void LinkLayer::handlePingRequest(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(ping_request_t), node, "PingRequest"))
		return;
	
	const ping_request_t *req = (const ping_request_t*) payload.constData();

	SparkleNode* target = wrapNode(QHostAddress(req->addr), req->port);
	
	if(*router.getSelfNode() == *target) {
		doPing(node, req->count);
		return;
	}
	
	sendPingInitiate(target, node, req->count);
}

/* PingInitiate */

void LinkLayer::sendPingInitiate(SparkleNode* node, SparkleNode* target, int count) {
	ping_request_t req;
	req.count = count;
	req.addr = target->getRealIP().toIPv4Address();
	req.port = target->getRealPort();
	
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
	ping.addr = node->getRealIP().toIPv4Address();
	ping.port = node->getRealPort();
	
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
		Log::fatal("link: got nonidentical pings");
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

	if(!router.getSelfNode()->isMaster()) {
		Log::warn("link: got RegisterRequest while not master");
		return;
	}

	const register_request_t* req = (const register_request_t*) payload.constData();

	node->configureByKey();
	node->setBehindNAT(req->isBehindNAT);

	if(!node->isBehindNAT()) {
		if(router.getMasters().count() == 1)
			node->setMaster(true);
		else
			node->setMaster(false);
	} else {
		node->setMaster(false);
	}

	sendRegisterReply(node);
	
	QList<SparkleNode*> updates;
	if(node->isMaster())	updates = router.getNodes();
	else			updates = router.getMasters();

	foreach(SparkleNode* update, updates)
		sendRoute(node, update);

	foreach(SparkleNode* master, router.getOtherMasters())
		sendRoute(master, node);

	router.addNode(node);
}

/* RegisterReply */

void LinkLayer::sendRegisterReply(SparkleNode* node) {
	register_reply_t reply;
	reply.isMaster = node->isMaster();
	reply.networkDivisor = networkDivisor;
	reply.sparkleIP = node->getSparkleIP().toIPv4Address();
	if(node->isBehindNAT()) {
		reply.realIP = node->getRealIP().toIPv4Address();
		reply.realPort = node->getRealPort();
	} else {
		reply.realIP = reply.realPort = 0;
	}
	
	Q_ASSERT(node->getSparkleMAC().length() == 6);
	memcpy(reply.sparkleMAC, node->getSparkleMAC().constData(), 6);
	
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
	} else {
		self = wrapNode(QHostAddress(joinPing.addr), joinPing.port);
		self->setBehindNAT(false);
	}
	self->setSparkleIP(QHostAddress(reply->sparkleIP));
	self->setSparkleMAC(QByteArray((const char*) reply->sparkleMAC, 6));
	self->setAuthKey(hostKeyPair);
	self->setMaster(reply->isMaster);
	router.setSelfNode(self);
	
	networkDivisor = reply->networkDivisor;
	Log::debug("link: network divisor is %1") << networkDivisor;
	
	joinStep = JoinFinished;
	emit joined(self);
}

/* Route */

void LinkLayer::sendRoute(SparkleNode* node, SparkleNode* target)
{
	route_t route;
	route.realIP = target->getRealIP().toIPv4Address();
	route.realPort = target->getRealPort();
	route.sparkleIP = target->getSparkleIP().toIPv4Address();
	route.isMaster = target->isMaster();

	Q_ASSERT(node->getSparkleMAC().length() == 6);
	memcpy(route.sparkleMAC, target->getSparkleMAC().constData(), 6);
	
	sendEncryptedPacket(Route, QByteArray((const char*) &route, sizeof(route_t)), node);
}

void LinkLayer::handleRoute(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(route_t), node, "Route"))
		return;

	if(!node->isMaster() && router.getOtherMasters().count() > 0) {
		Log::warn("link: Route packet from unauthoritative source [%1]:%2") << *node;
		return;
	}

	const route_t* route = (const route_t*) payload.constData();
	
	SparkleNode* target = wrapNode(QHostAddress(route->realIP), route->realPort);
	if(target == router.getSelfNode()) {
		Log::warn("link: attempt to add myself by Route packet from [%1]:%2") << *node;
		return;
	}
	
	target->setSparkleIP(QHostAddress(route->sparkleIP));
	target->setSparkleMAC(QByteArray((const char*) route->sparkleMAC, 6));
	target->setMaster(route->isMaster);
	
	router.addNode(target);
}

/* RouteRequest */

void LinkLayer::sendRouteRequest(QHostAddress host) {
	route_request_t req;
	req.sparkleIP = host.toIPv4Address();
	
	sendEncryptedPacket(RouteRequest, QByteArray((const char*) &req, sizeof(route_request_t)), 
				router.selectMaster());
}

void LinkLayer::handleRouteRequest(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(route_request_t), node, "RouteRequest"))
		return;
	
	if(!router.getSelfNode()->isMaster()) {
		Log::warn("link: i'm slave and got route request from [%1]:%2") << *node;
		return;
	}

	const route_request_t* req = (const route_request_t*) payload.constData();
	QHostAddress host(req->sparkleIP);
	
	SparkleNode* target = router.searchSparkleNode(host);
	if(target) {
		sendRoute(node, target);
	} else {
		sendRouteMissing(node, host);
	}
}

/* RouteMissing */

void LinkLayer::sendRouteMissing(SparkleNode* node, QHostAddress host) {
	route_missing_t req;
	req.sparkleIP = host.toIPv4Address();
	
	sendEncryptedPacket(RouteMissing, QByteArray((const char*) &req, sizeof(route_request_t)), node);
}

void LinkLayer::handleRouteMissing(QByteArray &payload, SparkleNode* node) {
	if(!checkPacketSize(payload, sizeof(route_missing_t), node, "RouteMissing"))
		return;
	
	const route_missing_t* req = (const route_missing_t*) payload.constData();
	QHostAddress host(req->sparkleIP);
	
	Log::info("link: no route to %1") << host;
}

/* Data */

void LinkLayer::handleDataPacket(QByteArray& packet, SparkleNode* node) {
	if(!checkPacketSize(packet, sizeof(ethernet_header_t) + sizeof(ipv4_header_t),
				node, "Data", PacketSizeGreater))
		return;
	
	const ethernet_header_t* eth = (const ethernet_header_t*) packet.constData();
	SparkleNode* self = router.getSelfNode();

	if(memcmp(eth->src, node->getSparkleMAC().constData(), 6) != 0) {
		Log::warn("link: remote [%1] packet with malformed source MAC") << node->getSparkleIP();
		return;
	}

	if(memcmp(eth->dest, self->getSparkleMAC().constData(), 6) != 0) {
		Log::warn("link: remote [%1] packet with malformed destination MAC") << node->getSparkleIP();
		return;
	}
	
	if(ntohs(eth->type) != 0x0800) { // IP
		Log::warn("link: remote [%1] non-IP (%2) packet") << node->getSparkleIP()
			<< QString::number(ntohs(eth->type), 16).rightJustified(4, '0');
		return;
	}

	QByteArray payload = packet.right(packet.size() - sizeof(ethernet_header_t));
	const ipv4_header_t* ip = (const ipv4_header_t*) payload.constData();

	if(ntohl(ip->src) != node->getSparkleIP().toIPv4Address()) {
		Log::warn("link: received IPv4 packet with malformed source address");
		return;
	}

	if(ntohl(ip->dest) != self->getSparkleIP().toIPv4Address()) {
		Log::warn("link: received IPv4 packet with malformed destination address");
		return;
	}
	
	emit tapPacketReady(packet);
}

/* ======= END ======= */

void LinkLayer::processPacket(QByteArray packet) {
	const ethernet_header_t* eth = (const ethernet_header_t*) packet.constData();
	SparkleNode* self = router.getSelfNode();

	if(memcmp(eth->src, self->getSparkleMAC().constData(), 6) != 0) {
		Log::warn("link: local packet from unknown source MAC");
		return;
	}
	
	QByteArray payload = packet.right(packet.size() - sizeof(ethernet_header_t));
	switch(ntohs(eth->type)) {
		case 0x0806: { // ARP
			if(memcmp(eth->dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0) {
				Log::warn("link: non-broadcasted local ARP packet");
				return;
			}
			
			const arp_packet_t* arp = (const arp_packet_t*) payload.constData();
			if(!(ntohs(arp->htype) == 1 /* ethernet */ && ntohs(arp->ptype) == 0x0800 /* ipv4 */ &&
				arp->hlen == 6 && arp->plen == 4 &&
					ntohl(arp->spa) == self->getSparkleIP().toIPv4Address() &&
					!memcmp(arp->sha, eth->src, 6))) {
				Log::warn("link: invalid local arp packet received");
				return;
			}
			
			if(ntohs(arp->oper) == 1 /* request */) {
				QHostAddress dest(ntohl(arp->tpa));
				SparkleNode* resolved = router.searchSparkleNode(dest);
				if(resolved == NULL) {
					if(!self->isMaster())
						sendRouteRequest(dest);
					else
						Log::info("link: no route to %1") << dest;
				} else {
					sendARPReply(resolved);
				}
			} else {
				Log::info("link: ARP packet with unexpected OPER=%1 received") << ntohs(arp->oper);
				return;
			}
			
			break;
		}
		
		case 0x0800: { // IPv4
			const ipv4_header_t* ip = (const ipv4_header_t*) payload.constData();
			if(ntohl(ip->src) != self->getSparkleIP().toIPv4Address()) {
				Log::warn("link: received local IPv4 packet with malformed source address");
				return;
			}
			
			QHostAddress dest(ntohl(ip->dest));
			SparkleNode* resolved = router.searchSparkleNode(dest);
			if(resolved != NULL) {
				sendEncryptedPacket(DataPacket, packet, resolved);
			} else if(htonl(ip->dest) == 0x0effffff) { // ignore broadcasta
				/* do nothing */
			} else if(htonl(ip->dest) >> 24 != 0xE0) { // avoid link-local
				Log::info("link: received local IPv4 packet for unknown destination [%1]")
						<< dest;
			}
			break;
		}
		
		case 0x86dd: { // IPv6
			/* Silently ignore. There're no IPv6 addresses assigned to iface anyway */
			break;
		}
		
		default: {
			Log::warn("link: received local packet of unknown type %1")
					<< QString::number(ntohs(eth->type), 16).rightJustified(4, '0');
		}
	}
}

void LinkLayer::sendARPReply(SparkleNode* node) {
	QByteArray packet(sizeof(ethernet_header_t) + sizeof(arp_packet_t), 0);
	SparkleNode* self = router.getSelfNode();
	
	ethernet_header_t* eth = (ethernet_header_t*) packet.data();
	memcpy(eth->dest, self->getSparkleMAC().constData(), 6);
	memcpy(eth->src, node->getSparkleMAC().constData(), 6);
	eth->type = htons(0x0806); // ARP
	
	arp_packet_t* arp = (arp_packet_t*) (packet.data() + sizeof(ethernet_header_t));
	arp->htype = htons(1); // ethernet
	arp->ptype = htons(0x0800); // IPv4
	arp->hlen = 6;
	arp->plen = 4;
	arp->oper = htons(2); // reply
	memcpy(arp->sha, eth->src, 6);
	arp->spa = htonl(node->getSparkleIP().toIPv4Address());
	memcpy(arp->tha, eth->dest, 6);
	arp->tpa = htonl(self->getSparkleIP().toIPv4Address());
	
	emit tapPacketReady(packet);
}

