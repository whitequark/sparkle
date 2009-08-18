/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2009 Sergey Gridassov
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

#ifndef __LINK_LAYER__H__
#define __LINK_LAYER__H__

#include <QObject>
#include <QHostInfo>
#include <QTime>

#include "RSAKeyPair.h"

class QHostAddress;
class QTimer;
class SparkleNode;
class PacketTransport;
class Router;

class LinkLayer : public QObject
{
	Q_OBJECT

public:
	LinkLayer(Router &router, PacketTransport &transport, RSAKeyPair &rsaKeyPair);

	bool createNetwork(QHostAddress localAddress, quint8 networkDivisor);
	bool joinNetwork(QHostAddress remoteAddress, quint16 remotePort, bool forceBehindNAT);

	void processPacket(QByteArray packet);

public slots:
	void exitNetwork();

signals:
	void networkPacketReady(QByteArray &data, QHostAddress host, quint16 port);
	void tapPacketReady(QByteArray &packet);
	void joined(SparkleNode* node);
	void readyForShutdown();

private slots:
	void handlePacket(QByteArray &data, QHostAddress host, quint16 port);
	
	void pingTimeout();
	void negotiationTimeout(SparkleNode* node);
	void joinTimeout();

private:
	enum {
		ProtocolVersion	= 9,
	};

	enum packet_type_t {
		ProtocolVersionRequest		= 1,
		ProtocolVersionReply		= 2,

		PublicKeyExchange		= 3,
		SessionKeyExchange		= 4,

		Ping				= 5,

		EncryptedPacket			= 10,

		IntroducePacket			= 11,

		MasterNodeRequest		= 12,
		MasterNodeReply			= 13,

		PingRequest			= 14,
		PingInitiate			= 15,

		RegisterRequest			= 16,
		RegisterReply			= 17,

		Route				= 18,

		RouteRequest			= 19,
		RouteInvalidate			= 21,
		RouteMissing			= 22,
		
		RoleUpdate			= 23,
		
		ExitNotification		= 24,

		DataPacket			= 30,
	};

	struct packet_header_t {
		uint16_t	type;
		uint16_t	length;
	};

	struct protocol_version_reply_t {
		uint32_t	version;
	};
	
	struct key_exchange_t {
		quint8		needOthersKey;
		quint32		cookie;
	};

	struct introduce_packet_t {
		quint32		sparkleIP;
		quint8		sparkleMAC[8];
	};

	struct master_node_reply_t {
		quint32		addr;
		quint16		port;
	};
	
	struct ping_request_t {
		quint32		addr;
		quint16		port;
		quint8		count;
	};

	struct ping_t {
		quint32		addr;
		quint16		port;
	};

	struct register_request_t {
		quint8		isBehindNAT;
	};

	struct register_reply_t {
		quint8		networkDivisor;
		quint8		isMaster;
		quint32		sparkleIP;
		quint8		sparkleMAC[6];
		/* filled only when NAT is detected */
		quint32		realIP;
		quint16		realPort;
	};

	struct route_t {
		quint32		sparkleIP;
		quint8		sparkleMAC[6];
		quint32		realIP;
		quint16		realPort;
		quint8		isMaster;
		quint8		isBehindNAT;
	};

	struct route_request_t {
		quint32		sparkleIP;
	};

	struct route_invalidate_t {
		quint32		realIP;
		quint16		realPort;
	};
	
	struct route_missing_t {
		quint32		sparkleIP;
	};
	
	struct role_update_t {
		quint8		isMasterNow;
	};

	struct ethernet_header_t {
		quint8		dest[6];
		quint8		src[6];
		quint16		type;
	} __attribute__((packed));

	struct arp_packet_t {
		quint16		htype;
		quint16		ptype;
		quint8		hlen;
		quint8		plen;
		quint16		oper;
		quint8		sha[6];
		quint32		spa;
		quint8		tha[6];
		quint32		tpa;
	} __attribute__((packed));

	struct ipv4_header_t {
		quint8		version;
		quint8		diffserv;
		quint16		size;
		quint16		id;
		quint16		fragments;
		quint8 		ttl;
		quint8 		protocol;
		quint16		checksum;
		quint32		src;
		quint32		dest;
	} __attribute__((packed));

	enum join_step_t {
		JoinVersionRequest,
		JoinMasterNodeRequest,
		JoinAwaitingPings,
		JoinRegistration,
		JoinFinished
	};

	bool initTransport();	

	SparkleNode* wrapNode(QHostAddress host, quint16 port);
	
	bool isMaster();

	void sendPacket(packet_type_t type, QByteArray data, SparkleNode* node);
	void sendEncryptedPacket(packet_type_t type, QByteArray data, SparkleNode *node);
	void encryptAndSend(QByteArray data, SparkleNode *node);

	enum packet_size_class_t {
		PacketSizeEqual,
		PacketSizeGreater
	};

	bool checkPacketSize(QByteArray& payload, quint16 requiredSize, 
					SparkleNode* node, const char* packetName,
							packet_size_class_t sizeClass = PacketSizeEqual);
	bool checkPacketExpection(SparkleNode* node, const char* packetName, join_step_t neededStep);

	void sendProtocolVersionRequest(SparkleNode* node);
	void handleProtocolVersionRequest(QByteArray &payload, SparkleNode* node);

	void sendProtocolVersionReply(SparkleNode* node);
	void handleProtocolVersionReply(QByteArray &payload, SparkleNode* node);

	void sendPublicKeyExchange(SparkleNode* node, const RSAKeyPair *key, bool needHisKey, quint32 cookie=0);
	void handlePublicKeyExchange(QByteArray &payload, SparkleNode* node);

	void sendSessionKeyExchange(SparkleNode* node, bool needHisKey);
	void handleSessionKeyExchange(QByteArray &payload, SparkleNode* node);

	void sendIntroducePacket(SparkleNode* node);
	void handleIntroducePacket(QByteArray &payload, SparkleNode* node);
	
	void sendMasterNodeRequest(SparkleNode* node);
	void handleMasterNodeRequest(QByteArray &payload, SparkleNode* node);
	
	void sendMasterNodeReply(SparkleNode* node, SparkleNode* masterNode);
	void handleMasterNodeReply(QByteArray &payload, SparkleNode* node);

	void sendPingRequest(SparkleNode* node, SparkleNode* target, int count);
	void handlePingRequest(QByteArray &payload, SparkleNode* node);

	void sendPingInitiate(SparkleNode* node, SparkleNode* target, int count);
	void handlePingInitiate(QByteArray &payload, SparkleNode* node);

	void doPing(SparkleNode* node, quint8 count);

	void sendPing(SparkleNode* node);
	void handlePing(QByteArray &payload, SparkleNode* node);
	void joinGotPinged();

	void sendRegisterRequest(SparkleNode* node, bool isBehindNAT);
	void handleRegisterRequest(QByteArray &payload, SparkleNode* node);

	void sendRegisterReply(SparkleNode* node);
	void handleRegisterReply(QByteArray &payload, SparkleNode* node);

	void sendRoute(SparkleNode* node, SparkleNode* target);
	void handleRoute(QByteArray &payload, SparkleNode* node);

	void sendRouteRequest(QHostAddress addr);
	void handleRouteRequest(QByteArray &payload, SparkleNode* node);

	void sendRouteMissing(SparkleNode* node, QHostAddress addr);
	void handleRouteMissing(QByteArray &payload, SparkleNode* node);

	void sendRouteInvalidate(SparkleNode* node, SparkleNode* target);
	void handleRouteInvalidate(QByteArray &payload, SparkleNode* node);

	void sendRoleUpdate(SparkleNode* node, bool isMasterNow);
	void handleRoleUpdate(QByteArray &payload, SparkleNode* node);

	void sendExitNotification(SparkleNode* node);
	void handleExitNotification(QByteArray &payload, SparkleNode* node);
	void reincarnateSomeone();

	void handleDataPacket(QByteArray &payload, SparkleNode* node);
	
	void sendARPReply(SparkleNode* node);

	RSAKeyPair &hostKeyPair;
	Router &router;
	PacketTransport& transport;

	QList<SparkleNode*> nodeSpool;
	QList<SparkleNode*> awaitingNegotiation;
	QHash<quint32, SparkleNode*> cookies;

	quint8 networkDivisor;

	join_step_t joinStep;

	QTimer *pingTimer, *joinTimer;
	SparkleNode* joinMaster;
	unsigned joinPingsEmitted, joinPingsArrived;
	ping_t joinPing;
	bool forceBehindNAT, preparingForShutdown;
};

#endif
