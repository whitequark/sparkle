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
class Route;

class LinkLayer : public QObject
{
	Q_OBJECT

public:
	LinkLayer(Router &router, PacketTransport &transport, RSAKeyPair &rsaKeyPair);

	bool createNetwork(QHostAddress localAddress);
	bool joinNetwork(QHostAddress remoteAddress, quint16 remotePort);

	void processPacket(QByteArray packet);

signals:
	void networkPacketReady(QByteArray &data, QHostAddress host, quint16 port);
	void tapPacketReady(QByteArray &packet);

private slots:
	void handlePacket(QByteArray &data, QHostAddress host, quint16 port);

private:
	enum {
		ProtocolVersion	= 2,
	};

	enum packet_type_t {
		ProtocolVersionRequest		= 1,
		ProtocolVersionReply		= 2,

		PublicKeyExchange		= 3,
		SessionKeyExchange		= 4,

		Ping				= 5,

		EncryptedPacket			= 6,

		MasterNodeRequest		= 7,
		MasterNodeReply			= 8,

		PingRequest			= 9,
		PingInitiate			= 10,

		RegisterRequest			= 15,
		RegisterReply			= 16,

		RoutingTable			= 17,

		RouteRequest			= 18,
		NoRouteForEntry			= 19,

		DataPacket			= 20,

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

	struct register_reply_t {
		quint32	addr;
		quint8	mac[6];
		quint8	isMaster;
	};

	struct routing_table_entry_t {
		quint32	sparkleIP;
		quint32	inetIP;
		quint16	port;
		quint8	isMaster;
		quint8	sparkleMac[6];
	};

	struct mac_header_t {
		quint8	to[6];
		quint8	from[6];
		quint16	type;
	} __attribute__((packed));

	struct arp_packet_t {
		quint16	htype;
		quint16 ptype;
		quint8	hlen;
		quint8	plen;
		quint16	oper;
		quint8	sha[6];
		quint32	spa;
		quint8	tha[6];
		quint32	tpa;
	} __attribute__((packed));

	enum join_step_t {
		JoinVersionRequest,
		JoinMasterNodeRequest,
		JoinAwaitingPings,
		JoinRegistration
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

	void sendPublicKeyExchange(SparkleNode* node, const RSAKeyPair *key, bool needHisKey);
	void handlePublicKeyExchange(QByteArray &payload, SparkleNode* node);

	void sendSessionKeyExchange(SparkleNode* node, bool needHisKey);
	void handleSessionKeyExchange(QByteArray &payload, SparkleNode* node);

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

	RSAKeyPair &hostKeyPair;
	Router &router;
	PacketTransport& transport;

	QList<SparkleNode*> nodeSpool;
	QList<SparkleNode*> awaitingNegotiation;

	join_step_t joinStep;
	
	/* */

	void reverseMac(quint8 *mac);
	void sendARPReply(const Route *node);
};

#endif
