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
class RoutesManager;

class LinkLayer : public QObject
{
	Q_OBJECT

public:
	LinkLayer(PacketTransport *transport, RSAKeyPair *hostPair, QObject *parent = 0);
	virtual ~LinkLayer();

	bool joinNetwork(QHostAddress host, quint16 port);
	bool createNetwork(QHostAddress localAddress);

	QHostAddress getSparkleIP() { return sparkleIP; }
	QByteArray getSparkleMac() { return sparkleMac; }

	void processPacket(QByteArray packet);

	struct node_def_t {
		QHostAddress	addr;
		quint16		port;
		QHostAddress	sparkleIP;
		QByteArray	sparkleMac;
	};

private slots:
	void handleDatagram(QByteArray &data, QHostAddress &host, quint16 port);
	void pingTimedOut();

signals:
	void joined();
	void sendPacketReq(QByteArray packet);

private:
	enum {
		ProtocolVersion	= 1,
	};

	enum packet_type_t {
		ProtocolVersionRequest		= 1,
		ProtocolVersionReply		= 2,

		PublicKeyExchange		= 3,
		PublicKeyReply			= 4,

		SessionKeyExchange		= 5,
		SessionKeyReply			= 6,
		SessionKeyAcknowlege		= 7,

		PingRequest			= 8,
		Ping				= 9,
		PingCompleted			= 10,

		EncryptedPacket			= 12,

		MasterNodeRequest		= 13,
		MasterNodeReply			= 14,

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

	struct master_node_reply_t {
		quint32	addr;
		quint16	port;
	};

	struct ping_request_t {
		quint32	seq;
		quint16	port;
	};

	struct ping_t {
		quint32 seq;
		quint32 addr;
	};

	struct ping_completed_t {
		quint32 seq;
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

	void sendPacket(packet_type_t type, SparkleNode *target, QByteArray data,
			bool encrypted, quint16 port = 0);
	void sendAsEncrypted(SparkleNode *node, QByteArray data, quint16 port = 0);

	void sendProtocolVersionRequest(QHostAddress host, quint16 port);
	void sendPingRequest(quint32 seq, quint16 localport, QHostAddress host, quint16 port);
	void sendMasterNodeRequest(QHostAddress host, quint16 port);
	void publicKeyExchange(QHostAddress host, quint16 port);
	void sendRegisterRequest(QHostAddress host, quint16 port);
	void sendRouteRequest(QHostAddress address);

	void joinGotVersion(int version);
	void joinPingGot();
	void joinGotMaster(QHostAddress host, quint16 port);

	void reverseMac(quint8 *mac);
	void sendARPReply(const node_def_t *node);

	SparkleNode *getOrConstructNode(QHostAddress host, quint16 port);

	QByteArray formRoute(const node_def_t *node, bool isMaster);

	QHostAddress remoteAddress, localAddress;
	quint16 remotePort;

	PacketTransport *transport;
	RSAKeyPair *hostPair;
	RoutesManager *routes;

	quint32 pingSeq;
	QTime pingTime;
	QTimer *pingTimer;
	bool pingReceived;

	bool isMaster;
	QByteArray sparkleMac;
	QHostAddress sparkleIP;

	QString error;

	enum join_step_t {
		RequestingProtocolVersion,
		RequestingPing,
		RequestingMasterNode,
		RegisteringInNetwork,
		Joined,
	};

	join_step_t joinStep;

	QList<SparkleNode *> nodes;
	QList<QHostAddress *> awaiting;
};

#endif
