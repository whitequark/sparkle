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

#include "RSAKeyPair.h"

class QUdpSocket;
class QHostAddress;
class SparkleNode;

class LinkLayer : public QObject
{
	Q_OBJECT

public:
	LinkLayer(RSAKeyPair *hostPair, quint16 port, QObject *parent = 0);
	virtual ~LinkLayer();

	bool createNetwork();
	bool joinNetwork(QString nodeName);

	QString errorString();

private slots:
	void joinTargetLookedUp(QHostInfo host);

	void haveDatagram();

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

		EncryptedPacket			= 8,

		GetMasterNodeRequest		= 9,
		GetMasterNodeReply		= 10,


	};

	struct packet_header_t {
		uint16_t	type;
		uint16_t	length;

	};

	struct protocol_version_reply_t {
		uint32_t	version;
	};

	struct get_master_node_reply_t {
		quint32	addr;
		quint16	port;
	};

	struct master_node_def_t {
		QHostAddress	addr;
		quint16		port;
	};


	void handleDatagram(QByteArray &data, QHostAddress &host, quint16 port);

	void sendPacket(packet_type_t type, QHostAddress host, quint16 port, QByteArray data, bool encrypted);
	void sendAsEncrypted(SparkleNode *node, QByteArray data);

	void sendProtocolVersionRequest(QHostAddress host, quint16 port);
	void sendGetMasterNodeRequest(QHostAddress host, quint16 port);
	void publicKeyExchange(QHostAddress host, quint16 port);

	void joinGotVersion(int version);
	void joinGotMaster(QHostAddress host, quint16 port);

	SparkleNode *getOrConstructNode(QHostAddress host, quint16 port);

	master_node_def_t *selectMaster();

	QUdpSocket *socket;

	QHostAddress remoteAddress;
	uint16_t port, remotePort;

	RSAKeyPair *hostPair;

	bool isMaster;

	QString error;

	enum join_step_t {
		RequestingProtocolVersion,
		RequestingMasterNode,
		RegisteringInNetwork,
	};

	join_step_t joinStep;

	QList<SparkleNode *> nodes;
	QList<master_node_def_t *> masters;
};

#endif
