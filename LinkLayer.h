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
#include "SparkleNode.h"

class QUdpSocket;
class QHostAddress;

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

		PacketEncrypted	= 1,
	};

	enum packet_type_t {
		ProtocolVersionRequest	= 1,
		ProtocolVersionReply	= 2,

		PublicKeyExchange	= 3,
		PublicKeyReply		= 4,

		SessionKeyExchange	= 5,
		SessionKeyReply		= 6,

		NetworkInformationRequest	= 7,
		NetworkInformationReply		= 8,


	};

	struct packet_header_t {
		uint16_t	type;
		uint16_t	length;
		uint32_t	flags;

	};

	struct protocol_version_reply_t {
		uint32_t	version;
	};

	void handleDatagram(QByteArray &data, QHostAddress &host, quint16 port);

	void sendPacket(packet_type_t type, QHostAddress host, quint16 port, QByteArray data, bool encrypted);

	void sendProtocolVersionRequest(QHostAddress host, quint16 port);
	void sendNetworkInformationRequest(QHostAddress host, quint16 port);
	void publicKeyExchange(QHostAddress host, quint16 port);

	void joinGotVersion(int version);

	SparkleNode getOrConstructNode(QHostAddress host, quint16 port);

	QUdpSocket *socket;

	QHostAddress remoteAddress;
	uint16_t port, remotePort;

	RSAKeyPair *hostPair;

	bool isMaster;

	QString error;

	enum join_step_t {
		RequestingProtocolVersion,
		RequestingNetworkInformation,
	};

	join_step_t joinStep;

	struct sparkleNode {
		QHostAddress	address;
		quint16		port;
	};


	QList<SparkleNode> nodes;
};

#endif
