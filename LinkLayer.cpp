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

#include <QCoreApplication>
#include <QUdpSocket>
#include <QStringList>
#include <QHostInfo>

#include "LinkLayer.h"
#include "SparkleNode.h"

LinkLayer::LinkLayer(RSAKeyPair *hostPair, quint16 port, QObject *parent) : QObject(parent)
{
	this->port = port;
	this->hostPair = hostPair;

	socket = new QUdpSocket(this);

	connect(socket, SIGNAL(readyRead()), this, SLOT(haveDatagram()));
}

LinkLayer::~LinkLayer() {

}

void hexdump(const char *title, QByteArray data) {
	printf("Dumping %s\n", title);

	unsigned char *raw = (unsigned char *) data.data();

	for(int i = 0; i < data.size(); i++) {
		if(i % 8 == 0)
			printf("\n");

		printf("%02X ", raw[i]);
	}

	printf("\n");
}

bool LinkLayer::joinNetwork(QString node) {
	QStringList parts = node.split(':');

	if(parts.count() != 2) {
		error = "Bad address format";

		return false;
	}

	remotePort = parts[1].toInt();

	printf("Looking up for %s... ", parts[0].toAscii().data());

	fflush(stdout);

	QHostInfo::lookupHost(parts[0], this, SLOT(joinTargetLookedUp(QHostInfo)));

	return true;
}

bool LinkLayer::createNetwork() {
	isMaster = true;

	if(socket->bind(port) == false) {
		error = socket->errorString();

		return false;
	}

	qDebug() << "Network created, listening at port" << port;

	return true;
}

QString LinkLayer::errorString() {
	return error;
}

void LinkLayer::haveDatagram() {
	while(socket->hasPendingDatagrams()) {
		QByteArray data(socket->pendingDatagramSize(), 0);
		QHostAddress host;
		quint16 port;

		socket->readDatagram(data.data(), data.size(), &host, &port);

		handleDatagram(data, host, port);
	}
}

void LinkLayer::handleDatagram(QByteArray &data, QHostAddress &host, quint16 port) {
	const packet_header_t *hdr = (packet_header_t *) data.constData();

	if((size_t) data.size() < sizeof(packet_header_t) || hdr->length > data.size()) {
		qWarning() << "Malformed packet from" << host.toString() << ":" << port;

		return;
	}

	QByteArray payload = data.right(data.size() - sizeof(packet_header_t));

	switch((packet_type_t) hdr->type) {		
	case ProtocolVersionRequest: {
		protocol_version_reply_t ver;
		ver.version = ProtocolVersion;

		sendPacket(ProtocolVersionReply, host, port, QByteArray((const char *) &ver,
							sizeof(protocol_version_reply_t)), false);

		break;
	}

	case ProtocolVersionReply: {
		if(hdr->length != sizeof(protocol_version_reply_t) + sizeof(packet_header_t)) {
			qWarning() << "Bad length" << hdr->length <<
				"on incoming packet from" << host.toString() << ":" << port;

			break;
		}
		protocol_version_reply_t *ver = (protocol_version_reply_t *) payload.data();

		if(joinStep == RequestingProtocolVersion)
			joinGotVersion(ver->version);

		break;
	}

	case PublicKeyExchange: {
		SparkleNode *node = getOrConstructNode(host, port);

		node->getRSA()->setPublicKey(payload);

		sendPacket(PublicKeyReply, host, port, hostPair->getPublicKey(), false);

		break;
	}

	case PublicKeyReply: {
		SparkleNode *node = getOrConstructNode(host, port);

		node->getRSA()->setPublicKey(payload);

		node->getToKey()->generate();

		QByteArray key = node->getToKey()->getKey();

		sendPacket(SessionKeyExchange, host, port, node->getRSA()->encrypt(key), false);

		break;
	}

	case SessionKeyExchange: {
		SparkleNode *node = getOrConstructNode(host, port);

		node->getToKey()->generate();

		node->getFromKey()->setKey(hostPair->decrypt(payload));

		QByteArray toKey = node->getRSA()->encrypt(node->getToKey()->getKey());

		sendPacket(SessionKeyReply, host, port, toKey, false);

		break;
	}

	case SessionKeyReply: {
		SparkleNode *node = getOrConstructNode(host, port);

		node->getFromKey()->setKey(hostPair->decrypt(payload));

		sendPacket(SessionKeyAcknowlege, host, port, QByteArray(), false);

		node->negotiationDone = true;

		while(!node->isQueueEmpty())
			sendAsEncrypted(node, node->getFromQueue());


		break;
	}

	case SessionKeyAcknowlege: {
		SparkleNode *node = getOrConstructNode(host, port);

		node->negotiationDone = true;

		while(!node->isQueueEmpty())
			sendAsEncrypted(node, node->getFromQueue());

		break;
	}

	case EncryptedPacket: {
		SparkleNode *node = getOrConstructNode(host, port);

		if(!node->negotiationDone) {
			printf("Encrypted packet from unknown node\n");

			break;
		}

		QByteArray decData = node->getFromKey()->decrypt(payload);

		handleDatagram(decData, host, port);

		break;
	}

	/* все следующие пакеты зашифрованы */

	case NetworkInformationRequest: {
		printf("FIXME: NetworkInformationRequest not implemented\n");

		sendPacket(NetworkInformationReply, host, port, QByteArray(), true);

		break;
	}

	case NetworkInformationReply: {
		printf("FIXME: NetworkInformationReply not implemented\n");

		break;
	}


	default:
		qWarning() << "Bad type" << hdr->type <<
			"on incoming packet from" << host.toString() << ":" << port;
	}
}

void LinkLayer::joinTargetLookedUp(QHostInfo host) {
	printf("done\n");

	if(host.error() != QHostInfo::NoError) {
		qCritical() << "Join failed: lookup error: " << host.errorString();

		QCoreApplication::exit(1);

		return;
	}

	foreach(QHostAddress addr, host.addresses()) {
		if(addr.protocol() == QAbstractSocket::IPv4Protocol) {
			remoteAddress = addr;

			qDebug() << "Joining via" << remoteAddress.toString() << "port" << remotePort;

			if(socket->bind(port) == false) {
				qCritical() << "Binding failed:" << socket->errorString();

				QCoreApplication::exit(1);

				return;
			}

			isMaster = false;

			joinStep = RequestingProtocolVersion;

			sendProtocolVersionRequest(remoteAddress, remotePort);

			return;
		}
	}

	qCritical() << "Join failed: IPv4 address not found";

	QCoreApplication::exit(1);
}

void LinkLayer::sendPacket(packet_type_t type, QHostAddress host, quint16 port,
			   QByteArray data, bool encrypted) {
	packet_header_t hdr;

	hdr.length = sizeof(packet_header_t) + data.size();
	hdr.type = type;

	data.prepend(QByteArray((const char *) &hdr, sizeof(packet_header_t)));

	if(!encrypted) {
		socket->writeDatagram(data, host, port);
	} else {
		SparkleNode *node = getOrConstructNode(host, port);

		if(!node->negotiationDone) {
			node->appendQueue(data);

			publicKeyExchange(host, port);
		} else {
			sendAsEncrypted(node, data);
		}
	}
}

void LinkLayer::sendAsEncrypted(SparkleNode *node, QByteArray data) {
	data = node->getToKey()->encrypt(data);

	return sendPacket(EncryptedPacket, node->getHost(), node->getPort(), data, false);
}

SparkleNode *LinkLayer::getOrConstructNode(QHostAddress host, quint16 port) {
	foreach(SparkleNode *node, nodes)
		if(node->getHost() == host && node->getPort() == port) {
			return node;
		}

	SparkleNode *node = new SparkleNode(host, port, this);

	nodes.append(node);

	return node;
}


void LinkLayer::joinGotVersion(int version) {
	if(version != ProtocolVersion) {
		qCritical() << "Join failed: protocol version not matching:" << version <<
				"in network," << ProtocolVersion << "in client";

		QCoreApplication::exit(1);
	}

	qDebug() << "Still joining";

	joinStep = RequestingNetworkInformation;

	sendNetworkInformationRequest(remoteAddress, remotePort);
}

void LinkLayer::sendProtocolVersionRequest(QHostAddress host, quint16 port) {
	QByteArray data;

	sendPacket(ProtocolVersionRequest, host, port, data, false);
}

void LinkLayer::sendNetworkInformationRequest(QHostAddress host, quint16 port) {
	QByteArray data;

	sendPacket(NetworkInformationRequest, host, port, data, true);
}

void LinkLayer::publicKeyExchange(QHostAddress host, quint16 port) {
	sendPacket(PublicKeyExchange, host, port, hostPair->getPublicKey(), false);
}
