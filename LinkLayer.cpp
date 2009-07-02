/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2009  Serge Gridassov
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

LinkLayer::LinkLayer(quint16 port, QObject *parent) : QObject(parent)
{
    this->port = port;

    socket = new QUdpSocket(this);

    connect(socket, SIGNAL(readyRead()), this, SLOT(haveDatagram()));

}

LinkLayer::~LinkLayer() {

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

	if(hdr->magic != PacketMagic) {
		qWarning() << "Bad magic" << hdr->magic <<
				"on incoming packet from" << host.toString() << ":" << port;

		return;
	}

	QByteArray payload = data.right(data.size() - sizeof(packet_header_t));

	switch((packet_type_t) hdr->type) {
	case ProtocolVersionRequest: {
		protocol_version_reply_t ver;
		ver.version = ProtocolVersion;

		sendPacket(ProtocolVersionReply, host, port, QByteArray((const char *) &ver,
							sizeof(protocol_version_reply_t)));

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

void LinkLayer::sendProtocolVersionRequest(QHostAddress host, quint16 port) {
	QByteArray data;

	sendPacket(ProtocolVersionRequest, host, port, data);
}

void LinkLayer::sendPacket(packet_type_t type, QHostAddress host, quint16 port, QByteArray data) {
	packet_header_t hdr;

	hdr.magic = PacketMagic;
	hdr.length = sizeof(packet_header_t) + data.size();
	hdr.type = type;

	data.prepend(QByteArray((const char *) &hdr, sizeof(packet_header_t)));

	socket->writeDatagram(data, host, port);
}

void LinkLayer::joinGotVersion(int version) {
	if(version != ProtocolVersion) {
		qCritical() << "Join failed: protocol version not matching:" << version <<
				"in network," << ProtocolVersion << "in client";

		QCoreApplication::exit(1);
	}

	qDebug() << "Still joining";
}
