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

#include <QUdpSocket>
#include "UdpPacketTransport.h"

UdpPacketTransport::UdpPacketTransport(quint16 port, QObject *parent)
	: PacketTransport(parent)
{
	this->port = port;

	socket = new QUdpSocket(this);

	connect(socket, SIGNAL(readyRead()), this, SLOT(haveDatagram()));
}

UdpPacketTransport::~UdpPacketTransport() {

}

bool UdpPacketTransport::beginReceiving() {
	return socket->bind(port);
}

void UdpPacketTransport::haveDatagram() {
	while(socket->hasPendingDatagrams()) {
		QByteArray data(socket->pendingDatagramSize(), 0);
		QHostAddress host;
		quint16 port;

		socket->readDatagram(data.data(), data.size(), &host, &port);

		emit receivedPacket(data, host, port);
	}
}

void UdpPacketTransport::sendPacket(QByteArray &packet, QHostAddress &host, quint16 port) {
	socket->writeDatagram(packet, host, port);
}

quint16 UdpPacketTransport::getPort() {
	return port;
}
