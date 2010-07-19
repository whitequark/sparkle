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

#include <Sparkle/UdpPacketTransport>
#include <Sparkle/Log>

#include <QUdpSocket>

using namespace Sparkle;

namespace Sparkle {

class UdpPacketTransportPrivate {
public:
	UdpPacketTransportPrivate(QHostAddress addr, quint16 port);
	
	QUdpSocket *socket;

	bool bound;
	quint16 port;
	QHostAddress addr;
};

}

UdpPacketTransportPrivate::UdpPacketTransportPrivate(QHostAddress addr, quint16 port) : bound(false), port(port), addr(addr) {

}


UdpPacketTransport::UdpPacketTransport(UdpPacketTransportPrivate &dd, QObject *parent) : PacketTransport(parent), d_ptr(&dd) {

}

UdpPacketTransport::UdpPacketTransport(QHostAddress addr, quint16 port, QObject *parent)
	: PacketTransport(parent), d_ptr(new UdpPacketTransportPrivate(addr, port))  {
	Q_D(UdpPacketTransport);

	d->socket = new QUdpSocket(this);

	connect(d->socket, SIGNAL(readyRead()), this, SLOT(haveDatagram()));
}

UdpPacketTransport::~UdpPacketTransport() {
	delete d_ptr;
}

bool UdpPacketTransport::beginReceiving() {
	Q_D(UdpPacketTransport);

	if(d->bound)
		return true;

	Log::debug("udp: receiving at [%1]:%2") << d->addr << d->port;
	return (d->bound = d->socket->bind(d->addr, d->port));
}

void UdpPacketTransport::endReceiving() {
	Q_D(UdpPacketTransport);
	
	if(!d->bound)
		return;

	Log::debug("udp: stopped receive");
	d->socket->close();
	d->bound = false;
}

void UdpPacketTransport::haveDatagram() {
	Q_D(UdpPacketTransport);
	
	while(d->socket->hasPendingDatagrams()) {
		QByteArray data(d->socket->pendingDatagramSize(), 0);
		QHostAddress host;
		quint16 port;

		d->socket->readDatagram(data.data(), data.size(), &host, &port);

		emit receivedPacket(data, host, port);
	}
}

void UdpPacketTransport::sendPacket(QByteArray &packet, QHostAddress host, quint16 port) {
	Q_D(UdpPacketTransport);
	
	d->socket->writeDatagram(packet, host, port);
}

quint16 UdpPacketTransport::port() {
	Q_D(const UdpPacketTransport);
	
	return d->port;
}
