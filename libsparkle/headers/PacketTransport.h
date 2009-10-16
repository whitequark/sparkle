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

#ifndef __PACKET_TRANSPORT_H__
#define __PACKET_TRANSPORT_H__

#include <QHostAddress>
#include <QObject>

class PacketTransport : public QObject {
	Q_OBJECT
public:
	PacketTransport(QObject *parent = 0) : QObject(parent) { }

	virtual ~PacketTransport() { }

	virtual bool beginReceiving() = 0;
	virtual quint16 getPort() = 0;

public slots:
	virtual void sendPacket(QByteArray &packet, QHostAddress host, quint16 port) = 0;

signals:
	virtual void receivedPacket(QByteArray &packet, QHostAddress host, quint16 port) = 0;
};


#endif
