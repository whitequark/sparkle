/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2009 Sergey Gridassov, Peter Zotov
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

#include <QtDebug>
#include <QtEndian>
#include <QHostAddress>

#include <lwip/api.h>

#include "LwIPTcpServer.h"
#include "LwIPDispatcher.h"
#include "LwIPEvent.h"

class LwIPTcpServerPrivate {
public:
	LwIPTcpServerPrivate() : conn(0), serverPort(0) {}

	struct netconn *conn;
	QHostAddress serverAddress;
	quint16 serverPort;
};

LwIPTcpServer::LwIPTcpServer(LwIPTcpServerPrivate &dd, QObject *parent) : QObject(parent), d_ptr(&dd) {

}

LwIPTcpServer::LwIPTcpServer(QObject *parent) : QObject(parent), d_ptr(new LwIPTcpServerPrivate) {

}

bool LwIPTcpServer::listen(const QHostAddress &address, quint16 port) {
	Q_D(LwIPTcpServer);

	if(d->conn == 0) {
		d->conn = LwIPDispatcher::createConn(NETCONN_TCP, this);

		if(d->conn == 0) {
			return false;
		}

		struct ip_addr addr;

		addr.addr = qToBigEndian(address.toIPv4Address());

		if(netconn_bind(d->conn, &addr, port) != ERR_OK)
			goto failure;

		if(netconn_listen(d->conn) != ERR_OK)
			goto failure;

		d->serverAddress = address;
		d->serverPort = port;

		return true;
	} else
		return false;

failure:
	LwIPDispatcher::disposeConn(d->conn);

	d->conn = 0;
	return false;

}

bool LwIPTcpServer::isListening() const {
	Q_D(const LwIPTcpServer);

	return d->conn != 0;
}

void LwIPTcpServer::close() {
	Q_D(LwIPTcpServer);

	if(d->conn != 0) {
		LwIPDispatcher::disposeConn(d->conn);

		d->conn = 0;
	}
}

LwIPTcpServer::~LwIPTcpServer() {
	close();

	delete d_ptr;
}

bool LwIPTcpServer::event(QEvent *ev) {
	if(ev->type() == (QEvent::Type) LwIPEvent::Type) {
		LwIPEvent *event = static_cast<LwIPEvent *>(ev);

		qDebug() << "LwIP Event for Tcp Server:" << event->event();

		return true;
	}

	return QObject::event(ev);
}

