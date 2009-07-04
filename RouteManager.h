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

#ifndef __ROUTE_MANAGER_H__
#define __ROUTE_MANAGER_H__

#include <QObject>
#include <QHostAddress>
#include "LinkLayer.h"

class Route {
public:
	QHostAddress	addr;
	quint16		port;
	QHostAddress	sparkleIP;
	QByteArray	sparkleMac;
};

class RouteManager : public QObject
{
	Q_OBJECT

public:
	RouteManager(QObject *parent = 0);
	virtual ~RouteManager();

	const Route *addRoute(QHostAddress addr,
					      quint16 port, QHostAddress sparkleIP,
					      QByteArray sparkleMac, bool isMaster);

	const Route *findByIP(QHostAddress ip);
	const Route *findByMAC(QByteArray mac);
	const Route *selectMaster();

	int getSlaveCount();
	int getMasterCount();

	const QList<Route *> &getMasters() { return masters; }
	const QList<Route *> &getSlaves() { return slaves; }

private:
	QList<Route *> masters, slaves;

};

#endif
