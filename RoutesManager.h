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

#ifndef __ROUTES_MANAGER_H__
#define __ROUTES_MANAGER_H__

#include <QObject>
#include <QHostAddress>
#include "LinkLayer.h"

class RoutesManager : public QObject
{
	Q_OBJECT

public:
	RoutesManager(QObject *parent = 0);
	virtual ~RoutesManager();

	const LinkLayer::node_def_t *addRoute(QHostAddress addr,
					      quint16 port, QHostAddress sparkleIP,
					      QByteArray sparkleMac, bool isMaster);

	const LinkLayer::node_def_t *findByIP(QHostAddress ip);
	const LinkLayer::node_def_t *findByMAC(QByteArray mac);
	const LinkLayer::node_def_t *selectMaster();

	int getSlaveCount();
	int getMasterCount();

	const QList<LinkLayer::node_def_t *> &getMasters() { return masters; }
	const QList<LinkLayer::node_def_t *> &getSlaves() { return slaves; }

private:
	QList<LinkLayer::node_def_t *> masters, slaves;

};

#endif
