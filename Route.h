/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2009 Peter Zotov
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

#ifndef __ROUTE_H__
#define __ROUTE_H__

#include <QObject>

class Route : public QObject {
	Q_OBJECT

public:
	Route(QHostAddress realIP, quint16 realPort, SparkleNode* node, Router* parent);
	
	QHostAddress getRealIP() const;
	quint16 getRealPort() const;
	
	const SparkleNode* getNode();
	
private:
	QHostAddress	ip;
	quint16		port;
	SparkleNode*	node;
};

#endif

