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

#include "RouteManager.h"

RouteManager::RouteManager(QObject *parent) : QObject(parent)
{

}

RouteManager::~RouteManager() {

}


const Route *RouteManager::selectMaster() {
	return masters.at(qrand() % masters.count());
}


const Route *RouteManager::findByIP(QHostAddress ip) {
	foreach(Route *def, masters)
		if(def->sparkleIP == ip)
			return def;

	foreach(Route *def, slaves)
		if(def->sparkleIP == ip)
			return def;

	return NULL;
}

const Route *RouteManager::findByMAC(QByteArray mac) {
	foreach(Route *def, masters)
		if(def->sparkleMac == mac)
			return def;

	foreach(Route *def, slaves)
		if(def->sparkleMac == mac)
			return def;

	return NULL;
}

int RouteManager::getMasterCount() {
	return masters.count();
}

int RouteManager::getSlaveCount() {
	return slaves.count();
}

const Route *RouteManager::addRoute(QHostAddress addr,
					      quint16 port, QHostAddress sparkleIP,
					      QByteArray sparkleMac, bool isMaster) {

	Route *node = new Route;
	node->addr = addr;
	node->port = port;
	node->sparkleIP = sparkleIP;
	node->sparkleMac = sparkleMac;
	if(isMaster)
		masters.append(node);
	else
		slaves.append(node);

	return node;
}
