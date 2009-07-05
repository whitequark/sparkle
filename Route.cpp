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

#include "Route.h"

Route::Route(QHostAddress realIP, quint16 realPort, SparkleNode* _node, Router* parent)
			: ip(realIP), port(realPort), node(_node), QObject(parent) {
}
	
QHostAddress Route::getRealIP() const {
	return ip;
}

quint16 Route::getRealPort() const {
	return port;
}
	
const SparkleNode* Route::getNode() {
	return node;
}

