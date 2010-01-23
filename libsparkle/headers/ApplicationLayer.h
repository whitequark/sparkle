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

#ifndef __APPLICATION_LAYER_H__
#define __APPLICATION_LAYER_H__

class LinkLayer;
class SparkleNode;
class QByteArray;

class ApplicationLayer {
public:
	enum Encapsulation {
		Ethernet	= 1,
		Messaging	= 2,
	};

	virtual void handleDataPacket(QByteArray &packet, SparkleNode *node) = 0;
};


#endif
