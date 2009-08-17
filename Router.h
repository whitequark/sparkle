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

#ifndef __ROUTER_H__
#define __ROUTER_H__

#include <QObject>
#include <QHostAddress>
#include "LinkLayer.h"

class Router : public QObject
{
	Q_OBJECT

public:
	Router();

	void setSelfNode(SparkleNode* node);
	SparkleNode* getSelfNode() const;
	
	void updateNode(SparkleNode* node);
	void removeNode(SparkleNode* node);
	
	SparkleNode* searchNode(QHostAddress realIP, quint16 realPort) const;
	SparkleNode* searchSparkleNode(QHostAddress sparkleIP) const;
	
	SparkleNode* selectMaster() const;
	SparkleNode* selectWhiteSlave() const;

	QList<SparkleNode*> getMasters() const;
	QList<SparkleNode*> getOtherMasters() const;
	QList<SparkleNode*> getNodes() const;
	QList<SparkleNode*> getOtherNodes() const;

private:
	SparkleNode* self;
	QList<SparkleNode*> nodes;
};

#endif
