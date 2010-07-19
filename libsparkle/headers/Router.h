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

class RouterPrivate;

class Router : public QObject
{
	Q_OBJECT
	Q_DECLARE_PRIVATE(Router)

protected:
	Router(RouterPrivate &dd, QObject *parent);

public:
	Router(QObject *parent = 0);
	virtual ~Router();
	
	void setSelfNode(SparkleNode* node);
	SparkleNode* getSelfNode() const;

	void updateNode(SparkleNode* node);
	void removeNode(SparkleNode* node);

	SparkleNode* findNode(QHostAddress realIP, quint16 realPort) const;
	SparkleNode* findSparkleNode(SparkleAddress sparkleMAC) const;

	bool hasRouteTo(SparkleAddress sparkleMAC) const;

	SparkleNode* selectMaster() const;
	SparkleNode* selectJoinMaster(QHostAddress excludeIP) const;
	SparkleNode* selectWhiteSlave() const;

	QList<SparkleNode*> masters() const;
	QList<SparkleNode*> otherMasters() const;
	QList<SparkleNode*> slaves() const;
	QList<SparkleNode*> nodes() const;
	QList<SparkleNode*> otherNodes() const;

	void clear();

	void notifyNodeUpdated(SparkleNode* node);

signals:
	void nodeAdded(SparkleNode* node);
	void nodeRemoved(SparkleNode* node);
	void nodeUpdated(SparkleNode* node);

	void peerAdded(SparkleAddress addr);
	void peerRemoved(SparkleAddress addr);

protected:
	RouterPrivate * const d_ptr;
};

#endif
