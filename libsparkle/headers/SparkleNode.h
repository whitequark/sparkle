/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2009 Sergey Gridassov, Peter Zotov
 *
 * Ths program is free software: you can redistribute it and/or modify
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


#ifndef __SPARKLE_NODE__H__
#define __SPARKLE_NODE__H__

#include <QObject>
#include <QHostAddress>
#include <QTimer>

#include "RSAKeyPair.h"
#include "BlowfishKey.h"
#include "Router.h"

class SparkleNode : public QObject
{
	Q_OBJECT

public:
	SparkleNode(Router& router, QHostAddress realIP, quint16 realPort);

	bool operator==(const SparkleNode& another) const;
	bool operator!=(const SparkleNode& another) const;

	QHostAddress realIP() const		{ return _realIP; }
	quint16 realPort() const		{ return _realPort; }

	QByteArray sparkleMAC() const	{ return _sparkleMAC; }
	QString prettySparkleMAC() const;

	bool isBehindNAT() const		{ return behindNAT; }
	void setBehindNAT(bool behindNAT);

	void setSparkleIP(const QHostAddress& ip);
	void setSparkleMAC(const QByteArray& mac);

	void setRealIP(const QHostAddress& ip);
	void setRealPort(quint16 port);

	const BlowfishKey *hisSessionKey() const	{ return &_hisSessionKey; }
	const BlowfishKey *mySessionKey() const		{ return &_mySessionKey; }

	const RSAKeyPair *authKey() const	{ return &_authKey; }

	bool setAuthKey(const RSAKeyPair &keyPair);
	bool setAuthKey(const QByteArray &publicKey);

	void configureByKey();

	void setHisSessionKey(const QByteArray &keyBytes);
	bool areKeysNegotiated();

	void setMaster(bool isMaster);
	bool isMaster();

	bool isQueueEmpty();
	void pushQueue(QByteArray data);
	QByteArray popQueue();
	void flushQueue();

	static QString makePrettyMAC(QByteArray mac);

public slots:
	void negotiationStart();
	void negotiationFinished();

signals:
	void negotiationTimedOut(SparkleNode*);

private slots:
	void negotiationTimeout();

private:
	Router& _router;

	QHostAddress _realIP;
	quint16 _realPort;

	QByteArray _sparkleMAC;

	bool master, behindNAT;

	RSAKeyPair _authKey;
	bool authKeyPresent;
	BlowfishKey _hisSessionKey, _mySessionKey;
	bool keysNegotiated;

	QList<QByteArray> queue;

	QTimer negotiationTimer;
};

#endif
