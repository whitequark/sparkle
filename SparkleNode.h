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

#include "RSAKeyPair.h"
#include "BlowfishKey.h"

class Router;

class SparkleNode : public QObject
{
	Q_OBJECT

public:
	SparkleNode(QHostAddress realIP, quint16 realPort);
	
	bool operator==(const SparkleNode& another) const;
	bool operator!=(const SparkleNode& another) const;

	QHostAddress getRealIP() const		{ return realIP; }
	quint16 getRealPort() const		{ return realPort; }

	QHostAddress getSparkleIP() const	{ return sparkleIP; }
	QByteArray getSparkleMAC() const	{ return sparkleMAC; }
	
	QString getPrettySparkleMAC() const;

	void setSparkleIP(const QHostAddress& ip);
	void setSparkleMAC(const QByteArray& mac);

	const BlowfishKey *getHisSessionKey() const	{ return &hisSessionKey; }
	const BlowfishKey *getMySessionKey() const	{ return &mySessionKey; }
	
	const RSAKeyPair *getAuthKey() const	{ return &authKey; }

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

private:
	QHostAddress realIP;
	quint16 realPort;

	QHostAddress sparkleIP;
	QByteArray sparkleMAC;
	
	bool master;

	RSAKeyPair authKey;
	bool authKeyPresent;
	BlowfishKey hisSessionKey, mySessionKey;
	bool keysNegotiated;

	QList<QByteArray> queue;
};

#endif
