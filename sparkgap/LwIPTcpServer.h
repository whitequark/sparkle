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

#ifndef __LWIP_TCP_SERVER__H__
#define __LWIP_TCP_SERVER__H__

#include <QObject>

class LwIPTcpServerPrivate;
class QHostAddress;

class LwIPTcpServer: public QObject {
	Q_OBJECT

	Q_DECLARE_PRIVATE(LwIPTcpServer);

protected:
	LwIPTcpServer(LwIPTcpServerPrivate &dd, QObject *parent);

public:
	LwIPTcpServer(QObject *parent = 0);
	virtual ~LwIPTcpServer();

	bool listen(const QHostAddress &address, quint16 port);
	bool isListening() const;
	void close();

protected:
	virtual bool event(QEvent *ev);

protected:
	LwIPTcpServerPrivate * const d_ptr;
};

#endif

