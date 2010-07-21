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

#ifndef __LWIPEVENT__H__
#define __LWIPEVENT__H__

#include <QEvent>

#include <lwip/api.h>

class LwIPEvent: public QEvent {
public:
	LwIPEvent(struct netconn *connection, enum netconn_evt event, quint16 length);

	enum {
		Type = QEvent::User
	};

public:
	struct netconn *connection() const;
	enum netconn_evt event() const;
	quint16 length();

private:
	struct netconn *m_connection;
	enum netconn_evt m_event;
	quint16 m_length;
};

#endif

