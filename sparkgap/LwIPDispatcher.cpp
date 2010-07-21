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

#include <QCoreApplication>
#include <QEvent>
#include <QEventLoop>
#include <QHash>

#include <Sparkle/Log>

#include <lwip/tcpip.h>
#include <lwip/api.h>

#include "LwIPDispatcher.h"
#include "LwIPEvent.h"

using namespace Sparkle;

enum {
	InitEventType = QEvent::User + 1,
};

class InitEvent : public QEvent {
public:
	InitEvent() : QEvent((QEvent::Type) InitEventType) { }
};

class LwIPDispatcherPrivate {
public:
	static void init_callback(void *arg);
	static void conn_callback(struct netconn *, enum netconn_evt, quint16 len);

	QEventLoop *loop;

	static LwIPDispatcher *instance;

	QHash<struct netconn *, QObject *> owners;
};

LwIPDispatcher::LwIPDispatcher(QObject *parent) : QObject(parent), d_ptr(new LwIPDispatcherPrivate) {
	Q_D(LwIPDispatcher);

	tcpip_init(&LwIPDispatcherPrivate::init_callback, this);

	d->instance = this;

	d->loop = new QEventLoop(this);

	d->loop->exec();

	delete d->loop;
}

LwIPDispatcher::~LwIPDispatcher() {
	delete d_ptr;
}

struct netconn *LwIPDispatcher::createConn(int type, QObject *target) {
	return LwIPDispatcherPrivate::instance->realCreateConn(type, target);
}

struct netconn *LwIPDispatcher::realCreateConn(int type, QObject *target) {
	Q_D(LwIPDispatcher);

	struct netconn *conn = netconn_new_with_callback((enum netconn_type) type, &LwIPDispatcherPrivate::conn_callback);

	if(conn)
		d->owners.insert(conn, target);

	return conn;
}

void LwIPDispatcher::disposeConn(struct netconn *conn) {
	return LwIPDispatcherPrivate::instance->realDisposeConn(conn);
}

void LwIPDispatcher::realDisposeConn(struct netconn *conn) {
	Q_D(LwIPDispatcher);

	d->owners.remove(conn);

	netconn_delete(conn);
}

bool LwIPDispatcher::event(QEvent *ev) {
	Q_D(LwIPDispatcher);

	switch(ev->type()) {
	case InitEventType:
		Log::info("dispatcher: LwIP initialized");

		d->loop->quit();

		return true;

	default:
		break;
	}

	return QObject::event(ev);

}

void LwIPDispatcherPrivate::init_callback(void *arg) {
	InitEvent *ev = new InitEvent();

	QObject *target = static_cast<QObject *>(arg);

	QCoreApplication::postEvent(target, ev);
}

void LwIPDispatcherPrivate::conn_callback(struct netconn *conn, enum netconn_evt event, quint16 len) {
	LwIPEvent *ev = new LwIPEvent(conn, event, len);

	instance->dispatch(ev);
}

void LwIPDispatcher::dispatch(LwIPEvent *ev) {
	Q_D(const LwIPDispatcher);

	if(d->owners.contains(ev->connection()))
		QCoreApplication::postEvent(d->owners[ev->connection()], ev);
	else
		delete ev;
}

LwIPDispatcher *LwIPDispatcherPrivate::instance = 0;

