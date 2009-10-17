/*
 * Sippy - zero-configuration fully distributed self-organizing encrypting IM
 * Copyright (C) 2009 Sergey Gridassov
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

#include <QApplication>

#include <LinkLayer.h>
#include <Log.h>

#include "ExtendedLogin.h"

ExtendedLogin::ExtendedLogin(LinkLayer *link, QObject *parent) : QObject(parent) {
	this->link = link;
	isClosed = false;

	qApp->setQuitOnLastWindowClosed(false);

	connect(qApp, SIGNAL(lastWindowClosed()), SLOT(sippyClosed()));
	connect(link, SIGNAL(readyForShutdown()), SLOT(linkShutDown()));
	connect(link, SIGNAL(joinFailed()), SLOT(linkJoinFailed()));
	connect(link, SIGNAL(joined(SparkleNode *)), SLOT(linkJoined()));

}

ExtendedLogin::~ExtendedLogin() {

}

void ExtendedLogin::sippyClosed() {
	isClosed = true;

	link->exitNetwork();
}

void ExtendedLogin::signaled() {
	sippyClosed();
}

void ExtendedLogin::linkShutDown() {
	qApp->quit();
}


void ExtendedLogin::login(bool create, QString host, bool behindNat) {
	this->createNetwork = create;
	this->behindNat = behindNat;
	this->enteredHost = host;

	QHostAddress addr;
	if(!addr.setAddress(host)) {

		QHostInfo::lookupHost(host, this, SLOT(hostnameResolved(QHostInfo)));

	} else
		doRealLogin(addr);
}

void ExtendedLogin::doRealLogin(QHostAddress address) {
	if(createNetwork) {
		Log::debug("Creating network with endpoint %1") << address;

	} else {
		Log::debug("Connecting to network %1") << address;

		link->joinNetwork(address, 1851, behindNat);

	}
}


void ExtendedLogin::hostnameResolved(QHostInfo info) {
	if(info.error() != QHostInfo::NoError) {
		Log::warn("cannot lookup address");

		emit loginFailed(tr("Lookup of %1 failed").arg(enteredHost));

		return;
	}

	QList<QHostAddress> list = info.addresses();

	doRealLogin(list[0]);
}

void ExtendedLogin::linkJoinFailed() {
	emit loginFailed(tr("Join failed"));
}

void ExtendedLogin::linkJoined() {
	emit loggedIn();
}

