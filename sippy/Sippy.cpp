/*
 * Sippy - zero-configuration fully distributed self-organizing encrypting IM
 * Copyright (C) 2009 Peter Zotov
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

#include <QMessageBox>
#include "Sippy.h"
#include "ui_Roster.h"
#include "DebugConsole.h"
#include "ConfigurationStorage.h"
#include "Log.h"
#include "LinkLayer.h"

Sippy::Sippy(ConfigurationStorage* _config, DebugConsole &_console, LinkLayer &_link, MessagingApplicationLayer &_app) :
		config(_config), console(_console),
		linkLayer(_link), appLayer(_app), connectDialog(_config, this)
{
	setupUi(this);

	console.connect(actionShowConsole, SIGNAL(triggered()), SLOT(show()));
	console.show();

	connectDialog.connect(actionConnect, SIGNAL(triggered()), SLOT(show()));
	connectDialog.connect(&connectDialog, SIGNAL(accepted()), SLOT(close()));

	connect(&connectDialog, SIGNAL(accepted()), SLOT(connectToNetwork()));
	connect(actionDisconnect, SIGNAL(triggered()), SLOT(disconnectFromNetwork()));

	connect(&linkLayer, SIGNAL(joinedNetwork(SparkleNode*)), SLOT(joined()));
	connect(&linkLayer, SIGNAL(joinFailed()), SLOT(joinFailed()));
	connect(&linkLayer, SIGNAL(leavedNetwork()), SLOT(leaved()));

	connectStateChanged(Disconnected);
}

void Sippy::connectStateChanged(connect_state_t state) {
	actionConnect->setEnabled(state == Disconnected);
	actionDisconnect->setEnabled(state != Disconnected);

	actionSetNickname->setEnabled(state == Connected);
}

void Sippy::connectToNetwork() {
	Log::debug("resolving %1") << config->address();
	QHostInfo::lookupHost(config->address(), this, SLOT(lookupFinished(QHostInfo)));
	statusbar->showMessage(tr("Resolving..."));
	connectStateChanged(Connecting);
}

void Sippy::lookupFinished(QHostInfo host) {
	if(host.error() != QHostInfo::NoError) {
		Log::error("cannot lookup target host %1") << host.hostName();
		QMessageBox::critical(this, tr("Lookup failure"), tr("Cannot resolve host %1").arg(host.hostName()));
	} else {
		QList<QHostAddress> list = host.addresses();
		QHostAddress addr = list[0];
		if(list.size() > 1)
			Log::warn("there are more than one IP address for host %1, using first (%2)") << host.hostName() << addr.toString();

		if(config->createNetwork()) {
			if(linkLayer.createNetwork(addr, 10)) {
				return;
			} else {
				Log::error("cannot bind to local endpoint");
				QMessageBox::critical(this, tr("Error"), tr("Cannot create network."));
			}
		} else {
			if(linkLayer.joinNetwork(addr, 1801, config->behindNat())) {
				statusbar->showMessage(tr("Joining..."));
				return;
			} else {
				Log::error("cannot initiate join");
				QMessageBox::critical(this, tr("Error"), tr("Cannot join network."));
			}
		}
	}

	statusbar->clearMessage();
	connectStateChanged(Disconnected);
}

void Sippy::joined() {
	Log::info("joined network");
	statusbar->showMessage(tr("Connected."));
	connectStateChanged(Connected);
}

void Sippy::joinFailed() {
	Log::error("join failed");
	QMessageBox::critical(this, tr("Error"), tr("Cannot join network."));
	statusbar->clearMessage();
	connectStateChanged(Disconnected);
}

void Sippy::disconnectFromNetwork() {
	Log::info("leaving network");
	statusbar->showMessage(tr("Leaving network..."));
	linkLayer.exitNetwork();
}

void Sippy::leaved() {
	Log::info("leave finished");
	statusbar->showMessage(tr("Disconnected."), 10000);
	connectStateChanged(Disconnected);
}
