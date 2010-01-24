/*
 * Sippy - zero-configuration fully distributed self-organizing encrypting IM
 * Copyright (C) 2009 Peter Zotov
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

#include <QMessageBox>
#include <QApplication>
#include "Roster.h"
#include "ui_Roster.h"
#include "RosterItem.h"
#include "ConfigurationStorage.h"
#include "Log.h"
#include "LinkLayer.h"
#include "Router.h"

Roster::Roster(ContactList &_contactList, LinkLayer &_link, MessagingApplicationLayer &_app) :
		config(ConfigurationStorage::instance()), linkLayer(_link),  router(_link.router()), appLayer(_app), contactList(_contactList), connectDialog(config, this), addContactDialog(contactList, this)
{
	QCoreApplication* app = QCoreApplication::instance();

	setupUi(this);

	actionContactInfo = new QAction(tr("Contact &info"), this);
	actionChat = new QAction(tr("Begin &chat"), this);
	actionEditContact = new QAction(tr("&Edit contact..."), this);
	actionRemoveContact = new QAction(tr("&Remove contact"), this);

	contactMenu = new QMenu(this);
	contactMenu->addAction(actionContactInfo);
	contactMenu->addAction(actionChat);
	contactMenu->addSeparator();
	contactMenu->addAction(actionEditContact);
	contactMenu->addAction(actionRemoveContact);

	connectDialog.connect(actionConnect, SIGNAL(triggered()), SLOT(show()));
	connectDialog.connect(&connectDialog, SIGNAL(accepted()), SLOT(close()));

	addContactDialog.connect(actionAddContact, SIGNAL(triggered()), SLOT(show()));
	connect(contactView, SIGNAL(currentItemChanged(QListWidgetItem*,QListWidgetItem*)), SLOT(selectItem(QListWidgetItem*,QListWidgetItem*)));
	connect(actionEditContact, SIGNAL(triggered()), SLOT(editItem()));
	connect(actionRemoveContact, SIGNAL(triggered()), SLOT(removeItem()));

	connect(&connectDialog, SIGNAL(accepted()), SLOT(connectToNetwork()));
	connect(actionDisconnect, SIGNAL(triggered()), SLOT(disconnectFromNetwork()));

	connect(&linkLayer, SIGNAL(joinedNetwork(SparkleNode*)), SLOT(joined()));
	connect(&linkLayer, SIGNAL(joinFailed()), SLOT(joinFailed()));
	connect(&linkLayer, SIGNAL(leavedNetwork()), SLOT(leaved()));

	connect(&contactList, SIGNAL(contactAdded(Contact*)), SLOT(addContact(Contact*)));
	connect(&contactList, SIGNAL(contactRemoved(Contact*)), SLOT(removeContact(Contact*)));

	appLayer.connect(statusBox, SIGNAL(statusTextChanged(QString)), SLOT(setStatusText(QString)));

	connect(actionAbout, SIGNAL(triggered()), SLOT(about()));

	app->connect(actionExit, SIGNAL(triggered()), SLOT(quit()));

	connectStateChanged(Disconnected);

	contactList.load();
}

void Roster::connectStateChanged(connect_state_t state) {
	actionConnect->setEnabled(state == Disconnected);
	actionDisconnect->setEnabled(state != Disconnected);

	bool connected = (state == Connected);
	actionContactInfo->setEnabled(connected);
	actionChat->setEnabled(connected);
}

void Roster::connectToNetwork() {
	Log::debug("im: resolving %1") << config->address();
	QHostInfo::lookupHost(config->address(), this, SLOT(lookupFinished(QHostInfo)));
	statusbar->showMessage(tr("Resolving..."));
	connectStateChanged(Connecting);
}

void Roster::lookupFinished(QHostInfo host) {
	if(host.error() != QHostInfo::NoError) {
		Log::error("im: cannot lookup target host %1") << host.hostName();
		QMessageBox::critical(this, tr("Lookup failure"), tr("Cannot resolve host %1").arg(host.hostName()));
	} else {
		QList<QHostAddress> list = host.addresses();
		QHostAddress addr = list[0];
		if(list.size() > 1)
			Log::warn("im: there are more than one IP address for host %1, using first (%2)") << host.hostName() << addr.toString();

		if(config->createNetwork()) {
			if(linkLayer.createNetwork(addr, 10)) {
				return;
			} else {
				Log::error("im: cannot bind to local endpoint");
				QMessageBox::critical(this, tr("Error"), tr("Cannot create network."));
			}
		} else {
			if(linkLayer.joinNetwork(addr, 1801, config->behindNat())) {
				statusbar->showMessage(tr("Joining..."));
				return;
			} else {
				Log::error("im: cannot initiate join");
				QMessageBox::critical(this, tr("Error"), tr("Cannot join network."));
			}
		}
	}

	statusbar->clearMessage();
	connectStateChanged(Disconnected);
}

void Roster::joined() {
	Log::info("im: joined network");
	statusbar->showMessage(tr("Connected."));
	connectStateChanged(Connected);
}

void Roster::joinFailed() {
	Log::error("im: join failed");
	QMessageBox::critical(this, tr("Error"), tr("Cannot join network."));
	statusbar->clearMessage();
	connectStateChanged(Disconnected);
}

void Roster::disconnectFromNetwork() {
	Log::info("im: leaving network");
	statusbar->showMessage(tr("Leaving network..."));
	linkLayer.exitNetwork();
}

void Roster::leaved() {
	Log::info("im: leave finished");
	statusbar->showMessage(tr("Disconnected."), 10000);
	connectStateChanged(Disconnected);
}

void Roster::addContact(Contact* contact) {
	QListWidgetItem* item = new QListWidgetItem(contactView);
	RosterItem* rosterItem = new RosterItem(appLayer, contact, item);
	connect(rosterItem, SIGNAL(menuRequested(QPoint)), SLOT(showMenu(QPoint)));
	contactViewItems[contact] = item;
	contactView->addItem(item);
	contactView->setItemWidget(item, rosterItem);
}

void Roster::removeContact(Contact *contact) {
	delete contactViewItems[contact];
	contactViewItems.remove(contact);
}

void Roster::selectItem(QListWidgetItem *current, QListWidgetItem *previous) {
	RosterItem* rcurr = static_cast<RosterItem*>(contactView->itemWidget(current));
	if(rcurr) {
		rcurr->setSelected(true);
		rcurr->setDetailed(true);
	}

	RosterItem* rprev = static_cast<RosterItem*>(contactView->itemWidget(previous));
	if(rprev) {
		rprev->setSelected(false);
		rprev->setDetailed(false);
	}
}

void Roster::editItem() {
	Contact* contact = contactViewItems.key(contactView->currentItem());
	editContactDialog.showFor(contact);
}

void Roster::removeItem() {
	Contact* contact = contactViewItems.key(contactView->currentItem());
	contactList.removeContact(contact);
}

void Roster::showMenu(QPoint point) {
	Contact* contact = contactViewItems.key(contactView->currentItem());

	contactMenu->exec(point);
}

void Roster::about() {
	QMessageBox::about(this, tr("About Sippy"), tr("Sippy is instant messaging client based on Sparkle: decentralyzed encrypting self-organizing peering network.\n (c) 2009, 2010 Sparkle Team\n  Peter Zotov <whitequark@whitequark.ru>\n  Sergey Gridassov <grindars@gmail.com>"));
}
