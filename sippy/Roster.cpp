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
#include <QInputDialog>
#include <QApplication>
#include "Roster.h"
#include "ui_Roster.h"
#include "ContactWidget.h"
#include "ConfigurationStorage.h"
#include "Log.h"
#include "LinkLayer.h"
#include "Router.h"
#include "CallWindow.h"

Roster::Roster(ContactList &_contactList, LinkLayer &_link, MessagingApplicationLayer &_app) :
		config(ConfigurationStorage::instance()), linkLayer(_link),  router(_link.router()), appLayer(_app), contactList(_contactList), connectDialog(this), addContactDialog(contactList, this), preferencesDialog(appLayer, this)
{
	QCoreApplication* app = QCoreApplication::instance();

	setupUi(this);

	actionContactInfo = new QAction(tr("Contact &info..."), this);
	actionChat = new QAction(tr("Begin &chat..."), this);
	actionCall = new QAction(tr("C&all..."), this);
	actionRequestAuthorization = new QAction(tr("&Request authorization"), this);
	actionEditContact = new QAction(tr("&Edit contact..."), this);
	actionRemoveContact = new QAction(tr("Re&move contact"), this);

	contactMenu = new QMenu(this);
	contactMenu->addAction(actionContactInfo);
	contactMenu->addAction(actionChat);
	contactMenu->addAction(actionCall);
	contactMenu->addSeparator();
	contactMenu->addAction(actionRequestAuthorization);
	contactMenu->addAction(actionEditContact);
	contactMenu->addAction(actionRemoveContact);

	connectDialog.connect(actionConnect, SIGNAL(triggered()), SLOT(show()));
	connectDialog.connect(&connectDialog, SIGNAL(accepted()), SLOT(close()));

	addContactDialog.connect(actionAddContact, SIGNAL(triggered()), SLOT(show()));
	connect(contactView, SIGNAL(currentItemChanged(QListWidgetItem*,QListWidgetItem*)), SLOT(selectItem(QListWidgetItem*,QListWidgetItem*)));
	connect(actionChat, SIGNAL(triggered()), SLOT(beginChat()));
	connect(actionCall, SIGNAL(triggered()), SLOT(beginCall()));
	connect(actionRequestAuthorization, SIGNAL(triggered()), SLOT(requestAuthorization()));
	connect(actionEditContact, SIGNAL(triggered()), SLOT(editItem()));
	connect(actionRemoveContact, SIGNAL(triggered()), SLOT(removeItem()));

	connect(&connectDialog, SIGNAL(accepted()), SLOT(connectToNetwork()));
	connect(actionDisconnect, SIGNAL(triggered()), SLOT(disconnectFromNetwork()));

	preferencesDialog.connect(actionPreferences, SIGNAL(triggered()), SLOT(show()));

	connect(&linkLayer, SIGNAL(joinedNetwork(SparkleNode*)), SLOT(joined()));
	connect(&linkLayer, SIGNAL(joinFailed()), SLOT(joinFailed()));
	connect(&linkLayer, SIGNAL(leavedNetwork()), SLOT(leaved()));

	connect(&contactList, SIGNAL(contactAdded(Contact*)), SLOT(addContact(Contact*)));
	connect(&contactList, SIGNAL(contactRemoved(Contact*)), SLOT(removeContact(Contact*)));

	appLayer.connect(statusBox, SIGNAL(statusTextChanged(QString)), SLOT(setStatusText(QString)));
	appLayer.connect(statusBox, SIGNAL(statusChanged(Messaging::Status)), SLOT(setStatus(Messaging::Status)));

	statusBox->connect(&appLayer, SIGNAL(statusTextChanged(QString)), SLOT(setStatusText(QString)));
	statusBox->connect(&appLayer, SIGNAL(statusChanged(Messaging::Status)), SLOT(setStatus(Messaging::Status)));

	config->connect(&appLayer, SIGNAL(statusTextChanged(QString)), SLOT(setStatusText(QString)));
	config->connect(&appLayer, SIGNAL(statusChanged(Messaging::Status)), SLOT(setStatus(Messaging::Status)));
	config->connect(&appLayer, SIGNAL(nickChanged(QString)), SLOT(setNick(QString)));

	connect(&appLayer, SIGNAL(authorizationAvailable(SparkleAddress)), SLOT(offerAuthorization()));
	connect(&appLayer, SIGNAL(messageAvailable(SparkleAddress)), SLOT(handleMessage(SparkleAddress)));
	connect(&appLayer, SIGNAL(callRequestAvailable(SparkleAddress)), SLOT(offerCall(SparkleAddress)));

	connect(actionAbout, SIGNAL(triggered()), SLOT(about()));

	app->connect(actionExit, SIGNAL(triggered()), SLOT(quit()));

	connectStateChanged(Disconnected);

	contactList.load();
	appLayer.setNick(config->nick());
	appLayer.setStatus(config->status());
	appLayer.setStatusText(config->statusText());
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

void Roster::createRosterItem(Contact* contact, bool detailed) {
	QListWidgetItem* item = contactViewItems[contact];
	ContactWidget* widget = new ContactWidget(appLayer, contact, detailed);
	connect(widget, SIGNAL(menuRequested(QPoint)), SLOT(showMenu(QPoint)));
	connect(widget, SIGNAL(invoked()), SLOT(beginChat()));
	contactView->addItem(item);
	contactView->setItemWidget(item, widget);
	item->setSizeHint(widget->sizeHint());
}

void Roster::addContact(Contact* contact) {
	QListWidgetItem* item = new QListWidgetItem(contactView);
	contactViewItems[contact] = item;
	createRosterItem(contact, false);
}

void Roster::removeContact(Contact *contact) {
	delete contactViewItems[contact];
	contactViewItems.remove(contact);
}

void Roster::selectItem(QListWidgetItem *current, QListWidgetItem *previous) {
	ContactWidget* rcurrent = static_cast<ContactWidget*>(contactView->itemWidget(current));
	if(rcurrent)
		contactView->removeItemWidget(current);
	if(current)
		createRosterItem(contactViewItems.key(current), true);

	ContactWidget* rprevious = static_cast<ContactWidget*>(contactView->itemWidget(previous));
	if(rprevious)
		contactView->removeItemWidget(previous);
	if(previous)
		createRosterItem(contactViewItems.key(previous), false);

	contactView->update();
}

void Roster::editItem() {
	editContactDialog.showFor(selectedContact());
}

void Roster::removeItem() {
	contactList.removeContact(selectedContact());
}

void Roster::requestAuthorization() {
	bool ok;
	QString reason = QInputDialog::getText(this, tr("Authorization request"), tr("Enter authorization reason (optionally):"), QLineEdit::Normal, "", &ok);
	if(ok) {
		Messaging::Authorization* req = new Messaging::Authorization(appLayer.nick(), reason, selectedContact()->address());
		appLayer.sendControlPacket(req);
	}
}

void Roster::offerAuthorization() {
	Messaging::Authorization* req = appLayer.getControlPacket<Messaging::Authorization>();
	Q_ASSERT(req != NULL);

	QString displayedNick, reason;
	if(req->nick() != "")
		displayedNick = QString(" (%1)").arg(req->nick());
	if(req->reason() != "")
		reason = tr("\nReason: %1").arg(req->reason());

	if(QMessageBox::question(this, tr("Authorization request"), tr("Peer %1%2 asks you for an authorization.%3\nAdd him/her to your contact list?").arg(req->peer().pretty(), displayedNick, reason), QMessageBox::Yes, QMessageBox::No) == QMessageBox::Yes) {
		Contact* contact = new Contact(req->peer());
		contact->setDisplayName(req->nick());
		contactList.addContact(contact);
	}
}

void Roster::showMenu(QPoint point) {
	Messaging::PeerState status = appLayer.peerState(selectedContact()->address());
	actionRequestAuthorization->setEnabled(status == Messaging::Unauthorized);
	actionCall->setEnabled(status == Messaging::Present || status == Messaging::NotPresent);
	contactMenu->popup(point);
}

ChatWindow* Roster::chatFor(SparkleAddress peer) {
	if(!chatWindows.contains(peer))
		chatWindows[peer] = new ChatWindow(appLayer, peer);

	return chatWindows[peer];
}

void Roster::beginChat() {
	chatFor(selectedContact()->address())->show();
}

void Roster::beginCall() {
	CallWindow* call = new CallWindow(appLayer, selectedContact());
	call->call();
	call->show();
}

void Roster::offerCall(SparkleAddress peer) {
	Contact* contact = contactList.findByAddress(peer);
	if(contact != NULL) {
		if(QMessageBox::question(this, tr("Incoming call"), tr("Contact %1 calls you. Reply?").arg(contact->fallbackName()), QMessageBox::Yes, QMessageBox::No) == QMessageBox::Yes) {
			CallWindow* call = new CallWindow(appLayer, contact);
			call->accept();
			call->show();
			return;
		}
	}

	Messaging::CallOperate* op = new Messaging::CallOperate(Messaging::RejectCall, peer);
	appLayer.sendControlPacket(op);
}

Contact* Roster::selectedContact() {
	return contactViewItems.key(contactView->currentItem());
}

void Roster::handleMessage(SparkleAddress peer) {
	ChatWindow* window = chatFor(peer);
	window->show();
	window->activateWindow();
}

void Roster::about() {
	QMessageBox::about(this, tr("About Sippy"), tr("Sippy is instant messaging client based on Sparkle: decentralyzed encrypting self-organizing peering network.\n (c) 2009, 2010 Sparkle Team\n  Peter Zotov <whitequark@whitequark.ru>\n  Sergey Gridassov <grindars@gmail.com>"));
}
