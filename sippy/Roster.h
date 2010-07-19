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

#ifndef ROSTER_H
#define ROSTER_H

#include <QMainWindow>
#include <QHostInfo>
#include <QHash>
#include <Sparkle/SparkleNode>

#include "ui_Roster.h"
#include "ConnectDialog.h"
#include "AddContactDialog.h"
#include "EditContactDialog.h"
#include "PreferencesDialog.h"
#include "Contact.h"
#include "ContactList.h"
#include "ChatWindow.h"

namespace Sparkle {
	class LinkLayer;
	class Router;
}

class MessagingApplicationLayer;
class ConfigurationStorage;
class ContactWidget;

class Roster : public QMainWindow, private Ui_Roster {
	Q_OBJECT

public:
	Roster(ContactList& contactList, Sparkle::LinkLayer &linkLayer, MessagingApplicationLayer &appLayer);

public slots:
	void connectToNetwork();
	void disconnectFromNetwork();

private slots:
	void lookupFinished(QHostInfo host);
	void joined();
	void joinFailed();
	void leaved();

	void selectItem(QListWidgetItem *current, QListWidgetItem *previous);
	void editItem();
	void removeItem();
	void requestAuthorization();
	void offerAuthorization();
	void beginChat();
	void showMenu(QPoint point);

	void addContact(Contact* contact);
	void removeContact(Contact* contact);

	void handleMessage(Sparkle::SparkleAddress peer);

	void about();

private:
	enum connect_state_t { Connected, Disconnected, Connecting };

	Roster();

	void connectStateChanged(connect_state_t state);
	void createRosterItem(Contact* contact, bool detailed = false);

	ChatWindow* chatFor(Sparkle::SparkleAddress peer);

	ConfigurationStorage* config;
	Sparkle::LinkLayer &linkLayer;
	Sparkle::Router& router;
	MessagingApplicationLayer &appLayer;

	ContactList	&contactList;
	QHash<Contact*, QListWidgetItem*> contactViewItems;

	QHash<Sparkle::SparkleAddress, ChatWindow*> chatWindows;

	/* UI elements */

	ConnectDialog connectDialog;
	AddContactDialog addContactDialog;
	EditContactDialog editContactDialog;
	PreferencesDialog preferencesDialog;

	QMenu* contactMenu;
	QAction* actionChat;
	QAction* actionContactInfo;
	QAction* actionRequestAuthorization;
	QAction* actionEditContact;
	QAction* actionRemoveContact;
};

#endif // ROSTER_H
