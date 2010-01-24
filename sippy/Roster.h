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
#include "ui_Roster.h"
#include "ConnectDialog.h"
#include "AddContactDialog.h"
#include "EditContactDialog.h"
#include "SparkleNode.h"
#include "Contact.h"
#include "ContactList.h"

class LinkLayer;
class Router;
class MessagingApplicationLayer;
class ConfigurationStorage;
class RosterItem;

class Roster : public QMainWindow, private Ui_Roster {
	Q_OBJECT

public:
	Roster(ContactList& contactList, LinkLayer &linkLayer, MessagingApplicationLayer &appLayer);

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
	void showMenu(QPoint point);

	void addContact(Contact* contact);
	void removeContact(Contact* contact);

	void about();

private:
	enum connect_state_t { Connected, Disconnected, Connecting };

	Roster();

	void connectStateChanged(connect_state_t state);

	ConfigurationStorage* config;
	LinkLayer &linkLayer;
	Router& router;
	MessagingApplicationLayer &appLayer;

	ContactList	&contactList;
	QHash<Contact*, QListWidgetItem*> contactViewItems;

	/* UI elements */

	ConnectDialog connectDialog;
	AddContactDialog addContactDialog;
	EditContactDialog editContactDialog;

	QMenu* contactMenu;
	QAction* actionChat;
	QAction* actionContactInfo;
	QAction* actionEditContact;
	QAction* actionRemoveContact;
};

#endif // ROSTER_H
