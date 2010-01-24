/*
 * Sippy - zero-configuration fully distributed self-organizing encrypting IM
 * Copyright (C) 2010 Peter Zotov
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

#include "ContactList.h"
#include "ConfigurationStorage.h"
#include "Contact.h"

ContactList::ContactList() :
		config(ConfigurationStorage::instance()) {
}

void ContactList::load() {
	clear();

	_contacts = config->contacts();
	for(int i = 0; i < _contacts.count(); i++) {
		emit contactAdded(_contacts[i]);
		connect(_contacts[i], SIGNAL(updated()), SLOT(save()));
	}
}

void ContactList::save() {
	config->setContacts(_contacts);
}

QList<Contact*> ContactList::contacts() {
	return _contacts;
}

bool ContactList::addContact(Contact* contact) {
	if(_contacts.contains(contact))
		return false;

	_contacts.append(contact);
	emit contactAdded(contact);
	connect(contact, SIGNAL(updated()), SLOT(save()));

	save();

	return true;
}

bool ContactList::removeContact(Contact* contact) {
	if(!_contacts.contains(contact))
		return false;

	_contacts.removeOne(contact);
	disconnect(contact, SIGNAL(updated()));
	emit contactRemoved(contact);

	save();

	return true;
}

Contact* ContactList::findByAddress(SparkleAddress address) {
	foreach(Contact* contact, _contacts) {
		if(contact->address() == address)
			return contact;
	}

	return NULL;
}

bool ContactList::hasAddress(SparkleAddress address) {
	return (findByAddress(address) != NULL);
}

void ContactList::clear() {
	for(int i = 0; i < _contacts.count(); i++) {
		disconnect(_contacts[i], SIGNAL(updated()));
		emit contactRemoved(_contacts[i]);
	}

	_contacts.clear();
}
