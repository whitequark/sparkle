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

#include "Contact.h"

using namespace Sparkle;

Contact::Contact(QString textAddress) {
	_address = SparkleAddress(QByteArray::fromHex(textAddress.replace(':', "").toLocal8Bit()));
}

Contact::Contact(SparkleAddress address) : _address(address) {
}

SparkleAddress Contact::address() const {
	return _address;
}

QString Contact::textAddress() const {
	return _address.pretty();
}

QString Contact::displayName() const {
	return _displayName;
}

Messaging::Status Contact::status() const {
	return _status;
}

QString Contact::statusText() const {
	return _statusText;
}

void Contact::setDisplayName(QString displayName) {
	_displayName = displayName;
	emit updated();
}

void Contact::setStatus(Messaging::Status status) {
	_status = status;
	emit updated();
}

void Contact::setStatusText(QString statusText) {
	_statusText = statusText;
	emit updated();
}
