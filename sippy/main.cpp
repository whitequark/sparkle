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

#include <QApplication>
#include <QFile>

#include <Sparkle/Log>
#include <Sparkle/Router>
#include <Sparkle/UdpPacketTransport>
#include <Sparkle/RSAKeyPair>
#include <Sparkle/LinkLayer>

#include "ConfigurationStorage.h"
#include "MessagingApplicationLayer.h"
#include "Roster.h"

using namespace Sparkle;

int main(int argc, char *argv[]) {
	QApplication app(argc, argv);
	ConfigurationStorage *config = ConfigurationStorage::instance();

	RSAKeyPair hostPair;

	QString keyName = config->getKeyName();

	if(!QFile::exists(keyName)) {
		if(!hostPair.generate(1024))
			Log::fatal("cannot generate new RSA keypair");

		if(!hostPair.writeToFile(keyName))
			Log::fatal("cannot write new RSA keypair");
	} else {
		if(!hostPair.readFromFile(keyName))
			Log::fatal("cannot read RSA keypair");
	}

	Router router;
	UdpPacketTransport transport(QHostAddress::Any, config->port());
	LinkLayer linkLayer(router, transport, hostPair);

	linkLayer.connect(&app, SIGNAL(aboutToQuit()), SLOT(exitNetwork()));

	ContactList contactList;
	MessagingApplicationLayer appLayer(contactList, linkLayer);
	Roster roster(contactList, linkLayer, appLayer);

	contactList.load();
	roster.show();

	return app.exec();
}
