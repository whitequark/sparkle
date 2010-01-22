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

#include <QApplication>
#include <QFile>

#include <Log.h>
#include <Router.h>
#include <UdpPacketTransport.h>

#include "DebugConsole.h"
#include "ConfigurationStorage.h"
#include "SippyApplicationLayer.h"

#include "Sippy.h"

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

	DebugConsole *console = new DebugConsole();

	Log::debug("port: %1") << config->port();;

	Router router;
	UdpPacketTransport transport(QHostAddress::Any, config->port());

	SippyApplicationLayer *appLayer = new SippyApplicationLayer(router);

	LinkLayer linkLayer(router, transport, hostPair, appLayer);

	appLayer->attachLinkLayer(&linkLayer);

	Sippy* sippy = new Sippy(config, console, &linkLayer, appLayer);

	sippy->show();

	return app.exec();
}
