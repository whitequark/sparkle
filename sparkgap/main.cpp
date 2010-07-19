/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2009 Sergey Gridassov, Peter Zotov
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

#include <signal.h>

#include <QtDebug>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QSocketNotifier>

#include <Sparkle/RSAKeyPair>
#include <Sparkle/LinkLayer>
#include <Sparkle/UdpPacketTransport>
#include <Sparkle/Log>
#include <Sparkle/Router>

#include "ArgumentParser.h"

#include "EthernetApplicationLayer.h"

#ifdef Q_OS_LINUX
#include "LinuxTAP.h"
#endif

#ifdef Q_OS_UNIX
#include "SignalHandler.h"
#endif

using namespace Sparkle;

QHostAddress checkoutAddress(QString strAddr) {
	QHostAddress ipAddr;
	if(!ipAddr.setAddress(strAddr)) {
		QHostInfo hostInfo = QHostInfo::fromName(strAddr);
		if(hostInfo.error() != QHostInfo::NoError) {
			Log::warn("cannot lookup address for host %1") << strAddr;
		} else {
			QList<QHostAddress> list = hostInfo.addresses();

			for(int i = 0; i < list.count(); i++)
				if(list[i].protocol() != QAbstractSocket::IPv4Protocol)
					list.removeAt(i); // IPv4 externals only now, sorry folks

			if(list.size() > 1)
				Log::warn("there are more than one IP address for host %1, using first (%2)")
						<< strAddr << list[0].toString();

			return list[0];
		}
	}
	return ipAddr;
}

int main(int argc, char *argv[]) {
#ifdef Q_OS_UNIX
	bool daemonize = false;

	for(int i = 1; i < argc; i++)
		if(!strcmp(argv[i], "-D") || !strcmp(argv[i], "--daemonize"))
			daemonize = true;

	if(daemonize) {
		if(fork() > 0)
			exit(0);
	}
#endif

	QCoreApplication app(argc, argv);
	app.setApplicationName("sparkle");

	QString profile = "default", configDir;
	bool createNetwork = false, noTap = false, forceBehindNAT = false;
	int networkDivisor = 10;
	QHostAddress localAddress = QHostAddress::Any, remoteAddress, bindAddress = QHostAddress::Any;
	quint16 localPort = 1801, remotePort = 1801;

	int keyLength = 1024;
	bool generateNewKeypair = false;

	qsrand(QDateTime::currentDateTime().toTime_t());

	{
		QString createStr, joinStr, endpointStr, bindStr, keyLenStr, getPubkeyStr,
			noTapStr, behindNatStr, daemonizeStr;

		ArgumentParser parser(app.arguments());

		parser.registerOption(QChar::Null, "profile", ArgumentParser::RequiredArgument, &profile, NULL,
			NULL, "use specified profile", "PROFILE");

		parser.registerOption('c', "create", ArgumentParser::OptionalArgument, &createStr, NULL,
			NULL, "create new network with divisor DIV (10 by default)", "DIV");

		parser.registerOption('j', "join", ArgumentParser::RequiredArgument, &joinStr, NULL,
			NULL, "\n\t\tjoin existing network, PORT defaults to 1801", "HOST[:PORT]");

		parser.registerOption('e', "endpoint", ArgumentParser::RequiredArgument, &endpointStr, NULL,
			NULL, "\n\t\tuse HOST:PORT as local endpoint, defaults to *:1801", "HOST[:PORT]");

		parser.registerOption('b', "bind-to", ArgumentParser::RequiredArgument, &bindStr, NULL,
			NULL, "\n\t\tbind to local interface with address IP (binds to all by default)", "IP");

		parser.registerOption('N', "force-nat", ArgumentParser::NoArgument, &behindNatStr, NULL,
			NULL, "skips any NAT checks with positive result", NULL);

#ifdef Q_OS_UNIX
		parser.registerOption('D', "daemonize", ArgumentParser::NoArgument, &daemonizeStr, NULL,
			NULL, "daemonize", NULL);
#endif

		parser.registerOption(QChar::Null, "generate-key", ArgumentParser::RequiredArgument,
			&keyLenStr, NULL, NULL, "generate new RSA key pair with specified length", "BITS");

		parser.registerOption(QChar::Null, "get-pubkey", ArgumentParser::NoArgument,
			&getPubkeyStr, NULL, NULL, "\tprint my public key", NULL);

		parser.registerOption(QChar::Null, "no-tap", ArgumentParser::NoArgument,
			&noTapStr, NULL, NULL, "\tdo not create TAP interface (`headless' mode)", NULL);

		if(!parser.parse()) { // help was displayed
			return 0;
		}

		configDir = QDir::homePath() + "/." + app.applicationName() + "/" + profile;
		QDir().mkdir(QDir::homePath() + "/." + app.applicationName());
		QDir().mkdir(configDir);

		if(!getPubkeyStr.isNull()) {
			RSAKeyPair keyPair;

			if(!keyPair.readFromFile(configDir + "/rsa_key")) {
				Log::fatal("cannot read RSA keypair");
			} else {
				printf("%s\n", QString(keyPair.publicKey().toBase64()).toLocal8Bit().constData());
				return 0;
			}
		}

		if(!createStr.isNull() && !joinStr.isNull())
			Log::fatal("options --create and --join cannot be specified simultaneously");

		if(createStr.isNull() && joinStr.isNull())
			Log::fatal("specify at least --create or --join option");

		if(!createStr.isNull()) {
			createNetwork = true;
			if(createStr != "set")
				networkDivisor = createStr.toInt();
			if(networkDivisor < 1 || networkDivisor > 50) {
				Log::fatal("impossible setting of network divisor");
			}
		}

		if(!joinStr.isNull()) {
			QStringList parts = joinStr.split(":");

			remoteAddress = checkoutAddress(parts[0]);
			if(remoteAddress.isNull()) {
				Log::fatal("invalid node address %1") << parts[0];
			}

			if(parts.size() == 1) {
				/* already assigned */
			} else if(parts.size() == 2) {
				remotePort = parts[1].toInt();
			} else {
				Log::fatal("invalid node address %1") << joinStr;
			}
		}

		if(!endpointStr.isNull()) {
			QStringList parts = endpointStr.split(":");

			if(parts[0] == "*") {
				localAddress = QHostAddress::Any;
			} else {
				localAddress = checkoutAddress(parts[0]);
				if(localAddress.isNull()) {
					Log::fatal("invalid address %1") << parts[0];
				}
			}

			if(parts.size() == 1) {
			} else if(parts.size() == 2) {
				localPort = parts[1].toInt();
			} else {
				Log::fatal("invalid endpoint %1") << joinStr;
			}
		}

		if(!bindStr.isNull()) {
			bindAddress = checkoutAddress(bindStr);
			if(bindAddress.isNull())
				Log::fatal("invalid address %1") << bindStr;
		}

		if(!keyLenStr.isNull()) {
			generateNewKeypair = true;
			keyLength = keyLenStr.toInt();
		}

		if(createNetwork && localAddress == QHostAddress::Any)
			Log::fatal("you need to specify local endpoint to create network");

		if(!noTapStr.isNull())
			noTap = true;

		if(!behindNatStr.isNull())
			forceBehindNAT = true;
	}

	RSAKeyPair hostPair;

	if(!QFile::exists(configDir + "/rsa_key") || generateNewKeypair) {
		Log::debug("generating new RSA key pair (%1 bits)") << keyLength;

		if(!hostPair.generate(keyLength))
			Log::fatal("cannot generate new keypair");

		if(!hostPair.writeToFile(configDir + "/rsa_key"))
			Log::fatal("cannot write new keypair");
	} else {
		if(!hostPair.readFromFile(configDir + "/rsa_key"))
			Log::fatal("cannot read RSA keypair");
	}

	Router router;
	UdpPacketTransport transport(bindAddress, localPort);
	LinkLayer linkLayer(router, transport, hostPair);

#ifdef Q_OS_UNIX
	SignalHandler* sighandler = SignalHandler::getInstance();
	QObject::connect(sighandler, SIGNAL(sigint()), &linkLayer, SLOT(exitNetwork()));
	QObject::connect(sighandler, SIGNAL(sigterm()), &linkLayer, SLOT(exitNetwork()));
	if(!daemonize)
		QObject::connect(sighandler, SIGNAL(sighup()), &linkLayer, SLOT(exitNetwork()));
#endif

	QObject::connect(&linkLayer, SIGNAL(leavedNetwork()), &app, SLOT(quit()));
	QObject::connect(&linkLayer, SIGNAL(joinFailed()), &linkLayer, SLOT(exitNetwork()));

	EthernetApplicationLayer* appLayer;
#ifdef Q_OS_LINUX
	if(!noTap) {

		LinuxTAP *tap = new LinuxTAP(linkLayer);

		if(tap->createInterface("sparkle%d") == false)
			Log::fatal("cannot initialize TAP");

		tap = tap;

		appLayer = new EthernetApplicationLayer(linkLayer, tap);
	} else {
		appLayer = new EthernetApplicationLayer(linkLayer, NULL); //dummy
	}
#else
		appLayer = new EthernetApplicationLayer(linkLayer, NULL);
#endif	

	if(createNetwork) {
		if(!linkLayer.createNetwork(localAddress, networkDivisor))
			Log::fatal("cannot create network");
	} else {
		if(!linkLayer.joinNetwork(remoteAddress, remotePort, forceBehindNAT))
			Log::fatal("cannot join network");
	}

	return app.exec();
}

