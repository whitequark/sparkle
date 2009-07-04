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

#include <QtDebug>
#include <openssl/rand.h>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>

#include "RSAKeyPair.h"
#include "ArgumentParser.h"
#include "LinkLayer.h"
#include "UdpPacketTransport.h"

#ifdef Q_WS_X11
#include "LinuxTAP.h"
#endif

QHostAddress checkoutAddress(QString strAddr) {
	QHostAddress ipAddr;
	if(!ipAddr.setAddress(strAddr)) {
		QHostInfo hostInfo = QHostInfo::fromName(strAddr);
		if(hostInfo.error() != QHostInfo::NoError) {
			qWarning() << "cannot lookup address" << strAddr;
		} else {
			QList<QHostAddress> list = hostInfo.addresses();
			if(list.size() > 1)
				qWarning() << "there are more than one IP address for host" << strAddr << ", using first";
			
			return list[0];
		}
	}
	return ipAddr;
}

void messageOutputHandler(QtMsgType type, const char *msg) {
	switch(type) {
		case QtDebugMsg: {
			printf("[DEBUG] %s\n", msg);
			break;
		}

		case QtWarningMsg: {
			printf("[WARN ] %s\n", msg);
			break;
		}

		case QtCriticalMsg: {
			printf("[ERROR] %s\n", msg);
			break;
		}

		case QtFatalMsg: {
			printf("[FATAL] %s\n", msg);
			QCoreApplication::exit(1);
		}
	}
}

int main(int argc, char *argv[]) {
	QCoreApplication app(argc, argv);
	app.setApplicationName("sparkle");
	
	qInstallMsgHandler(messageOutputHandler);

	QString profile = "default";
	bool createNetwork = false;
	QHostAddress localAddress, remoteAddress;
	quint16 localPort = 1801, remotePort = 1801;

	int keyLength = 1024;
	bool generateNewKeypair = false;

	{
		QString createStr, joinStr, portStr, keyLenStr;

		ArgumentParser parser(app.arguments());

		parser.registerOption(QChar::Null, "profile", ArgumentParser::RequiredArgument, &profile, NULL,
			NULL, "use specified profile", "PROFILE");

		parser.registerOption('c', "create", ArgumentParser::RequiredArgument, &createStr, NULL,
			NULL, "create new network using HOST as external address of this node", "HOST");

		parser.registerOption('j', "join", ArgumentParser::RequiredArgument, &joinStr, NULL,
			NULL, "join existing network (PORT defaults to 1801 if not specified)", "HOST:PORT");

		parser.registerOption('p', "port", ArgumentParser::RequiredArgument, &portStr, NULL,
			NULL, "listen at specified local UDP port PORT (defaults to 1801)", "PORT");

		parser.registerOption(QChar::Null, "generate-key", ArgumentParser::RequiredArgument,
			&keyLenStr, NULL, NULL, "generate new RSA key pair with specified length", "BITS");

		if(!parser.parse()) { // help was displayed
			return 0;
		}

		if(!createStr.isNull() && !joinStr.isNull())
			qFatal("options --create and --join cannot be specified simultaneously");
		
		if(createStr.isNull() && joinStr.isNull())
			qFatal("specify --create or --join option");
		
		if(!createStr.isNull()) {
			localAddress = checkoutAddress(createStr);
			if(localAddress.isNull())
				qFatal("invalid external address %s", createStr.data());
			createNetwork = true;
		}
		
		if(!joinStr.isNull()) {
			QStringList parts = joinStr.split(":");

			remoteAddress = checkoutAddress(parts[0]);
			if(remoteAddress.isNull())
				qFatal("invalid node address %s", parts[0].data());
			
			if(parts.size() == 1) {
			} else if(parts.size() == 2) {
				remotePort = parts[1].toInt();
			} else {
				qFatal("invalid node address %s", joinStr.data());
			}
		}
		
		if(!keyLenStr.isNull()) {
			generateNewKeypair = true;
			keyLength = keyLenStr.toInt();
		}
		
		if(!portStr.isNull()) {
			localPort = portStr.toInt();
		}
	}

	QString configDir = QDir::homePath() + "/." + app.applicationName() + "/" + profile;
	QDir().mkdir(QDir::homePath() + "/." + app.applicationName());
	QDir().mkdir(configDir);

	qsrand(QDateTime::currentDateTime().toTime_t());

	RSAKeyPair hostPair;
	
	if(!QFile::exists(configDir + "/rsa_key") || generateNewKeypair) {
		qDebug("generating new RSA key pair (%d bits)", keyLength);

		if(!hostPair.generate(keyLength)) {
			qFatal("cannot generate new keypair");
		}

		if(!hostPair.writeToFile(configDir + "/rsa_key")) {
			qFatal("cannot write new keypair");
		}
	} else {
		if(!hostPair.readFromFile(configDir + "/rsa_key")) {
			qFatal("cannot read RSA keypair");
		}
	}

	UdpPacketTransport *transport = new UdpPacketTransport(localPort);
	LinkLayer link(transport, &hostPair);

	if(createNetwork) {
		if(!link.createNetwork(localAddress)) {
			qFatal("cannot create network");
		}
	} else {
		if(!link.joinNetwork(remoteAddress, remotePort)) {
			qFatal("cannot join network");
		}
	}

#ifdef Q_WS_X11
	LinuxTAP tap(&link);
	if(tap.createInterface("sparkle%d") == false) {
		qFatal("cannot initialize TAP");
	}

#endif

	return app.exec();
}
