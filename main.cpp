/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2009 Sergey Gridassov
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
#include "ArgumentsParser.h"
#include "LinkLayer.h"

int main(int argc, char *argv[]) {
	QCoreApplication app(argc, argv);

	app.setApplicationName("sparkle");

	int keyLen = 1024;
	quint16 port = 1801;
	bool createNetwork = false;
	QString nodeName, profile = "default";

	{
		QString keyLenStr, portStr, createStr;

		ArgumentsParser parser(app.arguments());

		parser.registerOption(QChar::Null, "key-length", ArgumentsParser::RequiredArgument,
			&keyLenStr, NULL, NULL, "generate RSA key pair with specified length", "BITS");

		parser.registerOption('p', "port", ArgumentsParser::RequiredArgument, &portStr, NULL,
				      NULL, "use specified UDP port", "PORT");

		parser.registerOption('n', "node", ArgumentsParser::RequiredArgument, &nodeName, NULL,
				      NULL, "login using specified node", "ADDR");

		parser.registerOption(QChar::Null, "profile", ArgumentsParser::RequiredArgument, &profile, NULL,
		      NULL, "use specified profile", "PROFILE");

		parser.registerOption(QChar::Null, "create", ArgumentsParser::NoArgument, &createStr, NULL,
				      NULL, "create new network", NULL);

		parser.parse();

		if(!keyLenStr.isNull())
			keyLen = keyLenStr.toInt();

		createNetwork = createStr.isNull() == false;

		if(!portStr.isNull())
			port = portStr.toInt();
	}

	if(nodeName.isNull() && !createNetwork) {
		fprintf(stderr, "Node name not set\n");

		return 1;
	}

	QString configDir = QDir::homePath() + "/." + app.applicationName() + "/" + profile;
	QDir().mkdir(QDir::homePath() + "/." + app.applicationName());
	QDir().mkdir(configDir);


	uint time = QDateTime::currentDateTime().toTime_t();
	qsrand(time);

	RSAKeyPair hostPair;

	if(!QFile::exists(configDir + "/rsa_key")) {
		printf("Generating RSA key pair (%d bits)...", keyLen);

		fflush(stdout);

		if(!hostPair.generate(keyLen)) {
			printf(" failed!\n");

			return 1;
		}

		if(!hostPair.writeToFile(configDir + "/rsa_key")) {
			printf(" writing failed!\n");

			return 1;
		}

		printf(" done\n");

	} else
		if(!hostPair.readFromFile(configDir + "/rsa_key")) {
			fprintf(stderr, "Reading RSA key pair failed!\n");

			return 1;
		}

	LinkLayer link(&hostPair, port);

	if(createNetwork) {
		if(!link.createNetwork()) {
			qCritical() << "Creating network failed:" << link.errorString();

			return 1;
		}
	} else {
		if(!link.joinNetwork(nodeName)) {
			qCritical() << "Joining network failed:" << link.errorString();

			return 1;
		}
	}

	return app.exec();
}
