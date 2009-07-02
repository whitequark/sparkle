/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2009  Serge Gridassov
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

#include <openssl/rand.h>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>

#include "RSAKeyPair.h"
#include "ArgumentsParser.h"

int main(int argc, char *argv[]) {
	QCoreApplication app(argc, argv);

	app.setApplicationName("sparkle");

	int keyLen = 2048;

	{
		QString keyLenStr;

		ArgumentsParser parser(app.arguments());

		parser.registerOption(QChar::Null, "key-length", ArgumentsParser::RequiredArgument,
			&keyLenStr, NULL, NULL, "generate RSA key pair with specified length", "BITS");

		parser.parse();

		if(!keyLenStr.isNull())
			keyLen = keyLenStr.toInt();
	}

	uint time = QDateTime::currentDateTime().toTime_t();

	RAND_seed(&time, sizeof(time));

	QString configDir = QDir::homePath() + "/." + app.applicationName();;
	QDir().mkdir(configDir);

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
			printf("Reading RSA key pair failed!\n");

			return 1;
		}

	return app.exec();
}
