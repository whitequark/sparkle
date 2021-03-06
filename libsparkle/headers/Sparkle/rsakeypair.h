/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2009 Sergey Gridassov
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

#ifndef __RSA_KEY_PAIR__H__
#define __RSA_KEY_PAIR__H__

#include <QObject>
#include <Sparkle/Sparkle>

namespace Sparkle {

class RSAKeyPairPrivate;

class SPARKLE_DECL RSAKeyPair {
	Q_DECLARE_PRIVATE(RSAKeyPair)

protected:
	RSAKeyPair(RSAKeyPairPrivate &dd);

public:
	explicit RSAKeyPair();
	virtual ~RSAKeyPair();

	bool generate(int bits);
	bool writeToFile(QString filename) const;
	bool readFromFile(QString filename);

	QByteArray publicKey() const;
	bool setPublicKey(QByteArray key);

	QByteArray encrypt(QByteArray data);
	QByteArray decrypt(QByteArray data);

protected:
	RSAKeyPairPrivate * const d_ptr;
};

}

#endif
