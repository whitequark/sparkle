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


#include <openssl/rand.h>
#include "BlowfishKey.h"

BlowfishKey::BlowfishKey(QObject *parent) : QObject(parent)
{

}

BlowfishKey::~BlowfishKey() {

}

void BlowfishKey::generate() {
	rawKey.resize(32);
	RAND_bytes((unsigned char *) rawKey.data(), rawKey.size());

	BF_set_key(&key, rawKey.size(), (unsigned char *) rawKey.data());
}

QByteArray BlowfishKey::getKey() {
	return rawKey;
}

void BlowfishKey::setKey(QByteArray raw) {
	rawKey = raw;

	BF_set_key(&key, rawKey.size(), (unsigned char *) rawKey.data());
}

QByteArray BlowfishKey::encrypt(QByteArray data) {
	unsigned char chunk[8];

	QByteArray output;

	for(; data.size() > 0; data = data.right(data.size() - 8)) {
		BF_ecb_encrypt((unsigned char *) data.data(), chunk, &key, BF_ENCRYPT);

		output += QByteArray((char *) chunk, 8);
	}

	return output;
}

QByteArray BlowfishKey::decrypt(QByteArray data) {
	unsigned char chunk[8];

	QByteArray output;

	for(; data.size() > 0; data = data.right(data.size() - 8)) {
		BF_ecb_encrypt((unsigned char *) data.data(), chunk, &key, BF_DECRYPT);

		output += QByteArray((char *) chunk, 8);
	}

	return output;
}
