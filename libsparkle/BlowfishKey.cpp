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

#include "BlowfishKey.h"
#include "Log.h"
#include "crypto/havege.h"
#include "random.h"
#include <stdlib.h>

extern "C" const char *
blowfish_get_info(int algo, size_t *keylen, size_t *blocksize, size_t *contextsize,
		  int (**r_setkey)(void *c, const uint8_t *key, unsigned keylen),
		  void (**r_encrypt)(void *c, uint8_t *outbuf, const uint8_t *inbuf),
		  void (**r_decrypt)( void *c, uint8_t *outbuf, const uint8_t *inbuf));

BlowfishKey::BlowfishKey(QObject *parent) : QObject(parent)
{
	if(blowfish_get_info(4, &keylen, &blocksize, &contextsize, &cb_setkey, &cb_encrypt, &cb_decrypt) == NULL)
		Log::fatal("blowfish_get_info failed");

	keylen = 256;

	key = malloc(contextsize);
}

BlowfishKey::~BlowfishKey() {
	free(key);
}

void BlowfishKey::generate() {
	rawKey.resize(32);
	random_bytes((unsigned char *) rawKey.data(), rawKey.size());

	cb_setkey(key, (unsigned char *) rawKey.data(), rawKey.size());
}

QByteArray BlowfishKey::getBytes() const {
	return rawKey;
}

void BlowfishKey::setBytes(QByteArray raw) {
	rawKey = raw;

	cb_setkey(key, (unsigned char *) rawKey.data(), rawKey.size());
}

QByteArray BlowfishKey::encrypt(QByteArray data) const {
	unsigned char chunk[blocksize];

	QByteArray output;

	if(data.size() % blocksize != 0)
		data.resize((data.size() / blocksize + 1) * blocksize);

	for(; data.size() > 0; data = data.right(data.size() - blocksize)) {
		cb_encrypt(key, chunk, (unsigned char *) data.data());

		output += QByteArray((char *) chunk, blocksize);
	}

	return output;
}

QByteArray BlowfishKey::decrypt(QByteArray data) const {
	unsigned char chunk[blocksize];

	QByteArray output;

	for(; data.size() > 0; data = data.right(data.size() - blocksize)) {
		cb_decrypt(key, chunk, (unsigned char *) data.data());

		output += QByteArray((char *) chunk, blocksize);
	}

	return output;
}

