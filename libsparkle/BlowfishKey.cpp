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

#include <Sparkle/BlowfishKey>
#include <Sparkle/Log>

#include <stdlib.h>

#include "SparkleRandom.h"

using namespace Sparkle;

extern "C" const char *
blowfish_get_info(int algo, size_t *keylen, size_t *blocksize, size_t *contextsize,
		  int (**r_setkey)(void *c, const quint8 *key, unsigned keylen),
		  void (**r_encrypt)(void *c, quint8 *outbuf, const quint8 *inbuf),
		  void (**r_decrypt)( void *c, quint8 *outbuf, const quint8 *inbuf));

namespace Sparkle {

class BlowfishKeyPrivate {
public:
	BlowfishKeyPrivate();
	
	void generate();
	void setBytes(const QByteArray &raw);
	QByteArray encrypt(QByteArray data) const;
	QByteArray decrypt(QByteArray data) const;	
	
	void *key;
	QByteArray rawKey;

	size_t keylen, blocksize, contextsize;

	int (*cb_setkey)(void *c, const quint8 *key, unsigned keylen);
	void (*cb_encrypt)(void *c, quint8 *outbuf, const quint8 *inbuf);
	void (*cb_decrypt)(void *c, quint8 *outbuf, const quint8 *inbuf);
};

}

BlowfishKeyPrivate::BlowfishKeyPrivate() {
	if(blowfish_get_info(4, &keylen, &blocksize, &contextsize, &cb_setkey, &cb_encrypt, &cb_decrypt) == NULL)
		Log::fatal("blowfish_get_info failed");

	keylen = 256;

	key = malloc(contextsize);
}

void BlowfishKeyPrivate::generate() {
	rawKey.resize(32);
	SparkleRandom::bytes((unsigned char *) rawKey.data(), rawKey.size());

	cb_setkey(key, (unsigned char *) rawKey.data(), rawKey.size());
}

void BlowfishKeyPrivate::setBytes(const QByteArray &raw) {
	rawKey = raw;

	cb_setkey(key, (unsigned char *) rawKey.data(), rawKey.size());
}

QByteArray BlowfishKeyPrivate::encrypt(QByteArray data) const {

	unsigned char *chunk = new unsigned char[blocksize];

	QByteArray output;

	if(data.size() % blocksize != 0)
		data.resize((data.size() / blocksize + 1) * blocksize);

	for(; data.size() > 0; data = data.right(data.size() - blocksize)) {
		cb_encrypt(key, chunk, (unsigned char *) data.data());

		output += QByteArray((char *) chunk, blocksize);
	}

	delete chunk;

	return output;
}

QByteArray BlowfishKeyPrivate::decrypt(QByteArray data) const {
	unsigned char *chunk = new unsigned char[blocksize];
	
	QByteArray output;

	for(; data.size() > 0; data = data.right(data.size() - blocksize)) {
		cb_decrypt(key, chunk, (unsigned char *) data.data());

		output += QByteArray((char *) chunk, blocksize);
	}
	
	delete chunk;

	return output;
}

BlowfishKey::BlowfishKey(BlowfishKeyPrivate &dd, QObject *parent) : QObject(parent), d_ptr(&dd)
{

}

BlowfishKey::BlowfishKey(QObject *parent) : QObject(parent), d_ptr(new BlowfishKeyPrivate)
{

}

BlowfishKey::~BlowfishKey() {
	delete d_ptr;
}

void BlowfishKey::generate() {
	Q_D(BlowfishKey);

	d->generate();
}

QByteArray BlowfishKey::bytes() const {
	Q_D(const BlowfishKey);

	return d->rawKey;
}

void BlowfishKey::setBytes(QByteArray raw) {
	Q_D(BlowfishKey);
	
	d->setBytes(raw);
}

QByteArray BlowfishKey::encrypt(QByteArray data) const {
	Q_D(const BlowfishKey);

	return d->encrypt(data);
}


QByteArray BlowfishKey::decrypt(QByteArray data) const {
	Q_D(const BlowfishKey);

	return d->decrypt(data);
}

