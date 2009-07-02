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

#include "RSAKeyPair.h"

#include <QFile>
#include <openssl/pem.h>
#include <stdio.h>

RSAKeyPair::RSAKeyPair(QObject *parent) : QObject(parent) {
	key = RSA_new();
}

RSAKeyPair::~RSAKeyPair() {
	RSA_free(key);
}

bool RSAKeyPair::generate(int bits) {
	RSA *newKey = RSA_generate_key(bits, 65537, NULL, NULL);

	if(newKey != NULL) {
		RSA_free(key);
		key = newKey;

		return true;
	} else
		return false;

}

bool RSAKeyPair::writeToFile(QString filename) {
	BIO *mem = BIO_new(BIO_s_mem());

	if(mem == NULL)
		return false;

	if(PEM_write_bio_RSAPrivateKey(mem, key, NULL, NULL, 0, NULL, NULL) == 0) {
		BIO_free(mem);

		return false;
	}
	
	char *pointer;
	long len = BIO_get_mem_data(mem, &pointer);

	QByteArray data(pointer, len);

	BIO_free(mem);

	QFile keyFile(filename);
	if(!keyFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
		return false;
	}

	keyFile.write(data);

	keyFile.close();

	return true;
}

bool RSAKeyPair::readFromFile(QString filename) {
	QFile keyFile(filename);
	if(!keyFile.open(QIODevice::ReadOnly)) {
		return false;
	}

	QByteArray data = keyFile.readAll();

	keyFile.close();

	BIO *mem = BIO_new_mem_buf(data.data(), data.size());

	if(mem == NULL)
		return false;

	RSA *newKey = PEM_read_bio_RSAPrivateKey(mem, NULL, NULL, NULL);

	BIO_free(mem);

	if(newKey) {
		RSA_free(key);

		key = newKey;

		return true;
	} else
		return false;

}

