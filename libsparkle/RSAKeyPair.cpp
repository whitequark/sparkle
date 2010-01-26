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

#include "RSAKeyPair.h"

#include <QFile>
#include "crypto/rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include "random.h"
#include "Log.h"

RSAKeyPair::RSAKeyPair() {
	rsa_init(&key, RSA_PKCS_V15, 0, get_random, NULL);
}

RSAKeyPair::~RSAKeyPair() {
	mpi_free(&key.N, &key.E, &key.D, &key.P,
		&key.Q, &key.DP, &key.DQ, &key.QP,
		&key.RN, &key.RP, &key.RQ, NULL);
}

bool RSAKeyPair::generate(int bits) {
	return rsa_gen_key(&key, bits, 65537) == 0;
}

bool RSAKeyPair::writeToFile(QString filename) const {
	QByteArray rawKey;

	QDataStream stream(&rawKey, QIODevice::WriteOnly);

	stream << key.ver;
	stream << key.len;
	stream << key.N;
	stream << key.E;
	stream << key.D;
	stream << key.P;
	stream << key.Q;
	stream << key.DP;
	stream << key.DQ;
	stream << key.QP;
	stream << key.RN;
	stream << key.RP;
	stream << key.RQ;

	QFile keyFile(filename);
	if(!keyFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
		return false;
	}

	keyFile.write(rawKey.toBase64());

	keyFile.close();

	return true;
}

bool RSAKeyPair::readFromFile(QString filename) {
	QFile keyFile(filename);

	if(!keyFile.open(QIODevice::ReadOnly)) {
		return false;
	}

	QByteArray rawdata = keyFile.readAll();

	keyFile.close();

	if(rawdata.left(10) == "-----BEGIN")
		Log::fatal("Your private key is in wrong format, re-generate it");

	QByteArray data = QByteArray::fromBase64(rawdata);

	QDataStream stream(&data, QIODevice::ReadOnly);

	stream >> key.ver;
	stream >> key.len;
	stream >> key.N;
	stream >> key.E;
	stream >> key.D;
	stream >> key.P;
	stream >> key.Q;
	stream >> key.DP;
	stream >> key.DQ;
	stream >> key.QP;
	stream >> key.RN;
	stream >> key.RP;
	stream >> key.RQ;

	return true;
}

QByteArray RSAKeyPair::publicKey() const {
	QByteArray rawKey;

	QDataStream stream(&rawKey, QIODevice::WriteOnly);

	stream << key.ver;
	stream << key.len;
	stream << key.N;
	stream << key.E;
	stream << key.RN;

	return rawKey;
}

bool RSAKeyPair::setPublicKey(QByteArray data) {
	QDataStream stream(&data, QIODevice::ReadOnly);

	stream >> key.ver;
	stream >> key.len;
	stream >> key.N;
	stream >> key.E;
	stream >> key.RN;

	return true;
}

QByteArray RSAKeyPair::encrypt(QByteArray plaintext) {
	QByteArray output;

	int rsize = key.len;

	int flen = rsize - 11;
	unsigned char chunk[rsize];

	for(; plaintext.size() > 0; ) {
		int dlen = qMin<int>(flen, plaintext.length());

		rsa_pkcs1_encrypt(&key, RSA_PUBLIC, dlen, (unsigned char *) plaintext.data(), chunk);

		output += QByteArray((char *) chunk, rsize);

		plaintext = plaintext.right(plaintext.size() - dlen);
	}

	return output;
}

QByteArray RSAKeyPair::decrypt(QByteArray cryptotext) {
	QByteArray output;

	int rsize = key.len;

	unsigned char chunk[rsize];

	for(; cryptotext.size() > 0; ) {
		int dlen = qMin<int>(rsize, cryptotext.size());

		int dec;

		rsa_pkcs1_decrypt(&key, RSA_PRIVATE, &dec, (unsigned char *) cryptotext.data(), chunk, dlen);

		output += QByteArray((char *) chunk, dec);

		cryptotext = cryptotext.right(cryptotext.size() - rsize);
	}

	return output;
}

QDataStream & operator<< (QDataStream& stream, const mpi &data) {
	stream << ((qint32) data.s);
	stream << ((qint32) data.n);

	for(int i = 0; i < data.n; i++)
		stream << ((quint32) data.p[i]);

	return stream;
}

QDataStream & operator >> (QDataStream& stream, mpi &data) {
	stream >> (qint32 &) data.s;
	stream >> (qint32 &) data.n;

	data.p = (t_int *) malloc(sizeof(t_int) * data.n);

	for(int i = 0; i < data.n; i++)
		stream >> ((quint32 &) data.p[i]);

	return stream;
}
