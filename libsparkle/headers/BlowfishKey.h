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

#ifndef __BLOWFISH__H__
#define __BLOWFISH__H__

#include <QObject>
#include <stdint.h>

class BlowfishKey: public QObject
{
	Q_OBJECT
public:
	BlowfishKey(QObject *parent = 0);
	virtual ~BlowfishKey();

	void generate();

	QByteArray getBytes() const;
	void setBytes(QByteArray raw);
	
	QByteArray encrypt(QByteArray data) const;
	QByteArray decrypt(QByteArray data) const;

private:
	void *key;
	QByteArray rawKey;

	size_t keylen, blocksize, contextsize;
	int (*cb_setkey)(void *c, const uint8_t *key, unsigned keylen);
	void (*cb_encrypt)(void *c, uint8_t *outbuf, const uint8_t *inbuf);
	void (*cb_decrypt)(void *c, uint8_t *outbuf, const uint8_t *inbuf);
};

#endif
