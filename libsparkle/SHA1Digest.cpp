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

#include "crypto/sha1.h"
#include "SHA1Digest.h"

SHA1Digest::SHA1Digest(QObject *parent) : QObject(parent)
{

}

SHA1Digest::~SHA1Digest() {

}

QByteArray SHA1Digest::calculateSHA1(QByteArray data) {
	QByteArray ret;
	ret.resize(20);

	sha1((unsigned char *) data.data(), data.size(), (unsigned char *) ret.data());

	return ret;
}
