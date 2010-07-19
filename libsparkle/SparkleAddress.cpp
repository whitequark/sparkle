/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2009 Sergey Gridassov, Peter Zotov
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

#include <Sparkle/Log>
#include <Sparkle/SparkleAddress>
#include <QHash>

#include <string.h>

using namespace Sparkle;

SparkleAddress::SparkleAddress() {
	memset(_bytes, 0, SPARKLE_ADDRESS_SIZE);
}

SparkleAddress::SparkleAddress(QByteArray origin) {
	if(origin.size() != SPARKLE_ADDRESS_SIZE) {
		Log::error("attempting to create SparkleAddress with size %1") << origin.size();
		origin.resize(SPARKLE_ADDRESS_SIZE);
	}

	memcpy(_bytes, origin.constData(), SPARKLE_ADDRESS_SIZE);
}

SparkleAddress::SparkleAddress(const quint8 origin[SPARKLE_ADDRESS_SIZE]) {
	memcpy(_bytes, origin, SPARKLE_ADDRESS_SIZE);
}

bool SparkleAddress::isNull() const {
	for(int i = 0; i < SPARKLE_ADDRESS_SIZE; i++) {
		if(_bytes[i] != 0)
			return false;
	}

	return true;
}

const QByteArray SparkleAddress::bytes() const {
	return QByteArray((const char*) _bytes, SPARKLE_ADDRESS_SIZE);
}

const quint8* SparkleAddress::rawBytes() const {
	return _bytes;
}

bool SparkleAddress::operator==(SparkleAddress other) const {
	return !memcmp(_bytes, other._bytes, SPARKLE_ADDRESS_SIZE);
}

bool SparkleAddress::operator!=(SparkleAddress other) const {
	return !(*this == other);
}

QString SparkleAddress::pretty() const {
	return QString(bytes().toHex()).toUpper().replace(QRegExp("(..)"), "\\1:").left(SPARKLE_ADDRESS_SIZE * 3 - 1);
}

namespace Sparkle {

uint qHash(const SparkleAddress &key) {
	return qHash((const QByteArray &) key.bytes());
}

}
