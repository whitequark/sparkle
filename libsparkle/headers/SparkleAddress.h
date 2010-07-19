/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2009 Sergey Gridassov, Peter Zotov
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

#ifndef SPARKLEADDRESS_H
#define SPARKLEADDRESS_H

#include <QByteArray>

#define SPARKLE_ADDRESS_SIZE	6

class SparkleAddress
{	
public:
	SparkleAddress();
	SparkleAddress(QByteArray);
	SparkleAddress(const quint8[SPARKLE_ADDRESS_SIZE]);

	bool isNull() const;

	const QByteArray bytes() const;
	const quint8* rawBytes() const;

	bool operator==(SparkleAddress) const;
	bool operator!=(SparkleAddress) const;

	QString pretty() const;
	static QString makePrettyMAC(QByteArray mac);

private:
	quint8 _bytes[SPARKLE_ADDRESS_SIZE];
};

uint qHash(const SparkleAddress &key);

#endif // SPARKLEADDRESS_H
