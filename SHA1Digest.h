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

#ifndef __SHA1_DIGEST__H__
#define __SHA1_DIGEST__H__

#include <QObject>

class SHA1Digest : public QObject
{
	Q_OBJECT
public:
	static QByteArray calculateSHA1(QByteArray data);

private:
	SHA1Digest(QObject *parent = 0);
	virtual ~SHA1Digest();
};

#endif
