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

#ifndef __LINUX_TAP_H__
#define __LINUX_TAP_H__

#include <sys/socket.h>
#include <linux/if.h>
#include <QObject>

#include "TapInterface.h"

namespace Sparkle {
	class LinkLayer;
	class SparkleAddress;
}

class QSocketNotifier;
class QHostAddress;

class LinuxTAP : public TapInterface
{
	Q_OBJECT

public:
	LinuxTAP(Sparkle::LinkLayer &linkLayer);
	~LinuxTAP();

	bool createInterface(QString pattern);

public slots:
	virtual void setupInterface(Sparkle::SparkleAddress ha, QHostAddress ip);
	virtual void sendPacket(QByteArray packet);

private slots:
	void getPacket();

signals:
	void havePacket(QByteArray packet);

private:
	Sparkle::LinkLayer &linkLayer;
	QSocketNotifier *notify;

	int tun;

	char device[IFNAMSIZ];
	char *framebuf;
};

#endif
