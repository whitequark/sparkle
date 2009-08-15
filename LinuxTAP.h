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

class LinkLayer;
class QSocketNotifier;
class SparkleNode;

class LinuxTAP : public QObject
{
	Q_OBJECT

public:
	LinuxTAP(LinkLayer &linkLayer);
	~LinuxTAP();

	bool createInterface(QString pattern);

private slots:
	void joined(SparkleNode* node);
	void getPacket();
	void sendPacket(QByteArray& packet);

private:
	LinkLayer &linkLayer;
	QSocketNotifier *notify;

	int tun;

	char device[IFNAMSIZ];
	char *framebuf;
};

#endif
