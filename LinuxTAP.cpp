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

#include <QSocketNotifier>
#include <linux/if_tun.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>

#include "LinuxTAP.h"
#include "LinkLayer.h"
#include "SparkleNode.h"
#include "Log.h"

#define MTU 1518

LinuxTAP::LinuxTAP(LinkLayer &_linkLayer) : QObject(NULL), linkLayer(_linkLayer)
{
	connect(&linkLayer, SIGNAL(joined(SparkleNode*)), SLOT(joined(SparkleNode*)));
	connect(&linkLayer, SIGNAL(tapPacketReady(QByteArray&)), SLOT(sendPacket(QByteArray&)));

	tun = -1;
	framebuf = new char[MTU];
}

LinuxTAP::~LinuxTAP() {
	delete[] framebuf;
}

bool LinuxTAP::createInterface(QString pattern) {
	tun = open("/dev/net/tun", O_RDWR);

	if(tun == -1) {
		Log::error("tap: cannot open /dev/net/tun: %1") << QString::fromLocal8Bit(strerror(errno));

		return false;
	}
	
	struct ifreq ifr;
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, pattern.toAscii().data(), IFNAMSIZ);

	if(ioctl(tun, TUNSETIFF, &ifr) == -1) {
		Log::error("tap: cannot create iface: %1") << QString::fromLocal8Bit(strerror(errno));

		close(tun);

		return false;
	}

	memcpy(device, ifr.ifr_name, IFNAMSIZ);

	Log::debug("tap: registered interface %1") << device;

	notify = new QSocketNotifier(tun, QSocketNotifier::Read, this);
	connect(notify, SIGNAL(activated(int)), SLOT(getPacket()));
	notify->setEnabled(true);

	return true;
}

void LinuxTAP::joined(SparkleNode* node) {

	if(tun == -1) {
		Log::fatal("tap: joined to network before the device was created");
		
		return;
	}

	int fd = socket(PF_INET, SOCK_DGRAM, 0);

	if(fd == -1) {
		Log::fatal("tap: socket: %1") << QString::fromLocal8Bit(strerror(errno));
		
		return;
	}

	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifreq));
	
	ifr.ifr_mtu = MTU;
	memcpy(ifr.ifr_name, device, IFNAMSIZ);

	struct sockaddr_in *sockaddr = (sockaddr_in *) &ifr.ifr_addr;
	sockaddr->sin_family = AF_INET;
	sockaddr->sin_addr.s_addr = htonl(node->getSparkleIP().toIPv4Address());

	if(ioctl(fd, SIOCSIFADDR, &ifr) == -1) {
		Log::fatal("tap: SIOCSIFADDR: %1") << QString::fromLocal8Bit(strerror(errno));

		close(fd);
		return;
	}

	sockaddr = (sockaddr_in *) &ifr.ifr_netmask;
	sockaddr->sin_family = AF_INET;
	sockaddr->sin_addr.s_addr = 0xff; // 255.255.255.0

	if(ioctl(fd, SIOCSIFNETMASK, &ifr) == -1) {
		Log::fatal("tap: SIOCSIFNETMASK: %1") << QString::fromLocal8Bit(strerror(errno));

		close(fd);
		return;
	}

	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	memcpy(&ifr.ifr_hwaddr.sa_data, node->getSparkleMAC().constData(), 6);
	if(ioctl(fd, SIOCSIFHWADDR, &ifr) == -1) {
		Log::fatal("tap: SIOCSIFHWADDR: %1") << QString::fromLocal8Bit(strerror(errno));

		close(fd);
		return;
	}

	if(ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
		Log::fatal("tap: SIOCGIFFLAGS: %1") << QString::fromLocal8Bit(strerror(errno));

		close(fd);
		return;
	}

	ifr.ifr_flags |= IFF_UP;

	if(ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) {
		Log::fatal("tap: cannot bring interface up: %1") << QString::fromLocal8Bit(strerror(errno));

		close(fd);
		return;
	}

	close(fd);

	Log::debug("tap: ready");

	notify->setEnabled(true);
}

void LinuxTAP::getPacket() {
	int len = read(tun, framebuf, MTU);
	linkLayer.processPacket(QByteArray((char *) framebuf, len));
}

void LinuxTAP::sendPacket(QByteArray &data) {
	if(write(tun, data.data(), data.size()) != data.size())
		Log::debug("tap: packet truncated on write");
}
