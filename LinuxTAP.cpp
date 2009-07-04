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

LinuxTAP::LinuxTAP(LinkLayer *link, QObject *parent) : QObject(parent)
{
	this->link = link;

	connect(link, SIGNAL(joined()), SLOT(joined()));
	connect(link, SIGNAL(sendPacketReq(QByteArray)), SLOT(sendPacket(QByteArray)));

	tun = -1;
	framebuf = new char[1518]; // FIXME define MTU
}

LinuxTAP::~LinuxTAP() {
	delete framebuf;
}

bool LinuxTAP::createInterface(QString pattern) {
	tun = open("/dev/net/tun", O_RDWR);

	if(tun == -1) {
		qCritical("tap: cannot open /dev/net/tun: %s", strerror(errno));

		return false;
	}
	
	struct ifreq ifr;
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, pattern.toAscii().data(), IFNAMSIZ);

	if(ioctl(tun, TUNSETIFF, &ifr) == -1) {
		close(tun);
		qCritical("tap: cannot create iface: %s", strerror(errno));

		return false;
	}

	memcpy(device, ifr.ifr_name, IFNAMSIZ);

	qDebug("tap: registered interface %s", device);

	notify = new QSocketNotifier(tun, QSocketNotifier::Read, this);
	connect(notify, SIGNAL(activated(int)), SLOT(haveData()));
	notify->setEnabled(true);

	return true;
}

void LinuxTAP::joined() {

	if(tun == -1) {
		qFatal("tap: joined to network before the device was created");
		
		return;
	}

	qDebug("tap: configuring interface %s", device);

	int fd = socket(PF_INET, SOCK_DGRAM, 0);

	if(fd == -1) {
		qFatal("tap: socket: %s", strerror(errno));
		
		return;
	}

	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifreq)); // FIXME assign MTU

	memcpy(ifr.ifr_name, device, IFNAMSIZ);

	struct sockaddr_in *sockaddr = (sockaddr_in *) &ifr.ifr_addr;
	sockaddr->sin_family = AF_INET;
	sockaddr->sin_addr.s_addr = htonl(link->getSparkleIP().toIPv4Address());

	if(ioctl(fd, SIOCSIFADDR, &ifr) == -1) {
		close(fd);
		qFatal("tap: SIOCSIFADDR: %s", strerror(errno));

		return;
	}

	sockaddr = (sockaddr_in *) &ifr.ifr_netmask;
	sockaddr->sin_family = AF_INET;
	sockaddr->sin_addr.s_addr = 0xff;

	if(ioctl(fd, SIOCSIFNETMASK, &ifr) == -1) {
		close(fd);
		qFatal("tap: SIOCSIFNETMASK: %s", strerror(errno));

		return;
	}

	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	memcpy(&ifr.ifr_hwaddr.sa_data, link->getSparkleMac().data(), 6);
	if(ioctl(fd, SIOCSIFHWADDR, &ifr) == -1) {
		close(fd);
		qFatal("tap: SIOCSIFHWADDR: %s", strerror(errno));

		return;
	}

	if(ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
		close(fd);
		qFatal("tap: SIOCGIFFLAGS: %s", strerror(errno));

		return;
	}

	ifr.ifr_flags |= IFF_UP;

	if(ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) {
		close(fd);
		qFatal("tap: SIOCGIFFLAGS: %s", strerror(errno));

		return;
	}

	close(fd);

	notify->setEnabled(true);
}

void LinuxTAP::haveData() {
	int len = read(tun, framebuf, 1518); // FIXME MTU

	link->processPacket(QByteArray((char *) framebuf, len));
}

void LinuxTAP::sendPacket(QByteArray data) {
	write(tun, data.data(), data.size());
}
