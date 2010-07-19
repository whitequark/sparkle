/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2010 Sergey Gridassov
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
#include <QtEndian>

//#define ETHARP_TCPIP_INPUT 1

#include <lwip/tcpip.h>

#include <netif/etharp.h>

#include "LwIPTAP.h"

using namespace Sparkle;

LwIPTAP::LwIPTAP(QObject *parent) : TapInterface(parent), m_registered(false) {

}

LwIPTAP::~LwIPTAP() {
	if(m_registered) {
		netif_remove(&interface);
	}
}

void LwIPTAP::setupInterface(Sparkle::SparkleAddress ha, QHostAddress ip) {
	struct ip_addr addr, netmask, gw;

	addr.addr = qToBigEndian<quint32>(ip.toIPv4Address());
	IP4_ADDR(&netmask, 255, 0, 0, 0);
	IP4_ADDR(&gw, 0, 0, 0, 0);

	m_hw = ha.bytes();

	netif_add(&interface, &addr, &netmask, &gw, this, &if_init, tcpip_input);

	m_registered = true;

	netif_set_up(&interface);

	Log::debug("Registered lwIP interface");
}

void LwIPTAP::sendPacket(QByteArray packet) {
	/* We allocate a pbuf chain of pbufs from the pool. */
	struct pbuf *p = pbuf_alloc(PBUF_RAW, packet.size(), PBUF_POOL);
  
	if (p != NULL) {
		/* We iterate over the pbuf chain until we have read the entire packet into the pbuf. */
		for(struct pbuf *q = p; q != NULL; q = q->next) {


			memcpy(q->payload, packet.data(), q->len);
	
			packet = packet.right(packet.size() - q->len);
		}		

	
		int ret = interface.input(p, &interface);

		if(ret != ERR_OK) {
			Log::error("LwIP can't handle packet, code %1") << ret;

			pbuf_free(p);
		}
	} else
		Log::error("LwIPTAP: Attempt to allocate pbuf failed");
}

err_t LwIPTAP::if_output(struct netif *netif, struct pbuf *p) {
	LwIPTAP *tap = static_cast<LwIPTAP *>(netif->state);

	QByteArray buf;

	for(struct pbuf *q = p; q != NULL; q = q->next) {
		buf += QByteArray((char *) q->payload, q->len);
	}

	tap->receive(buf);

	return ERR_OK;
}

void LwIPTAP::receive(QByteArray data) {
	emit havePacket(data);
}

err_t LwIPTAP::if_init(struct netif *netif) {
	netif->flags = NETIF_FLAG_ETHARP;

	netif->hwaddr_len = 6;
	memcpy(netif->hwaddr, m_hw.data(), 6);
	netif->mtu = 1518;
	netif->name[0] = 's';
	netif->name[1] = 'p';
	netif->num = 0;
	netif->output = etharp_output;
	netif->linkoutput = if_output;

	return ERR_OK;
}

struct netif LwIPTAP::interface;
QByteArray LwIPTAP::m_hw;

