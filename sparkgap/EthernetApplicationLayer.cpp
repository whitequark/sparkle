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

#include <QtDebug>
#include <QtEndian>

#include <Sparkle/LinkLayer>
#include <Sparkle/Router>
#include <Sparkle/Log>
#include <Sparkle/SparkleAddress>
#include <Sparkle/SparkleNode>

#include "EthernetApplicationLayer.h"
#include "TapInterface.h"

using namespace Sparkle;

EthernetApplicationLayer::EthernetApplicationLayer(LinkLayer &_linkLayer, TapInterface* _tap) : router(_linkLayer.router()), linkLayer(_linkLayer), tap(_tap) {
	
	connect(&linkLayer, SIGNAL(joinedNetwork(SparkleNode *)), SLOT(initialize(SparkleNode *)));
	
	linkLayer.attachApplicationLayer(Ethernet, this);
	
	if(tap) {
		connect(tap, SIGNAL(havePacket(QByteArray)), SLOT(haveTapPacket(QByteArray)));
		connect(this, SIGNAL(sendTapPacket(QByteArray)), tap, SLOT(sendPacket(QByteArray)));
	}
}

EthernetApplicationLayer::~EthernetApplicationLayer() {
}

QHostAddress EthernetApplicationLayer::makeIPv4Address(SparkleAddress mac) {
	return QHostAddress(qToBigEndian<quint32>(*((const quint32*) (QByteArray("\x0E") + mac.bytes().left(3)).constData())));
}

void EthernetApplicationLayer::initialize(SparkleNode *self) {
	selfMAC = self->sparkleMAC();
	selfIPv4 = makeIPv4Address(selfMAC);
	if(tap)	tap->setupInterface(selfMAC, selfIPv4);
	Log::info("eth: initialized with IP [%1]") << selfIPv4;
}

void EthernetApplicationLayer::handleDataPacket(QByteArray &packet, SparkleAddress mac) {
	if((size_t) packet.length() <= sizeof(ethernet_header_t) + sizeof(ipv4_header_t)) {
		Log::warn("eth: malformed packet from %1") << mac.pretty();
		return;
	}

	const ethernet_header_t* eth = (const ethernet_header_t*) packet.constData();

	if(memcmp(eth->src, mac.rawBytes(), 6) != 0) {
		Log::warn("ethernet: remote %1 packet with malformed source MAC") << mac.pretty();
		return;
	}

	if(memcmp(eth->dest, selfMAC.rawBytes(), 6) != 0) {
		Log::warn("ethernet: remote %1 packet with malformed destination MAC") << mac.pretty();
		return;
	}

	if(qFromBigEndian<quint16>(eth->type) != 0x0800) { // IP
		Log::warn("ethernet: remote %1 non-IP (%2) packet") << mac.pretty()
			<< QString::number(qFromBigEndian<quint16>(eth->type), 16).rightJustified(4, '0');
		return;
	}

	QByteArray payload = packet.right(packet.size() - sizeof(ethernet_header_t));
	const ipv4_header_t* ip = (const ipv4_header_t*) payload.constData();

	if(qFromBigEndian<quint32>(ip->src) != makeIPv4Address(mac).toIPv4Address()) {
		Log::warn("eth: received IPv4 packet with malformed source address");
		return;
	}

	if(qFromBigEndian<quint32>(ip->dest) != selfIPv4.toIPv4Address()) {
		Log::warn("eth: received IPv4 packet with malformed destination address");
		return;
	}

	emit sendTapPacket(packet);
}

void EthernetApplicationLayer::haveTapPacket(QByteArray packet) {
	const ethernet_header_t* eth = (const ethernet_header_t*) packet.constData();

	if(memcmp(eth->src, selfMAC.rawBytes(), 6) != 0) {
		Log::warn("ethernet: local packet from unknown source MAC");
		return;
	}

	QByteArray payload = packet.right(packet.size() - sizeof(ethernet_header_t));
	switch(qFromBigEndian<quint16>(eth->type)) {
		case 0x0806: { // ARP
			if(memcmp(eth->dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0) {
				Log::warn("eth: non-broadcasted local ARP packet");
				return;
			}

			const arp_packet_t* arp = (const arp_packet_t*) payload.constData();
			if(!(qFromBigEndian<quint16>(arp->htype) == 1 /* ethernet */ && qFromBigEndian<quint16>(arp->ptype) == 0x0800 /* ipv4 */ &&
				arp->hlen == 6 && arp->plen == 4 &&
					qFromBigEndian<quint32>(arp->spa) == selfIPv4.toIPv4Address() &&
					!memcmp(arp->sha, eth->src, 6))) {
				Log::warn("eth: invalid local arp packet received");
				return;
			}

			if(qFromBigEndian<quint16>(arp->oper) == 1 /* request */) {
				quint32 dest = arp->tpa;
				SparkleAddress route = linkLayer.findPartialRoute(QByteArray((const char*) &dest, sizeof(dest)).right(3));
				if(route.isNull()) {
					Log::info("eth: no route to %1") << QHostAddress(qFromBigEndian<quint32>(arp->tpa));
				} else {
					sendARPReply(route);
				}
			} else {
				Log::info("eth: ARP packet with unexpected OPER=%1 received") << qFromBigEndian<quint16>(arp->oper);
				return;
			}

			break;
		}

		case 0x0800: { // IPv4
			const ipv4_header_t* ip = (const ipv4_header_t*) payload.constData();
			if(qFromBigEndian<quint32>(ip->src) != selfIPv4.toIPv4Address()) {
				Log::warn("eth: received local IPv4 packet with malformed source address");
				return;
			}

			quint32 dest = ip->dest;
			SparkleAddress route = linkLayer.findPartialRoute(QByteArray((const char*) &dest, sizeof(dest)).right(3));
			if(!route.isNull()) {
				linkLayer.sendDataPacket(route, Ethernet, packet);
			} else if(qToBigEndian<quint32>(ip->dest) == 0x0effffff) { // ignore broadcasta
				/* do nothing */
			} else if(qToBigEndian<quint32>(ip->dest) >> 24 != 0xE0) { // avoid link-local
				Log::info("eth: received local IPv4 packet for unknown destination [%1]")
						<< QHostAddress(qFromBigEndian<quint32>(ip->dest));
			}
			break;
		}

		case 0x86dd: { // IPv6
			/* Silently ignore. There're no IPv6 addresses assigned to iface anyway */
			break;
		}

		default: {
			Log::warn("eth: received local packet of unknown type %1")
					<< QString::number(qFromBigEndian<quint16>(eth->type), 16).rightJustified(4, '0');
		}
	}
}

void EthernetApplicationLayer::sendARPReply(SparkleAddress mac) {
	QByteArray packet(sizeof(ethernet_header_t) + sizeof(arp_packet_t), 0);
	SparkleNode* self = router.getSelfNode();

	ethernet_header_t* eth = (ethernet_header_t*) packet.data();
	memcpy(eth->dest, self->sparkleMAC().rawBytes(), 6);
	memcpy(eth->src, mac.rawBytes(), 6);
	eth->type = qToBigEndian<quint16>(0x0806); // ARP

	arp_packet_t* arp = (arp_packet_t*) (packet.data() + sizeof(ethernet_header_t));
	arp->htype = qToBigEndian<quint16>(1); // ethernet
	arp->ptype = qToBigEndian<quint16>(0x0800); // IPv4
	arp->hlen = 6;
	arp->plen = 4;
	arp->oper = qToBigEndian<quint16>(2); // reply
	memcpy(arp->sha, eth->src, 6);
	arp->spa = qToBigEndian<quint32>(makeIPv4Address(mac).toIPv4Address());
	memcpy(arp->tha, eth->dest, 6);
	arp->tpa = qToBigEndian<quint32>(selfIPv4.toIPv4Address());

	emit sendTapPacket(packet);
}

