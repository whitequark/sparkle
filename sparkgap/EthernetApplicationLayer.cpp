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

#include "EthernetApplicationLayer.h"
#include "TapInterface.h"

#include <arpa/inet.h>
#include <LinkLayer.h>
#include <Log.h>
#include <Router.h>

EthernetApplicationLayer::EthernetApplicationLayer(Router &_router, QObject *parent) : QObject(parent), router(_router) {

}

EthernetApplicationLayer::~EthernetApplicationLayer() {

}

void EthernetApplicationLayer::handleDataPacket(QByteArray &packet, SparkleNode *node) {
	if((size_t) packet.length() <= sizeof(ethernet_header_t) + sizeof(ipv4_header_t)) {
		Log::warn("ethernet: malformed packet from [%1]:%2") << *node;

		return;
	}
	const ethernet_header_t* eth = (const ethernet_header_t*) packet.constData();
	SparkleNode* self = router.getSelfNode();

	if(memcmp(eth->src, node->getSparkleMAC().constData(), 6) != 0) {
		Log::warn("ethernet: remote [%1] packet with malformed source MAC") << node->getSparkleIP();
		return;
	}

	if(memcmp(eth->dest, self->getSparkleMAC().constData(), 6) != 0) {
		Log::warn("ethernet: remote [%1] packet with malformed destination MAC") << node->getSparkleIP();
		return;
	}
	
	if(ntohs(eth->type) != 0x0800) { // IP
		Log::warn("ethernet: remote [%1] non-IP (%2) packet") << node->getSparkleIP()
			<< QString::number(ntohs(eth->type), 16).rightJustified(4, '0');
		return;
	}

	QByteArray payload = packet.right(packet.size() - sizeof(ethernet_header_t));
	const ipv4_header_t* ip = (const ipv4_header_t*) payload.constData();

	if(ntohl(ip->src) != node->getSparkleIP().toIPv4Address()) {
		Log::warn("ethernet: received IPv4 packet with malformed source address");
		return;
	}

	if(ntohl(ip->dest) != self->getSparkleIP().toIPv4Address()) {
		Log::warn("ethernet: received IPv4 packet with malformed destination address");
		return;
	}
	
	emit sendTapPacket(packet);
}

void EthernetApplicationLayer::attachLinkLayer(LinkLayer *link) {
	this->link = link;
}

void EthernetApplicationLayer::attachTap(TapInterface *tap) {
	connect(tap, SIGNAL(havePacket(QByteArray)), SLOT(haveTapPacket(QByteArray)));
	connect(link, SIGNAL(joined(SparkleNode *)), tap, SLOT(joined(SparkleNode *)));
	connect(this, SIGNAL(sendTapPacket(QByteArray)), tap, SLOT(sendPacket(QByteArray)));

}

void EthernetApplicationLayer::haveTapPacket(QByteArray packet) {
	const ethernet_header_t* eth = (const ethernet_header_t*) packet.constData();
	SparkleNode* self = router.getSelfNode();

	if(memcmp(eth->src, self->getSparkleMAC().constData(), 6) != 0) {
		Log::warn("ethernet: local packet from unknown source MAC");
		return;
	}
	
	QByteArray payload = packet.right(packet.size() - sizeof(ethernet_header_t));
	switch(ntohs(eth->type)) {
		case 0x0806: { // ARP
			if(memcmp(eth->dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0) {
				Log::warn("ethernet: non-broadcasted local ARP packet");
				return;
			}
			
			const arp_packet_t* arp = (const arp_packet_t*) payload.constData();
			if(!(ntohs(arp->htype) == 1 /* ethernet */ && ntohs(arp->ptype) == 0x0800 /* ipv4 */ &&
				arp->hlen == 6 && arp->plen == 4 &&
					ntohl(arp->spa) == self->getSparkleIP().toIPv4Address() &&
					!memcmp(arp->sha, eth->src, 6))) {
				Log::warn("link: invalid local arp packet received");
				return;
			}
			
			if(ntohs(arp->oper) == 1 /* request */) {
				QHostAddress dest(ntohl(arp->tpa));
				SparkleNode* resolved = router.searchSparkleNode(dest);
				if(resolved == NULL) {
					if(!self->isMaster())
						link->sendRouteRequest(dest);
					else
						Log::info("ethernet: no route to %1") << dest;
				} else {
					sendARPReply(resolved);
				}
			} else {
				Log::info("ethernet: ARP packet with unexpected OPER=%1 received") << ntohs(arp->oper);
				return;
			}
			
			break;
		}
		
		case 0x0800: { // IPv4
			const ipv4_header_t* ip = (const ipv4_header_t*) payload.constData();
			if(ntohl(ip->src) != self->getSparkleIP().toIPv4Address()) {
				Log::warn("ethernet: received local IPv4 packet with malformed source address");
				return;
			}
			
			QHostAddress dest(ntohl(ip->dest));
			SparkleNode* resolved = router.searchSparkleNode(dest);
			if(resolved != NULL) {
				link->sendDataToNode(packet, resolved);
			} else if(htonl(ip->dest) == 0x0effffff) { // ignore broadcasta
				/* do nothing */
			} else if(htonl(ip->dest) >> 24 != 0xE0) { // avoid link-local
				Log::info("ethernet: received local IPv4 packet for unknown destination [%1]")
						<< dest;
			}
			break;
		}
		
		case 0x86dd: { // IPv6
			/* Silently ignore. There're no IPv6 addresses assigned to iface anyway */
			break;
		}
		
		default: {
			Log::warn("ethernet: received local packet of unknown type %1")
					<< QString::number(ntohs(eth->type), 16).rightJustified(4, '0');
		}
	}
}

void EthernetApplicationLayer::sendARPReply(SparkleNode* node) {
	QByteArray packet(sizeof(ethernet_header_t) + sizeof(arp_packet_t), 0);
	SparkleNode* self = router.getSelfNode();
	
	ethernet_header_t* eth = (ethernet_header_t*) packet.data();
	memcpy(eth->dest, self->getSparkleMAC().constData(), 6);
	memcpy(eth->src, node->getSparkleMAC().constData(), 6);
	eth->type = htons(0x0806); // ARP
	
	arp_packet_t* arp = (arp_packet_t*) (packet.data() + sizeof(ethernet_header_t));
	arp->htype = htons(1); // ethernet
	arp->ptype = htons(0x0800); // IPv4
	arp->hlen = 6;
	arp->plen = 4;
	arp->oper = htons(2); // reply
	memcpy(arp->sha, eth->src, 6);
	arp->spa = htonl(node->getSparkleIP().toIPv4Address());
	memcpy(arp->tha, eth->dest, 6);
	arp->tpa = htonl(self->getSparkleIP().toIPv4Address());
	
	emit sendTapPacket(packet);
}

