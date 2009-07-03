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

#include <QCoreApplication>
#include <QStringList>
#include <QHostInfo>
#include <QTimer>
#include <arpa/inet.h>

#include "LinkLayer.h"
#include "SparkleNode.h"
#include "PacketTransport.h"
#include "SHA1Digest.h"

LinkLayer::LinkLayer(PacketTransport *transport, RSAKeyPair *hostPair,
		     QObject *parent) : QObject(parent)
{
	this->transport = transport;

	connect(transport, SIGNAL(receivedPacket(QByteArray&,QHostAddress&,quint16)),
		SLOT(handleDatagram(QByteArray&,QHostAddress&,quint16)));

	this->hostPair = hostPair;

	pingTimer = new QTimer(this);
	pingTimer->setSingleShot(true);
	connect(pingTimer, SIGNAL(timeout()), SLOT(pingTimedOut()));
}

LinkLayer::~LinkLayer() {

}

void hexdump(const char *title, QByteArray data) {
	printf("Dumping %s\n", title);

	unsigned char *raw = (unsigned char *) data.data();

	for(int i = 0; i < data.size(); i++) {
		if(i % 8 == 0)
			printf("\n");

		printf("%02X ", raw[i]);
	}

	printf("\n");
}

bool LinkLayer::joinNetwork(QString node) {
	QStringList parts = node.split(':');

	if(parts.count() != 2) {
		error = "Bad address format";

		return false;
	}

	remotePort = parts[1].toInt();

	printf("Looking up for %s... ", parts[0].toAscii().data());

	fflush(stdout);

	QHostInfo::lookupHost(parts[0], this, SLOT(joinTargetLookedUp(QHostInfo)));

	return true;
}

bool LinkLayer::createNetwork(QHostAddress local) {
	isMaster = true;

	QByteArray fingerprint = SHA1Digest::calculateSHA1(hostPair->getPublicKey());

	node_def_t *def = new node_def_t;
	this->localAddress = local;
	def->addr = local;
	def->port = transport->getPort();

	QByteArray mac = "\x02";
	mac += fingerprint.left(5);
	memcpy(def->sparkleMac, mac.data(), 6);

	char ip[4] = { 0, 0, 0, 14 };

	ip[0] = fingerprint[0];
	ip[1] = fingerprint[1];
	ip[2] = fingerprint[2];

	quint32 *num = (quint32 *) ip;

	def->sparkleAddress = QHostAddress(*num);
	sparkleIP = def->sparkleAddress;
	selfMac = mac;

	masters.append(def);

	qDebug() << "Network created, listening at port" << def->port;

	transport->beginReceiving();

	QTimer::singleShot(0, this, SIGNAL(joined()));

	return true;
}

QString LinkLayer::errorString() {
	return error;
}

void LinkLayer::handleDatagram(QByteArray &data, QHostAddress &host, quint16 port) {
	const packet_header_t *hdr = (packet_header_t *) data.constData();

	if((size_t) data.size() < sizeof(packet_header_t) || hdr->length > data.size()) {
		qWarning() << "Malformed packet from" << host.toString() << ":" << port;

		return;
	}

	QByteArray payload = data.right(data.size() - sizeof(packet_header_t));

	switch((packet_type_t) hdr->type) {		
	case ProtocolVersionRequest: {
		protocol_version_reply_t ver;
		ver.version = ProtocolVersion;

		sendPacket(ProtocolVersionReply, host, port, QByteArray((const char *) &ver,
							sizeof(protocol_version_reply_t)), false);

		break;
	}

	case ProtocolVersionReply: {
		if(hdr->length != sizeof(protocol_version_reply_t) + sizeof(packet_header_t)) {
			qWarning() << "Bad length" << hdr->length <<
				"on incoming packet from" << host.toString() << ":" << port;

			break;
		}
		protocol_version_reply_t *ver = (protocol_version_reply_t *) payload.data();

		if(joinStep == RequestingProtocolVersion)
			joinGotVersion(ver->version);

		break;
	}

	case PublicKeyExchange: {
		SparkleNode *node = getOrConstructNode(host, port);

		node->keyNegotiationDone = false;

		node->setPublicKey(payload);

		sendPacket(PublicKeyReply, host, port, hostPair->getPublicKey(), false);

		break;
	}

	case PublicKeyReply: {
		SparkleNode *node = getOrConstructNode(host, port);

		node->setPublicKey(payload);

		node->getToKey()->generate();

		QByteArray key = node->getToKey()->getKey();

		sendPacket(SessionKeyExchange, host, port, node->getRSA()->encrypt(key), false);

		break;
	}

	case SessionKeyExchange: {
		SparkleNode *node = getOrConstructNode(host, port);

		node->getToKey()->generate();

		node->getFromKey()->setKey(hostPair->decrypt(payload));

		QByteArray toKey = node->getRSA()->encrypt(node->getToKey()->getKey());

		sendPacket(SessionKeyReply, host, port, toKey, false);

		break;
	}

	case SessionKeyReply: {
		SparkleNode *node = getOrConstructNode(host, port);

		node->getFromKey()->setKey(hostPair->decrypt(payload));

		sendPacket(SessionKeyAcknowlege, host, port, QByteArray(), false);

		node->keyNegotiationDone = true;

		while(!node->isQueueEmpty())
			sendAsEncrypted(node, node->getFromQueue());


		break;
	}

	case SessionKeyAcknowlege: {
		SparkleNode *node = getOrConstructNode(host, port);

		node->keyNegotiationDone = true;

		while(!node->isQueueEmpty())
			sendAsEncrypted(node, node->getFromQueue());

		break;
	}

	case EncryptedPacket: {
		SparkleNode *node = getOrConstructNode(host, port);

		if(!node->keyNegotiationDone) {
			printf("Encrypted packet from unknown node\n");

			break;
		}

		QByteArray decData = node->getFromKey()->decrypt(payload);

		handleDatagram(decData, host, port);

		break;
	}

	case PingRequest: {
		if(hdr->length < sizeof(ping_request_t) + sizeof(packet_header_t)) {
			qWarning() << "Bad length" << hdr->length <<
				"on incoming packet from" << host.toString() << ":" << port;

			break;
		}

		ping_request_t *req = (ping_request_t *) payload.data();

		ping_t ping;
		ping.seq = req->seq;
		ping.addr = host.toIPv4Address();

		QByteArray pingData((char *) &ping, sizeof(ping_t));

		sendPacket(Ping, host, req->port, pingData, false);

		ping_completed_t comp;
		comp.seq = req->seq;

		QByteArray compData((char *) &comp, sizeof(ping_completed_t));

		sendPacket(PingCompleted, host, port, compData, false);

		break;
	}

	case Ping: {
		if(hdr->length < sizeof(ping_t) + sizeof(packet_header_t)) {
			qWarning() << "Bad length" << hdr->length <<
				"on incoming packet from" << host.toString() << ":" << port;

			break;
		}

		ping_t *ping = (ping_t *) payload.data();


		if(ping->seq == pingSeq) {
			qDebug() << "Ping:" << pingTime.elapsed() << "ms.";

			if(joinStep == RequestingPing) {
				pingReceived = true;

				localAddress = QHostAddress(ping->addr);

				if(pingTimer->isActive()) {
					pingTimer->stop();
					joinPingGot();
				}
			}
		}

		break;
	}

	case PingCompleted: {
		if(hdr->length < sizeof(ping_completed_t) + sizeof(packet_header_t)) {
			qWarning() << "Bad length" << hdr->length <<
				"on incoming packet from" << host.toString() << ":" << port;

			break;
		}

		ping_completed_t *ping = (ping_completed_t *) payload.data();

		if(joinStep == RequestingPing) {
			if(ping->seq == pingSeq) {
				if(pingReceived)
					joinPingGot();
				else
					pingTimer->start(10000);
			}
		}

		break;
	}


	/* все следующие пакеты зашифрованы */

	case MasterNodeRequest: {
		master_node_reply_t reply;

		node_def_t *def = selectMaster();

		reply.addr = def->addr.toIPv4Address();
		reply.port = def->port;

		QByteArray data((char *) &reply, sizeof(reply));

		sendPacket(MasterNodeReply, host, port, data, true);

		break;
	}

	case MasterNodeReply: {
		if(hdr->length < sizeof(master_node_reply_t) + sizeof(packet_header_t)) {
			qWarning() << "Bad length" << hdr->length <<
				"on incoming packet from" << host.toString() << ":" << port;

			break;
		}

		master_node_reply_t *ver = (master_node_reply_t *) payload.data();

		if(joinStep == RequestingMasterNode) {
			joinGotMaster(QHostAddress(ver->addr), ver->port);
		}

		break;
	}

	case RegisterRequest: {
		if(isMaster) {
			SparkleNode *node = getOrConstructNode(host, port);

			register_reply_t reply;
			reply.addr = node->getIP().toIPv4Address();
			QByteArray mac = node->getMAC();
			memcpy(reply.mac, mac.data(), sizeof(reply.mac));

			node_def_t *def = new node_def_t;
			def->addr = host;
			def->port = port;
			def->sparkleAddress = node->getIP();

			memcpy(def->sparkleMac, mac.data(), sizeof(reply.mac));

			if((slaves.count() + 1) / 10 > masters.count()) {
				reply.isMaster = 1;
				masters.append(def);
			} else {
				reply.isMaster = 0;
				slaves.append(def);
			}

			QByteArray data((char *) &reply, sizeof(reply));

			sendPacket(RegisterReply, host, port, data, true);

			routing_table_entry_t newRouteItem;
			newRouteItem.inetIP = def->addr.toIPv4Address();
			newRouteItem.isMaster = reply.isMaster;
			newRouteItem.port = def->port;
			newRouteItem.sparkleIP = def->sparkleAddress.toIPv4Address();
			memcpy(newRouteItem.sparkleMac, def->sparkleMac, 6);

			QByteArray newRoute((char *) &newRouteItem, sizeof(routing_table_entry_t));

			QByteArray routingData;
			size_t size = 0;

			foreach(node_def_t *ptr, masters) {
				routing_table_entry_t entry;
				entry.inetIP = ptr->addr.toIPv4Address();
				entry.isMaster = 1;
				entry.port = ptr->port;
				entry.sparkleIP = ptr->sparkleAddress.toIPv4Address();
				memcpy(entry.sparkleMac, ptr->sparkleMac, 6);

				QByteArray chunk((char *) &entry, sizeof(routing_table_entry_t));

				if(ptr->sparkleAddress != this->sparkleIP)
					sendPacket(RoutingTable, ptr->addr, ptr->port, newRoute, true);


				routingData += chunk;
				size += sizeof(routing_table_entry_t);

				if(size >= 65535 - sizeof(packet_header_t) * 2) {
					sendPacket(RoutingTable, host, port, routingData, true);
					size = 0;
					routingData.clear();
				}
			}

			if(reply.isMaster) {
				foreach(node_def_t *ptr, slaves) {
					routing_table_entry_t entry;
					entry.inetIP = ptr->addr.toIPv4Address();
					entry.isMaster = 0;
					entry.port = ptr->port;
					entry.sparkleIP = ptr->sparkleAddress.toIPv4Address();
					memcpy(entry.sparkleMac, ptr->sparkleMac, 6);

					routingData += QByteArray((char *) &entry, sizeof(routing_table_entry_t));
					size += sizeof(routing_table_entry_t);

					if(size >= 65535 - sizeof(packet_header_t) * 2) {
						sendPacket(RoutingTable, host, port, routingData, true);
						size = 0;
						routingData.clear();
					}
				}
			} else {
				sendPacket(RoutingTable, host, port, newRoute, true);
			}

			if(size > 0)
				sendPacket(RoutingTable, host, port, routingData, true);
		}

		break;
	}

	case RegisterReply: {

		if(hdr->length < sizeof(register_reply_t) + sizeof(packet_header_t)) {
			qWarning() << "Bad length" << hdr->length <<
				"on incoming packet from" << host.toString() << ":" << port;

			break;
		}

		if(joinStep == RegisteringInNetwork) {
			register_reply_t *reg = (register_reply_t *) payload.data();

			QByteArray mac((char *) reg->mac, sizeof(reg->mac));

			selfMac = mac;
			sparkleIP = QHostAddress(reg->addr);
			isMaster = reg->isMaster == 1;

			qDebug() << "Registered in network as" << (isMaster ? "master," : "slave,") <<
					"assigned IP" << sparkleIP.toString();

			joinStep = Joined;

			emit joined();
		}

		break;
	}

	case RoutingTable: {
		routing_table_entry_t *entry = (routing_table_entry_t *) payload.data();
		int count = payload.length() / sizeof(routing_table_entry_t);

		for(int i = 0; i < count; i++) {
			node_def_t *def = new node_def_t;

			def->addr = QHostAddress(entry[i].inetIP);
			def->port = entry[i].port;
			def->sparkleAddress = QHostAddress(entry[i].sparkleIP);
			memcpy(def->sparkleMac, entry[i].sparkleMac, 6);

			qDebug() << "Routing:" << def->sparkleAddress.toString() << ">>"
					<< def->addr.toString() << ":" << def->port;

			if(entry[i].isMaster)
				masters.append(def);
			else
				slaves.append(def);

			foreach(QHostAddress *ptr, awaiting)
				if(*ptr == def->sparkleAddress) {
					delete ptr;
					awaiting.removeOne(ptr);

					sendARPReply(def);
					break;
				}

		}

		break;
	}

	case RouteRequest: {
		if(hdr->length < sizeof(quint32) + sizeof(packet_header_t)) {
			qWarning() << "Bad length" << hdr->length <<
				"on incoming packet from" << host.toString() << ":" << port;

			break;
		}

		quint32 *ip = (quint32 *) payload.data();

		node_def_t *node = findByIP(QHostAddress(*ip));

		if(node == NULL)
			sendPacket(NoRouteForEntry, host, port, payload.left(sizeof(quint32)), true);
		else {
			routing_table_entry_t entry;
			entry.inetIP = node->addr.toIPv4Address();
			entry.isMaster = 0;
			entry.port = node->port;
			entry.sparkleIP = node->sparkleAddress.toIPv4Address();
			memcpy(entry.sparkleMac, node->sparkleMac, 6);

			sendPacket(RoutingTable, host, port,
				   QByteArray((char *) &entry, sizeof(routing_table_entry_t)), true);
		}

		break;
	}

	case NoRouteForEntry: {
		if(hdr->length < sizeof(quint32) + sizeof(packet_header_t)) {
			qWarning() << "Bad length" << hdr->length <<
				"on incoming packet from" << host.toString() << ":" << port;

			break;
		}

		quint32 *ip = (quint32 *) payload.data();

		QHostAddress target(*ip);

		qDebug() << target.toString() << "not exists in network";

		foreach(QHostAddress *ptr, awaiting) {
			if(*ptr == target) {
				delete ptr;
				awaiting.removeOne(ptr);
				break;
			}
		}

		break;
	}

	case DataPacket: {
		SparkleNode *node = getOrConstructNode(host, port);

		mac_header_t mac;
		memcpy(mac.from, node->getMAC().data(), 6);
		memcpy(mac.to, selfMac.data(), 6);
		mac.type = htons(0x0800);

		QByteArray packet = QByteArray((char *) &mac, sizeof(mac_header_t)) + payload;

		emit sendPacketReq(packet);

		break;
	}

	default:
		qWarning() << "Bad type" << hdr->type <<
			"on incoming packet from" << host.toString() << ":" << port;
	}
}

void LinkLayer::joinTargetLookedUp(QHostInfo host) {
	printf("done\n");

	if(host.error() != QHostInfo::NoError) {
		qCritical() << "Join failed: lookup error: " << host.errorString();

		QCoreApplication::exit(1);

		return;
	}

	foreach(QHostAddress addr, host.addresses()) {
		if(addr.protocol() == QAbstractSocket::IPv4Protocol) {
			remoteAddress = addr;

			qDebug() << "Joining via" << remoteAddress.toString() << "port" << remotePort;

			transport->beginReceiving();

			isMaster = false;

			joinStep = RequestingProtocolVersion;

			sendProtocolVersionRequest(remoteAddress, remotePort);

			return;
		}
	}

	qCritical() << "Join failed: IPv4 address not found";

	QCoreApplication::exit(1);
}

void LinkLayer::sendPacket(packet_type_t type, QHostAddress host, quint16 port,
			   QByteArray data, bool encrypted) {

	packet_header_t hdr;

	hdr.length = sizeof(packet_header_t) + data.size();
	hdr.type = type;

	data.prepend(QByteArray((const char *) &hdr, sizeof(packet_header_t)));

	if(!encrypted) {
		transport->sendPacket(data, host, port);
	} else {
		SparkleNode *node = getOrConstructNode(host, port);

		if(!node->keyNegotiationDone) {
			node->appendQueue(data);

			publicKeyExchange(host, port);
		} else {
			sendAsEncrypted(node, data);
		}
	}
}

void LinkLayer::sendAsEncrypted(SparkleNode *node, QByteArray data) {
	data = node->getToKey()->encrypt(data);

	return sendPacket(EncryptedPacket, node->getHost(), node->getPort(), data, false);
}

SparkleNode *LinkLayer::getOrConstructNode(QHostAddress host, quint16 port) {
	foreach(SparkleNode *node, nodes)
		if(node->getHost() == host && node->getPort() == port) {
			return node;
		}

	SparkleNode *node = new SparkleNode(host, port, this);

	nodes.append(node);

	return node;
}


void LinkLayer::joinGotVersion(int version) {
	if(version != ProtocolVersion) {
		qCritical() << "Join failed: protocol version not matching:" << version <<
				"in network," << ProtocolVersion << "in client";

		QCoreApplication::exit(1);
	}

	qDebug() << "Requesting ping";

	joinStep = RequestingPing;

	pingSeq = qrand();

	sendPingRequest(pingSeq, transport->getPort(), remoteAddress, remotePort);
}

void LinkLayer::pingTimedOut() {
	qCritical() << "Ping not passed though NAT. Forward port" << transport->getPort() <<
			"on your firewall";

	QCoreApplication::exit(1);
}

void LinkLayer::joinPingGot() {	
	qDebug() << "Requesting master node";

	joinStep = RequestingMasterNode;

	sendMasterNodeRequest(remoteAddress, remotePort);
}


void LinkLayer::joinGotMaster(QHostAddress host, quint16 port) {
	qDebug() << "Registering in network via master" << host.toString() << ":" << port;

	joinStep = RegisteringInNetwork;

	sendRegisterRequest(host, port);
}

void LinkLayer::sendProtocolVersionRequest(QHostAddress host, quint16 port) {
	QByteArray data;

	sendPacket(ProtocolVersionRequest, host, port, data, false);
}

void LinkLayer::sendMasterNodeRequest(QHostAddress host, quint16 port) {
	QByteArray data;

	sendPacket(MasterNodeRequest, host, port, data, true);
}

void LinkLayer::sendRegisterRequest(QHostAddress host, quint16 port) {
	QByteArray data;

	sendPacket(RegisterRequest, host, port, data, true);
}

void LinkLayer::publicKeyExchange(QHostAddress host, quint16 port) {
	SparkleNode *node = getOrConstructNode(host, port);

	node->keyNegotiationDone = false;

	sendPacket(PublicKeyExchange, host, port, hostPair->getPublicKey(), false);
}

LinkLayer::node_def_t *LinkLayer::selectMaster() {
	return masters.at(qrand() % masters.count());
}

void LinkLayer::sendPingRequest(quint32 seq, quint16 localport, QHostAddress host, quint16 port) {
	ping_request_t req;
	req.seq = seq;
	req.port = localport;

	QByteArray data((char *) &req, sizeof(ping_request_t));

	sendPacket(PingRequest, host, port, data, false);
	pingTime.start();
}

void LinkLayer::reverseMac(quint8 *mac) {
	quint8 nmac[6];

	for(int i = 0; i < 6; i++)
		nmac[i] = mac[5 - i];

	memcpy(mac, nmac, 6);
}

void LinkLayer::processEthernet(QByteArray packet) {

	mac_header_t hdr;
	memcpy(&hdr, packet.data(), sizeof(mac_header_t));

//	reverseMac(hdr.from);
//	reverseMac(hdr.to);

	if(memcmp(hdr.from, selfMac.data(), 6) != 0)
		return;

	hdr.type = ntohs(hdr.type);

//	hexdump("Incoming packet", packet);

	packet = packet.right(packet.size() - sizeof(mac_header_t));

	switch(hdr.type) {
	case 0x0806: {	// ARP
		arp_packet_t *arp = (arp_packet_t *) packet.data();
		if(ntohs(arp->htype) == 1 && ntohs(arp->ptype) == 0x800 &&
				arp->hlen == 6 && arp->plen == 4 &&
				ntohs(arp->oper) == 1) { // IPv4 over ethernet request

			QHostAddress target(ntohl(arp->tpa));

			foreach(QHostAddress *ptr, awaiting) {
				if(*ptr == target) {
					qDebug() << target.toString() << "still waiting resolution";

					return;
				}
			}


			qDebug() << "Searching for" << target.toString();

			node_def_t *node = findByIP(target);

			if(node != NULL)
				sendARPReply(node);
			else {
				if(isMaster) {
					qDebug() << "Target not exists";

				} else {
					qDebug() << "Requesting master for resolution";

					awaiting.append(new QHostAddress(target));

					sendRouteRequest(target);
				}
			}

		}
		break;
	}

	case 0x800: {
		node_def_t *node = findByMAC(hdr.to);

		if(!node) {
			qDebug() << "Warn: non-ARP packet to unknown node, dropped";

			break;
		}

		sendPacket(DataPacket, node->addr, node->port, packet, true);

		break;
	}

	case 0x86dd:	// IPv6
		break;


	default:
		printf("Ethernet packet with data size %d and type 0x%x dropped\n", packet.size(), hdr.type);

		break;
	}
}

void LinkLayer::sendARPReply(node_def_t *node) {
	mac_header_t mac;

	mac.type = htons(0x0806);
	memcpy(mac.from, node->sparkleMac, 6);
	memcpy(mac.to, selfMac.data(), 6);

	arp_packet_t arp;
	arp.htype = htons(1);
	arp.ptype = htons(0x800);
	arp.hlen = 6;
	arp.plen = 4;
	arp.oper = htons(2);
	memcpy(arp.sha, node->sparkleMac, 6);
	arp.spa = htonl(node->sparkleAddress.toIPv4Address());
	memcpy(arp.tha, selfMac.data(), 6);
	arp.tpa = sparkleIP.toIPv4Address();

	QByteArray packet = QByteArray((char *) &mac, sizeof(mac_header_t)) +
			    QByteArray((char *) &arp, sizeof(arp_packet_t));

	emit sendPacketReq(packet);
}

LinkLayer::node_def_t *LinkLayer::findByIP(QHostAddress ip) {
	foreach(node_def_t *def, masters)
		if(def->sparkleAddress == ip)
			return def;

	foreach(node_def_t *def, slaves)
		if(def->sparkleAddress == ip)
			return def;

	return NULL;
}

LinkLayer::node_def_t *LinkLayer::findByMAC(quint8 *mac) {
	foreach(node_def_t *def, masters)
		if(memcmp(def->sparkleMac, mac, 6) == 0)
			return def;

	foreach(node_def_t *def, slaves)
		if(memcmp(def->sparkleMac, mac, 6) == 0)
			return def;

	return NULL;
}


void LinkLayer::sendRouteRequest(QHostAddress address) {
	node_def_t *master = selectMaster();

	quint32 addr = address.toIPv4Address();

	sendPacket(RouteRequest, master->addr, master->port,
		   QByteArray((char *) &addr, sizeof(quint32)), true);
}
