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

#include <QCoreApplication>
#include <QStringList>
#include <QHostInfo>
#include <QTimer>
#include <arpa/inet.h>

#include "LinkLayer.h"
#include "SparkleNode.h"
#include "PacketTransport.h"
#include "SHA1Digest.h"
#include "RoutesManager.h"

LinkLayer::LinkLayer(PacketTransport *transport, RSAKeyPair *hostPair,
		     QObject *parent) : QObject(parent)
{
	this->transport = transport;

	connect(transport, SIGNAL(receivedPacket(QByteArray&, QHostAddress&, quint16)),
		SLOT(handleDatagram(QByteArray&, QHostAddress&, quint16)));

	this->hostPair = hostPair;

	routes = new RoutesManager(this);

	pingTimer = new QTimer(this);
	pingTimer->setSingleShot(true);
	connect(pingTimer, SIGNAL(timeout()), SLOT(pingTimedOut()));
}

LinkLayer::~LinkLayer() {

}

bool LinkLayer::joinNetwork(QHostAddress host, quint16 port) {
	remoteAddress = host;
	remotePort = port;

	qDebug() << "link: joining via" << remoteAddress.toString() << "port" << remotePort;

	if(!transport->beginReceiving()) {
		qCritical() << "link: cannot initiate transport (port is already bound?)";

		return false;
	}
	
	isMaster = false;

	joinStep = RequestingProtocolVersion;
	sendProtocolVersionRequest(remoteAddress, remotePort);

	return true;
}

// FIXME FIXME FIXME FIXME FIXME
bool LinkLayer::createNetwork(QHostAddress local) {
	isMaster = true;

	QByteArray fingerprint = SHA1Digest::calculateSHA1(hostPair->getPublicKey());

//	node_def_t *def = new node_def_t;
//	this->localAddress = local;
//	def->addr = local;
//	def->port = transport->getPort();

//	def->sparkleMac = SparkleNode::calculateSparkleMac(fingerprint);
//	def->sparkleIP = SparkleNode::calculateSparkleIP(fingerprint);
	
//	sparkleIP = def->sparkleIP;
//	sparkleMac = def->sparkleMac;

//	masters.append(def);

	routes->addRoute(local, transport->getPort(), SparkleNode::calculateSparkleIP(fingerprint),
			 SparkleNode::calculateSparkleMac(fingerprint), true);

	qDebug() << "Network created, listening at port" << transport->getPort();

	transport->beginReceiving();

	QTimer::singleShot(0, this, SIGNAL(joined()));

	return true;
}

void LinkLayer::handleDatagram(QByteArray &data, QHostAddress &host, quint16 port) {
	const packet_header_t *hdr = (packet_header_t *) data.constData();

	if((size_t) data.size() < sizeof(packet_header_t) || hdr->length > data.size()) {
		qWarning() << "Malformed packet from" << host.toString() << ":" << port;

		return;
	}

	QByteArray payload = data.right(data.size() - sizeof(packet_header_t));

	SparkleNode *node = getOrConstructNode(host, port);

	switch((packet_type_t) hdr->type) {		
		case ProtocolVersionRequest: {
			protocol_version_reply_t ver;
			ver.version = ProtocolVersion;

			sendPacket(ProtocolVersionReply, node, QByteArray((const char *) &ver,
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
			node->setKeyNegotiationDone(false);

			node->setPublicKey(payload);

			sendPacket(PublicKeyReply, node, hostPair->getPublicKey(), false);

			break;
		}

		case PublicKeyReply: {
			node->setPublicKey(payload);

			node->getToKey()->generate();

			QByteArray key = node->getToKey()->getBytes();

			sendPacket(SessionKeyExchange, node, node->getRSA()->encrypt(key), false);

			break;
		}

		case SessionKeyExchange: {
			node->getToKey()->generate();

			node->getFromKey()->setBytes(hostPair->decrypt(payload));

			QByteArray toKey = node->getRSA()->encrypt(node->getToKey()->getBytes());

			sendPacket(SessionKeyReply, node, toKey, false);
			
			break;
		}

		case SessionKeyReply: {
			node->getFromKey()->setBytes(hostPair->decrypt(payload));

			sendPacket(SessionKeyAcknowlege, node, QByteArray(), false);

			node->setKeyNegotiationDone(true);

			while(!node->isQueueEmpty())
				sendAsEncrypted(node, node->popQueue());

			break;
		}

		case SessionKeyAcknowlege: {
			node->setKeyNegotiationDone(true);

			while(!node->isQueueEmpty())
				sendAsEncrypted(node, node->popQueue());

			break;
		}

		case EncryptedPacket: {
			if(!node->isKeyNegotiationDone()) {
				qWarning() << "link: received encrypted packet from unknown endpoint "
						<< host << ":" << port;

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

			sendPacket(Ping, node, pingData, false, req->port);

			ping_completed_t comp;
			comp.seq = req->seq;

			QByteArray compData((char *) &comp, sizeof(ping_completed_t));

			sendPacket(PingCompleted, node, compData, false);

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

			const node_def_t *def = routes->selectMaster();

			reply.addr = def->addr.toIPv4Address();
			reply.port = def->port;

			QByteArray data((char *) &reply, sizeof(reply));

			sendPacket(MasterNodeReply, node, data, true);

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
				register_reply_t reply;
				reply.addr = node->getSparkleIP().toIPv4Address();
				QByteArray mac = node->getSparkleMAC();
				memcpy(reply.mac, mac.data(), sizeof(reply.mac));

/*				node_def_t *def = new node_def_t;
				def->addr = host;
				def->port = port;
				def->sparkleIP = node->getSparkleIP();

				def->sparkleMac = mac;
*/
				const node_def_t *def;

				if((routes->getSlaveCount() + 1) / 10 > routes->getMasterCount()) {
					def = routes->addRoute(host, port, node->getSparkleIP(), mac, true);
					reply.isMaster = 1;
				} else {
					def = routes->addRoute(host, port, node->getSparkleIP(), mac, false);
					reply.isMaster = 0;
				}

				QByteArray data((char *) &reply, sizeof(reply));

				sendPacket(RegisterReply, node, data, true);

				QByteArray newRoute = formRoute(def, reply.isMaster == 1);

				QByteArray routingData;
				size_t size = 0;

				foreach(const node_def_t *ptr, routes->getMasters()) {
					if(ptr->sparkleIP != this->sparkleIP) {
						SparkleNode *masterNode = getOrConstructNode(ptr->addr,
											     ptr->port);

						sendPacket(RoutingTable, masterNode, newRoute, true);
					}

					routingData += formRoute(ptr, true);
					size += sizeof(routing_table_entry_t);

					if(size >= 65535 - sizeof(packet_header_t) * 2) {
						sendPacket(RoutingTable, node, routingData, true);
						size = 0;
						routingData.clear();
					}
				}

				if(reply.isMaster) {
					foreach(node_def_t *ptr, routes->getSlaves()) {
						SparkleNode *slaveNode = getOrConstructNode(ptr->addr,
											    ptr->port);

						sendPacket(RoutingTable, slaveNode, newRoute, true);

						routingData += formRoute(ptr, false);
						size += sizeof(routing_table_entry_t);

						if(size >= 65535 - sizeof(packet_header_t) * 2) {
							sendPacket(RoutingTable, node, routingData, true);
							size = 0;
							routingData.clear();
						}
					}
				} else {
					sendPacket(RoutingTable, node, newRoute, true);
				}

				if(size > 0)
					sendPacket(RoutingTable, node, routingData, true);
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

				sparkleMac = mac;
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
				const node_def_t *def;

				if(entry[i].isMaster)
					def = routes->addRoute(QHostAddress(entry[i].inetIP),
							 entry[i].port, QHostAddress(entry[i].sparkleIP),
							 QByteArray((char *) entry[i].sparkleMac, 6),
							 true);
				else
					def = routes->addRoute(QHostAddress(entry[i].inetIP),
							 entry[i].port, QHostAddress(entry[i].sparkleIP),
							 QByteArray((char *) entry[i].sparkleMac, 6),
							 false);

				qDebug() << "Route:" << def->sparkleIP.toString() << ">>"
						<< def->addr.toString() << ":" << def->port;

				foreach(QHostAddress *ptr, awaiting)
					if(*ptr == def->sparkleIP) {
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

			const node_def_t *requestedNode = routes->findByIP(QHostAddress(*ip));

			if(requestedNode == NULL)
				sendPacket(NoRouteForEntry, node, payload.left(sizeof(quint32)), true);
			else {
				sendPacket(RoutingTable, node,
					   formRoute(requestedNode, false), true);
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
			memcpy(mac.from, node->getSparkleMAC().data(), 6);
			memcpy(mac.to, sparkleMac.data(), 6);
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

void LinkLayer::sendPacket(packet_type_t type, SparkleNode *node, QByteArray data, bool encrypted,
			   quint16 port) {

	packet_header_t hdr;

	hdr.length = sizeof(packet_header_t) + data.size();
	hdr.type = type;

	data.prepend(QByteArray((const char *) &hdr, sizeof(packet_header_t)));

	if(!encrypted) {
		transport->sendPacket(data, node->getHost(), port == 0 ? node->getPort() : port);
	} else {
		if(!node->isKeyNegotiationDone()) {
			node->pushQueue(data);

			publicKeyExchange(node->getHost(), node->getPort());
		} else {
			sendAsEncrypted(node, data, port);
		}
	}
}

void LinkLayer::sendAsEncrypted(SparkleNode *node, QByteArray data, quint16 port) {
	data = node->getToKey()->encrypt(data);

	return sendPacket(EncryptedPacket, node, data, false, port);
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

	joinPingGot();
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
	SparkleNode *node = getOrConstructNode(host, port);

	QByteArray data;

	sendPacket(ProtocolVersionRequest, node, data, false);
}

void LinkLayer::sendMasterNodeRequest(QHostAddress host, quint16 port) {
	SparkleNode *node = getOrConstructNode(host, port);

	QByteArray data;

	sendPacket(MasterNodeRequest, node, data, true);
}

void LinkLayer::sendRegisterRequest(QHostAddress host, quint16 port) {
	SparkleNode *node = getOrConstructNode(host, port);

	QByteArray data;

	sendPacket(RegisterRequest, node, data, true);
}

void LinkLayer::publicKeyExchange(QHostAddress host, quint16 port) {
	SparkleNode *node = getOrConstructNode(host, port);

	node->setKeyNegotiationDone(false);

	sendPacket(PublicKeyExchange, node, hostPair->getPublicKey(), false);
}

void LinkLayer::sendPingRequest(quint32 seq, quint16 localport, QHostAddress host, quint16 port) {
	SparkleNode *node = getOrConstructNode(host, port);

	ping_request_t req;
	req.seq = seq;
	req.port = localport;

	QByteArray data((char *) &req, sizeof(ping_request_t));

	pingReceived = false;

	sendPacket(PingRequest, node, data, false);

	pingTime.start();
}

void LinkLayer::sendRouteRequest(QHostAddress address) {
	const node_def_t *master = routes->selectMaster();
	SparkleNode *masterNode = getOrConstructNode(master->addr, master->port);

	quint32 addr = address.toIPv4Address();

	sendPacket(RouteRequest, masterNode,
		   QByteArray((char *) &addr, sizeof(quint32)), true);
}


void LinkLayer::reverseMac(quint8 *mac) {
	quint8 nmac[6];

	for(int i = 0; i < 6; i++)
		nmac[i] = mac[5 - i];

	memcpy(mac, nmac, 6);
}

void LinkLayer::processPacket(QByteArray packet) {
	mac_header_t hdr;
	memcpy(&hdr, packet.data(), sizeof(mac_header_t));

//	reverseMac(hdr.from);
//	reverseMac(hdr.to);

	if(memcmp(hdr.from, sparkleMac.data(), 6) != 0)
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

			const node_def_t *node = routes->findByIP(target);

			if(node != NULL)
				sendARPReply(node);
			else {
				if(isMaster) {
					qDebug() << "Target not exists";

				} else {
					awaiting.append(new QHostAddress(target));

					sendRouteRequest(target);
				}
			}

		}
		break;
	}

	case 0x0800: {
		const node_def_t *node = routes->findByMAC(QByteArray((char *)hdr.to, 6));

		if(!node)
			break;

		SparkleNode *sparkleNode = getOrConstructNode(
				node->addr, node->port);

		sendPacket(DataPacket, sparkleNode, packet, true);

		break;
	}

	case 0x86dd:	// IPv6
		break;


	default:
		printf("Ethernet packet with data size %d and type 0x%x dropped\n", packet.size(), hdr.type);

		break;
	}
}

void LinkLayer::sendARPReply(const node_def_t *node) {
	mac_header_t mac;

	mac.type = htons(0x0806);
	memcpy(mac.from, node->sparkleMac, 6);
	memcpy(mac.to, sparkleMac.data(), 6);

	arp_packet_t arp;
	arp.htype = htons(1);
	arp.ptype = htons(0x800);
	arp.hlen = 6;
	arp.plen = 4;
	arp.oper = htons(2);
	memcpy(arp.sha, node->sparkleMac, 6);
	arp.spa = htonl(node->sparkleIP.toIPv4Address());
	memcpy(arp.tha, sparkleMac.data(), 6);
	arp.tpa = sparkleIP.toIPv4Address();

	QByteArray packet = QByteArray((char *) &mac, sizeof(mac_header_t)) +
			    QByteArray((char *) &arp, sizeof(arp_packet_t));

	emit sendPacketReq(packet);
}

QByteArray LinkLayer::formRoute(const node_def_t *node, bool isMaster) {
	routing_table_entry_t route;
	route.inetIP = node->addr.toIPv4Address();
	route.isMaster = isMaster ? 1 : 0;
	route.port = node->port;
	route.sparkleIP = node->sparkleIP.toIPv4Address();
	memcpy(route.sparkleMac, node->sparkleMac.data(), 6);

	return QByteArray((char *) &route, sizeof(routing_table_entry_t));
}
