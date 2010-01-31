/*
 * Sippy - zero-configuration fully distributed self-organizing encrypting IM
 * Copyright (C) 2010 Peter Zotov
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

#include "Messaging.h"
#include <QDataStream>

using namespace Messaging;

ControlPacket::ControlPacket(PacketType type, SparkleAddress peer) : _type(type), _peer(peer) {
	_id = qrand();
}

ControlPacket::ControlPacket(QDataStream &stream, PacketType type, SparkleAddress peer) : _type(type), _peer(peer) {
	stream >> _id;
}

ControlPacket* ControlPacket::demarshall(QByteArray bytes, SparkleAddress peer) {
	QDataStream stream(bytes);

	quint16 type;
	stream >> type;

	switch((PacketType) type) {
		case AuthorizationPacket:
		return new Authorization(stream, peer);

		case MessagePacket:
		return new Message(stream, peer);

		case CallRequestPacket:
		return new CallRequest(stream, peer);

		case CallOperatePacket:
		return new CallOperate(stream, peer);
	}

	return NULL;
}

QByteArray ControlPacket::marshall() const {
	QByteArray bytes;
	QDataStream stream(&bytes, QIODevice::WriteOnly);

	stream << (quint16) _type;
	stream << _id;

	return bytes;
}

Authorization::Authorization(QDataStream &stream, SparkleAddress peer) : ControlPacket(stream, AuthorizationPacket, peer) {
	stream >> _nick;
	stream >> _reason;
}

QByteArray Authorization::marshall() const {
	QByteArray bytes = ControlPacket::marshall();
	QDataStream stream(&bytes, QIODevice::Append);

	stream << _nick;
	stream << _reason;

	return bytes;
}

Message::Message(QDataStream &stream, SparkleAddress peer) : ControlPacket(stream, MessagePacket, peer) {
	stream >> _timestamp;
	stream >> _text;
}

QByteArray Message::marshall() const {
	QByteArray bytes = ControlPacket::marshall();
	QDataStream stream(&bytes, QIODevice::Append);

	stream << _timestamp;
	stream << _text;

	return bytes;
}

CallOperate::CallOperate(QDataStream& stream, SparkleAddress peer) : ControlPacket(stream, CallOperatePacket, peer) {
	stream >> (quint16&) _action;
}

QByteArray CallOperate::marshall() const {
	QByteArray bytes = ControlPacket::marshall();
	QDataStream stream(&bytes, QIODevice::Append);

	stream << (quint16) _action;

	return bytes;
}

QString Messaging::filterHTML(QString text) {
	text = text.replace("&", "&amp;");
	text = text.replace("<", "&lt;");
	text = text.replace(">", "&gt;");
	return text;
}
