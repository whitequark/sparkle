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

QString Messaging::filterHTML(QString text) {
	text = text.replace("&", "&amp;");
	text = text.replace("<", "&lt;");
	text = text.replace(">", "&gt;");
	return text;
}
