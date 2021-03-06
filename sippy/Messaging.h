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

#ifndef MESSAGING_H
#define MESSAGING_H

#include <Qt>
#include <QObject>
#include <QString>
#include <QDateTime>
#include <Sparkle/SparkleAddress>

namespace Messaging {
	enum PeerState { /* an insider joke */
		Present       = 200,
		Unauthorized  = 403,
		NotPresent    = 404,
		InternalError = 500,
		Unavailable   = 503,
	};

	enum Status {
		Online,
		Away,
		Busy
	};

	enum PacketType {
		AuthorizationPacket = 1,
		MessagePacket       = 2,
	};

	class ControlPacket : public QObject
	{
		Q_OBJECT

	public:
		virtual QByteArray marshall() const;
		static ControlPacket* demarshall(QByteArray bytes, Sparkle::SparkleAddress peer);

		quint32 id() const	{ return _id; }
		PacketType type() const	{ return _type; }
		Sparkle::SparkleAddress peer() const	{ return _peer; }

		bool operator==(ControlPacket& other) { return _id == other.id(); }

	protected:
		ControlPacket(PacketType type, Sparkle::SparkleAddress peer);
		ControlPacket(QDataStream &stream, PacketType type, Sparkle::SparkleAddress peer);

	private:
		ControlPacket();

		quint32 _id;
		PacketType _type;
		Sparkle::SparkleAddress _peer;
	};

	class Authorization : public ControlPacket
	{
		Q_OBJECT

	public:
		Authorization(QString nick, QString reason, Sparkle::SparkleAddress peer) : ControlPacket(AuthorizationPacket, peer), _nick(nick), _reason(reason) { }

		Authorization(QDataStream &stream, Sparkle::SparkleAddress peer);
		virtual QByteArray marshall() const;

		QString nick() const	{ return _nick;	}
		QString reason() const	{ return _reason; }

	private:
		QString _nick, _reason;
	};

	class Message : public ControlPacket
	{
		Q_OBJECT

	public:
		Message(QString text, QDateTime timestamp, Sparkle::SparkleAddress peer) : ControlPacket(MessagePacket, peer), _timestamp(timestamp), _text(text) {}

		Message(QDataStream &stream, Sparkle::SparkleAddress peer);
		virtual QByteArray marshall() const;

		QDateTime timestamp() const	{ return _timestamp; }
		QString text() const		{ return _text; }

	private:
		QDateTime _timestamp;
		QString _text;
	};

	QString filterHTML(QString text);
}

#endif // MESSAGING_H
