#ifndef MESSAGING_H
#define MESSAGING_H

#include <Qt>
#include <QString>
#include <QDateTime>
#include <SparkleAddress.h>

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
		static ControlPacket* demarshall(QByteArray bytes, SparkleAddress peer);

		quint32 id() const	{ return _id; }
		PacketType type() const	{ return _type; }
		SparkleAddress peer() const	{ return _peer; }

		bool operator==(ControlPacket& other) { return _id == other.id(); }

	protected:
		ControlPacket(PacketType type, SparkleAddress peer);
		ControlPacket(QDataStream &stream, PacketType type, SparkleAddress peer);

	private:
		ControlPacket();

		quint32 _id;
		PacketType _type;
		SparkleAddress _peer;
	};

	class Authorization : public ControlPacket
	{
		Q_OBJECT

	public:
		Authorization(QString nick, QString reason, SparkleAddress peer) : ControlPacket(AuthorizationPacket, peer), _nick(nick), _reason(reason) { }

		Authorization(QDataStream &stream, SparkleAddress peer);
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
		Message(QString text, QDateTime timestamp, SparkleAddress peer) : ControlPacket(MessagePacket, peer), _timestamp(timestamp), _text(text) {}

		Message(QDataStream &stream, SparkleAddress peer);
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
