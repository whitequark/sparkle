/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2009 Peter Zotov
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

#ifndef __LOG_H__
#define __LOG_H__

#include <QObject>
#include <QString>
#include <QStringList>

class Log {
	enum loglevel_t {
		Debug		= 1,
		Info		= 2,
		Warning		= 3,
		Error		= 4,
		Fatal		= 5
	};
	
	class Stream {
	public:
		Stream(QString _format, loglevel_t _loglevel) : format(_format), ref_count(1), loglevel(_loglevel), base(10) {}
	
		QString format;
		QStringList list;
		uint ref_count;
		loglevel_t loglevel;
		uint base;
	};
	
	Stream* stream;
	
public:
	inline Log(const char* format, loglevel_t loglevel = Info) : stream(new Stream(QString(format), loglevel)) {}
	inline ~Log() { Log::emitMessage(stream->loglevel, prepare()); }
	
	inline Log& operator<<(short v) { stream->list.append(QString::number(v, stream->base)); return *this; }
	inline Log& operator<<(ushort v){ stream->list.append(QString::number(v, stream->base)); return *this; }
	inline Log& operator<<(int v)   { stream->list.append(QString::number(v, stream->base)); return *this; }
	inline Log& operator<<(uint v)  { stream->list.append(QString::number(v, stream->base)); return *this; }
	inline Log& operator<<(long v)  { stream->list.append(QString::number(v, stream->base)); return *this; }
	inline Log& operator<<(ulong v) { stream->list.append(QString::number(v, stream->base)); return *this; }
	
	inline Log& operator<<(char v)		{ stream->list.append(QString(v)); return *this; }
	inline Log& operator<<(const char* v)	{ stream->list.append(v); return *this; }
	inline Log& operator<<(bool v)		{ stream->list.append(v ? "true" : "false"); return *this; }

	inline static Log debug(const char* format)	{ return Log(format, Debug);	}
	inline static Log info(const char* format)	{ return Log(format, Info);	}
	inline static Log warn(const char* format)	{ return Log(format, Warning);	}
	inline static Log error(const char* format)	{ return Log(format, Error);	}
	inline static Log fatal(const char* format)	{ return Log(format, Fatal);	}
	
	QString prepare();
	
	static void emitMessage(loglevel_t loglevel, QString message);
};

#endif
