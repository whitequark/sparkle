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

#include <QCoreApplication>
#include <stdio.h>
#include <stdlib.h>

#include <Sparkle/Log>
#include <Sparkle/SparkleNode>

using namespace Sparkle;

QString Log::prepare() {
	QString imm = stream->format;
	foreach(QString a, stream->list) {
		imm = imm.arg(a);
	}
	return imm;
}

void Log::emitMessage(loglevel_t loglevel, QString message) {
	QString final;
	switch(loglevel) {
		case Debug:	final = "[DEBUG] "; break;
		case Info:	final = "[INFO ] "; break;
		case Warning:	final = "[WARN ] "; break;
		case Error:	final = "[ERROR] "; break;
		case Fatal:	final = "[FATAL] "; break;

		default:	final = "[?????] "; break;
	}

	final += message;
	final += "\n";

	if(loglevel >= Warning) {
		fprintf(stderr, "%s", qPrintable(final));
	} else {
		fprintf(stdout, "%s", qPrintable(final));
		fflush(stdout);
	}

	if(loglevel == Fatal) {
		fprintf(stderr, "Fatal error encountered, exiting.\n");
		exit(1);
	}
}

Log& Log::operator<<(short v) {
	stream->list.append(QString::number(v, stream->base));
	
	return *this;
}

Log& Log::operator<<(ushort v) {
	stream->list.append(QString::number(v, stream->base));
	
	return *this;
}

Log& Log::operator<<(int v) {
	stream->list.append(QString::number(v, stream->base));
	
	return *this;
}

Log& Log::operator<<(uint v)  {
	stream->list.append(QString::number(v, stream->base));
	
	return *this;
}

Log& Log::operator<<(long v) {
	stream->list.append(QString::number(v, stream->base));
	
	return *this;
}

Log& Log::operator<<(ulong v) {
	stream->list.append(QString::number(v, stream->base));
	
	return *this;
}

Log& Log::operator<<(double v) {
	stream->list.append(QString::number(v, 'g', 4));
	
	return *this;
}

Log& Log::operator<<(char v) {
	stream->list.append(QString(v));
	
	return *this;
}

Log& Log::operator<<(const char* v)	{
	stream->list.append(v);
	
	return *this;
}

Log& Log::operator<<(bool v) {
	stream->list.append(v ? "true" : "false");
	
	return *this;
}

Log& Log::operator<<(const QString &v) {
	stream->list.append(v);
	
	return *this;
}

Log& Log::operator<<(const QHostAddress &v)	{
	stream->list.append(v.toString());
	
	return *this;
}

Log& Log::operator<<(const SparkleNode &v)	{
	return *this << v.realIP().toString() << v.realPort();
}
	
