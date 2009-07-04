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
#include <cstdio>
#include <cstdlib>

#include "Log.h"

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
	
	final.replace('%', "%%"); // guard from printf() attack
	
	if(loglevel >= Warning)	std::fprintf(stderr, qPrintable(final));
	else			std::fprintf(stdout, qPrintable(final));
	
	if(loglevel == Fatal && !QCoreApplication::startingUp()) {
		std::fprintf(stderr, "Fatal error encountered, exiting.\n");
		QCoreApplication::exit(1);
	}
}

