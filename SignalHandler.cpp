/*
 * Sparkle - zero-configuration fully distributed self-organizing encrypting VPN
 * Copyright (C) 2009 Peter Zotov
 *
 * Ths program is free software: you can redistribute it and/or modify
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

#include <QSocketNotifier>
#include <unistd.h>
#include <signal.h>

#include "SignalHandler.h"

SignalHandler* SignalHandler::instance;

void handle_sigint(int) {
	write(SignalHandler::getInstance()->write_fd, "I", 1);
}

void handle_sigterm(int) {
	write(SignalHandler::getInstance()->write_fd, "T", 1);
}

SignalHandler::SignalHandler() {
	int fd[2];
	pipe(fd);
	
	write_fd = fd[1];
	
	notifier = new QSocketNotifier(fd[0], QSocketNotifier::Read);
	connect(notifier, SIGNAL(activated(int)), SLOT(signalled(int)));
	
	signal(SIGINT, &handle_sigint);
	signal(SIGTERM, &handle_sigterm);
}

void SignalHandler::signalled(int sock) {
	char signal;
	read(sock, &signal, 1);
	
	switch(signal) {
		case 'I': emit sigint();  break;
		case 'T': emit sigterm(); break;
	}
}

SignalHandler* SignalHandler::getInstance() {
	if(instance == NULL)
		instance = new SignalHandler();
	return instance;
}

