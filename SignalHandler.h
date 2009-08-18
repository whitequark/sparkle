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

#ifndef _SIGNAL_HANDLER_H_
#define _SIGNAL_HANDLER_H_

#include <QObject>

class QSocketNotifier;

class SignalHandler : public QObject {
	Q_OBJECT

	friend void handle_sigint(int);
	friend void handle_sigterm(int);
	friend void handle_sighup(int);

public:
	static SignalHandler* getInstance();

signals:
	void sigint();
	void sigterm();
	void sighup();

private slots:
	void signalled(int sock);

private:
	SignalHandler();
	SignalHandler(SignalHandler&);

	static SignalHandler* instance;
	
	QSocketNotifier* notifier;
	int write_fd;
};

#endif

