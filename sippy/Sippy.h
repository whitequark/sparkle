/*
 * Sippy - zero-configuration fully distributed self-organizing encrypting IM
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

#ifndef ROSTER_H
#define ROSTER_H

#include <QMainWindow>
#include <QHostInfo>
#include "ui_Roster.h"
#include "ConnectDialog.h"

class LinkLayer;
class SippyApplicationLayer;
class ConfigurationStorage;
class DebugConsole;

class Sippy : public QMainWindow, private Ui_Roster {
	Q_OBJECT

	typedef enum { Connected, Disconnected, Connecting } ConnectState;

public:
	Sippy(ConfigurationStorage* config, DebugConsole* console, LinkLayer* linkLayer, SippyApplicationLayer* appLayer);

public slots:
	void connectToNetwork();
	void disconnectFromNetwork();

private slots:
	void lookupFinished(QHostInfo host);
	void joined();
	void joinFailed();
	void leaved();

private:
	Sippy();

	void connectStateChanged(ConnectState state);

	ConfigurationStorage* config;
	DebugConsole* console;
	LinkLayer* linkLayer;
	SippyApplicationLayer* appLayer;

	ConnectDialog connectDialog;
};

#endif // ROSTER_H
