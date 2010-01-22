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

#ifndef CONNECTDIALOG_H
#define CONNECTDIALOG_H

#include <QDialog>
#include "ui_ConnectDialog.h"

class ConfigurationStorage;

class ConnectDialog : public QDialog, private Ui_ConnectDialog {
	Q_OBJECT
public:
	ConnectDialog(ConfigurationStorage* config, QWidget *parent);

public slots:
	virtual void accept();

private slots:
	void checkOptions();

private:
	ConnectDialog();

	ConfigurationStorage* config;
};

#endif // CONNECTDIALOG_H
