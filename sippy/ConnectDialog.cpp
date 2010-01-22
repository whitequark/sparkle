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

#include "ConnectDialog.h"
#include "ui_ConnectDialog.h"
#include "ConfigurationStorage.h"

ConnectDialog::ConnectDialog(ConfigurationStorage* _config, QWidget *parent) :
		QDialog(parent), config(_config)
{
	setupUi(this);

	createNetwork->setChecked(config->createNetwork());
	address->setText(config->address());
	forceNATPassthrough->setChecked(config->behindNat());

	connect(createNetwork, SIGNAL(toggled(bool)), SLOT(checkOptions()));

	checkOptions();
}

void ConnectDialog::checkOptions() {
	forceNATPassthrough->setEnabled(!createNetwork->isChecked());
	if(createNetwork->isChecked())
		forceNATPassthrough->setChecked(false);
}

void ConnectDialog::accept() {
	config->setCreateNetwork(createNetwork->isChecked());
	config->setAddress(address->text());
	config->setBehindNat(forceNATPassthrough->isChecked());
	emit accepted();
}
