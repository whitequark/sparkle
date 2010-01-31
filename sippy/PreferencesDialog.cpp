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

#include "PreferencesDialog.h"
#include "MessagingApplicationLayer.h"

PreferencesDialog::PreferencesDialog(MessagingApplicationLayer &_appLayer, QWidget *parent) : QDialog(parent), appLayer(_appLayer) {
	setupUi(this);

	connect(this, SIGNAL(accepted()), SLOT(close()));

	nickEdit->connect(&appLayer, SIGNAL(nickChanged(QString)), SLOT(setText(QString)));
}

void PreferencesDialog::accept() {
	appLayer.setNick(nickEdit->text());
	emit accepted();
}
