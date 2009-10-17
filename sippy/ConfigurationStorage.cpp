/*
 * Sippy - zero-configuration fully distributed self-organizing encrypting IM
 * Copyright (C) 2009 Sergey Gridassov
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

#include <QSettings>

#include "ConfigurationStorage.h"

ConfigurationStorage::ConfigurationStorage(QObject *parent) : QObject(parent) {
	settings = new QSettings(QSettings::IniFormat, QSettings::UserScope, "Sparkle Team", "Sippy", this);
}

ConfigurationStorage::~ConfigurationStorage() {

}

bool ConfigurationStorage::createNetwork() {
	return settings->value("network/create", false).toBool();
}

void ConfigurationStorage::setCreateNetwork(bool create) {
	settings->setValue("network/create", create);
}

QString ConfigurationStorage::host() {
	return settings->value("network/host", "").toString();
}

void ConfigurationStorage::setHost(QString host) {
	settings->setValue("network/host", host);
}

bool ConfigurationStorage::behindNat() {
	return settings->value("network/behind_nat", false).toBool();
}

void ConfigurationStorage::setBehindNat(bool behind) {
	settings->setValue("network/behind_nat", behind);
}

bool ConfigurationStorage::autoLogin() {
	return settings->value("network/auto_login", false).toBool();
}

void ConfigurationStorage::setAutoLogin(bool login) {
	settings->setValue("network/auto_login", login);
}

QString ConfigurationStorage::getKeyName() {
	return settings->fileName() + ".key";
}

