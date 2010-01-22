/*
 * Sippy - zero-configuration fully distributed self-organizing encrypting IM
 * Copyright (C) 2009 Sergey Gridassov, Peter Zotov
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
#include <QApplication>
#include <QStringList>
#include "ConfigurationStorage.h"

ConfigurationStorage::ConfigurationStorage(QObject *parent) : QObject(parent) {
	QString scope = "default";
	if(QApplication::arguments().count() > 1)
		scope = QApplication::arguments()[1];

	settings = new QSettings(QSettings::IniFormat, QSettings::UserScope, "sparkle", QString("sippy-%1").arg(scope), this);
	settings->setValue("sippy/version", "1");
	settings->sync();
}

ConfigurationStorage::~ConfigurationStorage() {

}

bool ConfigurationStorage::createNetwork() {
	return settings->value("network/create", false).toBool();
}

void ConfigurationStorage::setCreateNetwork(bool create) {
	settings->setValue("network/create", create);
}

QString ConfigurationStorage::address() {
	return settings->value("network/address", "").toString();
}

void ConfigurationStorage::setAddress(QString address) {
	settings->setValue("network/address", address);
}

quint16 ConfigurationStorage::port() {
	return settings->value("network/port", "1801").toInt();
}

void ConfigurationStorage::setPort(quint16 port) {
	settings->setValue("network/port", port);
}

bool ConfigurationStorage::behindNat() {
	return settings->value("network/behind_nat", false).toBool();
}

void ConfigurationStorage::setBehindNat(bool behind) {
	settings->setValue("network/behind_nat", behind);
}

bool ConfigurationStorage::autoLogin() {
	return settings->value("sippy/auto_login", false).toBool();
}

void ConfigurationStorage::setAutoLogin(bool login) {
	settings->setValue("sippy/auto_login", login);
}

QString ConfigurationStorage::getKeyName() {
	return settings->fileName() + ".key";
}

